//! Reference `/ipns/` Kad-DHT record validator (#198).
//!
//! Implements IPNS record validation per the spec
//! (https://specs.ipfs.tech/ipns/ipns-record/) for Ed25519 keys:
//!
//! - parses the `IpnsEntry` protobuf (`value=1`, `validityType=3`, `validity=4`,
//!   `sequence=5`, `ttl=6`, `pubKey=7`, `signatureV2=8`, `data=9`),
//! - verifies `signatureV2` over `"ipns-signature:" ‖ data` against the Ed25519
//!   key inlined in the `/ipns/<peer-id>` name,
//! - parses the DAG-CBOR `data` map (`Value` / `Validity` / `ValidityType` /
//!   `Sequence` / `TTL`) and cross-checks it against the protobuf fields,
//! - enforces monotonic `Sequence` against any existing record, and
//! - rejects records whose EOL `Validity` has elapsed.
//!
//! Non-Ed25519 names (e.g. RSA, where the key is carried in `pubKey`) are
//! rejected — this reference validator only covers the modern Ed25519 path.

const std = @import("std");
const pb = @import("../protobuf/wire.zig");
const pid = @import("peer_id");
const record_validator = @import("record_validator.zig");

const Ed25519 = std.crypto.sign.Ed25519;

const ipns_prefix = "/ipns/";
/// Domain-separation prefix for IPNS `signatureV2` (spec: signed bytes are
/// `"ipns-signature:" ‖ data`).
const signature_v2_domain = "ipns-signature:";
/// `ValidityType` 0 = EOL (the only defined type today).
const validity_type_eol: u64 = 0;

/// Decoded `IpnsEntry` protobuf (slices borrow the input record).
const Entry = struct {
    value: ?[]const u8 = null, // 1
    validity_type: ?u64 = null, // 3
    validity: ?[]const u8 = null, // 4
    sequence: ?u64 = null, // 5
    ttl: ?u64 = null, // 6
    signature_v2: ?[]const u8 = null, // 8
    data: ?[]const u8 = null, // 9
};

/// Decoded DAG-CBOR `data` map (slices borrow the input record).
const CborData = struct {
    value: ?[]const u8 = null,
    validity: ?[]const u8 = null,
    validity_type: ?u64 = null,
    sequence: ?u64 = null,
    ttl: ?u64 = null,
};

pub fn validate(
    ctx: ?*anyopaque,
    key: []const u8,
    value: []const u8,
    existing: ?[]const u8,
    now_ms: i64,
) record_validator.ValidationResult {
    const allocator = @as(*const std.mem.Allocator, @ptrCast(@alignCast(ctx.?))).*;
    if (!std.mem.startsWith(u8, key, ipns_prefix)) return .ignore;
    const name = key[ipns_prefix.len..];
    if (name.len == 0) return .reject;

    const entry = parseEntry(value) orelse return .reject;
    const data = entry.data orelse return .reject;
    const sig = entry.signature_v2 orelse return .reject;
    if (sig.len != Ed25519.Signature.encoded_length) return .reject;

    // Verify signatureV2 over the domain-separated `data` bytes against the key
    // inlined in the IPNS name. Binding the key to the name is what stops a peer
    // forging a record for a name it does not control.
    const pub_bytes = ed25519PubkeyFromIpnsName(allocator, name) catch return .reject;
    defer allocator.free(pub_bytes);
    if (pub_bytes.len != 32) return .reject;

    const signed = std.mem.concat(allocator, u8, &.{ signature_v2_domain, data }) catch return .reject;
    defer allocator.free(signed);

    const pk = Ed25519.PublicKey.fromBytes(pub_bytes[0..32].*) catch return .reject;
    const signature = Ed25519.Signature.fromBytes(sig[0..Ed25519.Signature.encoded_length].*);
    signature.verify(signed, pk) catch return .reject;

    const cdata = parseCborData(data) orelse return .reject;
    const seq = cdata.sequence orelse return .reject;

    // The protobuf top-level fields are advisory copies of the signed CBOR; if
    // present they must agree, so a peer cannot show one value to legacy readers
    // and another to the signature.
    if (entry.sequence) |s| if (s != seq) return .reject;
    if (entry.value) |v| if (cdata.value) |cv| if (!std.mem.eql(u8, v, cv)) return .reject;

    // Monotonic sequence: never replace a record with an older or equal one.
    if (existing) |prev| {
        if (parseEntry(prev)) |pe| {
            if (pe.data) |pdata| {
                if (parseCborData(pdata)) |pc| {
                    if (pc.sequence) |old| {
                        if (seq < old) return .reject;
                        if (seq == old) return .ignore;
                    }
                }
            }
        }
    }

    // EOL expiry: reject records whose validity timestamp has elapsed.
    const vtype = cdata.validity_type orelse entry.validity_type orelse validity_type_eol;
    if (vtype == validity_type_eol) {
        const validity = cdata.validity orelse entry.validity orelse return .reject;
        const expires_ms = parseRfc3339Ms(validity) orelse return .reject;
        if (now_ms > expires_ms) return .reject;
    }

    return .accept;
}

pub fn register(registry: *record_validator.Registry, allocator: *std.mem.Allocator) std.mem.Allocator.Error!void {
    try registry.register(ipns_prefix, validate, @ptrCast(allocator));
}

fn parseEntry(data: []const u8) ?Entry {
    var out: Entry = .{};
    var pos: usize = 0;
    while (pos < data.len) {
        const k = pb.decodeFieldKey(data[pos..]) catch return null;
        const fv = pb.nextFieldValue(data[pos + k.len ..], k.wire_type) catch return null;
        const total = k.len + fv.total;
        switch (k.field_number) {
            1 => out.value = fv.value,
            3 => out.validity_type = (pb.decodeVarUInt64(fv.value) catch return null).value,
            4 => out.validity = fv.value,
            5 => out.sequence = (pb.decodeVarUInt64(fv.value) catch return null).value,
            6 => out.ttl = (pb.decodeVarUInt64(fv.value) catch return null).value,
            8 => out.signature_v2 = fv.value,
            9 => out.data = fv.value,
            else => {},
        }
        pos += total;
    }
    return out;
}

// ── Minimal DAG-CBOR (the IPNS `data` map subset) ───────────────────────────

const CborReader = struct {
    data: []const u8,
    pos: usize = 0,

    const Head = struct { major: u8, arg: u64 };

    fn readHead(self: *CborReader) ?Head {
        if (self.pos >= self.data.len) return null;
        const b = self.data[self.pos];
        self.pos += 1;
        const major = b >> 5;
        const addl = b & 0x1f;
        const arg: u64 = switch (addl) {
            0...23 => addl,
            24 => self.readN(1) orelse return null,
            25 => self.readN(2) orelse return null,
            26 => self.readN(4) orelse return null,
            27 => self.readN(8) orelse return null,
            else => return null, // indefinite-length not allowed in DAG-CBOR
        };
        return .{ .major = major, .arg = arg };
    }

    fn readN(self: *CborReader, n: usize) ?u64 {
        if (self.pos + n > self.data.len) return null;
        var v: u64 = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) v = (v << 8) | self.data[self.pos + i];
        self.pos += n;
        return v;
    }

    fn readBytes(self: *CborReader, n: usize) ?[]const u8 {
        const len = std.math.cast(usize, n) orelse return null;
        if (self.pos + len > self.data.len) return null;
        const s = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return s;
    }

    /// Skip one item (only the major types that can appear in the IPNS map).
    fn skipValue(self: *CborReader, head: Head) ?void {
        switch (head.major) {
            0, 1 => {}, // int: fully consumed by the head
            2, 3 => _ = self.readBytes(head.arg) orelse return null,
            else => return null,
        }
        return {};
    }
};

fn parseCborData(data: []const u8) ?CborData {
    var r = CborReader{ .data = data };
    const head = r.readHead() orelse return null;
    if (head.major != 5) return null; // map
    var out: CborData = .{};
    var i: u64 = 0;
    while (i < head.arg) : (i += 1) {
        const kh = r.readHead() orelse return null;
        if (kh.major != 3) return null; // text key
        const name = r.readBytes(kh.arg) orelse return null;
        const vh = r.readHead() orelse return null;
        if (std.mem.eql(u8, name, "Value")) {
            if (vh.major != 2) return null;
            out.value = r.readBytes(vh.arg) orelse return null;
        } else if (std.mem.eql(u8, name, "Validity")) {
            if (vh.major != 2) return null;
            out.validity = r.readBytes(vh.arg) orelse return null;
        } else if (std.mem.eql(u8, name, "ValidityType")) {
            if (vh.major != 0) return null;
            out.validity_type = vh.arg;
        } else if (std.mem.eql(u8, name, "Sequence")) {
            if (vh.major != 0) return null;
            out.sequence = vh.arg;
        } else if (std.mem.eql(u8, name, "TTL")) {
            if (vh.major != 0) return null;
            out.ttl = vh.arg;
        } else {
            r.skipValue(vh) orelse return null;
        }
    }
    return out;
}

// ── RFC 3339 (IPNS `Validity`) → epoch milliseconds ─────────────────────────

/// Parse an IPNS EOL validity timestamp, e.g. `2099-12-31T23:59:59.000000000Z`,
/// into epoch milliseconds. Only the UTC (`Z`) form is accepted, matching the
/// IPNS spec. Returns null on any malformed input.
fn parseRfc3339Ms(s: []const u8) ?i64 {
    // YYYY-MM-DDTHH:MM:SS = 19 chars minimum, plus a trailing 'Z'.
    if (s.len < 20) return null;
    if (s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':') return null;
    if (s[s.len - 1] != 'Z') return null;
    const year = parseDigits(s[0..4]) orelse return null;
    const month = parseDigits(s[5..7]) orelse return null;
    const day = parseDigits(s[8..10]) orelse return null;
    const hour = parseDigits(s[11..13]) orelse return null;
    const min = parseDigits(s[14..16]) orelse return null;
    const sec = parseDigits(s[17..19]) orelse return null;
    if (month < 1 or month > 12 or day < 1 or day > 31) return null;
    if (hour > 23 or min > 59 or sec > 60) return null;

    var ms_frac: i64 = 0;
    if (s.len > 20) {
        if (s[19] != '.') return null;
        const frac = s[20 .. s.len - 1];
        if (frac.len == 0) return null;
        // Use the first three fractional digits (milliseconds); ignore the rest.
        var mult: i64 = 100;
        for (frac, 0..) |c, idx| {
            if (c < '0' or c > '9') return null;
            if (idx < 3) {
                ms_frac += @as(i64, c - '0') * mult;
                mult = @divTrunc(mult, 10);
            }
        }
    } else if (s.len != 20) {
        return null;
    }

    const days = daysFromCivil(@intCast(year), @intCast(month), @intCast(day));
    const secs = days * 86_400 + @as(i64, @intCast(hour)) * 3600 + @as(i64, @intCast(min)) * 60 + @as(i64, @intCast(sec));
    return secs * 1000 + ms_frac;
}

fn parseDigits(s: []const u8) ?u32 {
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

/// Days since the Unix epoch for a proleptic-Gregorian (y, m, d) — Howard
/// Hinnant's `days_from_civil`.
fn daysFromCivil(y_in: i64, m: i64, d: i64) i64 {
    const y = y_in - @as(i64, @intFromBool(m <= 2));
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400; // [0, 399]
    const doy = @divTrunc(153 * (m + (if (m > 2) @as(i64, -3) else 9)) + 2, 5) + d - 1; // [0, 365]
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy; // [0, 146096]
    return era * 146097 + doe - 719468;
}

const multihash_identity_code: u16 = 0x00;

fn ed25519PubkeyFromIpnsName(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const peer = try pid.PeerId.fromString(allocator, name);
    const mh = peer.getMultihash();
    if (@intFromEnum(mh.getCode()) != multihash_identity_code) return error.NotIdentityKey;
    const digest = mh.getDigest();
    var reader = try pid.PublicKeyReader.init(digest);
    if (reader.getType() != .ED25519) return error.NotEd25519;
    const data = reader.getData();
    if (data.len != 32) return error.InvalidKeyLength;
    return try allocator.dupe(u8, data);
}

// ── CBOR encode (test/tooling helper) ───────────────────────────────────────

fn cborUintHead(out: *std.ArrayList(u8), allocator: std.mem.Allocator, major: u8, n: u64) !void {
    const m: u8 = major << 5;
    if (n < 24) {
        try out.append(allocator, m | @as(u8, @intCast(n)));
    } else if (n <= 0xff) {
        try out.appendSlice(allocator, &.{ m | 24, @intCast(n) });
    } else if (n <= 0xffff) {
        try out.append(allocator, m | 25);
        try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(n))));
    } else if (n <= 0xffff_ffff) {
        try out.append(allocator, m | 26);
        try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, @intCast(n))));
    } else {
        try out.append(allocator, m | 27);
        try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u64, n)));
    }
}

fn cborText(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try cborUintHead(out, allocator, 3, s.len);
    try out.appendSlice(allocator, s);
}

fn cborBytes(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try cborUintHead(out, allocator, 2, s.len);
    try out.appendSlice(allocator, s);
}

/// Build the DAG-CBOR `data` map in canonical key order (length then bytewise):
/// `TTL` < `Value` < `Sequence` < `Validity` < `ValidityType`.
fn buildCborData(
    allocator: std.mem.Allocator,
    value: []const u8,
    validity: []const u8,
    sequence: u64,
    ttl: u64,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try cborUintHead(&out, allocator, 5, 5); // map(5)
    try cborText(&out, allocator, "TTL");
    try cborUintHead(&out, allocator, 0, ttl);
    try cborText(&out, allocator, "Value");
    try cborBytes(&out, allocator, value);
    try cborText(&out, allocator, "Sequence");
    try cborUintHead(&out, allocator, 0, sequence);
    try cborText(&out, allocator, "Validity");
    try cborBytes(&out, allocator, validity);
    try cborText(&out, allocator, "ValidityType");
    try cborUintHead(&out, allocator, 0, validity_type_eol);
    return out.toOwnedSlice(allocator);
}

/// Build a spec-shaped, signatureV2-signed IPNS record for tests and tooling.
pub fn buildSignedRecord(
    allocator: std.mem.Allocator,
    kp: Ed25519.KeyPair,
    sequence: u64,
    value: []const u8,
    validity: []const u8,
) ![]u8 {
    const ttl: u64 = 3600 * 1_000_000_000; // 1h in ns (spec TTL unit)
    const data = try buildCborData(allocator, value, validity, sequence, ttl);
    defer allocator.free(data);

    const signed = try std.mem.concat(allocator, u8, &.{ signature_v2_domain, data });
    defer allocator.free(signed);
    const sig = try kp.sign(signed, null);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try pb.appendLengthDelimited(&out, allocator, 1, value);
    try pb.appendFieldKey(&out, allocator, 3, .varint);
    try pb.appendVarUInt64(&out, allocator, validity_type_eol);
    try pb.appendLengthDelimited(&out, allocator, 4, validity);
    try pb.appendFieldKey(&out, allocator, 5, .varint);
    try pb.appendVarUInt64(&out, allocator, sequence);
    try pb.appendFieldKey(&out, allocator, 6, .varint);
    try pb.appendVarUInt64(&out, allocator, ttl);
    try pb.appendLengthDelimited(&out, allocator, 8, &sig.toBytes());
    try pb.appendLengthDelimited(&out, allocator, 9, data);
    return out.toOwnedSlice(allocator);
}

const far_future = "2099-12-31T23:59:59.000000000Z";

fn ipnsKeyForKeyPair(allocator: std.mem.Allocator, kp: Ed25519.KeyPair) ![]u8 {
    const peer = try @import("../keypair.zig").peerIdFromKeyPair(allocator, .{ .ed25519 = kp });
    var b58_buf: [128]u8 = undefined;
    const b58 = try peer.toBase58(&b58_buf);
    return std.fmt.allocPrint(allocator, "/ipns/{s}", .{b58});
}

test "ipns validator accepts monotonic signed records" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const key = try ipnsKeyForKeyPair(a, kp);
    defer a.free(key);

    const rec1 = try buildSignedRecord(a, kp, 1, "/ipfs/bafy", far_future);
    defer a.free(rec1);
    const rec2 = try buildSignedRecord(a, kp, 2, "/ipfs/bafy2", far_future);
    defer a.free(rec2);

    var reg = record_validator.Registry.init(a);
    defer reg.deinit();
    var alloc_slot = a;
    try register(&reg, &alloc_slot);

    try std.testing.expect(reg.validate(key, rec1, null, 0) == .accept);
    try std.testing.expect(reg.validate(key, rec2, rec1, 0) == .accept);
    try std.testing.expect(reg.validate(key, rec1, rec2, 0) == .reject); // older sequence
    try std.testing.expect(reg.validate(key, rec2, rec2, 0) == .ignore); // equal sequence
}

test "ipns validator rejects tampered signature" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x43);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const key = try ipnsKeyForKeyPair(a, kp);
    defer a.free(key);

    const rec = try buildSignedRecord(a, kp, 1, "/ipfs/bafy", far_future);
    defer a.free(rec);
    const bad = try a.dupe(u8, rec);
    defer a.free(bad);
    bad[bad.len - 1] ^= 0xFF; // corrupt the trailing CBOR data byte

    var reg = record_validator.Registry.init(a);
    defer reg.deinit();
    var alloc_slot = a;
    try register(&reg, &alloc_slot);
    try std.testing.expect(reg.validate(key, bad, null, 0) == .reject);
}

test "ipns validator rejects records signed by a different key" {
    const a = std.testing.allocator;
    var seed_a: [32]u8 = undefined;
    @memset(&seed_a, 0x11);
    var seed_b: [32]u8 = undefined;
    @memset(&seed_b, 0x22);
    const kp_a = try Ed25519.KeyPair.generateDeterministic(seed_a);
    const kp_b = try Ed25519.KeyPair.generateDeterministic(seed_b);

    // Record signed by B, but published under A's name → must be rejected.
    const key_a = try ipnsKeyForKeyPair(a, kp_a);
    defer a.free(key_a);
    const rec_b = try buildSignedRecord(a, kp_b, 1, "/ipfs/bafy", far_future);
    defer a.free(rec_b);

    var reg = record_validator.Registry.init(a);
    defer reg.deinit();
    var alloc_slot = a;
    try register(&reg, &alloc_slot);
    try std.testing.expect(reg.validate(key_a, rec_b, null, 0) == .reject);
}

test "ipns validator rejects expired records" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x55);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const key = try ipnsKeyForKeyPair(a, kp);
    defer a.free(key);

    const rec = try buildSignedRecord(a, kp, 1, "/ipfs/bafy", "2000-01-01T00:00:00.000000000Z");
    defer a.free(rec);

    var reg = record_validator.Registry.init(a);
    defer reg.deinit();
    var alloc_slot = a;
    try register(&reg, &alloc_slot);

    // now = 2001-ish (ms): past the validity → reject; a now before 2000 accepts.
    try std.testing.expect(reg.validate(key, rec, null, 978_307_200_000) == .reject);
    try std.testing.expect(reg.validate(key, rec, null, 0) == .accept);
}

test "rfc3339 parses to epoch milliseconds" {
    try std.testing.expectEqual(@as(?i64, 0), parseRfc3339Ms("1970-01-01T00:00:00Z"));
    try std.testing.expectEqual(@as(?i64, 1000), parseRfc3339Ms("1970-01-01T00:00:01Z"));
    try std.testing.expectEqual(@as(?i64, 1_500), parseRfc3339Ms("1970-01-01T00:00:01.5Z"));
    try std.testing.expectEqual(@as(?i64, null), parseRfc3339Ms("2020-01-01 00:00:00Z"));
    try std.testing.expectEqual(@as(?i64, null), parseRfc3339Ms("2020-01-01T00:00:00")); // no Z
}

// Cross-implementation interop vector: a real IPNS record marshaled by go
// (boxo `ipns.NewRecord` + `MarshalRecord`) for a deterministic Ed25519 key
// (seed = 0x42×32), value `/ipfs/bafybeig…`, sequence 7, EOL 2099-12-31. The
// name below is go's canonical base36 CIDv1 libp2p-key form. Regenerate with
// `scripts/gen-ipns-vector`. This proves the validator accepts records produced
// by the reference implementation — not only by our own `buildSignedRecord`.
const boxo_ipns_name = "/ipns/k51qzi5uqu5dh0hmqwzu47an7qt7e1h5lyer5kjjntgl9e4qwb07kctxsovmdu";
const boxo_ipns_record_b64 =
    "CkEvaXBmcy9iYWZ5YmVpZ2R5cnp0NXNmcDd1ZG03aHU3NnVoN3kyNm5mM2VmdXlscWFiZjNvY2xn" ++
    "dHF5NTVmYnpkaRJAt3DvX1QnNiYj9KZ0f2L+m0UsoQ/Xf3voJeo2dryiiY+Z04tj5rCFDxMug48" ++
    "dvTRriKoWiuv/qUDwfsqwjUqDDRgAIhQyMDk5LTEyLTMxVDIzOjU5OjU5WigHMIDA4oXjaEJALzco" ++
    "TtKujP6f9JhQVAmuIj9FK75ZQR6t2ekanLt3dtb0Foyyn3OzMb1Z63RK3OCZBpZb46sjC50jxes" ++
    "vLrk2DEqNAaVjVFRMGwAAA0YwuKAAZVZhbHVlWEEvaXBmcy9iYWZ5YmVpZ2R5cnp0NXNmcDd1ZG03" ++
    "aHU3NnVoN3kyNm5mM2VmdXlscWFiZjNvY2xndHF5NTVmYnpkaWhTZXF1ZW5jZQdoVmFsaWRpdHlU" ++
    "MjA5OS0xMi0zMVQyMzo1OTo1OVpsVmFsaWRpdHlUeXBlAA==";

test "ipns validator accepts a go (boxo) reference record" {
    const a = std.testing.allocator;
    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(boxo_ipns_record_b64);
    const rec = try a.alloc(u8, n);
    defer a.free(rec);
    try dec.decode(rec, boxo_ipns_record_b64);

    var reg = record_validator.Registry.init(a);
    defer reg.deinit();
    var alloc_slot = a;
    try register(&reg, &alloc_slot);

    // Accept under the record's EOL (2099); reject once that validity elapses.
    try std.testing.expect(reg.validate(boxo_ipns_name, rec, null, 0) == .accept);
    const after_eol_ms: i64 = 4_200_000_000_000; // ~2103
    try std.testing.expect(reg.validate(boxo_ipns_name, rec, null, after_eol_ms) == .reject);

    // The parsed sequence must match what go signed (7).
    const entry = parseEntry(rec).?;
    try std.testing.expectEqual(@as(?u64, 7), entry.sequence);
}
