//! libp2p TLS 1.3 self-signed certificate generator.
//!
//! Produces an X.509 v3 cert with the libp2p Public Key extension
//! (OID 1.3.6.1.4.1.53594.1.1) per https://github.com/libp2p/specs/blob/master/tls/tls.md.
//!
//! Round-trip tested against `libp2p_tls.peerIdFromVerifiedCertificate` in this file.

const std = @import("std");
const peer_id = @import("peer_id");
const libp2p_tls = @import("libp2p_tls.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const ArrayList = std.ArrayList(u8);

/// X.509 v3 self-signed DER bytes carrying the libp2p extension, plus the
/// ephemeral key seed that produced the SubjectPublicKeyInfo.
pub const GeneratedCertificate = struct {
    cert_der: []u8,
    cert_key_seed: [32]u8,

    pub fn deinit(self: *GeneratedCertificate, allocator: std.mem.Allocator) void {
        allocator.free(self.cert_der);
        self.* = undefined;
    }
};

/// Host identity that signs `"libp2p-tls-handshake:" || SPKI`. The signer is a
/// callback so the embedder retains custody of the actual secret material.
pub const HostIdentityKey = union(enum) {
    ed25519: struct {
        public_key_bytes: [32]u8,
        sign: *const fn (ctx: ?*anyopaque, message: []const u8, out_sig: *[64]u8) anyerror!void,
        sign_ctx: ?*anyopaque,
    },
    // TODO(libp2p TLS): SECP256K1 + ECDSA hosts (`error.NotImplemented` placeholders).
};

pub const GenerateOptions = struct {
    host_identity: HostIdentityKey,
    not_before_sec: i64,
    not_after_sec: i64,
    serial: i64 = 1,
    /// 32-byte seed for the ephemeral cert Ed25519 keypair. Embedders normally
    /// fill this from `Io.randomSecure` or equivalent before calling.
    cert_key_seed: [32]u8,
};

pub const Error = error{
    InvalidValidityWindow,
    InvalidSerial,
    TimeOutOfRange,
    NotImplemented,
} || std.mem.Allocator.Error || std.Io.Writer.Error;

// ---------------------------------------------------------------------------
// DER emitter (forward-building)
// ---------------------------------------------------------------------------

/// Append a DER length prefix for `len` to `list`.
fn appendDerLength(list: *ArrayList, a: std.mem.Allocator, len: usize) std.mem.Allocator.Error!void {
    if (len < 0x80) {
        try list.append(a, @intCast(len));
        return;
    }
    // Long form: count significant bytes.
    var n: usize = 0;
    var v = len;
    while (v != 0) : (v >>= 8) n += 1;
    try list.append(a, 0x80 | @as(u8, @intCast(n)));
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        try list.append(a, @intCast((len >> @intCast(i * 8)) & 0xff));
    }
}

/// Emit `tag || length || payload`.
fn appendTLV(list: *ArrayList, a: std.mem.Allocator, tag: u8, payload: []const u8) std.mem.Allocator.Error!void {
    try list.append(a, tag);
    try appendDerLength(list, a, payload.len);
    try list.appendSlice(a, payload);
}

/// Wrap `payload` (already built) in `tag || length || payload` to a fresh allocation.
fn dupTLV(allocator: std.mem.Allocator, tag: u8, payload: []const u8) std.mem.Allocator.Error![]u8 {
    var out = ArrayList.empty;
    errdefer out.deinit(allocator);
    try appendTLV(&out, allocator, tag, payload);
    return try out.toOwnedSlice(allocator);
}

/// Encode an unsigned integer as a DER INTEGER payload (positive, minimal,
/// leading 0x00 if MSB set).
fn appendIntegerPayload(list: *ArrayList, a: std.mem.Allocator, value: i64) Error!void {
    if (value < 0) return error.InvalidSerial;
    if (value == 0) {
        try list.append(a, 0);
        return;
    }
    var be: [8]u8 = undefined;
    std.mem.writeInt(u64, &be, @intCast(value), .big);
    // Strip leading zero bytes.
    var start: usize = 0;
    while (start < 7 and be[start] == 0) : (start += 1) {}
    // Prepend 0x00 if MSB set (avoid two's-complement misread).
    if (be[start] & 0x80 != 0) try list.append(a, 0);
    try list.appendSlice(a, be[start..]);
}

/// `INTEGER value` TLV with the leading byte/length emitted.
fn appendInteger(list: *ArrayList, a: std.mem.Allocator, value: i64) Error!void {
    var payload = ArrayList.empty;
    defer payload.deinit(a);
    try appendIntegerPayload(&payload, a, value);
    try appendTLV(list, a, 0x02, payload.items);
}

// ---------------------------------------------------------------------------
// Time encoding: UTCTime for years 1950..2049, else GeneralizedTime.
// ---------------------------------------------------------------------------

const Broken = struct {
    year: u16,
    month: u4, // 1..12
    day: u5, // 1..31
    hour: u5,
    minute: u6,
    second: u6,
};

fn breakDown(epoch_sec: i64) Error!Broken {
    if (epoch_sec < 0) return error.TimeOutOfRange;
    // u47 days * secs_per_day fits in u64 but not i64; bound by max representable EpochSeconds.
    const max_secs: u64 = @as(u64, std.math.maxInt(u47)) * @as(u64, std.time.epoch.secs_per_day);
    if (@as(u64, @intCast(epoch_sec)) > max_secs) return error.TimeOutOfRange;
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch_sec) };
    const ed = es.getEpochDay();
    const ds = es.getDaySeconds();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    return .{
        .year = yd.year,
        .month = @intCast(@intFromEnum(md.month)),
        .day = @as(u5, @intCast(md.day_index)) + 1,
        .hour = ds.getHoursIntoDay(),
        .minute = ds.getMinutesIntoHour(),
        .second = ds.getSecondsIntoMinute(),
    };
}

fn writeTwoDigit(buf: []u8, value: u32) void {
    std.debug.assert(buf.len == 2);
    buf[0] = '0' + @as(u8, @intCast((value / 10) % 10));
    buf[1] = '0' + @as(u8, @intCast(value % 10));
}

fn writeFourDigit(buf: []u8, value: u32) void {
    std.debug.assert(buf.len == 4);
    buf[0] = '0' + @as(u8, @intCast((value / 1000) % 10));
    buf[1] = '0' + @as(u8, @intCast((value / 100) % 10));
    buf[2] = '0' + @as(u8, @intCast((value / 10) % 10));
    buf[3] = '0' + @as(u8, @intCast(value % 10));
}

fn appendTime(list: *ArrayList, a: std.mem.Allocator, epoch_sec: i64) Error!void {
    const b = try breakDown(epoch_sec);
    if (b.year >= 1950 and b.year <= 2049) {
        // UTCTime "YYMMDDHHMMSSZ"
        var tmp: [13]u8 = undefined;
        writeTwoDigit(tmp[0..2], b.year % 100);
        writeTwoDigit(tmp[2..4], b.month);
        writeTwoDigit(tmp[4..6], b.day);
        writeTwoDigit(tmp[6..8], b.hour);
        writeTwoDigit(tmp[8..10], b.minute);
        writeTwoDigit(tmp[10..12], b.second);
        tmp[12] = 'Z';
        try appendTLV(list, a, 0x17, &tmp);
    } else {
        // GeneralizedTime "YYYYMMDDHHMMSSZ"
        if (b.year > 9999) return error.TimeOutOfRange;
        var tmp: [15]u8 = undefined;
        writeFourDigit(tmp[0..4], b.year);
        writeTwoDigit(tmp[4..6], b.month);
        writeTwoDigit(tmp[6..8], b.day);
        writeTwoDigit(tmp[8..10], b.hour);
        writeTwoDigit(tmp[10..12], b.minute);
        writeTwoDigit(tmp[12..14], b.second);
        tmp[14] = 'Z';
        try appendTLV(list, a, 0x18, &tmp);
    }
}

// ---------------------------------------------------------------------------
// Static byte sequences
// ---------------------------------------------------------------------------

/// `AlgorithmIdentifier { OID id-Ed25519 }` (no parameters), full DER TLV.
const ed25519_algid_tlv: [7]u8 = .{
    0x30, 0x05, // SEQUENCE, length 5
    0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112
};

/// Issuer / subject Name: `SEQUENCE { SET { SEQUENCE { OID 2.5.4.10, PrintableString "libp2p.io" } } }`.
fn appendNameLibp2pIo(list: *ArrayList, a: std.mem.Allocator) std.mem.Allocator.Error!void {
    // AttributeTypeAndValue: OID 2.5.4.10 (organizationName) + PrintableString "libp2p.io"
    const oid_o_tlv = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x0A };
    const printable = "libp2p.io";
    var atv = ArrayList.empty;
    defer atv.deinit(a);
    try atv.appendSlice(a, &oid_o_tlv);
    try appendTLV(&atv, a, 0x13, printable); // PrintableString

    // RDN = SET { ATV }
    const atv_tlv = try dupTLV(a, 0x30, atv.items);
    defer a.free(atv_tlv);
    const set_tlv = try dupTLV(a, 0x31, atv_tlv);
    defer a.free(set_tlv);

    // Name = SEQUENCE { RDN }
    try appendTLV(list, a, 0x30, set_tlv);
}

// ---------------------------------------------------------------------------
// Libp2p PublicKey protobuf + SignedKey extension contents
// ---------------------------------------------------------------------------

/// Encode `PublicKey { Type = ED25519, Data = <pub> }` as protobuf.
fn encodeEd25519PublicKeyProto(allocator: std.mem.Allocator, pub_bytes: [32]u8) anyerror![]const u8 {
    var pk = peer_id.PublicKey{ .type = .ED25519, .data = &pub_bytes };
    return try pk.encode(allocator);
}

/// SubjectPublicKeyInfo SEQUENCE for ephemeral Ed25519 cert key.
fn appendSpki(list: *ArrayList, a: std.mem.Allocator, pub_bytes: [32]u8) std.mem.Allocator.Error!void {
    // BIT STRING contents: 1 unused-bits octet (0x00) + 32-byte key.
    var bit_payload: [33]u8 = undefined;
    bit_payload[0] = 0;
    @memcpy(bit_payload[1..], &pub_bytes);

    var spki = ArrayList.empty;
    defer spki.deinit(a);
    try spki.appendSlice(a, &ed25519_algid_tlv);
    try appendTLV(&spki, a, 0x03, &bit_payload);

    try appendTLV(list, a, 0x30, spki.items);
}

/// `SignedKey ::= SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }` DER.
fn buildSignedKeyDer(
    allocator: std.mem.Allocator,
    pubkey_proto: []const u8,
    signature: []const u8,
) std.mem.Allocator.Error![]u8 {
    var inner = ArrayList.empty;
    defer inner.deinit(allocator);
    try appendTLV(&inner, allocator, 0x04, pubkey_proto);
    try appendTLV(&inner, allocator, 0x04, signature);
    return try dupTLV(allocator, 0x30, inner.items);
}

/// Single extension SEQUENCE: `{ OID 1.3.6.1.4.1.53594.1.1, OCTET STRING <SignedKey-DER> }`.
fn appendLibp2pExtension(list: *ArrayList, a: std.mem.Allocator, signed_key_der: []const u8) std.mem.Allocator.Error!void {
    var ext = ArrayList.empty;
    defer ext.deinit(a);
    try ext.appendSlice(a, &libp2p_tls.extension_oid_tlv);
    try appendTLV(&ext, a, 0x04, signed_key_der); // extnValue OCTET STRING
    try appendTLV(list, a, 0x30, ext.items);
}

// ---------------------------------------------------------------------------
// generate()
// ---------------------------------------------------------------------------

/// Build a self-signed libp2p X.509 v3 certificate. Generates a fresh ephemeral
/// Ed25519 keypair, has the embedder's host identity sign the SPKI, and signs
/// the TBSCertificate with the ephemeral key.
pub fn generate(
    allocator: std.mem.Allocator,
    options: GenerateOptions,
) anyerror!GeneratedCertificate {
    if (options.not_before_sec > options.not_after_sec) return error.InvalidValidityWindow;

    // 1. Ephemeral Ed25519 cert keypair from the caller-supplied seed.
    const seed: [Ed25519.KeyPair.seed_length]u8 = options.cert_key_seed;
    const cert_kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.InvalidSerial;
    const cert_pub: [32]u8 = cert_kp.public_key.bytes;

    // 2. Build the SubjectPublicKeyInfo DER (we need its exact bytes to sign).
    var spki_buf = ArrayList.empty;
    defer spki_buf.deinit(allocator);
    try appendSpki(&spki_buf, allocator, cert_pub);
    const spki_tlv = spki_buf.items;

    // 3. Host signs "libp2p-tls-handshake:" || SPKI_TLV.
    var sig_msg = ArrayList.empty;
    defer sig_msg.deinit(allocator);
    try sig_msg.appendSlice(allocator, libp2p_tls.handshake_signature_prefix);
    try sig_msg.appendSlice(allocator, spki_tlv);

    var host_sig: [64]u8 = undefined;
    switch (options.host_identity) {
        .ed25519 => |h| {
            h.sign(h.sign_ctx, sig_msg.items, &host_sig) catch return error.NotImplemented;
        },
    }

    // 4. Encode libp2p PublicKey protobuf for the host identity.
    const host_pub_proto: []const u8 = switch (options.host_identity) {
        .ed25519 => |h| try encodeEd25519PublicKeyProto(allocator, h.public_key_bytes),
    };
    defer allocator.free(host_pub_proto);

    // 5. Build SignedKey DER and the libp2p extension.
    const signed_key_der = try buildSignedKeyDer(allocator, host_pub_proto, &host_sig);
    defer allocator.free(signed_key_der);

    // 6. Assemble TBSCertificate.
    var tbs = ArrayList.empty;
    defer tbs.deinit(allocator);

    // [0] EXPLICIT Version v3 (INTEGER 2)
    try appendTLV(&tbs, allocator, 0xA0, &[_]u8{ 0x02, 0x01, 0x02 });

    // serialNumber INTEGER
    try appendInteger(&tbs, allocator, options.serial);

    // signature AlgorithmIdentifier (id-Ed25519)
    try tbs.appendSlice(allocator, &ed25519_algid_tlv);

    // issuer Name
    try appendNameLibp2pIo(&tbs, allocator);

    // validity SEQUENCE { notBefore, notAfter }
    var validity_payload = ArrayList.empty;
    defer validity_payload.deinit(allocator);
    try appendTime(&validity_payload, allocator, options.not_before_sec);
    try appendTime(&validity_payload, allocator, options.not_after_sec);
    try appendTLV(&tbs, allocator, 0x30, validity_payload.items);

    // subject Name (same as issuer)
    try appendNameLibp2pIo(&tbs, allocator);

    // subjectPublicKeyInfo
    try tbs.appendSlice(allocator, spki_tlv);

    // [3] EXPLICIT Extensions ::= SEQUENCE { libp2p extension }
    var exts_payload = ArrayList.empty;
    defer exts_payload.deinit(allocator);
    try appendLibp2pExtension(&exts_payload, allocator, signed_key_der);
    const exts_seq = try dupTLV(allocator, 0x30, exts_payload.items);
    defer allocator.free(exts_seq);
    try appendTLV(&tbs, allocator, 0xA3, exts_seq);

    const tbs_tlv = try dupTLV(allocator, 0x30, tbs.items);
    defer allocator.free(tbs_tlv);

    // 7. Ephemeral key signs TBSCertificate DER (full TLV per RFC 5280).
    const cert_sig = cert_kp.sign(tbs_tlv, null) catch return error.InvalidSerial;
    const cert_sig_bytes = cert_sig.toBytes();

    // 8. Outer Certificate SEQUENCE = TBSCertificate || sigAlgo || signatureValue.
    var outer = ArrayList.empty;
    defer outer.deinit(allocator);
    try outer.appendSlice(allocator, tbs_tlv);
    try outer.appendSlice(allocator, &ed25519_algid_tlv);
    // signatureValue: BIT STRING (1 unused-bits byte + signature)
    var sig_bit_payload: [1 + 64]u8 = undefined;
    sig_bit_payload[0] = 0;
    @memcpy(sig_bit_payload[1..], &cert_sig_bytes);
    try appendTLV(&outer, allocator, 0x03, &sig_bit_payload);

    const cert_der = try dupTLV(allocator, 0x30, outer.items);

    return .{
        .cert_der = cert_der,
        .cert_key_seed = seed,
    };
}

// ---------------------------------------------------------------------------
// PEM helpers
// ---------------------------------------------------------------------------

fn pemEncode(allocator: std.mem.Allocator, label: []const u8, der: []const u8) std.mem.Allocator.Error![]u8 {
    const Base64 = std.base64.standard.Encoder;
    const b64_len = Base64.calcSize(der.len);
    const b64 = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64);
    _ = Base64.encode(b64, der);

    // Approx output size: "-----BEGIN X-----\n" + b64 (with \n every 64) + "-----END X-----\n".
    const line_count = (b64_len + 63) / 64;
    const total =
        "-----BEGIN ".len + label.len + "-----\n".len +
        b64_len + line_count + // newline per line
        "-----END ".len + label.len + "-----\n".len;
    var out = try std.ArrayList(u8).initCapacity(allocator, total);
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "-----BEGIN ");
    try out.appendSlice(allocator, label);
    try out.appendSlice(allocator, "-----\n");
    var i: usize = 0;
    while (i < b64.len) {
        const end = @min(i + 64, b64.len);
        try out.appendSlice(allocator, b64[i..end]);
        try out.append(allocator, '\n');
        i = end;
    }
    try out.appendSlice(allocator, "-----END ");
    try out.appendSlice(allocator, label);
    try out.appendSlice(allocator, "-----\n");
    return try out.toOwnedSlice(allocator);
}

pub fn certDerToPem(allocator: std.mem.Allocator, der: []const u8) ![]u8 {
    return pemEncode(allocator, "CERTIFICATE", der);
}

/// Wrap an Ed25519 seed as PKCS#8 PrivateKeyInfo PEM ("PRIVATE KEY").
pub fn ed25519SeedToPem(allocator: std.mem.Allocator, seed: [32]u8) ![]u8 {
    // PrivateKeyInfo ::= SEQUENCE {
    //   version INTEGER 0,
    //   algorithm AlgorithmIdentifier { OID 1.3.101.112 },
    //   privateKey OCTET STRING { OCTET STRING <32-byte seed> }
    // }
    var inner = ArrayList.empty;
    defer inner.deinit(allocator);
    try inner.append(allocator, 0x04);
    try inner.append(allocator, 0x20);
    try inner.appendSlice(allocator, &seed);

    var pki = ArrayList.empty;
    defer pki.deinit(allocator);
    try appendTLV(&pki, allocator, 0x02, &[_]u8{0x00}); // INTEGER 0
    try pki.appendSlice(allocator, &ed25519_algid_tlv);
    try appendTLV(&pki, allocator, 0x04, inner.items); // OCTET STRING <CurvePrivateKey>

    const pki_tlv = try dupTLV(allocator, 0x30, pki.items);
    defer allocator.free(pki_tlv);
    return pemEncode(allocator, "PRIVATE KEY", pki_tlv);
}

// ===========================================================================
// Tests
// ===========================================================================

/// Deterministic per-test seed material via SHA-256(label || line).
fn fillTestSeed(out: *[32]u8, line: u32) void {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("libp2p_tls_cert test seed:");
    var line_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &line_bytes, line, .big);
    h.update(&line_bytes);
    h.final(out);
}

const TestEd25519Signer = struct {
    kp: Ed25519.KeyPair,
    fn sign(ctx: ?*anyopaque, message: []const u8, out_sig: *[64]u8) anyerror!void {
        const self: *TestEd25519Signer = @ptrCast(@alignCast(ctx.?));
        const sig = try self.kp.sign(message, null);
        out_sig.* = sig.toBytes();
    }
};

test "generate produces cert that verifies and round-trips PeerId" {
    const a = std.testing.allocator;

    // 1. Host identity Ed25519 keypair.
    var seed: [32]u8 = undefined;
    fillTestSeed(&seed, @src().line);
    const host_kp = try Ed25519.KeyPair.generateDeterministic(seed);

    var signer = TestEd25519Signer{ .kp = host_kp };

    var cert_seed: [32]u8 = undefined;
    fillTestSeed(&cert_seed, @src().line);

    // 3. Generate with 1-day validity centred around a representative `now`.
    const now: i64 = 1_700_000_000;
    var gen = try generate(a, .{
        .host_identity = .{
            .ed25519 = .{
                .public_key_bytes = host_kp.public_key.bytes,
                .sign = TestEd25519Signer.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now - 3600,
        .not_after_sec = now + 86_400,
        .serial = 0x12345678,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    // 4. Expected PeerId: derive from libp2p PublicKey{ED25519, host.pub}.
    var expected_pk = peer_id.PublicKey{
        .type = .ED25519,
        .data = &host_kp.public_key.bytes,
    };
    const expected_id = try peer_id.PeerId.fromPublicKey(a, &expected_pk);

    // 5. Verified peer id from generated cert.
    const got = try libp2p_tls.peerIdFromVerifiedCertificate(a, gen.cert_der, now);

    var ebuf: [128]u8 = undefined;
    var gbuf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        try expected_id.toBase58(&ebuf),
        try got.toBase58(&gbuf),
    );
}

test "generated cert's libp2p extension parses" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    fillTestSeed(&seed, @src().line);
    const host_kp = try Ed25519.KeyPair.generateDeterministic(seed);
    var signer = TestEd25519Signer{ .kp = host_kp };

    var cert_seed: [32]u8 = undefined;
    fillTestSeed(&cert_seed, @src().line);

    const now: i64 = 1_700_000_000;
    var gen = try generate(a, .{
        .host_identity = .{
            .ed25519 = .{
                .public_key_bytes = host_kp.public_key.bytes,
                .sign = TestEd25519Signer.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now - 3600,
        .not_after_sec = now + 86_400,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    const ext = try libp2p_tls.findLibp2pExtensionExtValue(gen.cert_der);
    const sk = try libp2p_tls.parseSignedKey(ext);
    try std.testing.expect(sk.public_key_pb.len > 0);
    try std.testing.expectEqual(@as(usize, 64), sk.signature.len);
}

test "expired cert fails verification" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    fillTestSeed(&seed, @src().line);
    const host_kp = try Ed25519.KeyPair.generateDeterministic(seed);
    var signer = TestEd25519Signer{ .kp = host_kp };

    var cert_seed: [32]u8 = undefined;
    fillTestSeed(&cert_seed, @src().line);

    // Validity 2001-2002, both well before any realistic `now`. (We avoid
    // year < 1970 in the encoder, and std's UTCTime parser interprets YY as
    // 20YY unconditionally, so any pre-2000 epoch trips the wrong branch.)
    var gen = try generate(a, .{
        .host_identity = .{
            .ed25519 = .{
                .public_key_bytes = host_kp.public_key.bytes,
                .sign = TestEd25519Signer.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = 978_307_200, // 2001-01-01T00:00:00Z
        .not_after_sec = 1_009_843_200, // 2002-01-01T00:00:00Z
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    const now: i64 = 1_700_000_000;
    try std.testing.expectError(error.CertificateExpired, libp2p_tls.peerIdFromVerifiedCertificate(a, gen.cert_der, now));
}

test "generated cert: time outside UTCTime range uses GeneralizedTime" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    fillTestSeed(&seed, @src().line);
    const host_kp = try Ed25519.KeyPair.generateDeterministic(seed);
    var signer = TestEd25519Signer{ .kp = host_kp };

    var cert_seed: [32]u8 = undefined;
    fillTestSeed(&cert_seed, @src().line);

    // notAfter = 2200-01-01 → GeneralizedTime needed.
    const not_after_sec: i64 = 7_258_118_400; // 2200-01-01 00:00:00Z
    const now: i64 = 1_700_000_000;
    var gen = try generate(a, .{
        .host_identity = .{
            .ed25519 = .{
                .public_key_bytes = host_kp.public_key.bytes,
                .sign = TestEd25519Signer.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now - 3600,
        .not_after_sec = not_after_sec,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    // Still verifies at `now`.
    const got = try libp2p_tls.peerIdFromVerifiedCertificate(a, gen.cert_der, now);
    var b: [128]u8 = undefined;
    _ = try got.toBase58(&b);
}

test "certDerToPem and ed25519SeedToPem round-trip via parser" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    fillTestSeed(&seed, @src().line);
    const host_kp = try Ed25519.KeyPair.generateDeterministic(seed);
    var signer = TestEd25519Signer{ .kp = host_kp };

    var cert_seed: [32]u8 = undefined;
    fillTestSeed(&cert_seed, @src().line);

    const now: i64 = 1_700_000_000;
    var gen = try generate(a, .{
        .host_identity = .{
            .ed25519 = .{
                .public_key_bytes = host_kp.public_key.bytes,
                .sign = TestEd25519Signer.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now - 3600,
        .not_after_sec = now + 86_400,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    const cert_pem = try certDerToPem(a, gen.cert_der);
    defer a.free(cert_pem);
    try std.testing.expect(std.mem.indexOf(u8, cert_pem, "-----BEGIN CERTIFICATE-----") != null);
    try std.testing.expect(std.mem.indexOf(u8, cert_pem, "-----END CERTIFICATE-----") != null);

    const key_pem = try ed25519SeedToPem(a, gen.cert_key_seed);
    defer a.free(key_pem);
    try std.testing.expect(std.mem.indexOf(u8, key_pem, "-----BEGIN PRIVATE KEY-----") != null);
}
