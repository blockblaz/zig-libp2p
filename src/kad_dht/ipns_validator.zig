//! Reference `/ipns/` Kad-DHT record validator (#198).
//!
//! Parses the IPNS protobuf record, enforces monotonic `sequence`, and verifies
//! `signatureV1` for Ed25519 identity peer names.

const std = @import("std");
const pb = @import("../protobuf/wire.zig");
const pid = @import("peer_id");
const record_validator = @import("record_validator.zig");

const Ed25519 = std.crypto.sign.Ed25519;

const ipns_prefix = "/ipns/";

const Parsed = struct {
    sequence: u64 = 0,
    has_sequence: bool = false,
    signature_v1: ?[]const u8 = null,
};

pub fn validate(
    ctx: ?*anyopaque,
    key: []const u8,
    value: []const u8,
    existing: ?[]const u8,
) record_validator.ValidationResult {
    const allocator = @as(*const std.mem.Allocator, @ptrCast(@alignCast(ctx.?))).*;
    if (!std.mem.startsWith(u8, key, ipns_prefix)) return .ignore;
    const name = key[ipns_prefix.len..];
    if (name.len == 0) return .reject;

    const parsed = parseRecord(value) orelse return .reject;
    if (!parsed.has_sequence) return .reject;
    const sig = parsed.signature_v1 orelse return .reject;
    if (sig.len != Ed25519.Signature.encoded_length) return .reject;

    if (existing) |prev| {
        const old = parseRecord(prev) orelse return .reject;
        if (old.has_sequence and parsed.sequence < old.sequence) return .reject;
        if (old.has_sequence and parsed.sequence == old.sequence) return .ignore;
    }

    const unsigned = marshalForSignature(allocator, value) catch return .reject;
    defer allocator.free(unsigned);

    const pub_bytes = ed25519PubkeyFromIpnsName(allocator, name) catch return .reject;
    defer allocator.free(pub_bytes);
    if (pub_bytes.len != 32) return .reject;

    const pk = Ed25519.PublicKey.fromBytes(pub_bytes[0..32].*) catch return .reject;
    const signature = Ed25519.Signature.fromBytes(sig[0..Ed25519.Signature.encoded_length].*);
    signature.verify(unsigned, pk) catch return .reject;
    return .accept;
}

pub fn register(registry: *record_validator.Registry, allocator: *std.mem.Allocator) std.mem.Allocator.Error!void {
    try registry.register(ipns_prefix, validate, @ptrCast(allocator));
}

fn parseRecord(data: []const u8) ?Parsed {
    var out: Parsed = .{};
    var pos: usize = 0;
    while (pos < data.len) {
        const key = pb.decodeFieldKey(data[pos..]) catch return null;
        const fv = pb.nextFieldValue(data[pos + key.len ..], key.wire_type) catch return null;
        const total = key.len + fv.total;
        switch (key.field_number) {
            4 => {
                const dec = pb.decodeVarUInt64(fv.value) catch return null;
                out.sequence = dec.value;
                out.has_sequence = true;
            },
            5 => out.signature_v1 = fv.value,
            else => {},
        }
        pos += total;
    }
    return out;
}

fn marshalForSignature(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var pos: usize = 0;
    while (pos < data.len) {
        const key = try pb.decodeFieldKey(data[pos..]);
        const fv = try pb.nextFieldValue(data[pos + key.len ..], key.wire_type);
        const total = key.len + fv.total;
        switch (key.field_number) {
            5, 6, 7, 8, 9 => {},
            else => try out.appendSlice(allocator, data[pos .. pos + total]),
        }
        pos += total;
    }
    return try out.toOwnedSlice(allocator);
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

/// Build a signed IPNS record for tests and tooling.
pub fn buildSignedRecord(
    allocator: std.mem.Allocator,
    kp: std.crypto.sign.Ed25519.KeyPair,
    sequence: u64,
    value: []const u8,
) ![]u8 {
    var unsigned: std.ArrayList(u8) = .empty;
    defer unsigned.deinit(allocator);
    try pb.appendLengthDelimited(&unsigned, allocator, 1, value);
    try pb.appendFieldKey(&unsigned, allocator, 4, .varint);
    try pb.appendVarUInt64(&unsigned, allocator, sequence);
    const sig = try kp.sign(unsigned.items, null);
    try pb.appendLengthDelimited(&unsigned, allocator, 5, &sig.toBytes());
    return try unsigned.toOwnedSlice(allocator);
}

test "ipns validator accepts monotonic signed records" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const peer = try @import("../keypair.zig").peerIdFromKeyPair(a, .{ .ed25519 = kp });
    var b58_buf: [128]u8 = undefined;
    const b58 = try peer.toBase58(&b58_buf);
    const key = try std.fmt.allocPrint(a, "/ipns/{s}", .{b58});
    defer a.free(key);

    const rec1 = try buildSignedRecord(a, kp, 1, "/ipfs/bafy");
    defer a.free(rec1);
    const rec2 = try buildSignedRecord(a, kp, 2, "/ipfs/bafy2");
    defer a.free(rec2);

    var reg = record_validator.Registry.init(a);
    defer reg.deinit();
    var alloc_slot = a;
    try register(&reg, &alloc_slot);

    try std.testing.expect(reg.validate(key, rec1, null) == .accept);
    try std.testing.expect(reg.validate(key, rec2, rec1) == .accept);
    try std.testing.expect(reg.validate(key, rec1, rec2) == .reject);
}

test "ipns validator rejects tampered signature" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x43);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const peer = try @import("../keypair.zig").peerIdFromKeyPair(a, .{ .ed25519 = kp });
    var b58_buf: [128]u8 = undefined;
    const b58 = try peer.toBase58(&b58_buf);
    const key = try std.fmt.allocPrint(a, "/ipns/{s}", .{b58});
    defer a.free(key);

    const rec = try buildSignedRecord(a, kp, 1, "/ipfs/bafy");
    defer a.free(rec);
    var bad = try a.dupe(u8, rec);
    defer a.free(bad);
    bad[bad.len - 1] ^= 0xFF;

    var reg = record_validator.Registry.init(a);
    defer reg.deinit();
    var alloc_slot = a;
    try register(&reg, &alloc_slot);
    try std.testing.expect(reg.validate(key, bad, null) == .reject);
}
