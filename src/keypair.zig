//! PEM-encoded private keys and [`peer_id.PeerId`] derivation (Ed25519 and secp256k1, pure Zig).

const std = @import("std");
const pid = @import("peer_id");

/// Supported host key material loaded from PEM.
pub const KeyPair = union(enum) {
    ed25519: std.crypto.sign.Ed25519.KeyPair,
    secp256k1: std.crypto.ecdsa.EcdsaSecp256k1Sha256.KeyPair,
};

pub const PemError = error{
    MalformedPem,
    InvalidDer,
    UnsupportedKeyType,
    InvalidKeyMaterial,
} || std.base64.Error;

/// Object identifier `1.3.101.112` (Ed25519) as DER `OBJECT IDENTIFIER` TLV.
const oid_ed25519_tlv: [5]u8 = .{ 0x06, 0x03, 0x2B, 0x65, 0x70 };
/// Named curve `1.3.132.0.10` (secp256k1) as DER `OBJECT IDENTIFIER` TLV.
const oid_secp256k1_named_curve: [7]u8 = .{ 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A };

fn readDerLength(data: []const u8, pos: *usize) PemError!usize {
    if (pos.* >= data.len) return error.InvalidDer;
    const fb = data[pos.*];
    pos.* += 1;
    if (fb < 0x80) return fb;
    const n = fb & 0x7f;
    if (n == 0 or n > 4 or pos.* + n > data.len) return error.InvalidDer;
    var len: usize = 0;
    for (0..n) |_| {
        len = (len << 8) | data[pos.*];
        pos.* += 1;
    }
    return len;
}

fn readTlv(data: []const u8, pos: *usize, tag: u8) PemError![]const u8 {
    if (pos.* >= data.len or data[pos.*] != tag) return error.InvalidDer;
    pos.* += 1;
    const len = try readDerLength(data, pos);
    if (pos.* + len > data.len) return error.InvalidDer;
    const slice = data[pos.*..][0..len];
    pos.* += len;
    return slice;
}

fn pemFirstBlockBody(pem: []const u8) PemError![]const u8 {
    const start_marker = "-----BEGIN";
    const end_marker = "-----END";
    const idx = std.mem.indexOf(u8, pem, start_marker) orelse return error.MalformedPem;
    const nl = std.mem.indexOfScalar(u8, pem[idx..], '\n') orelse return error.MalformedPem;
    const body_start = idx + nl + 1;
    const end_rel = std.mem.indexOf(u8, pem[body_start..], end_marker) orelse return error.MalformedPem;
    return std.mem.trim(u8, pem[body_start .. body_start + end_rel], " \t\r\n");
}

fn keypairFromSec1EcSequence(seq: []const u8) PemError!KeyPair {
    var j: usize = 0;
    _ = try readTlv(seq, &j, 0x02);
    const sk_raw = try readTlv(seq, &j, 0x04);
    if (sk_raw.len != 32) return error.InvalidKeyMaterial;
    const sk_bytes: [32]u8 = sk_raw[0..32].*;
    const sec = std.crypto.ecdsa.EcdsaSecp256k1Sha256.SecretKey.fromBytes(sk_bytes) catch return error.InvalidKeyMaterial;
    const kp = std.crypto.ecdsa.EcdsaSecp256k1Sha256.KeyPair.fromSecretKey(sec) catch return error.InvalidKeyMaterial;
    return .{ .secp256k1 = kp };
}

fn keypairFromEcPrivateOctets(key_octets: []const u8) PemError!KeyPair {
    var k: usize = 0;
    const ec_der = try readTlv(key_octets, &k, 0x04);
    if (k != key_octets.len) return error.InvalidDer;
    return keypairFromSec1EcSequence(ec_der);
}

fn parsePkcs8PrivateKeyInfo(seq: []const u8) PemError!KeyPair {
    var j: usize = 0;
    _ = try readTlv(seq, &j, 0x02);
    const alg = try readTlv(seq, &j, 0x30);
    const key_octets = try readTlv(seq, &j, 0x04);
    if (j != seq.len) return error.InvalidDer;

    if (std.mem.indexOf(u8, alg, &oid_ed25519_tlv) != null) {
        var k: usize = 0;
        const seed = try readTlv(key_octets, &k, 0x04);
        if (k != key_octets.len) return error.InvalidDer;
        if (seed.len != 32) return error.InvalidKeyMaterial;
        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed[0..32].*) catch return error.InvalidKeyMaterial;
        return .{ .ed25519 = kp };
    }
    if (std.mem.indexOf(u8, alg, &oid_secp256k1_named_curve) != null) {
        return keypairFromEcPrivateOctets(key_octets);
    }
    return error.UnsupportedKeyType;
}

/// Parse an unencrypted PKCS#8 or SEC1 EC private key DER blob.
pub fn keyPairFromDer(der: []const u8) PemError!KeyPair {
    if (der.len < 4) return error.InvalidDer;
    if (der[0] != 0x30) return error.InvalidDer;
    var i: usize = 0;
    const seq = try readTlv(der, &i, 0x30);
    if (i != der.len) return error.InvalidDer;
    if (seq.len < 3 or seq[0] != 0x02 or seq[1] != 0x01) return error.UnsupportedKeyType;
    return switch (seq[2]) {
        0x00 => parsePkcs8PrivateKeyInfo(seq),
        0x01 => keypairFromSec1EcSequence(seq),
        else => error.UnsupportedKeyType,
    };
}

/// Load the first PEM private key block (`BEGIN PRIVATE KEY` or `BEGIN EC PRIVATE KEY`).
pub fn keyPairFromPem(allocator: std.mem.Allocator, pem: []const u8) PemError!KeyPair {
    const b64 = try pemFirstBlockBody(pem);
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const upper = decoder.calcSizeUpperBound(b64.len);
    const der = try allocator.alloc(u8, upper);
    defer allocator.free(der);
    const n = try decoder.decode(der, b64);
    return keyPairFromDer(der[0..n]);
}

/// Errors from [`peer_id.PeerId.fromPublicKey`] (identity / SHA2-256 multihash path).
pub const PeerIdFromKeyPairError = @typeInfo(
    @typeInfo(@TypeOf(pid.PeerId.fromPublicKey)).@"fn".return_type.?,
).error_union.error_set;

/// Derive a libp2p PeerId from a loaded key pair (protobuf public key encoding).
pub fn peerIdFromKeyPair(allocator: std.mem.Allocator, kp: KeyPair) PeerIdFromKeyPairError!pid.PeerId {
    switch (kp) {
        .ed25519 => |k| {
            const b = k.public_key.toBytes();
            var pk = pid.PublicKey{ .type = .ED25519, .data = &b };
            return try pid.PeerId.fromPublicKey(allocator, &pk);
        },
        .secp256k1 => |k| {
            const comp = k.public_key.toCompressedSec1();
            var pk = pid.PublicKey{ .type = .SECP256K1, .data = &comp };
            return try pid.PeerId.fromPublicKey(allocator, &pk);
        },
    }
}

test "keyPairFromPem ed25519 matches PeerId.fromPublicKey" {
    const a = std.testing.allocator;
    const pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MC4CAQAwBQYDK2VwBCIEIB8/f4rB+k4+LRJPQe1pK4IwPlkgqaIVlw2texF6iTww
        \\-----END PRIVATE KEY-----
    ;
    const kp = try keyPairFromPem(a, pem);
    try std.testing.expect(kp == .ed25519);

    const id_kp = try peerIdFromKeyPair(a, kp);
    const pub_bytes = kp.ed25519.public_key.toBytes();
    var lpk = pid.PublicKey{ .type = .ED25519, .data = &pub_bytes };
    const id_direct = try pid.PeerId.fromPublicKey(a, &lpk);
    try std.testing.expect(id_kp.eql(&id_direct));
}

test "keyPairFromPem secp256k1 matches PeerId.fromPublicKey" {
    const a = std.testing.allocator;
    const pem =
        \\-----BEGIN EC PRIVATE KEY-----
        \\MHQCAQEEIKqnXBejXoc7JfzLviqAicxps0BYkswkrKyFBBwviOKCoAcGBSuBBAAK
        \\oUQDQgAEDMl/Jnvu8UgTbIccjXgecOxJSImk7Rmi96y4ecjma1mEwbhDZH41+A0l
        \\eOdKeV6gdOPJF/HzwqZSGfsxjKnkBQ==
        \\-----END EC PRIVATE KEY-----
    ;
    const kp = try keyPairFromPem(a, pem);
    try std.testing.expect(kp == .secp256k1);

    const id_kp = try peerIdFromKeyPair(a, kp);
    const comp = kp.secp256k1.public_key.toCompressedSec1();
    var lpk = pid.PublicKey{ .type = .SECP256K1, .data = &comp };
    const id_direct = try pid.PeerId.fromPublicKey(a, &lpk);
    try std.testing.expect(id_kp.eql(&id_direct));
}

test "secp256k1 sign verify round trip" {
    const a = std.testing.allocator;
    const pem =
        \\-----BEGIN EC PRIVATE KEY-----
        \\MHQCAQEEIKqnXBejXoc7JfzLviqAicxps0BYkswkrKyFBBwviOKCoAcGBSuBBAAK
        \\oUQDQgAEDMl/Jnvu8UgTbIccjXgecOxJSImk7Rmi96y4ecjma1mEwbhDZH41+A0l
        \\eOdKeV6gdOPJF/HzwqZSGfsxjKnkBQ==
        \\-----END EC PRIVATE KEY-----
    ;
    const kp = try keyPairFromPem(a, pem);
    const msg = "libp2p host";
    const sig = try kp.secp256k1.sign(msg, null);
    try sig.verify(msg, kp.secp256k1.public_key);
}
