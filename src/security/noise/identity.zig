//! libp2p Noise identity: sign / verify over `noise-libp2p-static-key:` ‖ 32-byte X25519 static public key.

const std = @import("std");
const pid = @import("peer_id");
const keypair = @import("../../keypair.zig");
const payload_mod = @import("payload.zig");
const libp2p_tls_cert = @import("../libp2p_tls_cert.zig");
const zquic_rsa = @import("zquic_rsa");

const Sha256 = std.crypto.hash.sha2.Sha256;
const RsaPkcs1v15Sha256 = zquic_rsa.PKCS1v1_5(Sha256);

const Ed25519 = std.crypto.sign.Ed25519;
const Secp256k1 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const static_key_challenge_prefix = "noise-libp2p-static-key:";

pub const Error = error{
    InvalidIdentityKey,
    BadSignature,
    PeerIdMismatch,
    InvalidEd25519SignatureLength,
    UnsupportedNoiseIdentityKeyType,
    OutOfMemory,
} || payload_mod.Error || keypair.PeerIdFromKeyPairError;

/// Message signed by the host identity over the peer's Noise static X25519 public key.
pub fn signingMessage(remote_noise_static_pk: [32]u8) [static_key_challenge_prefix.len + 32]u8 {
    var m: [static_key_challenge_prefix.len + 32]u8 = undefined;
    @memcpy(m[0..static_key_challenge_prefix.len], static_key_challenge_prefix);
    @memcpy(m[static_key_challenge_prefix.len..][0..32], &remote_noise_static_pk);
    return m;
}

fn encodeLibp2pPublicKey(allocator: std.mem.Allocator, kp: keypair.KeyPair) Error![]const u8 {
    return switch (kp) {
        .ed25519 => |k| {
            const b = k.public_key.toBytes();
            var pk = pid.PublicKey{ .type = .ED25519, .data = &b };
            return pk.encode(allocator) catch |e| return mapWriteError(e);
        },
        .secp256k1 => |k| {
            const comp = k.public_key.toCompressedSec1();
            var pk = pid.PublicKey{ .type = .SECP256K1, .data = &comp };
            return pk.encode(allocator) catch |e| return mapWriteError(e);
        },
    };
}

fn mapWriteError(e: anyerror) Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidIdentityKey,
    };
}

fn mapSignError(e: anyerror) Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidIdentityKey,
    };
}

/// Build protobuf `NoiseHandshakePayload` bytes (identity key + signature + optional muxer extensions).
pub fn encodeSignedPayload(
    allocator: std.mem.Allocator,
    host: keypair.KeyPair,
    noise_static_pk: [32]u8,
    stream_muxers: []const []const u8,
) Error![]u8 {
    const msg = signingMessage(noise_static_pk);
    const id_key = try encodeLibp2pPublicKey(allocator, host);
    defer allocator.free(id_key);

    const sig_bytes: []const u8 = switch (host) {
        .ed25519 => |k| blk: {
            const sig = k.sign(&msg, null) catch |e| return mapSignError(e);
            break :blk try allocator.dupe(u8, &sig.toBytes());
        },
        .secp256k1 => |k| blk: {
            const sig = k.sign(&msg, null) catch |e| return mapSignError(e);
            var der_buf: [Secp256k1.Signature.der_encoded_length_max]u8 = undefined;
            const der = sig.toDer(&der_buf);
            break :blk try allocator.dupe(u8, der);
        },
    };
    defer allocator.free(sig_bytes);

    return try payload_mod.encode(allocator, id_key, sig_bytes, stream_muxers);
}

fn verifySignature(host_type: pid.KeyType, key_data: []const u8, identity_sig: []const u8, msg: []const u8) Error!void {
    switch (host_type) {
        .ED25519 => {
            if (identity_sig.len != Ed25519.Signature.encoded_length) return error.InvalidEd25519SignatureLength;
            const pk = Ed25519.PublicKey.fromBytes(key_data[0..32].*) catch return error.InvalidIdentityKey;
            const sig = Ed25519.Signature.fromBytes(identity_sig[0..Ed25519.Signature.encoded_length].*);
            sig.verify(msg, pk) catch return error.BadSignature;
        },
        .SECP256K1 => {
            const pk = Secp256k1.PublicKey.fromSec1(key_data) catch return error.InvalidIdentityKey;
            const sig = Secp256k1.Signature.fromDer(identity_sig) catch return error.BadSignature;
            sig.verify(msg, pk) catch return error.BadSignature;
        },
        .ECDSA => {
            // libp2p ECDSA identities embed an X.509 SubjectPublicKeyInfo (the same
            // encoding used in libp2p TLS); extract the SEC1 uncompressed point
            // from the inner BIT STRING (#87).
            const sec1 = sec1FromSubjectPublicKeyInfo(key_data) catch return error.InvalidIdentityKey;
            const pk = EcdsaP256.PublicKey.fromSec1(sec1) catch return error.InvalidIdentityKey;
            const sig = EcdsaP256.Signature.fromDer(identity_sig) catch return error.BadSignature;
            sig.verify(msg, pk) catch return error.BadSignature;
        },
        .RSA => {
            const pk = zquic_rsa.PublicKey.fromDer(key_data) catch return error.InvalidIdentityKey;
            const sig = RsaPkcs1v15Sha256.Signature{ .bytes = identity_sig };
            sig.verify(msg, pk) catch return error.BadSignature;
        },
        else => return error.InvalidIdentityKey,
    }
}

/// Strip an X.509 SubjectPublicKeyInfo wrapper down to the inner SEC1-encoded
/// uncompressed EC point. SubjectPublicKeyInfo is `SEQUENCE { AlgorithmIdentifier,
/// BIT STRING }`; we only need the BIT STRING's payload bytes after the unused-bits
/// byte (which must be 0 for a SEC1 point).
fn sec1FromSubjectPublicKeyInfo(spki: []const u8) error{MalformedSpki}![]const u8 {
    if (spki.len < 2 or spki[0] != 0x30) return error.MalformedSpki;
    var seq_len: usize = spki[1];
    var p: usize = 2;
    if (seq_len & 0x80 != 0) {
        const n = seq_len & 0x7f;
        if (n == 0 or n > 4 or p + n > spki.len) return error.MalformedSpki;
        seq_len = 0;
        for (spki[p .. p + n]) |b| seq_len = (seq_len << 8) | b;
        p += n;
    }
    if (p + seq_len > spki.len) return error.MalformedSpki;

    // AlgorithmIdentifier SEQUENCE
    if (spki[p] != 0x30) return error.MalformedSpki;
    var alg_len: usize = spki[p + 1];
    var alg_hdr: usize = 2;
    if (alg_len & 0x80 != 0) {
        const n = alg_len & 0x7f;
        if (n == 0 or n > 4 or p + alg_hdr + n > spki.len) return error.MalformedSpki;
        alg_len = 0;
        for (spki[p + alg_hdr .. p + alg_hdr + n]) |b| alg_len = (alg_len << 8) | b;
        alg_hdr += n;
    }
    p += alg_hdr + alg_len;
    if (p >= spki.len) return error.MalformedSpki;

    // BIT STRING (0x03)
    if (spki[p] != 0x03) return error.MalformedSpki;
    var bs_len: usize = spki[p + 1];
    var bs_hdr: usize = 2;
    if (bs_len & 0x80 != 0) {
        const n = bs_len & 0x7f;
        if (n == 0 or n > 4 or p + bs_hdr + n > spki.len) return error.MalformedSpki;
        bs_len = 0;
        for (spki[p + bs_hdr .. p + bs_hdr + n]) |b| bs_len = (bs_len << 8) | b;
        bs_hdr += n;
    }
    const bs_start = p + bs_hdr;
    if (bs_start + bs_len > spki.len or bs_len < 1) return error.MalformedSpki;
    if (spki[bs_start] != 0) return error.MalformedSpki; // unused-bits byte
    return spki[bs_start + 1 .. bs_start + bs_len];
}

/// Verify handshake payload and return the remote [`pid.PeerId`]. `payload_plaintext` and inner slices must outlive this call.
pub fn verifySignedPayload(
    allocator: std.mem.Allocator,
    payload_plaintext: []const u8,
    remote_noise_static_pk: [32]u8,
    expected: ?pid.PeerId,
    max_payload: usize,
    mux_scratch: *std.ArrayList([]const u8),
) Error!pid.PeerId {
    const dec = try payload_mod.decode(payload_plaintext, max_payload, mux_scratch, allocator);
    const reader = pid.PublicKeyReader.init(dec.identity_key) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidIdentityKey,
    };
    const kt = reader.getType();
    const data = reader.getData();
    const sm = signingMessage(remote_noise_static_pk);
    const msg: []const u8 = &sm;
    try verifySignature(kt, data, dec.identity_sig, msg);

    var pk = pid.PublicKey{ .type = kt, .data = data };
    const peer_id = try pid.PeerId.fromPublicKey(allocator, &pk);
    if (expected) |exp| {
        if (!peer_id.eql(&exp)) return error.PeerIdMismatch;
    }
    return peer_id;
}

test "encodeSignedPayload verifySignedPayload ed25519" {
    const a = std.testing.allocator;
    var mux = std.ArrayList([]const u8).empty;
    defer mux.deinit(a);

    const pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MC4CAQAwBQYDK2VwBCIEIB8/f4rB+k4+LRJPQe1pK4IwPlkgqaIVlw2texF6iTww
        \\-----END PRIVATE KEY-----
    ;
    const host = try keypair.keyPairFromPem(a, pem);
    var noise_sk: [32]u8 = undefined;
    @memset(&noise_sk, 0x55);
    const noise_kp = try std.crypto.dh.X25519.KeyPair.generateDeterministic(noise_sk);

    const enc = try encodeSignedPayload(a, host, noise_kp.public_key, &.{"/yamux/1.0.0"});
    defer a.free(enc);

    const peer = try verifySignedPayload(a, enc, noise_kp.public_key, null, 16 * 1024, &mux);
    const expected = try keypair.peerIdFromKeyPair(a, host);
    try std.testing.expect(peer.eql(&expected));
}

test "verifySignedPayload rejects wrong noise static key" {
    const a = std.testing.allocator;
    var mux = std.ArrayList([]const u8).empty;
    defer mux.deinit(a);

    const pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MC4CAQAwBQYDK2VwBCIEIB8/f4rB+k4+LRJPQe1pK4IwPlkgqaIVlw2texF6iTww
        \\-----END PRIVATE KEY-----
    ;
    const host = try keypair.keyPairFromPem(a, pem);
    var noise_sk: [32]u8 = undefined;
    @memset(&noise_sk, 0x55);
    const noise_kp = try std.crypto.dh.X25519.KeyPair.generateDeterministic(noise_sk);

    const enc = try encodeSignedPayload(a, host, noise_kp.public_key, &.{});
    defer a.free(enc);

    var wrong_pk = noise_kp.public_key;
    wrong_pk[0] ^= 0xff;

    try std.testing.expectError(error.BadSignature, verifySignedPayload(a, enc, wrong_pk, null, 16 * 1024, &mux));
}

test "sec1FromSubjectPublicKeyInfo strips ASN.1 wrapper to raw P-256 point" {
    // Minimal hand-built SPKI for an ECDSA-P256 public key (1.2.840.10045.2.1 +
    // 1.2.840.10045.3.1.7 OIDs are abbreviated as placeholders here; the SEC1
    // payload itself is what we care about). Layout:
    //   SEQUENCE {
    //     SEQUENCE { dummy alg oids }
    //     BIT STRING { 0x00 || <SEC1 point bytes...> }
    //   }
    const sec1_point = [_]u8{
        0x04, // uncompressed point indicator
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1a,
        0x1b,
        0x1c,
        0x1d,
        0x1e,
        0x1f,
        0x20,
        0x21,
        0x22,
        0x23,
        0x24,
        0x25,
        0x26,
        0x27,
        0x28,
        0x29,
        0x2a,
        0x2b,
        0x2c,
        0x2d,
        0x2e,
        0x2f,
        0x30,
        0x31,
        0x32,
        0x33,
        0x34,
        0x35,
        0x36,
        0x37,
        0x38,
        0x39,
        0x3a,
        0x3b,
        0x3c,
        0x3d,
        0x3e,
        0x3f,
        0x40,
    };
    var spki: [128]u8 = undefined;
    spki[0] = 0x30; // outer SEQUENCE
    // body: alg-header(2) + alg-body(0) + bs-header(2) + unused(1) + sec1
    const bs_body_len: u8 = 1 + sec1_point.len;
    const seq_body_len: u8 = 2 + 0 + 2 + bs_body_len;
    spki[1] = seq_body_len;
    spki[2] = 0x30; // AlgorithmIdentifier SEQUENCE
    spki[3] = 0; // empty for this test
    spki[4] = 0x03; // BIT STRING
    spki[5] = bs_body_len;
    spki[6] = 0x00; // unused-bits byte
    @memcpy(spki[7..][0..sec1_point.len], &sec1_point);
    const total_len: usize = 2 + @as(usize, seq_body_len);

    const stripped = try sec1FromSubjectPublicKeyInfo(spki[0..total_len]);
    try std.testing.expectEqualSlices(u8, &sec1_point, stripped);
}

test "sec1FromSubjectPublicKeyInfo rejects malformed input" {
    try std.testing.expectError(error.MalformedSpki, sec1FromSubjectPublicKeyInfo(&[_]u8{ 0x00, 0x00 }));
    // Missing BIT STRING.
    try std.testing.expectError(error.MalformedSpki, sec1FromSubjectPublicKeyInfo(&[_]u8{ 0x30, 0x02, 0x30, 0x00 }));
}

test "verifySignedPayload ECDSA-P256 host round-trip (#87)" {
    const a = std.testing.allocator;
    var mux = std.ArrayList([]const u8).empty;
    defer mux.deinit(a);

    var host_seed: [32]u8 = undefined;
    @memset(&host_seed, 0x42);
    const host_kp = EcdsaP256.KeyPair.generateDeterministic(host_seed) catch unreachable;
    const sec1: [65]u8 = host_kp.public_key.toUncompressedSec1();

    const id_key = try libp2p_tls_cert.encodeEcdsaPublicKeyProto(a, sec1);
    defer a.free(id_key);

    var noise_sk: [32]u8 = undefined;
    @memset(&noise_sk, 0x77);
    const noise_kp = try std.crypto.dh.X25519.KeyPair.generateDeterministic(noise_sk);
    const sm = signingMessage(noise_kp.public_key);
    const sig = host_kp.sign(&sm, null) catch unreachable;
    var der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&der_buf);

    const enc = try payload_mod.encode(a, id_key, sig_der, &.{"/yamux/1.0.0"});
    defer a.free(enc);

    const peer = try verifySignedPayload(a, enc, noise_kp.public_key, null, 16 * 1024, &mux);
    const reader = try pid.PublicKeyReader.init(id_key);
    var pk = pid.PublicKey{ .type = .ECDSA, .data = reader.getData() };
    const expected = try pid.PeerId.fromPublicKey(a, &pk);
    try std.testing.expect(peer.eql(&expected));
}

test "verifySignedPayload RSA host round-trip (#87)" {
    const a = std.testing.allocator;
    var mux = std.ArrayList([]const u8).empty;
    defer mux.deinit(a);

    const kp = try zquic_rsa.KeyPair.fromDer(@embedFile("../../testdata/zquic_rsa/id_rsa.der"));
    const rsa_pkcs1 = try encodePkcs1RsaPublicKeyDer(a, kp.public);
    defer a.free(rsa_pkcs1);

    var libp2p_pk = pid.PublicKey{ .type = .RSA, .data = rsa_pkcs1 };
    const id_key = try libp2p_pk.encode(a);
    defer a.free(id_key);

    var noise_sk: [32]u8 = undefined;
    @memset(&noise_sk, 0x88);
    const noise_kp = try std.crypto.dh.X25519.KeyPair.generateDeterministic(noise_sk);
    const sm = signingMessage(noise_kp.public_key);

    var sig_buf: [zquic_rsa.max_modulus_len]u8 = undefined;
    const sig = try kp.signPkcsv1_5(Sha256, &sm, &sig_buf);

    const enc = try payload_mod.encode(a, id_key, sig.bytes, &.{});
    defer a.free(enc);

    const peer = try verifySignedPayload(a, enc, noise_kp.public_key, null, 16 * 1024, &mux);
    const expected = try pid.PeerId.fromPublicKey(a, &libp2p_pk);
    try std.testing.expect(peer.eql(&expected));
}

/// PKCS#1 `RSAPublicKey` DER (`SEQUENCE { n INTEGER, e INTEGER }`) for libp2p `PublicKey.Type = RSA`.
fn encodePkcs1RsaPublicKeyDer(allocator: std.mem.Allocator, pk: zquic_rsa.PublicKey) Error![]u8 {
    var n_raw: [zquic_rsa.max_modulus_len]u8 = undefined;
    const n_len = zquic_rsa.byteLen(pk.modulus.bits());
    pk.modulus.v.toBytes(n_raw[0..n_len], .big) catch return error.InvalidIdentityKey;

    var e_raw: [zquic_rsa.max_modulus_len]u8 = undefined;
    const e_limbs = zquic_rsa.byteLen(pk.modulus.bits());
    pk.public_exponent.toBytes(e_raw[0..e_limbs], .big) catch return error.InvalidIdentityKey;

    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    try appendDerIntegerTlv(&inner, allocator, n_raw[0..n_len]);
    try appendDerIntegerTlv(&inner, allocator, e_raw[0..e_limbs]);
    return dupDerTlv(allocator, 0x30, inner.items);
}

fn appendDerIntegerTlv(list: *std.ArrayList(u8), allocator: std.mem.Allocator, big_endian: []const u8) Error!void {
    var start: usize = 0;
    while (start < big_endian.len - 1 and big_endian[start] == 0) start += 1;
    const needs_pad = (big_endian[start] & 0x80) != 0;
    var payload: [zquic_rsa.max_modulus_len + 1]u8 = undefined;
    const payload_len = if (needs_pad) blk: {
        payload[0] = 0;
        @memcpy(payload[1 .. 1 + big_endian.len - start], big_endian[start..]);
        break :blk big_endian.len - start + 1;
    } else blk: {
        @memcpy(payload[0 .. big_endian.len - start], big_endian[start..]);
        break :blk big_endian.len - start;
    };
    try appendDerTlv(list, allocator, 0x02, payload[0..payload_len]);
}

fn appendDerTlv(list: *std.ArrayList(u8), allocator: std.mem.Allocator, tag: u8, payload: []const u8) Error!void {
    try list.append(allocator, tag);
    if (payload.len < 128) {
        try list.append(allocator, @intCast(payload.len));
    } else if (payload.len < 256) {
        try list.append(allocator, 0x81);
        try list.append(allocator, @intCast(payload.len));
    } else {
        try list.append(allocator, 0x82);
        try list.append(allocator, @intCast(payload.len >> 8));
        try list.append(allocator, @intCast(payload.len & 0xff));
    }
    try list.appendSlice(allocator, payload);
}

fn dupDerTlv(allocator: std.mem.Allocator, tag: u8, body: []const u8) Error![]u8 {
    var tmp = std.ArrayList(u8).empty;
    defer tmp.deinit(allocator);
    try appendDerTlv(&tmp, allocator, tag, body);
    return try allocator.dupe(u8, tmp.items);
}
