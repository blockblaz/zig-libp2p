//! libp2p Noise identity: sign / verify over `noise-libp2p-static-key:` ‖ 32-byte X25519 static public key.

const std = @import("std");
const pid = @import("peer_id");
const keypair = @import("../../keypair.zig");
const payload_mod = @import("payload.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Secp256k1 = std.crypto.ecdsa.EcdsaSecp256k1Sha256;

pub const static_key_challenge_prefix = "noise-libp2p-static-key:";

pub const Error = error{
    InvalidIdentityKey,
    BadSignature,
    PeerIdMismatch,
    InvalidEd25519SignatureLength,
    OutOfMemory,
} || payload_mod.Error || keypair.PeerIdFromKeyPairError;

/// Message signed by the host identity over the peer's Noise static X25519 public key.
pub fn signingMessage(remote_noise_static_pk: [32]u8) [static_key_challenge_prefix.len + 32]u8 {
    var m: [static_key_challenge_prefix.len + 32]u8 = undefined;
    @memcpy(m[0..static_key_challenge_prefix.len], static_key_challenge_prefix);
    @memcpy(m[static_key_challenge_prefix.len..][0..32], &remote_noise_static_pk);
    return m;
}

fn encodeLibp2pPublicKey(allocator: std.mem.Allocator, kp: keypair.KeyPair) std.mem.Allocator.Error![]u8 {
    return switch (kp) {
        .ed25519 => |k| {
            const b = k.public_key.toBytes();
            var pk = pid.PublicKey{ .type = .ED25519, .data = &b };
            return try pk.encode(allocator);
        },
        .secp256k1 => |k| {
            const comp = k.public_key.toCompressedSec1();
            var pk = pid.PublicKey{ .type = .SECP256K1, .data = &comp };
            return try pk.encode(allocator);
        },
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
            const sig = try k.sign(&msg, null);
            break :blk try allocator.dupe(u8, &sig.toBytes());
        },
        .secp256k1 => |k| blk: {
            const sig = try k.sign(&msg, null);
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
        else => return error.InvalidIdentityKey,
    }
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
