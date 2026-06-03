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
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Secp256k1 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const ArrayList = std.ArrayList(u8);

/// Algorithm the ephemeral certificate key uses (determines which PEM writer
/// the consumer must call for the matching private key).
pub const CertKeyKind = enum {
    ed25519,
    ecdsa_p256,
    secp256k1,
};

/// X.509 v3 self-signed DER bytes carrying the libp2p extension, plus the
/// ephemeral key seed that produced the SubjectPublicKeyInfo. `key_kind` tells
/// the consumer which `*_to_pem` helper to call.
pub const GeneratedCertificate = struct {
    cert_der: []u8,
    cert_key_seed: [32]u8,
    key_kind: CertKeyKind,

    pub fn deinit(self: *GeneratedCertificate, allocator: std.mem.Allocator) void {
        allocator.free(self.cert_der);
        self.* = undefined;
    }
};

/// Host identity that signs `"libp2p-tls-handshake:" || SPKI`. The signer is a
/// callback so the embedder retains custody of the actual secret material.
///
/// The variant also pins the cert keypair algorithm: Ed25519 host → Ed25519
/// cert; ECDSA-P-256 host → ECDSA-P-256 cert. (libp2p TLS allows mismatch in
/// principle, but every consumer in-tree wants matched-algorithm certs and
/// matching keeps the API surface minimal.)
pub const HostIdentityKey = union(enum) {
    ed25519: struct {
        public_key_bytes: [32]u8,
        sign: *const fn (ctx: ?*anyopaque, message: []const u8, out_sig: *[64]u8) anyerror!void,
        sign_ctx: ?*anyopaque,
    },
    /// ECDSA on the NIST P-256 curve (SECG `secp256r1` / OID `prime256v1`).
    /// `public_key_sec1_uncompressed` is the raw 65-byte SEC1 uncompressed
    /// point (`0x04 || X || Y`); this module re-wraps it as PKIX
    /// SubjectPublicKeyInfo before placing it in the libp2p protobuf, because
    /// the verifier (`libp2p_tls.verifyHostKeySignature`'s `.ECDSA` arm)
    /// expects the protobuf `Data` field to be PKIX SPKI, not raw SEC1.
    /// `sign` must produce a DER-encoded `ECDSA-Sig-Value` SEQUENCE of two
    /// INTEGERs (`r`, `s`) over SHA-256(message); `out_sig` is a scratch buffer
    /// sized to `EcdsaP256Sha256.Signature.der_encoded_length_max` (72 bytes)
    /// and `sign` writes the actual length via `out_sig_len`.
    ecdsa_p256: struct {
        public_key_sec1_uncompressed: [65]u8,
        sign: *const fn (ctx: ?*anyopaque, message: []const u8, out_sig: []u8, out_sig_len: *usize) anyerror!void,
        sign_ctx: ?*anyopaque,
    },
    /// Host identity on secp256k1 (compressed SEC1 public key, 33 bytes).
    secp256k1: struct {
        public_key_sec1_compressed: [33]u8,
        sign: *const fn (ctx: ?*anyopaque, message: []const u8, out_sig: []u8, out_sig_len: *usize) anyerror!void,
        sign_ctx: ?*anyopaque,
    },
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

/// `AlgorithmIdentifier { id-ecPublicKey (1.2.840.10045.2.1), prime256v1 (1.2.840.10045.3.1.7) }`
/// per RFC 5480. Used as the SPKI `algorithm` for ECDSA-P-256 cert keys.
const ecdsa_p256_algid_tlv: [21]u8 = .{
    0x30, 0x13, // SEQUENCE 19
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID 1.2.840.10045.2.1
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7
};

/// `AlgorithmIdentifier { ecdsa-with-SHA256 (1.2.840.10045.4.3.2) }`. Used as the
/// `signatureAlgorithm` for certs signed with an ECDSA-P-256 key.
const ecdsa_sha256_algid_tlv: [12]u8 = .{
    0x30, 0x0A,
    0x06, 0x08,
    0x2A, 0x86,
    0x48, 0xCE,
    0x3D, 0x04,
    0x03, 0x02,
};

/// `AlgorithmIdentifier { OID secp256k1 (1.3.132.0.10) }` for ephemeral cert SPKI.
const secp256k1_algid_tlv: [9]u8 = .{
    0x30, 0x07,
    0x06, 0x05,
    0x2B, 0x81,
    0x04, 0x00,
    0x0A,
};

/// OID `prime256v1` (1.2.840.10045.3.1.7) as a complete TLV — used inside
/// SEC1 `EC PRIVATE KEY` PEM as the `parameters [0] EXPLICIT namedCurve`.
const ec_param_prime256v1_oid_tlv: [10]u8 = .{
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
};

/// Subject/Issuer name with libp2p OID TLV bytes embedded in the org PrintableString (trap for #120 tests).
fn appendNameWithOidInPrintable(list: *ArrayList, a: std.mem.Allocator) std.mem.Allocator.Error!void {
    const oid_o_tlv = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x0A };
    var printable: [9 + libp2p_tls.extension_oid_tlv.len]u8 = undefined;
    @memcpy(printable[0..9], "libp2p.io");
    @memcpy(printable[9..], &libp2p_tls.extension_oid_tlv);

    var atv = ArrayList.empty;
    defer atv.deinit(a);
    try atv.appendSlice(a, &oid_o_tlv);
    try appendTLV(&atv, a, 0x13, printable[0..]);

    const atv_tlv = try dupTLV(a, 0x30, atv.items);
    defer a.free(atv_tlv);
    const set_tlv = try dupTLV(a, 0x31, atv_tlv);
    defer a.free(set_tlv);
    try appendTLV(list, a, 0x30, set_tlv);
}

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

/// Encode `PublicKey { Type = ECDSA, Data = <PKIX SPKI of P-256 pubkey> }` as
/// protobuf. Per `libp2p_tls.verifyHostKeySignature`'s `.ECDSA` arm the `Data`
/// field is PKIX `SubjectPublicKeyInfo`, not raw SEC1 — we wrap the SEC1
/// uncompressed point here so the verifier can parse it back.
///
/// Exposed for embedders that need to compute the matching PeerId from a raw
/// ECDSA-P-256 SEC1 host pubkey (cf. `peer_id.PeerId.fromPublicKey`).
/// Encode `PublicKey { Type = SECP256K1, Data = <compressed SEC1> }` as protobuf.
pub fn encodeSecp256k1PublicKeyProto(allocator: std.mem.Allocator, sec1_compressed: [33]u8) anyerror![]const u8 {
    var pk = peer_id.PublicKey{ .type = .SECP256K1, .data = &sec1_compressed };
    return try pk.encode(allocator);
}

pub fn encodeEcdsaPublicKeyProto(allocator: std.mem.Allocator, sec1_uncompressed: [65]u8) anyerror![]const u8 {
    // Build PKIX SPKI: SEQUENCE { ecdsa_p256_algid, BIT STRING { 0x00 || SEC1 } }
    var bit_payload: [1 + 65]u8 = undefined;
    bit_payload[0] = 0;
    @memcpy(bit_payload[1..], &sec1_uncompressed);

    var spki_inner = ArrayList.empty;
    defer spki_inner.deinit(allocator);
    try spki_inner.appendSlice(allocator, &ecdsa_p256_algid_tlv);
    try appendTLV(&spki_inner, allocator, 0x03, &bit_payload);
    const spki_tlv = try dupTLV(allocator, 0x30, spki_inner.items);
    defer allocator.free(spki_tlv);

    var pk = peer_id.PublicKey{ .type = .ECDSA, .data = spki_tlv };
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

/// SubjectPublicKeyInfo SEQUENCE for ephemeral ECDSA-P-256 cert key (RFC 5480).
fn appendSpkiSecp256k1(list: *ArrayList, a: std.mem.Allocator, sec1_compressed: [33]u8) std.mem.Allocator.Error!void {
    var bit_payload: [1 + 33]u8 = undefined;
    bit_payload[0] = 0;
    @memcpy(bit_payload[1..], &sec1_compressed);

    var spki = ArrayList.empty;
    defer spki.deinit(a);
    try spki.appendSlice(a, &secp256k1_algid_tlv);
    try appendTLV(&spki, a, 0x03, &bit_payload);
    try appendTLV(list, a, 0x30, spki.items);
}

fn appendSpkiEcdsaP256(list: *ArrayList, a: std.mem.Allocator, sec1_uncompressed: [65]u8) std.mem.Allocator.Error!void {
    var bit_payload: [1 + 65]u8 = undefined;
    bit_payload[0] = 0;
    @memcpy(bit_payload[1..], &sec1_uncompressed);

    var spki = ArrayList.empty;
    defer spki.deinit(a);
    try spki.appendSlice(a, &ecdsa_p256_algid_tlv);
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
/// keypair (algorithm matched to the host identity kind), has the embedder's
/// host identity sign the SPKI, and signs the TBSCertificate with the
/// ephemeral key.
pub fn generate(
    allocator: std.mem.Allocator,
    options: GenerateOptions,
) anyerror!GeneratedCertificate {
    if (options.not_before_sec > options.not_after_sec) return error.InvalidValidityWindow;

    return switch (options.host_identity) {
        .ed25519 => |h| try generateEd25519(allocator, options, h),
        .ecdsa_p256 => |h| try generateEcdsaP256(allocator, options, h),
        .secp256k1 => |h| try generateSecp256k1(allocator, options, h),
    };
}

fn generateSecp256k1(
    allocator: std.mem.Allocator,
    options: GenerateOptions,
    host: @FieldType(HostIdentityKey, "secp256k1"),
) anyerror!GeneratedCertificate {
    // Ephemeral cert key is ECDSA-P-256 (libp2p TLS spec vector 3); host identity stays secp256k1.
    const seed: [32]u8 = options.cert_key_seed;
    const cert_kp = EcdsaP256.KeyPair.generateDeterministic(seed) catch return error.InvalidSerial;
    const cert_pub_sec1 = cert_kp.public_key.toUncompressedSec1();

    var spki_buf = ArrayList.empty;
    defer spki_buf.deinit(allocator);
    try appendSpkiEcdsaP256(&spki_buf, allocator, cert_pub_sec1);
    const spki_tlv = spki_buf.items;

    var sig_msg = ArrayList.empty;
    defer sig_msg.deinit(allocator);
    try sig_msg.appendSlice(allocator, libp2p_tls.handshake_signature_prefix);
    try sig_msg.appendSlice(allocator, spki_tlv);

    var host_sig_buf: [Secp256k1.Signature.der_encoded_length_max]u8 = undefined;
    var host_sig_len: usize = 0;
    host.sign(host.sign_ctx, sig_msg.items, &host_sig_buf, &host_sig_len) catch return error.NotImplemented;
    if (host_sig_len > host_sig_buf.len) return error.NotImplemented;
    const host_sig = host_sig_buf[0..host_sig_len];

    const host_pub_proto = try encodeSecp256k1PublicKeyProto(allocator, host.public_key_sec1_compressed);
    defer allocator.free(host_pub_proto);

    const signed_key_der = try buildSignedKeyDer(allocator, host_pub_proto, host_sig);
    defer allocator.free(signed_key_der);

    const tbs_tlv = try buildTbsCertificate(allocator, options, spki_tlv, &ecdsa_sha256_algid_tlv, signed_key_der);
    defer allocator.free(tbs_tlv);

    const cert_sig = cert_kp.sign(tbs_tlv, null) catch return error.InvalidSerial;
    var cert_sig_der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const cert_sig_der = cert_sig.toDer(&cert_sig_der_buf);

    var outer = ArrayList.empty;
    defer outer.deinit(allocator);
    try outer.appendSlice(allocator, tbs_tlv);
    try outer.appendSlice(allocator, &ecdsa_sha256_algid_tlv);
    var sig_bit = ArrayList.empty;
    defer sig_bit.deinit(allocator);
    try sig_bit.append(allocator, 0);
    try sig_bit.appendSlice(allocator, cert_sig_der);
    try appendTLV(&outer, allocator, 0x03, sig_bit.items);

    const cert_der = try dupTLV(allocator, 0x30, outer.items);

    return .{
        .cert_der = cert_der,
        .cert_key_seed = seed,
        .key_kind = .ecdsa_p256,
    };
}

fn generateEd25519(
    allocator: std.mem.Allocator,
    options: GenerateOptions,
    host: @FieldType(HostIdentityKey, "ed25519"),
) anyerror!GeneratedCertificate {
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
    host.sign(host.sign_ctx, sig_msg.items, &host_sig) catch return error.NotImplemented;

    // 4. Encode libp2p PublicKey protobuf for the host identity.
    const host_pub_proto = try encodeEd25519PublicKeyProto(allocator, host.public_key_bytes);
    defer allocator.free(host_pub_proto);

    // 5. Build SignedKey DER and the libp2p extension.
    const signed_key_der = try buildSignedKeyDer(allocator, host_pub_proto, &host_sig);
    defer allocator.free(signed_key_der);

    // 6. Assemble TBSCertificate.
    const tbs_tlv = try buildTbsCertificate(allocator, options, spki_tlv, &ed25519_algid_tlv, signed_key_der);
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
        .key_kind = .ed25519,
    };
}

fn generateEcdsaP256(
    allocator: std.mem.Allocator,
    options: GenerateOptions,
    host: @FieldType(HostIdentityKey, "ecdsa_p256"),
) anyerror!GeneratedCertificate {
    // 1. Ephemeral ECDSA-P-256 cert keypair from the caller-supplied seed.
    //    `generateDeterministic` clamps/decodes the seed as a P-256 scalar.
    const seed: [32]u8 = options.cert_key_seed;
    const cert_kp = EcdsaP256.KeyPair.generateDeterministic(seed) catch return error.InvalidSerial;
    const cert_pub_sec1: [65]u8 = cert_kp.public_key.toUncompressedSec1();

    // 2. Build SPKI exactly.
    var spki_buf = ArrayList.empty;
    defer spki_buf.deinit(allocator);
    try appendSpkiEcdsaP256(&spki_buf, allocator, cert_pub_sec1);
    const spki_tlv = spki_buf.items;

    // 3. Host signs "libp2p-tls-handshake:" || SPKI_TLV.
    var sig_msg = ArrayList.empty;
    defer sig_msg.deinit(allocator);
    try sig_msg.appendSlice(allocator, libp2p_tls.handshake_signature_prefix);
    try sig_msg.appendSlice(allocator, spki_tlv);

    var host_sig_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    var host_sig_len: usize = 0;
    host.sign(host.sign_ctx, sig_msg.items, &host_sig_buf, &host_sig_len) catch return error.NotImplemented;
    if (host_sig_len > host_sig_buf.len) return error.NotImplemented;
    const host_sig = host_sig_buf[0..host_sig_len];

    // 4. Encode libp2p PublicKey protobuf (Data = PKIX SPKI of the host P-256 key).
    const host_pub_proto = try encodeEcdsaPublicKeyProto(allocator, host.public_key_sec1_uncompressed);
    defer allocator.free(host_pub_proto);

    // 5. Build SignedKey DER and the libp2p extension.
    const signed_key_der = try buildSignedKeyDer(allocator, host_pub_proto, host_sig);
    defer allocator.free(signed_key_der);

    // 6. Assemble TBSCertificate (sigAlgo = ecdsa-with-SHA-256).
    const tbs_tlv = try buildTbsCertificate(allocator, options, spki_tlv, &ecdsa_sha256_algid_tlv, signed_key_der);
    defer allocator.free(tbs_tlv);

    // 7. Ephemeral key signs TBSCertificate DER. ECDSA signature is a DER
    //    SEQUENCE { r INTEGER, s INTEGER } produced by `toDer`.
    const cert_sig = cert_kp.sign(tbs_tlv, null) catch return error.InvalidSerial;
    var cert_sig_der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const cert_sig_der = cert_sig.toDer(&cert_sig_der_buf);

    // 8. Outer Certificate.
    var outer = ArrayList.empty;
    defer outer.deinit(allocator);
    try outer.appendSlice(allocator, tbs_tlv);
    try outer.appendSlice(allocator, &ecdsa_sha256_algid_tlv);
    // signatureValue: BIT STRING { 0x00 unused-bits || DER ECDSA-Sig-Value }
    var sig_bit = ArrayList.empty;
    defer sig_bit.deinit(allocator);
    try sig_bit.append(allocator, 0);
    try sig_bit.appendSlice(allocator, cert_sig_der);
    try appendTLV(&outer, allocator, 0x03, sig_bit.items);

    const cert_der = try dupTLV(allocator, 0x30, outer.items);

    return .{
        .cert_der = cert_der,
        .cert_key_seed = seed,
        .key_kind = .ecdsa_p256,
    };
}

/// Build the TBSCertificate DER (full SEQUENCE TLV). Shared by Ed25519 and
/// ECDSA paths — only the signature `AlgorithmIdentifier` and the SPKI bytes
/// differ. Returned allocation is owned by the caller.
fn buildTbsCertificate(
    allocator: std.mem.Allocator,
    options: GenerateOptions,
    spki_tlv: []const u8,
    sig_algid_tlv: []const u8,
    signed_key_der: ?[]const u8,
) Error![]u8 {
    var tbs = ArrayList.empty;
    defer tbs.deinit(allocator);

    // [0] EXPLICIT Version v3 (INTEGER 2)
    try appendTLV(&tbs, allocator, 0xA0, &[_]u8{ 0x02, 0x01, 0x02 });

    // serialNumber INTEGER
    try appendInteger(&tbs, allocator, options.serial);

    // signature AlgorithmIdentifier
    try tbs.appendSlice(allocator, sig_algid_tlv);

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

    if (signed_key_der) |sk| {
        var exts_payload = ArrayList.empty;
        defer exts_payload.deinit(allocator);
        try appendLibp2pExtension(&exts_payload, allocator, sk);
        const exts_seq = try dupTLV(allocator, 0x30, exts_payload.items);
        defer allocator.free(exts_seq);
        try appendTLV(&tbs, allocator, 0xA3, exts_seq);
    }

    return try dupTLV(allocator, 0x30, tbs.items);
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

/// Wrap an ECDSA-P-256 secret-scalar seed as SEC1 `EC PRIVATE KEY` PEM (RFC 5915).
///
/// PEM label `EC PRIVATE KEY` is chosen specifically so zquic's vendored TLS
/// parser (`vendor/tls/src/PrivateKey.zig::findKey`) takes the `parseEcDer`
/// branch — its `parseDer` (PKCS#8) path expects a different structure and
/// fails for raw EC keys. This is the format zquic accepts.
///
/// `cert_key_seed` is interpreted as a P-256 secret scalar (deterministic
/// keypair generation in `EcdsaP256.KeyPair.generateDeterministic`).
pub fn ecdsaP256SeedToPem(allocator: std.mem.Allocator, seed: [32]u8) ![]u8 {
    const kp = EcdsaP256.KeyPair.generateDeterministic(seed) catch return error.InvalidSerial;
    const secret_bytes: [32]u8 = kp.secret_key.toBytes();
    const sec1_pub: [65]u8 = kp.public_key.toUncompressedSec1();

    // ECPrivateKey ::= SEQUENCE {
    //   version INTEGER (1),
    //   privateKey OCTET STRING <32-byte secret scalar, big-endian>,
    //   parameters [0] EXPLICIT ECParameters { namedCurve OID prime256v1 },
    //   publicKey [1] EXPLICIT BIT STRING <0x00 || SEC1 uncompressed pub>
    // }
    var inner = ArrayList.empty;
    defer inner.deinit(allocator);
    try appendTLV(&inner, allocator, 0x02, &[_]u8{0x01}); // INTEGER 1
    try appendTLV(&inner, allocator, 0x04, &secret_bytes); // privateKey OCTET STRING
    // [0] EXPLICIT containing OID prime256v1
    try appendTLV(&inner, allocator, 0xA0, &ec_param_prime256v1_oid_tlv);
    // [1] EXPLICIT containing BIT STRING (0x00 unused-bits || SEC1)
    var bit_payload: [1 + 65]u8 = undefined;
    bit_payload[0] = 0;
    @memcpy(bit_payload[1..], &sec1_pub);
    const bs_tlv = try dupTLV(allocator, 0x03, &bit_payload);
    defer allocator.free(bs_tlv);
    try appendTLV(&inner, allocator, 0xA1, bs_tlv);

    const seq = try dupTLV(allocator, 0x30, inner.items);
    defer allocator.free(seq);
    return pemEncode(allocator, "EC PRIVATE KEY", seq);
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

// ---------------------------------------------------------------------------
// ECDSA-P-256 tests
// ---------------------------------------------------------------------------

const TestEcdsaSigner = struct {
    kp: EcdsaP256.KeyPair,
    fn sign(ctx: ?*anyopaque, message: []const u8, out_sig: []u8, out_sig_len: *usize) anyerror!void {
        const self: *TestEcdsaSigner = @ptrCast(@alignCast(ctx.?));
        const sig = try self.kp.sign(message, null);
        var buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
        const der = sig.toDer(&buf);
        if (der.len > out_sig.len) return error.NoSpaceLeft;
        @memcpy(out_sig[0..der.len], der);
        out_sig_len.* = der.len;
    }
};

test "generate ECDSA-P-256 produces cert that verifies and round-trips PeerId" {
    const a = std.testing.allocator;

    var host_seed: [32]u8 = undefined;
    fillTestSeed(&host_seed, @src().line);
    const host_kp = try EcdsaP256.KeyPair.generateDeterministic(host_seed);
    var signer = TestEcdsaSigner{ .kp = host_kp };
    const host_pub_sec1 = host_kp.public_key.toUncompressedSec1();

    var cert_seed: [32]u8 = undefined;
    fillTestSeed(&cert_seed, @src().line);

    const now: i64 = 1_700_000_000;
    var gen = try generate(a, .{
        .host_identity = .{
            .ecdsa_p256 = .{
                .public_key_sec1_uncompressed = host_pub_sec1,
                .sign = TestEcdsaSigner.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now - 3600,
        .not_after_sec = now + 86_400,
        .serial = 0xDEADBEEF,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    try std.testing.expectEqual(CertKeyKind.ecdsa_p256, gen.key_kind);

    // Expected PeerId: built from libp2p PublicKey { ECDSA, Data = PKIX SPKI }.
    const host_pub_proto = try encodeEcdsaPublicKeyProto(a, host_pub_sec1);
    defer a.free(host_pub_proto);
    const reader = try peer_id.PublicKeyReader.init(host_pub_proto);
    const spki_bytes = reader.getData();
    const owned = try a.dupe(u8, spki_bytes);
    defer a.free(owned);
    var expected_pk = peer_id.PublicKey{ .type = .ECDSA, .data = owned };
    const expected_id = try peer_id.PeerId.fromPublicKey(a, &expected_pk);

    const got = try libp2p_tls.peerIdFromVerifiedCertificate(a, gen.cert_der, now);

    var ebuf: [128]u8 = undefined;
    var gbuf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        try expected_id.toBase58(&ebuf),
        try got.toBase58(&gbuf),
    );
}

test "generated ECDSA cert's libp2p extension parses" {
    const a = std.testing.allocator;
    var host_seed: [32]u8 = undefined;
    fillTestSeed(&host_seed, @src().line);
    const host_kp = try EcdsaP256.KeyPair.generateDeterministic(host_seed);
    var signer = TestEcdsaSigner{ .kp = host_kp };

    var cert_seed: [32]u8 = undefined;
    fillTestSeed(&cert_seed, @src().line);

    const now: i64 = 1_700_000_000;
    var gen = try generate(a, .{
        .host_identity = .{
            .ecdsa_p256 = .{
                .public_key_sec1_uncompressed = host_kp.public_key.toUncompressedSec1(),
                .sign = TestEcdsaSigner.sign,
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
    // ECDSA signatures are DER SEQUENCE; length is variable (~70-72 bytes).
    try std.testing.expect(sk.signature.len > 0);
    try std.testing.expect(sk.signature.len <= EcdsaP256.Signature.der_encoded_length_max);
    try std.testing.expectEqual(@as(u8, 0x30), sk.signature[0]); // DER SEQUENCE
}

test "ecdsaP256SeedToPem produces parseable SEC1 EC PRIVATE KEY" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    fillTestSeed(&seed, @src().line);

    const pem = try ecdsaP256SeedToPem(a, seed);
    defer a.free(pem);

    try std.testing.expect(std.mem.indexOf(u8, pem, "-----BEGIN EC PRIVATE KEY-----") != null);
    try std.testing.expect(std.mem.indexOf(u8, pem, "-----END EC PRIVATE KEY-----") != null);

    // Strip header/footer and base64-decode to validate it parses as a DER
    // ECPrivateKey SEQUENCE with version=1, an OCTET STRING (the secret), and
    // explicit [0] / [1] tagged children.
    const begin_lit = "-----BEGIN EC PRIVATE KEY-----";
    const end_lit = "-----END EC PRIVATE KEY-----";
    const start = std.mem.indexOf(u8, pem, begin_lit).? + begin_lit.len;
    const end = std.mem.indexOf(u8, pem, end_lit).?;
    var stripped = std.ArrayList(u8).empty;
    defer stripped.deinit(a);
    for (pem[start..end]) |c| {
        if (c != '\n' and c != '\r' and c != ' ') try stripped.append(a, c);
    }
    var der_buf: [256]u8 = undefined;
    const der_len = (try std.base64.standard.Decoder.calcSizeForSlice(stripped.items));
    try std.testing.expect(der_len <= der_buf.len);
    try std.base64.standard.Decoder.decode(der_buf[0..der_len], stripped.items);

    // Top-level SEQUENCE.
    try std.testing.expectEqual(@as(u8, 0x30), der_buf[0]);

    // Verify the embedded secret-scalar octet string matches what
    // `generateDeterministic(seed)` produces — i.e. the PEM round-trips
    // through the same key derivation the cert path uses.
    const kp = try EcdsaP256.KeyPair.generateDeterministic(seed);
    const expected_secret = kp.secret_key.toBytes();
    // The secret OCTET STRING (0x04, 0x20, <32 bytes>) appears after the
    // version INTEGER (0x02, 0x01, 0x01).
    try std.testing.expect(std.mem.indexOf(u8, der_buf[0..der_len], &expected_secret) != null);
}

// ---------------------------------------------------------------------------
// secp256k1 tests (#127)
// ---------------------------------------------------------------------------

const TestSecp256k1Signer = struct {
    kp: Secp256k1.KeyPair,
    fn sign(ctx: ?*anyopaque, message: []const u8, out_sig: []u8, out_sig_len: *usize) anyerror!void {
        const self: *TestSecp256k1Signer = @ptrCast(@alignCast(ctx.?));
        const sig = try self.kp.sign(message, null);
        var buf: [Secp256k1.Signature.der_encoded_length_max]u8 = undefined;
        const der = sig.toDer(&buf);
        if (der.len > out_sig.len) return error.NoSpaceLeft;
        @memcpy(out_sig[0..der.len], der);
        out_sig_len.* = der.len;
    }
};

test "generate secp256k1 produces cert that verifies and round-trips PeerId" {
    const a = std.testing.allocator;

    var host_seed: [32]u8 = undefined;
    fillTestSeed(&host_seed, @src().line);
    const host_kp = try Secp256k1.KeyPair.generateDeterministic(host_seed);
    var signer = TestSecp256k1Signer{ .kp = host_kp };
    const host_pub = host_kp.public_key.toCompressedSec1();

    var cert_seed: [32]u8 = undefined;
    fillTestSeed(&cert_seed, @src().line);

    const now: i64 = 1_700_000_000;
    var gen = try generate(a, .{
        .host_identity = .{
            .secp256k1 = .{
                .public_key_sec1_compressed = host_pub,
                .sign = TestSecp256k1Signer.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now - 3600,
        .not_after_sec = now + 86_400,
        .serial = 0x534B31,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    try std.testing.expectEqual(CertKeyKind.ecdsa_p256, gen.key_kind);

    const host_pub_proto = try encodeSecp256k1PublicKeyProto(a, host_pub);
    defer a.free(host_pub_proto);
    const reader = try peer_id.PublicKeyReader.init(host_pub_proto);
    const owned = try a.dupe(u8, reader.getData());
    defer a.free(owned);
    var expected_pk = peer_id.PublicKey{ .type = .SECP256K1, .data = owned };
    const expected_id = try peer_id.PeerId.fromPublicKey(a, &expected_pk);

    const got = try libp2p_tls.peerIdFromVerifiedCertificate(a, gen.cert_der, now);

    var ebuf: [128]u8 = undefined;
    var gbuf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        try expected_id.toBase58(&ebuf),
        try got.toBase58(&gbuf),
    );
}

test "trap cert: libp2p OID in subject DN only is not an extension" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    fillTestSeed(&seed, @src().line);
    const cert_kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const cert_pub = cert_kp.public_key.bytes;

    var spki_buf = ArrayList.empty;
    defer spki_buf.deinit(a);
    try appendSpki(&spki_buf, a, cert_pub);
    const spki_tlv = spki_buf.items;

    const now: i64 = 1_700_000_000;
    var tbs = ArrayList.empty;
    defer tbs.deinit(a);
    try appendTLV(&tbs, a, 0xA0, &[_]u8{ 0x02, 0x01, 0x02 });
    try appendInteger(&tbs, a, 1);
    try tbs.appendSlice(a, &ed25519_algid_tlv);
    try appendNameWithOidInPrintable(&tbs, a);
    var validity_payload = ArrayList.empty;
    defer validity_payload.deinit(a);
    try appendTime(&validity_payload, a, now - 3600);
    try appendTime(&validity_payload, a, now + 86_400);
    try appendTLV(&tbs, a, 0x30, validity_payload.items);
    try appendNameWithOidInPrintable(&tbs, a);
    try tbs.appendSlice(a, spki_tlv);

    const tbs_tlv = try dupTLV(a, 0x30, tbs.items);
    defer a.free(tbs_tlv);

    const cert_sig = try cert_kp.sign(tbs_tlv, null);
    var outer = ArrayList.empty;
    defer outer.deinit(a);
    try outer.appendSlice(a, tbs_tlv);
    try outer.appendSlice(a, &ed25519_algid_tlv);
    var sig_bit_payload: [1 + 64]u8 = undefined;
    sig_bit_payload[0] = 0;
    @memcpy(sig_bit_payload[1..], &cert_sig.toBytes());
    try appendTLV(&outer, a, 0x03, &sig_bit_payload);
    const cert_der = try dupTLV(a, 0x30, outer.items);
    defer a.free(cert_der);

    try std.testing.expect(std.mem.indexOf(u8, cert_der, &libp2p_tls.extension_oid_tlv) != null);
    try std.testing.expectError(error.MissingLibp2pExtension, libp2p_tls.findLibp2pExtensionExtValue(cert_der));
}
