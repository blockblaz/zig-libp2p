//! libp2p TLS 1.3 identity helpers: X.509 libp2p extension + PeerId derivation.
//!
//! Specification: https://github.com/libp2p/specs/blob/master/tls/tls.md
//!
//! ## Profiles (issue #16)
//!
//! * **QUIC + TLS 1.3 (libp2p-on-QUIC):** After the QUIC handshake, TLS uses application-layer
//!   protocol [`quic_application_layer_protocol`] (value `libp2p`). [`transport.quic_v1`] presets
//!   (`libp2pZquicServerConfig` / `libp2pZquicClientConfig`) set this via `tls_alpn`, which aliases
//!   the constant below—keep them in sync. zquic ≥ 1.6.4 requests a client certificate on libp2p
//!   listeners and exposes the dialer leaf on [`zquic.transport.io.serverConnPeerLeafCertificateDer`];
//!   the server leaf stays on [`zquic.transport.io.Client.peerLeafCertificateDer`]. [`transport.quic_peer_identity`]
//!   maps both to [`verifiedPeerIdFromQuicLeafCertificate`]. For raw TLS bytes elsewhere, use
//!   [`leafCertificateDerFromTls13HandshakeCertificateMessage`] then [`peerIdFromVerifiedCertificate`].
//! * **TCP (or other) via multistream-select:** negotiate [`multistream_protocol_id`] (`/tls/1.0.0`)
//!   before the TLS layer, per the TLS spec multistream path.
//! * **Noise XX** for devnets that require it is **not** implemented here; track [#36](https://github.com/ch4r10t33r/zig-libp2p/issues/36).
//!
//! This module parses the libp2p Public Key extension (IANA enterprise OID) from a leaf
//! certificate and derives a PeerId from the embedded protobuf public key (spec test vectors).
//!
//! For authenticated handshakes, use [`peerIdFromVerifiedCertificate`]: it enforces a single
//! certificate, self-signature and validity window (`std.crypto.Certificate.verify`), and verifies
//! the host key signature over `handshake_signature_prefix` || SubjectPublicKeyInfo (TLS spec).
//! [`peerIdFromCertificate`] only parses the extension and derives a PeerId (no crypto proof).

const std = @import("std");
const peer_id = @import("peer_id");

const X509 = std.crypto.Certificate;

/// TLS ALPN identifier for libp2p over QUIC (TLS 1.3). Same bytes as `transport.quic_v1.tls_alpn`.
pub const quic_application_layer_protocol: []const u8 = "libp2p";

/// Multistream protocol id when TLS is negotiated via multistream-select (not QUIC ALPN).
pub const multistream_protocol_id: []const u8 = "/tls/1.0.0";

/// Transcript prefix the libp2p host key signs (TLS spec, peer authentication).
pub const handshake_signature_prefix: []const u8 = "libp2p-tls-handshake:";

/// Object identifier `1.3.6.1.4.1.53594.1.1` as used in the libp2p Public Key extension (`OBJECT IDENTIFIER` contents only).
pub const extension_oid_contents: [10]u8 = .{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xA2, 0x5A, 0x01, 0x01 };

/// Full DER `OBJECT IDENTIFIER` TLV for [`extension_oid_contents`].
pub const extension_oid_tlv: [12]u8 = .{ 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xA2, 0x5A, 0x01, 0x01 };

pub const TlsHandshakeCertificateMessageError = error{
    MalformedTlsHandshakeCertificateMessage,
};

pub const QuicPeerIdentityError = VerifyPeerCertificateError || error{PeerIdMismatch};

pub const Error = error{
    MissingLibp2pExtension,
    MalformedExtension,
    MalformedSignedKey,
    InvalidPublicKeyProtobuf,
    UnsupportedAsn1Length,
    CertificateTrailingData,
    MalformedSubjectPublicKeyInfo,
    HandshakeMessageTooLong,
    SignedKeySignatureInvalid,
    InvalidHostPublicKeyEncoding,
    UnsupportedHostPublicKeyType,
} || std.mem.Allocator.Error;

/// Full TLS identity verification (certificate + SignedKey), per the libp2p TLS spec.
pub const VerifyPeerCertificateError = Error || X509.ParseError || X509.Parsed.VerifyError;

fn readShortDerLength(buf: []const u8, pos: usize) Error!struct { len: usize, header: usize } {
    if (pos >= buf.len) return error.MalformedExtension;
    const first = buf[pos];
    if (first & 0x80 == 0) {
        return .{ .len = first, .header = 1 };
    }
    const nbytes = first & 0x7f;
    if (nbytes == 0 or nbytes > 4 or pos + 1 + nbytes > buf.len) return error.UnsupportedAsn1Length;
    var len: usize = 0;
    for (buf[pos + 1 .. pos + 1 + nbytes]) |b| {
        len = (len << 8) | b;
    }
    return .{ .len = len, .header = 1 + nbytes };
}

fn readConstructedTLV(buf: []const u8, pos: usize, expected_tag: u8) Error!struct { payload: []const u8, next: usize } {
    if (pos >= buf.len or buf[pos] != expected_tag) return error.MalformedExtension;
    const lh = try readShortDerLength(buf, pos + 1);
    const start = pos + 1 + lh.header;
    const end = start + lh.len;
    if (end > buf.len) return error.MalformedExtension;
    return .{ .payload = buf[start..end], .next = end };
}

/// Raw `extnValue` OCTET STRING payload for the libp2p extension (still DER-encoded `SignedKey`).
pub fn findLibp2pExtensionExtValue(cert_der: []const u8) Error![]const u8 {
    const idx = std.mem.indexOf(u8, cert_der, &extension_oid_tlv) orelse return error.MissingLibp2pExtension;
    var pos = idx + extension_oid_tlv.len;
    if (pos < cert_der.len and cert_der[pos] == 0x01) {
        if (pos + 2 >= cert_der.len) return error.MalformedExtension;
        pos += 3;
    }
    const oct = try readConstructedTLV(cert_der, pos, 0x04);
    return oct.payload;
}

/// Parse `SignedKey` (`SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }`).
pub fn parseSignedKey(signed_key_der: []const u8) Error!struct { public_key_pb: []const u8, signature: []const u8 } {
    const seq = try readConstructedTLV(signed_key_der, 0, 0x30);
    if (seq.next != signed_key_der.len) return error.MalformedSignedKey;

    var p: usize = 0;
    const pk = try readConstructedTLV(seq.payload, p, 0x04);
    p = pk.next;
    const sig = try readConstructedTLV(seq.payload, p, 0x04);
    p = sig.next;
    if (p != seq.payload.len) return error.MalformedSignedKey;

    return .{ .public_key_pb = pk.payload, .signature = sig.payload };
}

/// SubjectPublicKeyInfo DER of the certificate’s ephemeral key (RFC 5280), as signed in the TLS handshake.
fn subjectPublicKeyInfoTlv(cert_der: []const u8) (Error || X509.ParseError)![]const u8 {
    const b = cert_der;
    const certificate = try X509.der.Element.parse(b, 0);
    const tbs_certificate = try X509.der.Element.parse(b, certificate.slice.start);
    const version_elem = try X509.der.Element.parse(b, tbs_certificate.slice.start);
    const serial_number = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
        try X509.der.Element.parse(b, version_elem.slice.end)
    else
        version_elem;
    const tbs_signature = try X509.der.Element.parse(b, serial_number.slice.end);
    const issuer = try X509.der.Element.parse(b, tbs_signature.slice.end);
    const validity = try X509.der.Element.parse(b, issuer.slice.end);
    const subject = try X509.der.Element.parse(b, validity.slice.end);
    const spki_start: u32 = subject.slice.end;
    const pub_key_info = try X509.der.Element.parse(b, spki_start);
    return b[spki_start..pub_key_info.slice.end];
}

fn sec1FromSubjectPublicKeyInfoPkix(spki: []const u8) Error![]const u8 {
    const seq = try readConstructedTLV(spki, 0, 0x30);
    if (seq.next != spki.len) return error.MalformedSubjectPublicKeyInfo;
    var pos: usize = 0;
    const algo = try readConstructedTLV(seq.payload, pos, 0x30);
    pos = algo.next;
    const bitstr = try readConstructedTLV(seq.payload, pos, 0x03);
    if (bitstr.payload.len < 2) return error.MalformedSubjectPublicKeyInfo;
    if (bitstr.payload[0] != 0) return error.MalformedSubjectPublicKeyInfo;
    return bitstr.payload[1..];
}

fn verifyHostKeySignature(
    key_type: peer_id.KeyType,
    pubkey_data: []const u8,
    signature: []const u8,
    message: []const u8,
) Error!void {
    const Ed25519 = std.crypto.sign.Ed25519;
    const ecdsa = std.crypto.sign.ecdsa;
    switch (key_type) {
        .ED25519 => {
            if (pubkey_data.len != Ed25519.PublicKey.encoded_length) return error.InvalidHostPublicKeyEncoding;
            if (signature.len != Ed25519.Signature.encoded_length) return error.SignedKeySignatureInvalid;
            const pk = Ed25519.PublicKey.fromBytes(pubkey_data[0..Ed25519.PublicKey.encoded_length].*) catch
                return error.InvalidHostPublicKeyEncoding;
            const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            sig.verify(message, pk) catch return error.SignedKeySignatureInvalid;
        },
        .SECP256K1 => {
            if (pubkey_data.len != 33) return error.InvalidHostPublicKeyEncoding;
            const pk = ecdsa.EcdsaSecp256k1Sha256.PublicKey.fromSec1(pubkey_data) catch
                return error.InvalidHostPublicKeyEncoding;
            const sig = ecdsa.EcdsaSecp256k1Sha256.Signature.fromDer(signature) catch
                return error.SignedKeySignatureInvalid;
            sig.verify(message, pk) catch return error.SignedKeySignatureInvalid;
        },
        .ECDSA => {
            const sec1 = sec1FromSubjectPublicKeyInfoPkix(pubkey_data) catch
                return error.InvalidHostPublicKeyEncoding;
            const pk = ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(sec1) catch
                return error.InvalidHostPublicKeyEncoding;
            const sig = ecdsa.EcdsaP256Sha256.Signature.fromDer(signature) catch
                return error.SignedKeySignatureInvalid;
            sig.verify(message, pk) catch return error.SignedKeySignatureInvalid;
        },
        .RSA, .CURVE25519 => return error.UnsupportedHostPublicKeyType,
    }
}

/// Verify libp2p TLS identity: single self-signed cert (time range), libp2p extension, and host signature.
pub fn peerIdFromVerifiedCertificate(
    allocator: std.mem.Allocator,
    cert_der: []const u8,
    now_sec: i64,
) VerifyPeerCertificateError!peer_id.PeerId {
    if (cert_der.len > std.math.maxInt(u32)) return error.CertificateFieldHasInvalidLength;

    const cert_el = try X509.der.Element.parse(cert_der, 0);
    if (@as(usize, @intCast(cert_el.slice.end)) != cert_der.len)
        return error.CertificateTrailingData;

    const x509 = X509{ .buffer = cert_der, .index = 0 };
    try X509.verify(x509, x509, now_sec);

    const spki = try subjectPublicKeyInfoTlv(cert_der);
    const msg_len = handshake_signature_prefix.len + spki.len;
    if (msg_len > 512) return error.HandshakeMessageTooLong;
    var msg_buf: [512]u8 = undefined;
    @memcpy(msg_buf[0..handshake_signature_prefix.len], handshake_signature_prefix);
    @memcpy(msg_buf[handshake_signature_prefix.len..][0..spki.len], spki);
    const message = msg_buf[0..msg_len];

    const ext = try findLibp2pExtensionExtValue(cert_der);
    const sk = try parseSignedKey(ext);
    const reader = peer_id.PublicKeyReader.init(sk.public_key_pb) catch return error.InvalidPublicKeyProtobuf;
    const pk_data = reader.getData();
    if (pk_data.len == 0) return error.InvalidPublicKeyProtobuf;

    try verifyHostKeySignature(reader.getType(), pk_data, sk.signature, message);

    const owned = try allocator.dupe(u8, pk_data);
    defer allocator.free(owned);

    var pk = peer_id.PublicKey{
        .type = reader.getType(),
        .data = owned,
    };
    return peer_id.PeerId.fromPublicKey(allocator, &pk) catch return error.InvalidPublicKeyProtobuf;
}

/// Derive [`PeerId`] from a **single** leaf certificate’s libp2p extension (Ed25519, ECDSA, Secp256k1, … per protobuf).
fn readTlsHandshakeU24(buf: []const u8, pos: usize) TlsHandshakeCertificateMessageError!struct { v: u32, next: usize } {
    if (pos + 3 > buf.len) return error.MalformedTlsHandshakeCertificateMessage;
    const v = (@as(u32, buf[pos]) << 16) | (@as(u32, buf[pos + 1]) << 8) | @as(u32, buf[pos + 2]);
    return .{ .v = v, .next = pos + 3 };
}

/// Parse a TLS 1.3 `Certificate` handshake message (type `0x0b`) and return the first entry’s DER.
/// `message` is the full record: 1-byte type, 3-byte length, then body (RFC 8446 §4.4.2).
pub fn leafCertificateDerFromTls13HandshakeCertificateMessage(message: []const u8) TlsHandshakeCertificateMessageError![]const u8 {
    if (message.len < 4) return error.MalformedTlsHandshakeCertificateMessage;
    if (message[0] != 0x0b) return error.MalformedTlsHandshakeCertificateMessage;
    const lh = try readTlsHandshakeU24(message, 1);
    const body_end = lh.next + lh.v;
    if (body_end > message.len) return error.MalformedTlsHandshakeCertificateMessage;
    const body = message[lh.next..body_end];
    if (body.len < 1) return error.MalformedTlsHandshakeCertificateMessage;
    const ctx_len = body[0];
    const after_ctx = 1 + ctx_len;
    if (after_ctx > body.len) return error.MalformedTlsHandshakeCertificateMessage;
    const list_h = try readTlsHandshakeU24(body, after_ctx);
    const list_end = list_h.next + list_h.v;
    if (list_end > body.len) return error.MalformedTlsHandshakeCertificateMessage;
    const list = body[list_h.next..list_end];
    if (list.len < 3) return error.MalformedTlsHandshakeCertificateMessage;
    const cert_len_h = try readTlsHandshakeU24(list, 0);
    const cert_end = cert_len_h.next + cert_len_h.v;
    if (cert_end > list.len) return error.MalformedTlsHandshakeCertificateMessage;
    return list[cert_len_h.next..cert_end];
}

/// Full libp2p identity verification on a QUIC peer leaf cert, optionally matching `/p2p` from the dial multiaddr.
pub fn verifiedPeerIdFromQuicLeafCertificate(
    allocator: std.mem.Allocator,
    cert_der: []const u8,
    expected_peer: ?peer_id.PeerId,
    now_sec: i64,
) QuicPeerIdentityError!peer_id.PeerId {
    const id = try peerIdFromVerifiedCertificate(allocator, cert_der, now_sec);
    if (expected_peer) |exp| {
        if (!std.meta.eql(id, exp)) return error.PeerIdMismatch;
    }
    return id;
}

/// Decode the libp2p extension and derive a PeerId **without** verifying the
/// certificate's self-signature, validity window, or the libp2p SignedKey
/// signature. **Do not use this for authenticated handshakes** — a hostile peer
/// can supply any PeerId in the extension and this function will happily return
/// it. Prefer [`peerIdFromVerifiedCertificate`] / [`verifiedPeerIdFromQuicLeafCertificate`]
/// (#89). Retained for test-vector replay and protocol-id derivation scenarios
/// where the cert is already trusted out-of-band.
pub fn peerIdFromCertificateUnverified(allocator: std.mem.Allocator, cert_der: []const u8) Error!peer_id.PeerId {
    const ext = try findLibp2pExtensionExtValue(cert_der);
    const sk = try parseSignedKey(ext);
    const reader = peer_id.PublicKeyReader.init(sk.public_key_pb) catch return error.InvalidPublicKeyProtobuf;
    const data = reader.getData();
    if (data.len == 0) return error.InvalidPublicKeyProtobuf;

    const owned = try allocator.dupe(u8, data);
    defer allocator.free(owned);

    var pk = peer_id.PublicKey{
        .type = reader.getType(),
        .data = owned,
    };
    return peer_id.PeerId.fromPublicKey(allocator, &pk) catch return error.InvalidPublicKeyProtobuf;
}

/// Back-compat alias for [`peerIdFromCertificateUnverified`]. The renamed name
/// makes the security trade-off explicit at the call site; this alias keeps
/// existing callers compiling. Schedule for removal after embedders migrate.
pub const peerIdFromCertificate = peerIdFromCertificateUnverified;

fn tlsVectorValidityMidpointSec(cert_der: []const u8) X509.ParseError!i64 {
    const c = X509{ .buffer = cert_der, .index = 0 };
    const p = try c.parse();
    return @intCast((p.validity.not_before + p.validity.not_after) / 2);
}

test "libp2p TLS spec vector 1 (Ed25519) peer id" {
    const a = std.testing.allocator;
    const hex =
        \\308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77
    ;
    var buf: [512]u8 = undefined;
    const cert_slice = try std.fmt.hexToBytes(&buf, hex);
    const cert = cert_slice;

    const id = try peerIdFromCertificate(a, cert);
    var b58: [128]u8 = undefined;
    const s = try id.toBase58(&b58);
    try std.testing.expectEqualStrings("12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv", s);

    const now = try tlsVectorValidityMidpointSec(cert);
    const id_v = try peerIdFromVerifiedCertificate(a, cert, now);
    var b58_v: [128]u8 = undefined;
    const s_v = try id_v.toBase58(&b58_v);
    try std.testing.expectEqualStrings("12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv", s_v);
}

test "libp2p TLS spec vector 2 (ECDSA) peer id" {
    const a = std.testing.allocator;
    const hex =
        \\308201f63082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f2044730450220064ea8124774caf8f50e57f436aa62350ce652418c019df5d98a3ac666c9386a022100aa59d704a931b5f72fb9222cb6cc51f954d04a4e2e5450f8805fe8918f71eaae300a06082a8648ce3d04030203470030440220799395b0b6c1e940a7e4484705f610ab51ed376f19ff9d7c16757cfbf61b8d4302206205c03fbb0f95205c779be86581d3e31c01871ad5d1f3435bcf375cb0e5088a
    ;
    var buf: [512]u8 = undefined;
    const cert_slice = try std.fmt.hexToBytes(&buf, hex);
    const cert = cert_slice;
    const id = try peerIdFromCertificate(a, cert);
    var b58: [128]u8 = undefined;
    const s = try id.toBase58(&b58);
    try std.testing.expectEqualStrings("QmfXbAwNjJLXfesgztEHe8HwgVDCMMpZ9Eax1HYq6hn9uE", s);

    const now = try tlsVectorValidityMidpointSec(cert);
    const id_v = try peerIdFromVerifiedCertificate(a, cert, now);
    var b58_v: [128]u8 = undefined;
    const s_v = try id_v.toBase58(&b58_v);
    try std.testing.expectEqualStrings("QmfXbAwNjJLXfesgztEHe8HwgVDCMMpZ9Eax1HYq6hn9uE", s_v);
}

test "libp2p TLS spec vector 3 (secp256k1) peer id" {
    const a = std.testing.allocator;
    const hex =
        \\308201ba3082015fa0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea38184308181307f060a2b0601040183a25a01010471306f0425080212210206dc6968726765b820f050263ececf7f71e4955892776c0970542efd689d2382044630440220145e15a991961f0d08cd15425bb95ec93f6ffa03c5a385eedc34ecf464c7a8ab022026b3109b8a3f40ef833169777eb2aa337cfb6282f188de0666d1bcec2a4690dd300a06082a8648ce3d0403020349003046022100e1a217eeef9ec9204b3f774a08b70849646b6a1e6b8b27f93dc00ed58545d9fe022100b00dafa549d0f03547878338c7b15e7502888f6d45db387e5ae6b5d46899cef0
    ;
    var buf: [512]u8 = undefined;
    const cert_slice = try std.fmt.hexToBytes(&buf, hex);
    const cert = cert_slice;
    const id = try peerIdFromCertificate(a, cert);
    var b58: [128]u8 = undefined;
    const s = try id.toBase58(&b58);
    try std.testing.expectEqualStrings("16Uiu2HAkutTMoTzDw1tCvSRtu6YoixJwS46S1ZFxW8hSx9fWHiPs", s);

    const now = try tlsVectorValidityMidpointSec(cert);
    const id_v = try peerIdFromVerifiedCertificate(a, cert, now);
    var b58_v: [128]u8 = undefined;
    const s_v = try id_v.toBase58(&b58_v);
    try std.testing.expectEqualStrings("16Uiu2HAkutTMoTzDw1tCvSRtu6YoixJwS46S1ZFxW8hSx9fWHiPs", s_v);
}

test "libp2p TLS spec vector 4 (invalid) rejected after verify" {
    const a = std.testing.allocator;
    const hex =
        \\308201f73082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f204473045022100bb6e03577b7cc7a3cd1558df0da2b117dfdcc0399bc2504ebe7de6f65cade72802206de96e2a5be9b6202adba24ee0362e490641ac45c240db71fe955f2c5cf8df6e300a06082a8648ce3d0403020348003045022100e847f267f43717358f850355bdcabbefb2cfbf8a3c043b203a14788a092fe8db022027c1d04a2d41fd6b57a7e8b3989e470325de4406e52e084e34a3fd56eef0d0df
    ;
    var buf: [512]u8 = undefined;
    const cert_slice = try std.fmt.hexToBytes(&buf, hex);
    const cert = cert_slice;
    const now = try tlsVectorValidityMidpointSec(cert);
    try std.testing.expectError(error.SignedKeySignatureInvalid, peerIdFromVerifiedCertificate(a, cert, now));
}

test "missing extension" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.MissingLibp2pExtension, peerIdFromCertificate(a, &[_]u8{ 0x30, 0x00 }));
}

test "QUIC TLS ALPN matches libp2p TLS spec string" {
    try std.testing.expectEqualStrings("libp2p", quic_application_layer_protocol);
}

test "verified path rejects expired certificate" {
    const a = std.testing.allocator;
    // Same cert as spec vector 1 (Ed25519).
    const hex =
        \\308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77
    ;
    var buf: [512]u8 = undefined;
    const cert_slice = try std.fmt.hexToBytes(&buf, hex);
    const cert = cert_slice;

    // Cert validity: notBefore = 1975-01-01, notAfter = 4096-01-01. Use a moment
    // before notBefore to exercise the cert-time-range check (#89).
    const way_before: i64 = -1_000_000_000;
    try std.testing.expectError(error.CertificateNotYetValid, peerIdFromVerifiedCertificate(a, cert, way_before));
}

test "unverified path returns same PeerId as verified for valid spec vector" {
    const a = std.testing.allocator;
    const hex =
        \\308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77
    ;
    var buf: [512]u8 = undefined;
    const cert_slice = try std.fmt.hexToBytes(&buf, hex);
    const cert = cert_slice;

    const id_unverified = try peerIdFromCertificateUnverified(a, cert);
    const now = try tlsVectorValidityMidpointSec(cert);
    const id_verified = try peerIdFromVerifiedCertificate(a, cert, now);

    var b1: [128]u8 = undefined;
    var b2: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        try id_unverified.toBase58(&b1),
        try id_verified.toBase58(&b2),
    );
}

test "unverified path warns about no-crypto helper via doc-comment" {
    // This is a behavioural test of the alias: both names resolve to the same fn.
    try std.testing.expectEqual(@as(*const @TypeOf(peerIdFromCertificateUnverified), &peerIdFromCertificateUnverified), &peerIdFromCertificate);
}

test "parse synthetic TLS 1.3 Certificate handshake (first leaf)" {
    // certificate_request_context = empty, list = one entry: u24 len + cert + u16 ext = 3+1+2
    const body = [_]u8{
        0x00, // ctx len
        0x00, 0x00, 0x06, // list length = 6
        0x00, 0x00, 0x01, // cert octet string length = 1
        0xab,
        0x00, 0x00, // certificate extensions length = 0
    };
    var msg: [4 + body.len]u8 = undefined;
    msg[0] = 0x0b;
    msg[1] = 0x00;
    msg[2] = 0x00;
    msg[3] = @intCast(body.len);
    @memcpy(msg[4..], &body);
    const leaf = try leafCertificateDerFromTls13HandshakeCertificateMessage(&msg);
    try std.testing.expectEqual(@as(usize, 1), leaf.len);
    try std.testing.expectEqual(@as(u8, 0xab), leaf[0]);
}
