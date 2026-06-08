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
//! [`peerIdFromCertificateUnverified`] only parses the extension and derives a PeerId (no crypto proof).

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

/// TBSCertificate `extensions` field payload (`SEQUENCE OF Extension`), if present.
fn tbsExtensionsSequencePayload(cert_der: []const u8) (Error || X509.ParseError)![]const u8 {
    const b = cert_der;
    if (b.len < 4) return error.MissingLibp2pExtension;
    const certificate = try X509.der.Element.parse(b, 0);
    if (certificate.slice.start >= b.len or certificate.slice.end > b.len) return error.MissingLibp2pExtension;
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

    var pos: u32 = pub_key_info.slice.end;
    while (pos < tbs_certificate.slice.end) {
        if (pos >= b.len) return error.MalformedExtension;
        if (b[pos] == 0xA3) {
            const explicit = try readConstructedTLV(b, pos, 0xA3);
            const inner = try readConstructedTLV(explicit.payload, 0, 0x30);
            return inner.payload;
        }
        const elem = try X509.der.Element.parse(b, pos);
        pos = elem.slice.end;
    }
    return error.MissingLibp2pExtension;
}

/// Raw `extnValue` OCTET STRING payload for the libp2p extension (still DER-encoded `SignedKey`).
///
/// Walks the TBSCertificate `[3] EXPLICIT Extensions` sequence and matches OID
/// `1.3.6.1.4.1.53594.1.1` only inside a proper `Extension` entry (#120).
pub fn findLibp2pExtensionExtValue(cert_der: []const u8) Error![]const u8 {
    const exts = tbsExtensionsSequencePayload(cert_der) catch |err| switch (err) {
        error.MissingLibp2pExtension, error.MalformedExtension => |e| return e,
        else => return error.MissingLibp2pExtension,
    };

    var pos: usize = 0;
    var found: ?[]const u8 = null;
    while (pos < exts.len) {
        const ext = try readConstructedTLV(exts, pos, 0x30);
        pos = ext.next;
        if (ext.payload.len < extension_oid_tlv.len) continue;
        if (!std.mem.eql(u8, ext.payload[0..extension_oid_tlv.len], &extension_oid_tlv)) continue;

        var p = extension_oid_tlv.len;
        if (p < ext.payload.len and ext.payload[p] == 0x01) {
            if (p + 2 >= ext.payload.len) return error.MalformedExtension;
            p += 3;
        }
        const oct = try readConstructedTLV(ext.payload, p, 0x04);
        if (found != null) return error.MalformedExtension;
        found = oct.payload;
    }
    return found orelse error.MissingLibp2pExtension;
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
    const parsed = try x509.parse();

    // RFC 5280 §4.1.2.5.1 validity check. We do NOT use the time comparison
    // baked into `std.crypto.Certificate.verify`: its UTCTime parser maps every
    // two-digit year via `2000 + YY`, so a notBefore of `750101…Z` (rcgen's
    // default 1975-01-01, also the libp2p spec test vectors) is read as 2075 and
    // every real-world `now` trips `CertificateNotYetValid`. We re-derive the
    // window here with the correct 19xx/20xx pivot.
    try verifyValidityWindow(cert_der, parsed, now_sec);

    // Re-use std's issuer + self-signature verification, but neutralise its
    // (buggy) time comparison by handing it a timestamp inside the window it
    // parsed. libp2p/rcgen certs use a far-future notAfter (GeneralizedTime
    // 4096), so the parsed notBefore is always a safe in-window value.
    const std_neutral_now: i64 = @intCast(parsed.validity.not_before);
    try parsed.verify(parsed, std_neutral_now);

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

/// RFC 5280 §4.1.2.5 validity-window check that handles UTCTime two-digit years
/// correctly (`YY >= 50` → `19YY`, `YY < 50` → `20YY`).
///
/// `std.crypto.Certificate.parseTime` always computes `2000 + YY`, which is wrong
/// for the very common notBefore of `1975-01-01` emitted by rcgen (rust-libp2p)
/// and used by the libp2p TLS spec test vectors — it gets read as 2075 and any
/// present-day `now_sec` fails with `CertificateNotYetValid`. We locate the
/// validity element via the already-parsed issuer slice (validity sits between
/// issuer and subject in a TBSCertificate) and re-parse both bounds here.
fn verifyValidityWindow(
    cert_der: []const u8,
    parsed: X509.Parsed,
    now_sec: i64,
) (X509.ParseError || X509.Parsed.VerifyError)!void {
    const validity = try X509.der.Element.parse(cert_der, parsed.issuer_slice.end);
    const not_before_elem = try X509.der.Element.parse(cert_der, validity.slice.start);
    const not_after_elem = try X509.der.Element.parse(cert_der, not_before_elem.slice.end);

    const not_before = try asn1TimeToUnixSeconds(cert_der, not_before_elem);
    const not_after = try asn1TimeToUnixSeconds(cert_der, not_after_elem);

    if (now_sec < not_before) return error.CertificateNotYetValid;
    if (now_sec > not_after) return error.CertificateExpired;
}

/// Parse an ASN.1 `UTCTime` or `GeneralizedTime` element to seconds since the
/// Unix epoch, applying the RFC 5280 two-digit-year pivot for `UTCTime`.
fn asn1TimeToUnixSeconds(cert_der: []const u8, elem: X509.der.Element) X509.ParseError!i64 {
    const bytes = cert_der[elem.slice.start..elem.slice.end];
    var year: i64 = undefined;
    var i: usize = 0;
    switch (elem.identifier.tag) {
        .utc_time => {
            // "YYMMDDHHMMSSZ"
            if (bytes.len != 13 or bytes[12] != 'Z') return error.CertificateTimeInvalid;
            const yy = try asn1TwoDigits(bytes[0..2]);
            year = if (yy >= 50) 1900 + @as(i64, yy) else 2000 + @as(i64, yy);
            i = 2;
        },
        .generalized_time => {
            // "YYYYMMDDHHMMSSZ" (fractional seconds / offsets unused by libp2p certs)
            if (bytes.len < 15) return error.CertificateTimeInvalid;
            const hi = try asn1TwoDigits(bytes[0..2]);
            const lo = try asn1TwoDigits(bytes[2..4]);
            year = @as(i64, hi) * 100 + @as(i64, lo);
            i = 4;
        },
        else => return error.CertificateFieldHasWrongDataType,
    }

    const month = try asn1TwoDigits(bytes[i..][0..2]);
    const day = try asn1TwoDigits(bytes[i + 2 ..][0..2]);
    const hour = try asn1TwoDigits(bytes[i + 4 ..][0..2]);
    const minute = try asn1TwoDigits(bytes[i + 6 ..][0..2]);
    const second = try asn1TwoDigits(bytes[i + 8 ..][0..2]);
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or minute > 59 or second > 60)
        return error.CertificateTimeInvalid;

    const days = daysFromCivil(year, @intCast(month), @intCast(day));
    return days * 86_400 + @as(i64, hour) * 3_600 + @as(i64, minute) * 60 + @as(i64, second);
}

fn asn1TwoDigits(b: *const [2]u8) X509.ParseError!u8 {
    if (b[0] < '0' or b[0] > '9' or b[1] < '0' or b[1] > '9') return error.CertificateTimeInvalid;
    return (b[0] - '0') * 10 + (b[1] - '0');
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`). Valid for any year; handles leap years and centuries.
fn daysFromCivil(year: i64, month: i64, day: i64) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400; // [0, 399]
    const mp = @mod(month + 9, 12); // Mar=0 … Feb=11
    const doy = @divTrunc(153 * mp + 2, 5) + day - 1; // [0, 365]
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy; // [0, 146096]
    return era * 146_097 + doe - 719_468;
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
        // Use `PeerId.eql` (compares multihash code + size + digest) — NOT
        // `std.meta.eql` on the struct. `PeerId.multihash` is `Multihash(64)`,
        // a fixed 64-byte buffer plus an active-length field; bytes past the
        // active length carry whatever the heap had there at construction
        // time. `std.meta.eql` compares the WHOLE buffer including those
        // bytes, so two semantically-equal PeerIds (same code, same size,
        // same digest) can compare unequal if their out-of-range padding
        // differs. That made every outbound QUIC dial fail with
        // `error.PeerIdMismatch` once a real `/p2p/...` expected_peer was
        // threaded in, because the verified cert and the dial multiaddr
        // had been constructed via different paths.
        var exp_var = exp;
        if (!id.eql(&exp_var)) return error.PeerIdMismatch;
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

/// A real present-day timestamp (2023-11-14T22:13:20Z) used to exercise the
/// verified path against the libp2p spec vectors, whose validity window is
/// 1975-01-01..4096-01-01. Using a genuine `now` (rather than the midpoint of
/// std's mis-parsed window) is the regression guard for the UTCTime two-digit
/// year bug: before the fix, this value sits below the mis-read 2075 notBefore
/// and the verified path fails with `CertificateNotYetValid`.
const spec_vector_now_sec: i64 = 1_700_000_000;

test "libp2p TLS spec vector 1 (Ed25519) peer id" {
    const a = std.testing.allocator;
    const hex =
        \\308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77
    ;
    var buf: [512]u8 = undefined;
    const cert_slice = try std.fmt.hexToBytes(&buf, hex);
    const cert = cert_slice;

    const id = try peerIdFromCertificateUnverified(a, cert);
    var b58: [128]u8 = undefined;
    const s = try id.toBase58(&b58);
    try std.testing.expectEqualStrings("12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv", s);

    const now = spec_vector_now_sec;
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
    const id = try peerIdFromCertificateUnverified(a, cert);
    var b58: [128]u8 = undefined;
    const s = try id.toBase58(&b58);
    try std.testing.expectEqualStrings("QmfXbAwNjJLXfesgztEHe8HwgVDCMMpZ9Eax1HYq6hn9uE", s);

    const now = spec_vector_now_sec;
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
    const id = try peerIdFromCertificateUnverified(a, cert);
    var b58: [128]u8 = undefined;
    const s = try id.toBase58(&b58);
    try std.testing.expectEqualStrings("16Uiu2HAkutTMoTzDw1tCvSRtu6YoixJwS46S1ZFxW8hSx9fWHiPs", s);

    const now = spec_vector_now_sec;
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
    const now = spec_vector_now_sec;
    try std.testing.expectError(error.SignedKeySignatureInvalid, peerIdFromVerifiedCertificate(a, cert, now));
}

test "missing extension" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.MissingLibp2pExtension, peerIdFromCertificateUnverified(a, &[_]u8{ 0x30, 0x00 }));
}

test "verifiedPeerIdFromQuicLeafCertificate rejects expected_peer mismatch" {
    const a = std.testing.allocator;
    const libp2p_tls_cert = @import("libp2p_tls_cert.zig");
    const Ed25519 = std.crypto.sign.Ed25519;

    var host_seed: [32]u8 = undefined;
    @memset(&host_seed, 0x11);
    const host_kp = try Ed25519.KeyPair.generateDeterministic(host_seed);
    const TestSigner = struct {
        kp: Ed25519.KeyPair,
        fn sign(ctx: ?*anyopaque, message: []const u8, out_sig: *[64]u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            out_sig.* = (try self.kp.sign(message, null)).toBytes();
        }
    };
    var signer = TestSigner{ .kp = host_kp };

    var cert_seed: [32]u8 = undefined;
    @memset(&cert_seed, 0x22);
    const now: i64 = 1_700_000_000;
    var gen = try libp2p_tls_cert.generate(a, .{
        .host_identity = .{
            .ed25519 = .{
                .public_key_bytes = host_kp.public_key.bytes,
                .sign = TestSigner.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now - 3600,
        .not_after_sec = now + 86_400,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    const wrong = try peer_id.PeerId.random();
    try std.testing.expectError(
        error.PeerIdMismatch,
        verifiedPeerIdFromQuicLeafCertificate(a, gen.cert_der, wrong, now),
    );
}

test "QUIC TLS ALPN matches libp2p TLS spec string" {
    try std.testing.expectEqualStrings("libp2p", quic_application_layer_protocol);
}

// Regression test for the `std.meta.eql` vs `PeerId.eql` bug at the top of
// this file: `verifiedPeerIdFromQuicLeafCertificate` USED to compare the
// derived PeerId against `expected_peer` with `std.meta.eql`, which compares
// the entire 64-byte Multihash buffer including bytes past the active length.
// That made every real QUIC dial fail with `error.PeerIdMismatch` even though
// the multihash digests matched. The fix swaps in `PeerId.eql` (code + size +
// digest only). This test constructs the SAME PeerId twice through DIFFERENT
// allocation paths (so out-of-range buffer bytes differ) and asserts the
// happy path returns it.
test "verifiedPeerIdFromQuicLeafCertificate accepts matching expected_peer (PeerId.eql semantics)" {
    const a = std.testing.allocator;
    const libp2p_tls_cert = @import("libp2p_tls_cert.zig");
    const Ed25519 = std.crypto.sign.Ed25519;

    var host_seed: [32]u8 = undefined;
    @memset(&host_seed, 0x33);
    const host_kp = try Ed25519.KeyPair.generateDeterministic(host_seed);
    const TestSigner = struct {
        kp: Ed25519.KeyPair,
        fn sign(ctx: ?*anyopaque, message: []const u8, out_sig: *[64]u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            out_sig.* = (try self.kp.sign(message, null)).toBytes();
        }
    };
    var signer = TestSigner{ .kp = host_kp };

    var cert_seed: [32]u8 = undefined;
    @memset(&cert_seed, 0x44);
    const now: i64 = 1_700_000_000;
    var gen = try libp2p_tls_cert.generate(a, .{
        .host_identity = .{
            .ed25519 = .{
                .public_key_bytes = host_kp.public_key.bytes,
                .sign = TestSigner.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now - 3600,
        .not_after_sec = now + 86_400,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    // Construct the expected PeerId via the libp2p PublicKey protobuf path
    // — the same path consumers use to derive their `/p2p/...` dial-target
    // peer id. The cert's SignedKey extension carries the SAME pubkey, but
    // the two PeerId structs reach their `multihash` field through different
    // allocations, so any bytes past the active digest length differ.
    const PublicKey = @import("peer_id").PublicKey;
    var data_buf: [32]u8 = host_kp.public_key.bytes;
    var pk = PublicKey{ .type = .ED25519, .data = &data_buf };
    const expected = try peer_id.PeerId.fromPublicKey(a, &pk);

    const verified = try verifiedPeerIdFromQuicLeafCertificate(a, gen.cert_der, expected, now);
    try std.testing.expect(verified.eql(&expected));
}

// Regression test for the zeam-observed PeerIdMismatch on ECDSA-P-256 hosts:
// the v0.1.6 test above covers the Ed25519 round-trip but ECDSA wraps the
// pubkey in a PKIX SPKI DER inside the libp2p PublicKey protobuf's `.data`
// field. This test mirrors zeam's exact init() formula for deriving `me`
// (encodeEcdsaPublicKeyProto → PublicKeyReader → PublicKey{ECDSA, getData}
// → fromPublicKey), mints a cert from the same host pubkey, and verifies
// the same PeerId comes back.
test "verifiedPeerIdFromQuicLeafCertificate accepts matching expected_peer (ECDSA-P-256, zeam-shape)" {
    const a = std.testing.allocator;
    const libp2p_tls_cert = @import("libp2p_tls_cert.zig");
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    var host_seed: [32]u8 = undefined;
    @memset(&host_seed, 0x55);
    const host_kp = try EcdsaP256.KeyPair.generateDeterministic(host_seed);
    const TestSigner = struct {
        kp: EcdsaP256.KeyPair,
        fn sign(
            ctx: ?*anyopaque,
            message: []const u8,
            out_sig: []u8,
            out_sig_len: *usize,
        ) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            const sig = try self.kp.sign(message, null);
            var der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
            const der = sig.toDer(&der_buf);
            if (der.len > out_sig.len) return error.NoSpaceLeft;
            @memcpy(out_sig[0..der.len], der);
            out_sig_len.* = der.len;
        }
    };
    var signer = TestSigner{ .kp = host_kp };
    const host_pub_sec1: [65]u8 = host_kp.public_key.toUncompressedSec1();

    var cert_seed: [32]u8 = undefined;
    @memset(&cert_seed, 0x66);
    const now: i64 = 1_700_000_000;
    var gen = try libp2p_tls_cert.generate(a, .{
        .host_identity = .{
            .ecdsa_p256 = .{
                .public_key_sec1_uncompressed = host_pub_sec1,
                .sign = TestSigner.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now - 3600,
        .not_after_sec = now + 86_400,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    // Compute expected PeerId via the EXACT chain zeam's init() uses:
    // encodeEcdsaPublicKeyProto → PublicKeyReader.init → getData → PublicKey
    // {ECDSA, that-data} → PeerId.fromPublicKey.
    const host_pub_proto = try libp2p_tls_cert.encodeEcdsaPublicKeyProto(a, host_pub_sec1);
    defer a.free(host_pub_proto);
    const pk_reader = try peer_id.PublicKeyReader.init(host_pub_proto);
    var host_pk = peer_id.PublicKey{
        .type = .ECDSA,
        .data = pk_reader.getData(),
    };
    const expected = try peer_id.PeerId.fromPublicKey(a, &host_pk);

    const verified = try verifiedPeerIdFromQuicLeafCertificate(a, gen.cert_der, expected, now);
    try std.testing.expect(verified.eql(&expected));
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

test "verified path accepts rcgen UTCTime notBefore (1975) at present time" {
    const a = std.testing.allocator;
    // Spec vector 1 cert: notBefore = UTCTime "750101130000Z" (1975-01-01),
    // notAfter = GeneralizedTime "40960101130000Z". This is the exact shape
    // rust-libp2p/rcgen emits. std's UTCTime parser reads "75" as 2075, so the
    // verified path used to reject every present-day handshake with
    // CertificateNotYetValid. Verify a real 2023/2024-era timestamp is accepted.
    const hex =
        \\308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77
    ;
    var buf: [512]u8 = undefined;
    const cert = try std.fmt.hexToBytes(&buf, hex);

    // 2023-11-14T22:13:20Z: comfortably inside [1975, 4096], but below the
    // mis-parsed 2075 notBefore — i.e. the value that exposed the bug.
    const present_now: i64 = 1_700_000_000;
    const id = try peerIdFromVerifiedCertificate(a, cert, present_now);
    var b58: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv",
        try id.toBase58(&b58),
    );
}

test "daysFromCivil matches known epochs" {
    try std.testing.expectEqual(@as(i64, 0), daysFromCivil(1970, 1, 1));
    try std.testing.expectEqual(@as(i64, 10_957), daysFromCivil(2000, 1, 1));
    // 1975-01-01 is 1826 days after the epoch (4 common years + 1 leap year).
    try std.testing.expectEqual(@as(i64, 1826), daysFromCivil(1975, 1, 1));
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
    const now = spec_vector_now_sec;
    const id_verified = try peerIdFromVerifiedCertificate(a, cert, now);

    var b1: [128]u8 = undefined;
    var b2: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        try id_unverified.toBase58(&b1),
        try id_verified.toBase58(&b2),
    );
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
