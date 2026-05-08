//! libp2p TLS 1.3 identity helpers: X.509 libp2p extension + PeerId derivation.
//!
//! Specification: https://github.com/libp2p/specs/blob/master/tls/tls.md
//!
//! zquic runs QUIC TLS 1.3; set ALPN to `transport.quic_v1.tls_alpn` for libp2p-on-QUIC.
//! This module parses the libp2p Public Key extension (IANA enterprise OID) from a leaf
//! certificate and derives a PeerId from the embedded protobuf public key (spec test vectors).
//!
//! Signature verification over `handshake_signature_prefix` || SubjectPublicKeyInfo is not
//! implemented here; callers must not treat PeerId match alone as authenticated until that lands.

const std = @import("std");
const peer_id = @import("peer_id");

/// Multistream protocol id when TLS is negotiated via multistream-select (not QUIC ALPN).
pub const multistream_protocol_id: []const u8 = "/tls/1.0.0";

/// Transcript prefix the libp2p host key signs (TLS spec, peer authentication).
pub const handshake_signature_prefix: []const u8 = "libp2p-tls-handshake:";

/// Object identifier `1.3.6.1.4.1.53594.1.1` as used in the libp2p Public Key extension (`OBJECT IDENTIFIER` contents only).
pub const extension_oid_contents: [10]u8 = .{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xA2, 0x5A, 0x01, 0x01 };

/// Full DER `OBJECT IDENTIFIER` TLV for [`extension_oid_contents`].
pub const extension_oid_tlv: [12]u8 = .{ 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xA2, 0x5A, 0x01, 0x01 };

pub const Error = error{
    MissingLibp2pExtension,
    MalformedExtension,
    MalformedSignedKey,
    InvalidPublicKeyProtobuf,
    UnsupportedAsn1Length,
};

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

/// Derive [`PeerId`] from a **single** leaf certificate’s libp2p extension (Ed25519, ECDSA, Secp256k1, … per protobuf).
pub fn peerIdFromCertificate(allocator: std.mem.Allocator, cert_der: []const u8) Error!peer_id.PeerId {
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

test "libp2p TLS spec vector 1 (Ed25519) peer id" {
    const a = std.testing.allocator;
    const hex =
        \\308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77
    ;
    var buf: [512]u8 = undefined;
    const n = try std.fmt.hexToBytes(&buf, hex);
    const cert = buf[0..n];

    const id = try peerIdFromCertificate(a, cert);
    var b58: [128]u8 = undefined;
    const s = try id.toBase58(&b58);
    try std.testing.expectEqualStrings("12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv", s);
}

test "libp2p TLS spec vector 2 (ECDSA) peer id" {
    const a = std.testing.allocator;
    const hex =
        \\308201f63082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f2044730450220064ea8124774caf8f50e57f436aa62350ce652418c019df5d98a3ac666c9386a022100aa59d704a931b5f72fb9222cb6cc51f954d04a4e2e5450f8805fe8918f71eaae300a06082a8648ce3d04030203470030440220799395b0b6c1e940a7e4484705f610ab51ed376f19ff9d7c16757cfbf61b8d4302206205c03fbb0f95205c779be86581d3e31c01871ad5d1f3435bcf375cb0e5088a
    ;
    var buf: [512]u8 = undefined;
    const n = try std.fmt.hexToBytes(&buf, hex);
    const id = try peerIdFromCertificate(a, buf[0..n]);
    var b58: [128]u8 = undefined;
    const s = try id.toBase58(&b58);
    try std.testing.expectEqualStrings("QmfXbAwNjJLXfesgztEHe8HwgVDCMMpZ9Eax1HYq6hn9uE", s);
}

test "libp2p TLS spec vector 3 (secp256k1) peer id" {
    const a = std.testing.allocator;
    const hex =
        \\308201ba3082015fa0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea38184308181307f060a2b0601040183a25a01010471306f0425080212210206dc6968726765b820f050263ececf7f71e4955892776c0970542efd689d2382044630440220145e15a991961f0d08cd15425bb95ec93f6ffa03c5a385eedc34ecf464c7a8ab022026b3109b8a3f40ef833169777eb2aa337cfb6282f188de0666d1bcec2a4690dd300a06082a8648ce3d0403020349003046022100e1a217eeef9ec9204b3f774a08b70849646b6a1e6b8b27f93dc00ed58545d9fe022100b00dafa549d0f03547878338c7b15e7502888f6d45db387e5ae6b5d46899cef0
    ;
    var buf: [512]u8 = undefined;
    const n = try std.fmt.hexToBytes(&buf, hex);
    const id = try peerIdFromCertificate(a, buf[0..n]);
    var b58: [128]u8 = undefined;
    const s = try id.toBase58(&b58);
    try std.testing.expectEqualStrings("16Uiu2HAkutTMoTzDw1tCvSRtu6YoixJwS46S1ZFxW8hSx9fWHiPs", s);
}

test "missing extension" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.MissingLibp2pExtension, peerIdFromCertificate(a, &[_]u8{ 0x30, 0x00 }));
}
