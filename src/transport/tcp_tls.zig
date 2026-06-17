//! libp2p TLS 1.3 on TCP (`/tls/1.0.0` + ALPN `libp2p`). See [`stream_upgrade`] (#86).
//!
//! Spec: https://github.com/libp2p/specs/blob/master/tls/tls.md

const std = @import("std");
const libp2p_tls = @import("../security/libp2p_tls.zig");
const peer_id_mod = @import("peer_id");

pub const stream_upgrade = @import("tcp_tls/stream_upgrade.zig");
pub const sni = @import("tcp_tls/sni.zig");

/// Multistream-select id negotiated before the TLS handshake.
pub const multistream_protocol_id: []const u8 = libp2p_tls.multistream_protocol_id;

/// Line-terminated multistream token (`/tls/1.0.0\n`).
pub const multistream_select_line: []const u8 = "/tls/1.0.0\n";

/// Verify a peer leaf certificate DER (same path as QUIC). Prefer [`stream_upgrade.negotiateInitiator`].
pub fn verifyPeerLeafCertificate(
    allocator: std.mem.Allocator,
    cert_der: []const u8,
    expected_peer: ?peer_id_mod.PeerId,
    now_sec: i64,
) libp2p_tls.QuicPeerIdentityError!peer_id_mod.PeerId {
    return libp2p_tls.verifiedPeerIdFromQuicLeafCertificate(allocator, cert_der, expected_peer, now_sec);
}

pub const HandshakeResult = stream_upgrade.HandshakeResult;
pub const SecureChannel = stream_upgrade.SecureChannel;
pub const OwnedCertKeyPair = stream_upgrade.OwnedCertKeyPair;

pub const negotiateInitiator = stream_upgrade.negotiateInitiator;
pub const negotiateResponder = stream_upgrade.negotiateResponder;
pub const certKeyPairFromPem = stream_upgrade.certKeyPairFromPem;
pub const toTransportError = stream_upgrade.toTransportError;
pub const default_tls_server_name = sni.default_server_name;
pub const serverNameFromMultiaddr = sni.serverNameFromMultiaddr;
pub const resolveTlsServerName = sni.resolveTlsServerName;

test "multistream_select_line ends with newline" {
    try std.testing.expect(std.mem.endsWith(u8, multistream_select_line, "\n"));
}

test "verifyPeerLeafCertificate accepts spec vector 1 (Ed25519)" {
    const a = std.testing.allocator;
    const hex =
        \\308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77
    ;
    var buf: [512]u8 = undefined;
    const cert = try std.fmt.hexToBytes(&buf, hex);
    const id = try verifyPeerLeafCertificate(a, cert, null, 35_000_000_000);
    var b58: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv",
        try id.toBase58(&b58),
    );
}

// `stream_upgrade.zig` loopback tests use Io.Threaded + tcp listen/dial and are
// not force-discovered here (same exclusion as noise/stream_upgrade, tcp.zig).
