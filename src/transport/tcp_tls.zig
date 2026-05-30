//! libp2p TLS 1.3 on a TCP stream — wire-protocol scaffold (#86).
//!
//! Spec: https://github.com/libp2p/specs/blob/master/tls/tls.md
//!
//! Today, QUIC libp2p-TLS is fully wired in [`transport.quic`] / [`transport.quic_v1`]
//! and the cert-extension verification helpers in [`security.libp2p_tls`] are
//! transport-agnostic. The remaining piece for TCP is the actual TLS 1.3
//! handshake pump on top of a stream socket. That pump needs the `tls.nonblock`
//! `Client` / `Server` types from zquic's vendored TLS module, which zquic does
//! not currently re-export on its public surface (only `zquic.tls.handshake.*`
//! is public). Until [zquic upstream]
//! (https://github.com/ch4r10t33r/zquic) exposes `tls.nonblock`, this module
//! ships the parts that are useful immediately:
//!
//! * [`multistream_protocol_id`] / [`multistreamSelectLine`] — the
//!   `/tls/1.0.0\n` token to negotiate before the handshake.
//! * [`verifyPeerLeafCertificate`] — re-entry point for cert + libp2p extension
//!   verification once the embedder has run the handshake elsewhere and pulled
//!   the peer leaf cert DER out.
//! * [`PendingHandshake`] — opaque state holder that documents the contract
//!   embedders should satisfy and lets callers stand up plumbing today.
//!
//! Tracking issue: [#86](https://github.com/ch4r10t33r/zig-libp2p/issues/86).

const std = @import("std");
const libp2p_tls = @import("../security/libp2p_tls.zig");
const peer_id_mod = @import("peer_id");

/// Multistream-select id that MUST be negotiated on the underlying TCP stream
/// before either side starts the TLS 1.3 ClientHello.
pub const multistream_protocol_id: []const u8 = libp2p_tls.multistream_protocol_id;

/// The exact bytes to send / expect on the wire during multistream-select
/// (line-terminated form). Convenience for callers that already drive
/// multistream-select with raw lines.
pub const multistream_select_line: []const u8 = "/tls/1.0.0\n";

/// Verify a peer's leaf certificate DER end-to-end: X.509 self-signature,
/// validity window (using `now_sec`), libp2p extension presence, and the
/// SignedKey signature over `"libp2p-tls-handshake:" || SPKI`. Returns the
/// derived PeerId. Optional `expected_peer` enforces a `/p2p/<id>` match.
///
/// This is the same machinery the QUIC path uses; surfacing it here makes
/// the eventual TCP-side handshake pump a thin shim.
pub fn verifyPeerLeafCertificate(
    allocator: std.mem.Allocator,
    cert_der: []const u8,
    expected_peer: ?peer_id_mod.PeerId,
    now_sec: i64,
) libp2p_tls.QuicPeerIdentityError!peer_id_mod.PeerId {
    return libp2p_tls.verifiedPeerIdFromQuicLeafCertificate(allocator, cert_der, expected_peer, now_sec);
}

/// Opaque state slot for the future end-to-end handshake driver. The contract:
///
/// * `is_client` — initiator or responder role.
/// * `now_sec`   — clock used for the validity window check after handshake.
/// * `expected_peer` — optional PeerId to enforce against the libp2p extension.
///
/// Once zquic exposes `tls.nonblock`, the driver will accept reader/writer
/// hooks and drive the NonBlock state machine; the resulting cipher and the
/// verified PeerId become the handshake's two outputs.
pub const PendingHandshake = struct {
    is_client: bool,
    now_sec: i64,
    expected_peer: ?peer_id_mod.PeerId = null,
};

test "multistream_protocol_id matches the spec value" {
    try std.testing.expectEqualStrings("/tls/1.0.0", multistream_protocol_id);
}

test "multistream_select_line ends with newline" {
    try std.testing.expect(std.mem.endsWith(u8, multistream_select_line, "\n"));
    try std.testing.expect(std.mem.startsWith(u8, multistream_select_line, multistream_protocol_id));
}

test "verifyPeerLeafCertificate accepts spec vector 1 (Ed25519)" {
    const a = std.testing.allocator;
    const hex =
        \\308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77
    ;
    var buf: [512]u8 = undefined;
    const cert = try std.fmt.hexToBytes(&buf, hex);
    // The spec vector encodes notBefore = UTCTime 75-01-01 (interpreted by
    // std.crypto.Certificate as 2075-01-01) and notAfter = 4096-01-01, so we
    // pick a `now_sec` deep inside that range.
    const now: i64 = 35_000_000_000;
    const id = try verifyPeerLeafCertificate(a, cert, null, now);
    var b58: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv",
        try id.toBase58(&b58),
    );
}

test "PendingHandshake init records role + clock" {
    const ph = PendingHandshake{ .is_client = true, .now_sec = 42 };
    try std.testing.expect(ph.is_client);
    try std.testing.expectEqual(@as(i64, 42), ph.now_sec);
    try std.testing.expectEqual(@as(?peer_id_mod.PeerId, null), ph.expected_peer);
}
