//! libp2p [`PeerId`](`peer_id.PeerId`) from TLS peer leaf certificates on zquic QUIC connections (#16).
//!
//! * **Outbound (dialer):** zquic captures the **server** leaf during [`ClientHandshake.processServerFlight`]. Use
//!   [`verifiedPeerIdFromLibp2pQuicClient`] after `client.conn.phase == .connected`, or [`quic_endpoint.dialExtended`]
//!   with default TLS verification.
//! * **Inbound (listener):** after mutual TLS, the **client** leaf is available from
//!   [`zquic.transport.io.serverConnPeerLeafCertificateDer`]. Use [`verifiedPeerIdFromLibp2pQuicServerConn`].

const std = @import("std");
const peer_id_mod = @import("peer_id");
const libp2p_tls = @import("../../security/libp2p_tls.zig");
const zquic = @import("zquic");
const ZIo = zquic.transport.io;

pub const VerifiedPeerIdFromQuicError = libp2p_tls.QuicPeerIdentityError || error{MissingPeerCertificate};

/// Verify the remote TLS identity using [`libp2p_tls.peerIdFromVerifiedCertificate`] and optionally match `expected_peer`.
pub fn verifiedPeerIdFromLibp2pQuicClient(
    client: *const ZIo.Client,
    allocator: std.mem.Allocator,
    expected_peer: ?peer_id_mod.PeerId,
    now_sec: i64,
) VerifiedPeerIdFromQuicError!peer_id_mod.PeerId {
    const der = client.peerLeafCertificateDer() orelse return error.MissingPeerCertificate;
    return try libp2p_tls.verifiedPeerIdFromQuicLeafCertificate(allocator, der, expected_peer, now_sec);
}

/// Verify the dialer's TLS identity on an accepted **server** QUIC connection (mutual TLS / libp2p-on-QUIC).
pub fn verifiedPeerIdFromLibp2pQuicServerConn(
    conn: *const ZIo.ConnState,
    allocator: std.mem.Allocator,
    expected_peer: ?peer_id_mod.PeerId,
    now_sec: i64,
) VerifiedPeerIdFromQuicError!peer_id_mod.PeerId {
    const der = ZIo.serverConnPeerLeafCertificateDer(conn) orelse return error.MissingPeerCertificate;
    return try libp2p_tls.verifiedPeerIdFromQuicLeafCertificate(allocator, der, expected_peer, now_sec);
}
