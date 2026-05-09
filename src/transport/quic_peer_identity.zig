//! libp2p [`PeerId`](`peer_id.PeerId`) from the **server** TLS leaf certificate on a zquic QUIC client (#16).
//!
//! zquic captures the peer certificate during [`ClientHandshake.processServerFlight`]; use
//! [`verifiedPeerIdFromLibp2pQuicClient`] after `conn.phase == .connected`.
//!
//! The accepting **server** does not yet receive a client `Certificate` flight in zquic’s TLS stack,
//! so inbound PeerId from the dialer is not available here.

const std = @import("std");
const peer_id_mod = @import("peer_id");
const libp2p_tls = @import("../security/libp2p_tls.zig");
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
