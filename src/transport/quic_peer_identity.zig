//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./quic/peer_identity.zig");

pub const VerifiedPeerIdFromQuicError = _shim_src.VerifiedPeerIdFromQuicError;
pub const verifiedPeerIdFromLibp2pQuicClient = _shim_src.verifiedPeerIdFromLibp2pQuicClient;
pub const verifiedPeerIdFromLibp2pQuicServerConn = _shim_src.verifiedPeerIdFromLibp2pQuicServerConn;
