//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./core/peer_events.zig");

pub const ConnectionFailureResult = _shim_src.ConnectionFailureResult;
pub const Direction = _shim_src.Direction;
pub const DisconnectReason = _shim_src.DisconnectReason;
pub const DiscoverySource = _shim_src.DiscoverySource;
pub const PeerConnectedPayload = _shim_src.PeerConnectedPayload;
pub const PeerConnectionFailedPayload = _shim_src.PeerConnectionFailedPayload;
pub const PeerDisconnectedPayload = _shim_src.PeerDisconnectedPayload;
pub const PeerDiscoveredPayload = _shim_src.PeerDiscoveredPayload;
