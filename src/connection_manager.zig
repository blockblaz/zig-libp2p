//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./core/connection_manager.zig");

pub const ConnectionEstablishedOptions = _shim_src.ConnectionEstablishedOptions;
pub const ConnectionId = _shim_src.ConnectionId;
pub const ConnectionLimits = _shim_src.ConnectionLimits;
pub const ConnectionManager = _shim_src.ConnectionManager;
pub const KnownPeerDialStatus = _shim_src.KnownPeerDialStatus;
pub const PeerIdContext = _shim_src.PeerIdContext;
pub const max_reconnect_failures = _shim_src.max_reconnect_failures;
