//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./protocols/ping/ping_wire_quic.zig");

pub const WireQuicPingError = _shim_src.WireQuicPingError;
pub const initiatorPingRoundTripMs = _shim_src.initiatorPingRoundTripMs;
pub const responderHandleInbound = _shim_src.responderHandleInbound;
