//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./quic/relay_live.zig");

pub const Error = _shim_src.Error;
pub const Config = _shim_src.Config;
pub const StreamLeg = _shim_src.StreamLeg;
pub const Bridge = _shim_src.Bridge;
pub const RelayVirtualConn = _shim_src.RelayVirtualConn;
pub const CircuitDial = _shim_src.CircuitDial;
pub const RuntimeHooks = _shim_src.RuntimeHooks;
pub const ReservationEventKind = _shim_src.ReservationEventKind;
pub const LiveRelay = _shim_src.LiveRelay;
