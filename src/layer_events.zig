//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./core/layer_events.zig");

pub const GossipsubFailure = _shim_src.GossipsubFailure;
pub const ReqRespFailure = _shim_src.ReqRespFailure;
pub const TransportFailure = _shim_src.TransportFailure;
