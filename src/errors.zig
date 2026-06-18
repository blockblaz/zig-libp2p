//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./primitives/errors.zig");

pub const GossipsubError = _shim_src.GossipsubError;
pub const ReqRespError = _shim_src.ReqRespError;
pub const TransportError = _shim_src.TransportError;
pub const clearLastErrorMessage = _shim_src.clearLastErrorMessage;
pub const lastErrorMessage = _shim_src.lastErrorMessage;
pub const setLastErrorMessage = _shim_src.setLastErrorMessage;
