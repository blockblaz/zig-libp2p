//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./quic/dcutr_live.zig");

pub const Error = _shim_src.Error;
pub const Config = _shim_src.Config;
pub const FailReason = _shim_src.FailReason;
pub const TlsPemRef = _shim_src.TlsPemRef;
pub const RuntimeHooks = _shim_src.RuntimeHooks;
pub const LiveDcutr = _shim_src.LiveDcutr;
