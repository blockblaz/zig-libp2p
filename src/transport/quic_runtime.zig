//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./quic/runtime.zig");

pub const TlsPemSource = _shim_src.TlsPemSource;
pub const QuicRuntimeOptions = _shim_src.QuicRuntimeOptions;
pub const RelayRuntimeOptions = _shim_src.RelayRuntimeOptions;
pub const DcutrRuntimeOptions = _shim_src.DcutrRuntimeOptions;
pub const AutonatRuntimeOptions = _shim_src.AutonatRuntimeOptions;
pub const QuicRuntime = _shim_src.QuicRuntime;
