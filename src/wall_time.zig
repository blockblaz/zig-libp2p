//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./primitives/wall_time.zig");

pub const milliTimestamp = _shim_src.milliTimestamp;
pub const unixTimestamp = _shim_src.unixTimestamp;
