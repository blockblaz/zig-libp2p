//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./primitives/metrics.zig");

pub const Metrics = _shim_src.Metrics;
pub const SwarmDropReason = _shim_src.SwarmDropReason;
