//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./primitives/protocol.zig");

pub const LeanSupportedProtocol = _shim_src.LeanSupportedProtocol;
pub const blocks_by_range_v1 = _shim_src.blocks_by_range_v1;
pub const blocks_by_root_v1 = _shim_src.blocks_by_root_v1;
pub const status_v1 = _shim_src.status_v1;
