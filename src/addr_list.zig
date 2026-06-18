//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./primitives/addr_list.zig");

pub const ParseCsvError = _shim_src.ParseCsvError;
pub const freeList = _shim_src.freeList;
pub const parseCsv = _shim_src.parseCsv;
