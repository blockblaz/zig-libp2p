//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/gossipsub/duplicate_cache.zig");

pub const DuplicateCache = _shim_src.DuplicateCache;
