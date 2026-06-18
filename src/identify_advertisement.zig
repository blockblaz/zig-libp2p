//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./core/identify_advertisement.zig");

pub const Advertisement = _shim_src.Advertisement;
