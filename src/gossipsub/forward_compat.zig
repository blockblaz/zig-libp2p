//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/gossipsub/forward_compat.zig");

pub const Scope = _shim_src.Scope;
pub const noteUnknownField = _shim_src.noteUnknownField;
