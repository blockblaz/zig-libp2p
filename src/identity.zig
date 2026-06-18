//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./primitives/identity.zig");

pub const ParseError = _shim_src.ParseError;
pub const PeerId = _shim_src.PeerId;
pub const PublicKey = _shim_src.PublicKey;
