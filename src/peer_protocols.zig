//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./core/peer_protocols.zig");

pub const Store = _shim_src.Store;
