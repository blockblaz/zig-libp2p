//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/discovery/root.zig");

pub const dns_wire = _shim_src.dns_wire;
pub const mdns = _shim_src.mdns;
