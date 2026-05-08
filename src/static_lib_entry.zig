//! Root translation unit for `libzig-libp2p.a`: pulls in the exported C ABI.

comptime {
    _ = @import("zeam_ffi.zig");
}

pub const zig_libp2p = @import("zig_libp2p");
