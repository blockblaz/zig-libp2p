//! Root translation unit for `libzig-libp2p.a`: pulls in C ABI exports for Zeam.

comptime {
    _ = @import("zeam_bridge.zig");
}

pub const zig_libp2p = @import("zig_libp2p");
