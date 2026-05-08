//! Pure-Zig libp2p-oriented networking helpers for Lean Ethereum clients.
//!
//! Add this package in `build.zig.zon`, then `b.dependency("zig_libp2p", …)`
//! and `dep.module("zig_libp2p")` on your executable or library module.

pub const protocol = @import("protocol.zig");
pub const varint = @import("varint.zig");
pub const addr_list = @import("addr_list.zig");
pub const multistream = @import("multistream.zig");

/// Block Snappy (`zig_snappy`), same module name as in Zeam.
pub const snappyz = @import("snappyz");
/// Snappy framing for libp2p streams (`snappyframesz`).
pub const snappyframesz = @import("snappyframesz");

pub const req_resp = struct {
    pub const frame = @import("req_resp/frame.zig");
    pub const stream = @import("req_resp/stream.zig");
    pub const snappy_wire = @import("req_resp/snappy_wire.zig");
};
