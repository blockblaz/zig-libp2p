//! Pure-Zig libp2p stack for Lean Ethereum clients (Zeam integration).
//!
//! The exported C ABI for the Zeam host is rooted at `static_lib_entry.zig`
//! (see `build.zig`); this module is the dependency-friendly API surface.

pub const protocol = @import("protocol.zig");
pub const varint = @import("varint.zig");
pub const addr_list = @import("addr_list.zig");

pub const req_resp = struct {
    pub const frame = @import("req_resp/frame.zig");
};
