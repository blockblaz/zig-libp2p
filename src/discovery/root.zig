//! LAN peer discovery modules (#207).

pub const dns_wire = @import("dns_wire.zig");
pub const mdns = @import("mdns.zig");

test {
    _ = @import("dns_wire.zig");
    _ = @import("mdns.zig");
}
