//! Parse a comma-separated list of multiaddr strings.

const std = @import("std");
const zl = @import("zig_libp2p");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    const csv = "/ip4/127.0.0.1/tcp/9000, /ip4/10.0.0.1/udp/4001/quic-v1";
    const list = try zl.addr_list.parseCsv(gpa, csv);
    defer zl.addr_list.freeList(gpa, list);
    std.debug.print("parsed {d} multiaddrs:\n", .{list.len});
    for (list) |m| {
        const s = try m.toString(gpa);
        defer gpa.free(s);
        std.debug.print("  {s}\n", .{s});
    }
}
