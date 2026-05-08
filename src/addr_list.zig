//! Parse comma-separated multiaddr strings in the same shape Zeam passes across
//! the FFI boundary (`EthLibp2p` / `multiaddrsToString`).

const std = @import("std");
const Multiaddr = @import("multiaddr").Multiaddr;

pub fn parseCsv(allocator: std.mem.Allocator, csv: []const u8) ![]Multiaddr {
    var out = std.ArrayList(Multiaddr).empty;
    errdefer {
        for (out.items) |m| m.deinit();
        out.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, csv, ',');
    while (it.next()) |chunk| {
        const t = std.mem.trim(u8, chunk, " \t\r\n");
        if (t.len == 0) continue;
        const ma = try Multiaddr.fromString(allocator, t);
        try out.append(allocator, ma);
    }
    return try out.toOwnedSlice(allocator);
}

pub fn freeList(allocator: std.mem.Allocator, list: []Multiaddr) void {
    for (list) |m| m.deinit();
    allocator.free(list);
}

test "parseCsv splits and trims" {
    const a = std.testing.allocator;
    const csv = " /ip4/127.0.0.1/tcp/9000 , /ip4/10.0.0.1/udp/4000 ";
    const list = try parseCsv(a, csv);
    defer freeList(a, list);
    try std.testing.expectEqual(@as(usize, 2), list.len);
    const s0 = try list[0].toString(a);
    defer a.free(s0);
    const s1 = try list[1].toString(a);
    defer a.free(s1);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/tcp/9000", s0);
    try std.testing.expectEqualStrings("/ip4/10.0.0.1/udp/4000", s1);
}
