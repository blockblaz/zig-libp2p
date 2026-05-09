//! Parse comma-separated multiaddr strings (trimmed entries, empty chunks skipped).

const std = @import("std");
const multiaddr_mod = @import("multiaddr");
const Multiaddr = multiaddr_mod.Multiaddr;

pub const ParseCsvError = blk: {
    const ret = @typeInfo(@TypeOf(Multiaddr.fromString)).@"fn".return_type.?;
    break :blk @typeInfo(ret).error_union.error_set || std.mem.Allocator.Error;
};

pub fn parseCsv(allocator: std.mem.Allocator, csv: []const u8) ParseCsvError![]Multiaddr {
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
