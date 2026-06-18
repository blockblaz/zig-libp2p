//! Lean consensus req/resp protocol id strings and numeric wire tags.
//! Discriminants stay stable for interoperability with other Lean clients.

const std = @import("std");

pub const blocks_by_root_v1 = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";
pub const blocks_by_range_v1 = "/leanconsensus/req/blocks_by_range/1/ssz_snappy";
pub const status_v1 = "/leanconsensus/req/status/1/ssz_snappy";

pub const LeanSupportedProtocol = enum(u32) {
    blocks_by_root = 0,
    status = 1,
    blocks_by_range = 2,

    pub fn protocolId(self: LeanSupportedProtocol) []const u8 {
        return switch (self) {
            .blocks_by_root => blocks_by_root_v1,
            .status => status_v1,
            .blocks_by_range => blocks_by_range_v1,
        };
    }

    pub fn fromInt(tag: u32) ?LeanSupportedProtocol {
        return switch (tag) {
            0 => .blocks_by_root,
            1 => .status,
            2 => .blocks_by_range,
            else => null,
        };
    }

    pub fn fromSlice(s: []const u8) ?LeanSupportedProtocol {
        if (std.mem.eql(u8, s, blocks_by_root_v1)) return .blocks_by_root;
        if (std.mem.eql(u8, s, status_v1)) return .status;
        if (std.mem.eql(u8, s, blocks_by_range_v1)) return .blocks_by_range;
        return null;
    }
};

test "discriminants stable wire tags" {
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(LeanSupportedProtocol.blocks_by_root));
    try std.testing.expectEqual(@as(u32, 1), @intFromEnum(LeanSupportedProtocol.status));
    try std.testing.expectEqual(@as(u32, 2), @intFromEnum(LeanSupportedProtocol.blocks_by_range));
}

test "fromInt round trip" {
    inline for (std.enums.values(LeanSupportedProtocol)) |p| {
        try std.testing.expectEqual(p, LeanSupportedProtocol.fromInt(@intFromEnum(p)).?);
    }
    try std.testing.expectEqual(@as(?LeanSupportedProtocol, null), LeanSupportedProtocol.fromInt(3));
}
