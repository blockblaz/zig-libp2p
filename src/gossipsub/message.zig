//! gossipsub `Message` protobuf (publish payload).

const std = @import("std");
const w = @import("../protobuf/wire.zig");

pub const Error = w.Error;

pub const MessageView = struct {
    from: ?[]const u8 = null,
    data: ?[]const u8 = null,
    seqno: ?[]const u8 = null,
    topic: ?[]const u8 = null,
    signature: ?[]const u8 = null,
    key: ?[]const u8 = null,
};

pub const MessageOwned = struct {
    from: ?[]u8 = null,
    data: ?[]u8 = null,
    seqno: ?[]u8 = null,
    topic: ?[]u8 = null,
    signature: ?[]u8 = null,
    key: ?[]u8 = null,

    pub fn deinit(self: *MessageOwned, allocator: std.mem.Allocator) void {
        if (self.from) |x| allocator.free(x);
        if (self.data) |x| allocator.free(x);
        if (self.seqno) |x| allocator.free(x);
        if (self.topic) |x| allocator.free(x);
        if (self.signature) |x| allocator.free(x);
        if (self.key) |x| allocator.free(x);
        self.* = .{};
    }
};

fn appendOptBytes(list: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, slice: ?[]const u8) std.mem.Allocator.Error!void {
    if (slice) |s| {
        try w.appendLengthDelimited(list, allocator, field, s);
    }
}

pub fn encode(allocator: std.mem.Allocator, msg: MessageView) std.mem.Allocator.Error![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);
    try appendOptBytes(&list, allocator, 1, msg.from);
    try appendOptBytes(&list, allocator, 2, msg.data);
    try appendOptBytes(&list, allocator, 3, msg.seqno);
    try appendOptBytes(&list, allocator, 4, msg.topic);
    try appendOptBytes(&list, allocator, 5, msg.signature);
    try appendOptBytes(&list, allocator, 6, msg.key);
    return try list.toOwnedSlice(allocator);
}

pub fn decode(allocator: std.mem.Allocator, wire: []const u8) (Error || std.mem.Allocator.Error)!MessageOwned {
    var out: MessageOwned = .{};
    errdefer out.deinit(allocator);

    var off: usize = 0;
    while (off < wire.len) {
        const key = try w.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try w.nextFieldValue(wire[off..], key.wire_type);
        off += nv.total;

        if (key.wire_type != .length_delimited) return error.UnsupportedWireType;
        const duped = try allocator.dupe(u8, nv.value);
        errdefer allocator.free(duped);

        switch (key.field_number) {
            1 => {
                if (out.from != null) return error.UnsupportedWireType;
                out.from = duped;
            },
            2 => {
                if (out.data != null) return error.UnsupportedWireType;
                out.data = duped;
            },
            3 => {
                if (out.seqno != null) return error.UnsupportedWireType;
                out.seqno = duped;
            },
            4 => {
                if (out.topic != null) return error.UnsupportedWireType;
                out.topic = duped;
            },
            5 => {
                if (out.signature != null) return error.UnsupportedWireType;
                out.signature = duped;
            },
            6 => {
                if (out.key != null) return error.UnsupportedWireType;
                out.key = duped;
            },
            else => {
                allocator.free(duped);
                return error.UnsupportedWireType;
            },
        }
    }
    return out;
}

test "message topic and data round trip" {
    const a = std.testing.allocator;
    const wire = try encode(a, .{
        .topic = "blocks",
        .data = &[_]u8{ 1, 2, 3, 4 },
    });
    defer a.free(wire);
    var got = try decode(a, wire);
    defer got.deinit(a);
    try std.testing.expectEqualStrings("blocks", got.topic.?);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, got.data.?);
}
