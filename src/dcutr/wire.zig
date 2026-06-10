//! DCUtR (Direct Connection Upgrade through Relay) wire codec (#91).
//!
//! Spec: https://github.com/libp2p/specs/blob/master/relay/DCUtR.md

const std = @import("std");
const Io = std.Io;
const proto = @import("../protobuf/wire.zig");
const varint = @import("../varint.zig");

pub const protocol_line: []const u8 = "/libp2p/dcutr\n";
pub const protocol_id: []const u8 = std.mem.trimEnd(u8, protocol_line, "\n");

pub const Error = proto.Error || error{
    MessageTooLarge,
    InvalidMessageType,
    TooManyAddrs,
    MissingRequiredField,
} || std.mem.Allocator.Error;

pub const Limits = struct {
    max_frame_bytes: usize = 4096,
    max_addrs: usize = 32,
    max_addr_bytes: usize = 1024,

    pub const standard: Limits = .{};
};

pub const PunchType = enum(u32) {
    connect = 100,
    sync = 300,
};

pub const MessageView = struct {
    msg_type: PunchType,
    obs_addrs: []const []const u8 = &.{},
};

pub const MessageOwned = struct {
    msg_type: PunchType,
    obs_addrs: [][]u8 = &[_][]u8{},

    pub fn deinit(self: *MessageOwned, allocator: std.mem.Allocator) void {
        for (self.obs_addrs) |a| allocator.free(a);
        if (self.obs_addrs.len > 0) allocator.free(self.obs_addrs);
        self.* = .{ .msg_type = .sync };
    }
};

fn decodePunchType(v: u64) Error!PunchType {
    return switch (v) {
        100 => .connect,
        300 => .sync,
        else => error.InvalidMessageType,
    };
}

pub fn encode(allocator: std.mem.Allocator, msg: MessageView) ![]u8 {
    var list = std.ArrayList(u8).empty;
    errdefer list.deinit(allocator);
    try proto.appendFieldKey(&list, allocator, 1, .varint);
    try proto.appendVarUInt64(&list, allocator, @intFromEnum(msg.msg_type));
    for (msg.obs_addrs) |a| try proto.appendLengthDelimited(&list, allocator, 2, a);
    return try list.toOwnedSlice(allocator);
}

pub fn decodeOwned(allocator: std.mem.Allocator, wire_bytes: []const u8, limits: Limits) Error!MessageOwned {
    if (wire_bytes.len > limits.max_frame_bytes) return error.MessageTooLarge;
    var out: MessageOwned = .{ .msg_type = .sync };
    var addrs = std.ArrayList([]u8).empty;
    errdefer {
        for (addrs.items) |a| allocator.free(a);
        addrs.deinit(allocator);
    }
    var type_set = false;
    var off: usize = 0;
    while (off < wire_bytes.len) {
        const key = try proto.decodeFieldKey(wire_bytes[off..]);
        off += key.len;
        const cap: usize = if (key.field_number == 2) limits.max_addr_bytes else 8;
        const nv = try proto.nextFieldValueLimited(wire_bytes[off..], key.wire_type, cap);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                const d = try proto.decodeVarUInt64(nv.value);
                out.msg_type = try decodePunchType(d.value);
                type_set = true;
            },
            2 => {
                if (addrs.items.len >= limits.max_addrs) return error.TooManyAddrs;
                try addrs.append(allocator, try allocator.dupe(u8, nv.value));
            },
            else => {},
        }
    }
    if (!type_set) return error.MissingRequiredField;
    out.obs_addrs = try addrs.toOwnedSlice(allocator);
    return out;
}

pub fn writeLengthPrefixed(w: *Io.Writer, payload: []const u8) Io.Writer.Error!void {
    var scratch: [varint.max_encoding_bytes]u8 = undefined;
    const prefix = varint.encodeToScratch(&scratch, payload.len);
    try Io.Writer.writeAll(w, prefix);
    try Io.Writer.writeAll(w, payload);
    try Io.Writer.flush(w);
}

pub fn readLengthPrefixedAlloc(r: *Io.Reader, allocator: std.mem.Allocator, max_total: usize) (Io.Reader.ShortError || Error)![]u8 {
    var len_buf: [varint.max_encoding_bytes]u8 = undefined;
    var got: usize = 0;
    while (got < len_buf.len) {
        const n = try r.readSliceShort(len_buf[got..][0..1]);
        if (n == 0) return error.Truncated;
        got += n;
        const d = varint.decode(len_buf[0..got]) catch continue;
        if (d.value > max_total) return error.MessageTooLarge;
        const payload = try allocator.alloc(u8, @intCast(d.value));
        errdefer allocator.free(payload);
        var filled: usize = 0;
        while (filled < payload.len) {
            const m = try r.readSliceShort(payload[filled..]);
            if (m == 0) return error.Truncated;
            filled += m;
        }
        return payload;
    }
    return error.Truncated;
}

test "connect round trip" {
    const a = std.testing.allocator;
    const wire_bytes = try encode(a, .{
        .msg_type = .connect,
        .obs_addrs = &.{"/ip4/1.2.3.4/udp/4001/quic-v1"},
    });
    defer a.free(wire_bytes);
    var decoded = try decodeOwned(a, wire_bytes, .standard);
    defer decoded.deinit(a);
    try std.testing.expectEqual(PunchType.connect, decoded.msg_type);
    try std.testing.expectEqual(@as(usize, 1), decoded.obs_addrs.len);
}
