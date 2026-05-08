//! gossipsub `RPC` protobuf (proto2) encoding aligned with
//! [go-libp2p-pubsub `rpc.proto`](https://github.com/libp2p/go-libp2p-pubsub/blob/master/pb/rpc.proto).

const std = @import("std");
const w = @import("../protobuf/wire.zig");

pub const Error = w.Error || error{MissingSubscribeFields};

fn consumeFieldValue(buf: []const u8, wire_type: w.WireType) Error![]const u8 {
    return switch (wire_type) {
        .varint => buf[0..(try w.decodeVarUInt64(buf)).len],
        .fixed64 => if (buf.len < 8) error.Truncated else buf[0..8],
        .fixed32 => if (buf.len < 4) error.Truncated else buf[0..4],
        .length_delimited => blk: {
            const ln = try w.decodeVarUInt64(buf);
            const n: usize = @intCast(ln.value);
            const end = ln.len + n;
            if (buf.len < end) return error.Truncated;
            break :blk buf[ln.len..end];
        },
    };
}

fn fieldTotalLen(buf: []const u8, wire_type: w.WireType) Error!usize {
    return switch (wire_type) {
        .varint => (try w.decodeVarUInt64(buf)).len,
        .fixed64 => 8,
        .fixed32 => 4,
        .length_delimited => blk: {
            const ln = try w.decodeVarUInt64(buf);
            const n: usize = @intCast(ln.value);
            if (buf.len < ln.len + n) return error.Truncated;
            break :blk ln.len + n;
        },
    };
}

/// `optional ControlMessage control = 3` with an empty nested message.
pub fn encodeEmptyControlRpc(allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);
    try w.appendLengthDelimited(&list, allocator, 3, "");
    return try list.toOwnedSlice(allocator);
}

/// One `SubOpts` in `repeated SubOpts subscriptions = 1` (subscribe + topic id).
pub fn encodeSubscribe(allocator: std.mem.Allocator, topic: []const u8, subscribe: bool) std.mem.Allocator.Error![]u8 {
    var sub = std.ArrayList(u8).empty;
    defer sub.deinit(allocator);
    try w.appendFieldKey(&sub, allocator, 1, .varint);
    try w.appendVarUInt64(&sub, allocator, if (subscribe) 1 else 0);
    try w.appendLengthDelimited(&sub, allocator, 2, topic);

    const payload = try sub.toOwnedSlice(allocator);
    defer allocator.free(payload);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try w.appendLengthDelimited(&out, allocator, 1, payload);
    return try out.toOwnedSlice(allocator);
}

pub const SubscribeView = struct {
    subscribe: bool,
    topic: []u8,
};

/// Reads the first `subscriptions` entry only; returns null if none.
pub fn decodeFirstSubscribe(allocator: std.mem.Allocator, rpc: []const u8) (Error || std.mem.Allocator.Error)!?SubscribeView {
    var off: usize = 0;
    while (off < rpc.len) {
        const key = try w.decodeFieldKey(rpc[off..]);
        off += key.len;
        const val_buf = rpc[off..];
        const v = try consumeFieldValue(val_buf, key.wire_type);
        const total = try fieldTotalLen(val_buf, key.wire_type);
        off += total;

        if (key.field_number != 1) continue;
        if (key.wire_type != .length_delimited) return error.UnsupportedWireType;

        var sub_off: usize = 0;
        var subscribe: ?bool = null;
        var topic: ?[]const u8 = null;
        while (sub_off < v.len) {
            const sk = try w.decodeFieldKey(v[sub_off..]);
            sub_off += sk.len;
            const inner = v[sub_off..];
            const chunk = try consumeFieldValue(inner, sk.wire_type);
            const inner_total = try fieldTotalLen(inner, sk.wire_type);
            sub_off += inner_total;

            switch (sk.field_number) {
                1 => {
                    if (sk.wire_type != .varint) return error.UnsupportedWireType;
                    const vv = try w.decodeVarUInt64(chunk);
                    subscribe = vv.value != 0;
                },
                2 => {
                    if (sk.wire_type != .length_delimited) return error.UnsupportedWireType;
                    topic = chunk;
                },
                else => return error.UnsupportedWireType,
            }
        }
        const sub = subscribe orelse return error.MissingSubscribeFields;
        const top = topic orelse return error.MissingSubscribeFields;
        return SubscribeView{
            .subscribe = sub,
            .topic = try allocator.dupe(u8, top),
        };
    }
    return null;
}

/// Returns an owned copy of the raw `ControlMessage` bytes for field `3`, or null.
pub fn decodeControlPayload(allocator: std.mem.Allocator, rpc: []const u8) (Error || std.mem.Allocator.Error)!?[]u8 {
    var off: usize = 0;
    while (off < rpc.len) {
        const key = try w.decodeFieldKey(rpc[off..]);
        off += key.len;
        const val_buf = rpc[off..];
        const v = try consumeFieldValue(val_buf, key.wire_type);
        const total = try fieldTotalLen(val_buf, key.wire_type);
        off += total;

        if (key.field_number == 3 and key.wire_type == .length_delimited) {
            return try allocator.dupe(u8, v);
        }
    }
    return null;
}

pub fn deinitSubscribeView(allocator: std.mem.Allocator, s: *SubscribeView) void {
    allocator.free(s.topic);
    s.* = undefined;
}

test "encodeEmptyControlRpc matches two-byte empty submessage" {
    const a = std.testing.allocator;
    const buf = try encodeEmptyControlRpc(a);
    defer a.free(buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x1a, 0x00 }, buf);
    const ctl = try decodeControlPayload(a, buf);
    defer if (ctl) |c| a.free(c);
    try std.testing.expect(ctl != null);
    try std.testing.expectEqual(@as(usize, 0), ctl.?.len);
}

test "subscribe round trip" {
    const a = std.testing.allocator;
    const wire = try encodeSubscribe(a, "hello-topic", true);
    defer a.free(wire);
    var got = (try decodeFirstSubscribe(a, wire)).?;
    defer deinitSubscribeView(a, &got);
    try std.testing.expect(got.subscribe);
    try std.testing.expectEqualStrings("hello-topic", got.topic);
}

test "decodeFirstSubscribe returns null on control-only rpc" {
    const a = std.testing.allocator;
    const wire = try encodeEmptyControlRpc(a);
    defer a.free(wire);
    try std.testing.expectEqual(@as(?SubscribeView, null), try decodeFirstSubscribe(a, wire));
}
