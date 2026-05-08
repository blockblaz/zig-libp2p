//! gossipsub `RPC` protobuf (proto2) encoding aligned with
//! [go-libp2p-pubsub `rpc.proto`](https://github.com/libp2p/go-libp2p-pubsub/blob/master/pb/rpc.proto).

const std = @import("std");
const w = @import("../protobuf/wire.zig");
const errors = @import("../errors.zig");
const lim = @import("wire_limits.zig");

pub const Error = errors.GossipsubError || w.Error || error{MissingSubscribeFields};

/// `optional ControlMessage control = 3` with an empty nested message.
pub fn encodeEmptyControlRpc(allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);
    try w.appendLengthDelimited(&list, allocator, 3, "");
    return try list.toOwnedSlice(allocator);
}

/// One `SubOpts` in `repeated SubOpts subscriptions = 1` (subscribe + topic id).
pub fn encodeSubscribe(allocator: std.mem.Allocator, topic: []const u8, subscribe: bool) (Error || std.mem.Allocator.Error)![]u8 {
    if (topic.len > lim.max_topic_str_bytes) return error.PayloadTooLarge;
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
        const ld_cap_top: usize = switch (key.field_number) {
            1 => lim.max_subopts_blob_bytes,
            else => lim.max_rpc_length_delimited_bytes,
        };
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(val_buf, key.wire_type, ld_cap_top)
        else
            try w.nextFieldValue(val_buf, key.wire_type);
        const v = nv.value;
        off += nv.total;

        if (key.field_number != 1) continue;
        if (key.wire_type != .length_delimited) return error.UnsupportedWireType;

        var sub_off: usize = 0;
        var subscribe: ?bool = null;
        var topic: ?[]const u8 = null;
        while (sub_off < v.len) {
            const sk = try w.decodeFieldKey(v[sub_off..]);
            sub_off += sk.len;
            const inner = v[sub_off..];
            const ld_cap_inner: usize = switch (sk.field_number) {
                2 => lim.max_topic_str_bytes,
                else => lim.max_subopts_blob_bytes,
            };
            const iv = if (sk.wire_type == .length_delimited)
                try w.nextFieldValueLimited(inner, sk.wire_type, ld_cap_inner)
            else
                try w.nextFieldValue(inner, sk.wire_type);
            const chunk = iv.value;
            sub_off += iv.total;

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
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(val_buf, key.wire_type, lim.max_rpc_length_delimited_bytes)
        else
            try w.nextFieldValue(val_buf, key.wire_type);
        const v = nv.value;
        off += nv.total;

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

/// `repeated Message publish = 2` with a single encoded `Message` wire blob.
pub fn encodePublish(allocator: std.mem.Allocator, message_wire: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    if (message_wire.len > lim.max_rpc_length_delimited_bytes) return error.PayloadTooLarge;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try w.appendLengthDelimited(&out, allocator, 2, message_wire);
    return try out.toOwnedSlice(allocator);
}

/// First `publish` entry (raw `Message` bytes), or null.
pub fn decodeFirstPublish(allocator: std.mem.Allocator, rpc: []const u8) (Error || std.mem.Allocator.Error)!?[]u8 {
    var off: usize = 0;
    while (off < rpc.len) {
        const key = try w.decodeFieldKey(rpc[off..]);
        off += key.len;
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(rpc[off..], key.wire_type, lim.max_rpc_length_delimited_bytes)
        else
            try w.nextFieldValue(rpc[off..], key.wire_type);
        off += nv.total;
        if (key.field_number == 2 and key.wire_type == .length_delimited) {
            return try allocator.dupe(u8, nv.value);
        }
    }
    return null;
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

test "publish wraps message wire" {
    const a = std.testing.allocator;
    const msg = @import("message.zig");
    const inner = try msg.encode(a, .{ .topic = "t", .data = "payload" });
    defer a.free(inner);
    const rpc = try encodePublish(a, inner);
    defer a.free(rpc);
    const got = (try decodeFirstPublish(a, rpc)).?;
    defer a.free(got);
    var decoded = try msg.decode(a, got);
    defer decoded.deinit(a);
    try std.testing.expectEqualStrings("t", decoded.topic.?);
    try std.testing.expectEqualStrings("payload", decoded.data.?);
}

test "decodeControlPayload rejects oversized field" {
    const a = std.testing.allocator;
    const big = try a.alloc(u8, lim.max_rpc_length_delimited_bytes + 1);
    defer a.free(big);
    var list = std.ArrayList(u8).empty;
    defer list.deinit(a);
    try w.appendLengthDelimited(&list, a, 3, big);
    try std.testing.expectError(error.LengthDelimitedTooLong, decodeControlPayload(a, list.items));
}
