//! `ControlMessage` protobuf fragments (graft / prune) for gossipsub v1.1.

const std = @import("std");
const w = @import("../protobuf/wire.zig");

pub const Error = w.Error || error{MissingPruneTopic};

/// `repeated ControlGraft graft = 3` with a single graft for `topicID`.
pub fn encodeGraft(allocator: std.mem.Allocator, topic_id: []const u8) std.mem.Allocator.Error![]u8 {
    var graft = std.ArrayList(u8).empty;
    defer graft.deinit(allocator);
    try w.appendLengthDelimited(&graft, allocator, 1, topic_id);

    var ctl = std.ArrayList(u8).empty;
    defer ctl.deinit(allocator);
    try w.appendLengthDelimited(&ctl, allocator, 3, graft.items);
    return try ctl.toOwnedSlice(allocator);
}

/// `repeated ControlPrune prune = 4` with topic and optional backoff (seconds).
pub fn encodePrune(allocator: std.mem.Allocator, topic_id: []const u8, backoff_seconds: ?u64) std.mem.Allocator.Error![]u8 {
    var prune = std.ArrayList(u8).empty;
    defer prune.deinit(allocator);
    try w.appendLengthDelimited(&prune, allocator, 1, topic_id);
    if (backoff_seconds) |b| {
        try w.appendFieldKey(&prune, allocator, 3, .varint);
        try w.appendVarUInt64(&prune, allocator, b);
    }

    var ctl = std.ArrayList(u8).empty;
    defer ctl.deinit(allocator);
    try w.appendLengthDelimited(&ctl, allocator, 4, prune.items);
    return try ctl.toOwnedSlice(allocator);
}

/// First `ControlGraft.topicID` in a `ControlMessage` wire blob, or null.
pub fn decodeFirstGraftTopic(allocator: std.mem.Allocator, control: []const u8) (Error || std.mem.Allocator.Error)!?[]u8 {
    var off: usize = 0;
    while (off < control.len) {
        const key = try w.decodeFieldKey(control[off..]);
        off += key.len;
        const nv = try w.nextFieldValue(control[off..], key.wire_type);
        off += nv.total;

        if (key.field_number != 3 or key.wire_type != .length_delimited) continue;

        var go: usize = 0;
        while (go < nv.value.len) {
            const gk = try w.decodeFieldKey(nv.value[go..]);
            go += gk.len;
            const gv = try w.nextFieldValue(nv.value[go..], gk.wire_type);
            go += gv.total;
            if (gk.field_number == 1 and gk.wire_type == .length_delimited) {
                return try allocator.dupe(u8, gv.value);
            }
        }
    }
    return null;
}

pub const PruneView = struct {
    topic: []u8,
    backoff_seconds: ?u64,
};

/// First `ControlPrune` entry in a `ControlMessage` wire blob, or null.
pub fn decodeFirstPrune(allocator: std.mem.Allocator, control: []const u8) (Error || std.mem.Allocator.Error)!?PruneView {
    var off: usize = 0;
    while (off < control.len) {
        const key = try w.decodeFieldKey(control[off..]);
        off += key.len;
        const nv = try w.nextFieldValue(control[off..], key.wire_type);
        off += nv.total;

        if (key.field_number != 4 or key.wire_type != .length_delimited) continue;

        var topic: ?[]const u8 = null;
        var backoff: ?u64 = null;
        var po: usize = 0;
        while (po < nv.value.len) {
            const pk = try w.decodeFieldKey(nv.value[po..]);
            po += pk.len;
            const pv = try w.nextFieldValue(nv.value[po..], pk.wire_type);
            po += pv.total;
            switch (pk.field_number) {
                1 => {
                    if (pk.wire_type != .length_delimited) return error.UnsupportedWireType;
                    topic = pv.value;
                },
                3 => {
                    if (pk.wire_type != .varint) return error.UnsupportedWireType;
                    const vv = try w.decodeVarUInt64(pv.value);
                    backoff = vv.value;
                },
                else => {},
            }
        }
        const top = topic orelse return error.MissingPruneTopic;
        return PruneView{
            .topic = try allocator.dupe(u8, top),
            .backoff_seconds = backoff,
        };
    }
    return null;
}

pub fn deinitPruneView(allocator: std.mem.Allocator, p: *PruneView) void {
    allocator.free(p.topic);
    p.* = undefined;
}

test "graft topic round trip" {
    const a = std.testing.allocator;
    const wire = try encodeGraft(a, "/mesh/my-topic");
    defer a.free(wire);
    const topic = (try decodeFirstGraftTopic(a, wire)).?;
    defer a.free(topic);
    try std.testing.expectEqualStrings("/mesh/my-topic", topic);
}

test "prune topic and backoff round trip" {
    const a = std.testing.allocator;
    const wire = try encodePrune(a, "prune-topic", 60);
    defer a.free(wire);
    var got = (try decodeFirstPrune(a, wire)).?;
    defer deinitPruneView(a, &got);
    try std.testing.expectEqualStrings("prune-topic", got.topic);
    try std.testing.expectEqual(@as(?u64, 60), got.backoff_seconds);
}
