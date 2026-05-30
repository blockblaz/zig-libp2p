//! `ControlMessage` protobuf fragments (IHAVE / IWANT / graft / prune) for gossipsub v1.1.

const std = @import("std");
const w = @import("../protobuf/wire.zig");
const errors = @import("../errors.zig");
const lim = @import("wire_limits.zig");

pub const Error = errors.GossipsubError || w.Error || error{
    MissingPruneTopic,
    MissingIHaveTopic,
};

fn checkTopicLen(len: usize) Error!void {
    if (len > lim.max_topic_str_bytes) return error.PayloadTooLarge;
}

fn checkMessageIdLen(len: usize) Error!void {
    if (len > lim.max_message_id_bytes) return error.PayloadTooLarge;
}

/// `repeated ControlIHave ihave = 1` with one entry: topic plus optional message id list.
pub fn encodeIHave(allocator: std.mem.Allocator, topic_id: []const u8, message_ids: []const []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    try checkTopicLen(topic_id.len);
    if (message_ids.len > lim.max_message_ids_per_entry) return error.PayloadTooLarge;
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    try w.appendLengthDelimited(&inner, allocator, 1, topic_id);
    for (message_ids) |mid| {
        try checkMessageIdLen(mid.len);
        try w.appendLengthDelimited(&inner, allocator, 2, mid);
    }

    var ctl = std.ArrayList(u8).empty;
    defer ctl.deinit(allocator);
    try w.appendLengthDelimited(&ctl, allocator, 1, inner.items);
    return try ctl.toOwnedSlice(allocator);
}

pub const IHaveOwned = struct {
    topic: []u8,
    message_ids: [][]u8,
};

/// First `ControlIHave` in a `ControlMessage` wire blob, or null.
pub fn decodeFirstIHave(allocator: std.mem.Allocator, control: []const u8) (Error || std.mem.Allocator.Error)!?IHaveOwned {
    var off: usize = 0;
    while (off < control.len) {
        const key = try w.decodeFieldKey(control[off..]);
        off += key.len;
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(control[off..], key.wire_type, lim.max_control_entry_bytes)
        else
            try w.nextFieldValue(control[off..], key.wire_type);
        off += nv.total;

        if (key.field_number != 1 or key.wire_type != .length_delimited) continue;

        var topic: ?[]const u8 = null;
        var ids = std.ArrayList([]u8).empty;
        defer {
            for (ids.items) |m| allocator.free(m);
            ids.deinit(allocator);
        }

        var io: usize = 0;
        while (io < nv.value.len) {
            const ik = try w.decodeFieldKey(nv.value[io..]);
            io += ik.len;
            const ld_cap: usize = switch (ik.field_number) {
                1 => lim.max_topic_str_bytes,
                2 => lim.max_message_id_bytes,
                else => lim.max_control_entry_bytes,
            };
            const iv = if (ik.wire_type == .length_delimited)
                try w.nextFieldValueLimited(nv.value[io..], ik.wire_type, ld_cap)
            else
                try w.nextFieldValue(nv.value[io..], ik.wire_type);
            io += iv.total;
            switch (ik.field_number) {
                1 => {
                    if (ik.wire_type != .length_delimited) return error.UnsupportedWireType;
                    topic = iv.value;
                },
                2 => {
                    if (ik.wire_type != .length_delimited) return error.UnsupportedWireType;
                    if (ids.items.len >= lim.max_message_ids_per_entry) return error.PayloadTooLarge;
                    {
                        const copy = try allocator.dupe(u8, iv.value);
                        errdefer allocator.free(copy);
                        try ids.append(allocator, copy);
                    }
                },
                else => {},
            }
        }
        const top = topic orelse return error.MissingIHaveTopic;
        const owned_ids = try ids.toOwnedSlice(allocator);
        errdefer {
            for (owned_ids) |m| allocator.free(m);
            allocator.free(owned_ids);
        }
        const topic_dup = try allocator.dupe(u8, top);
        return IHaveOwned{ .topic = topic_dup, .message_ids = owned_ids };
    }
    return null;
}

pub fn deinitIHaveOwned(allocator: std.mem.Allocator, v: *IHaveOwned) void {
    allocator.free(v.topic);
    for (v.message_ids) |m| allocator.free(m);
    allocator.free(v.message_ids);
    v.* = undefined;
}

/// `repeated ControlIWant iwant = 2` with one entry holding the given message ids.
pub fn encodeIWant(allocator: std.mem.Allocator, message_ids: []const []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    if (message_ids.len > lim.max_message_ids_per_entry) return error.PayloadTooLarge;
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    for (message_ids) |mid| {
        try checkMessageIdLen(mid.len);
        try w.appendLengthDelimited(&inner, allocator, 1, mid);
    }

    var ctl = std.ArrayList(u8).empty;
    defer ctl.deinit(allocator);
    try w.appendLengthDelimited(&ctl, allocator, 2, inner.items);
    return try ctl.toOwnedSlice(allocator);
}

pub const IWantOwned = struct {
    message_ids: [][]u8,
};

/// First `ControlIWant` in a `ControlMessage` wire blob, or null.
pub fn decodeFirstIWant(allocator: std.mem.Allocator, control: []const u8) (Error || std.mem.Allocator.Error)!?IWantOwned {
    var off: usize = 0;
    while (off < control.len) {
        const key = try w.decodeFieldKey(control[off..]);
        off += key.len;
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(control[off..], key.wire_type, lim.max_control_entry_bytes)
        else
            try w.nextFieldValue(control[off..], key.wire_type);
        off += nv.total;

        if (key.field_number != 2 or key.wire_type != .length_delimited) continue;

        var ids = std.ArrayList([]u8).empty;
        defer {
            for (ids.items) |m| allocator.free(m);
            ids.deinit(allocator);
        }

        var io: usize = 0;
        while (io < nv.value.len) {
            const ik = try w.decodeFieldKey(nv.value[io..]);
            io += ik.len;
            const ld_cap: usize = switch (ik.field_number) {
                1 => lim.max_message_id_bytes,
                else => lim.max_control_entry_bytes,
            };
            const iv = if (ik.wire_type == .length_delimited)
                try w.nextFieldValueLimited(nv.value[io..], ik.wire_type, ld_cap)
            else
                try w.nextFieldValue(nv.value[io..], ik.wire_type);
            io += iv.total;
            switch (ik.field_number) {
                1 => {
                    if (ik.wire_type != .length_delimited) return error.UnsupportedWireType;
                    if (ids.items.len >= lim.max_message_ids_per_entry) return error.PayloadTooLarge;
                    {
                        const copy = try allocator.dupe(u8, iv.value);
                        errdefer allocator.free(copy);
                        try ids.append(allocator, copy);
                    }
                },
                else => {},
            }
        }
        const owned_ids = try ids.toOwnedSlice(allocator);
        return IWantOwned{ .message_ids = owned_ids };
    }
    return null;
}

pub fn deinitIWantOwned(allocator: std.mem.Allocator, v: *IWantOwned) void {
    for (v.message_ids) |m| allocator.free(m);
    allocator.free(v.message_ids);
    v.* = undefined;
}

/// Payload shape matches `ControlIDontWant` (repeated `messageIDs` only, same as `ControlIWant`).
pub const IDontWantOwned = IWantOwned;

pub fn deinitIDontWantOwned(allocator: std.mem.Allocator, v: *IDontWantOwned) void {
    deinitIWantOwned(allocator, v);
}

/// `repeated ControlIDontWant idontwant = 5` with one entry listing the given message ids.
pub fn encodeIDontWant(allocator: std.mem.Allocator, message_ids: []const []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    if (message_ids.len > lim.max_message_ids_per_entry) return error.PayloadTooLarge;
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    for (message_ids) |mid| {
        try checkMessageIdLen(mid.len);
        try w.appendLengthDelimited(&inner, allocator, 1, mid);
    }

    var ctl = std.ArrayList(u8).empty;
    defer ctl.deinit(allocator);
    try w.appendLengthDelimited(&ctl, allocator, 5, inner.items);
    return try ctl.toOwnedSlice(allocator);
}

/// First `ControlIDontWant` in a `ControlMessage` wire blob, or null.
pub fn decodeFirstIDontWant(allocator: std.mem.Allocator, control: []const u8) (Error || std.mem.Allocator.Error)!?IDontWantOwned {
    var off: usize = 0;
    while (off < control.len) {
        const key = try w.decodeFieldKey(control[off..]);
        off += key.len;
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(control[off..], key.wire_type, lim.max_control_entry_bytes)
        else
            try w.nextFieldValue(control[off..], key.wire_type);
        off += nv.total;

        if (key.field_number != 5 or key.wire_type != .length_delimited) continue;

        var ids = std.ArrayList([]u8).empty;
        defer {
            for (ids.items) |m| allocator.free(m);
            ids.deinit(allocator);
        }

        var io: usize = 0;
        while (io < nv.value.len) {
            const ik = try w.decodeFieldKey(nv.value[io..]);
            io += ik.len;
            const ld_cap: usize = switch (ik.field_number) {
                1 => lim.max_message_id_bytes,
                else => lim.max_control_entry_bytes,
            };
            const iv = if (ik.wire_type == .length_delimited)
                try w.nextFieldValueLimited(nv.value[io..], ik.wire_type, ld_cap)
            else
                try w.nextFieldValue(nv.value[io..], ik.wire_type);
            io += iv.total;
            switch (ik.field_number) {
                1 => {
                    if (ik.wire_type != .length_delimited) return error.UnsupportedWireType;
                    if (ids.items.len >= lim.max_message_ids_per_entry) return error.PayloadTooLarge;
                    {
                        const copy = try allocator.dupe(u8, iv.value);
                        errdefer allocator.free(copy);
                        try ids.append(allocator, copy);
                    }
                },
                else => {},
            }
        }
        const owned_ids = try ids.toOwnedSlice(allocator);
        return IDontWantOwned{ .message_ids = owned_ids };
    }
    return null;
}

/// `repeated ControlGraft graft = 3` with a single graft for `topicID`.
pub fn encodeGraft(allocator: std.mem.Allocator, topic_id: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    try checkTopicLen(topic_id.len);
    var graft = std.ArrayList(u8).empty;
    defer graft.deinit(allocator);
    try w.appendLengthDelimited(&graft, allocator, 1, topic_id);

    var ctl = std.ArrayList(u8).empty;
    defer ctl.deinit(allocator);
    try w.appendLengthDelimited(&ctl, allocator, 3, graft.items);
    return try ctl.toOwnedSlice(allocator);
}

/// `repeated ControlPrune prune = 4` with topic and optional backoff (seconds).
pub fn encodePrune(allocator: std.mem.Allocator, topic_id: []const u8, backoff_seconds: ?u64) (Error || std.mem.Allocator.Error)![]u8 {
    try checkTopicLen(topic_id.len);
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
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(control[off..], key.wire_type, lim.max_control_entry_bytes)
        else
            try w.nextFieldValue(control[off..], key.wire_type);
        off += nv.total;

        if (key.field_number != 3 or key.wire_type != .length_delimited) continue;

        var go: usize = 0;
        while (go < nv.value.len) {
            const gk = try w.decodeFieldKey(nv.value[go..]);
            go += gk.len;
            const ld_cap: usize = switch (gk.field_number) {
                1 => lim.max_topic_str_bytes,
                else => lim.max_control_entry_bytes,
            };
            const gv = if (gk.wire_type == .length_delimited)
                try w.nextFieldValueLimited(nv.value[go..], gk.wire_type, ld_cap)
            else
                try w.nextFieldValue(nv.value[go..], gk.wire_type);
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
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(control[off..], key.wire_type, lim.max_control_entry_bytes)
        else
            try w.nextFieldValue(control[off..], key.wire_type);
        off += nv.total;

        if (key.field_number != 4 or key.wire_type != .length_delimited) continue;

        var topic: ?[]const u8 = null;
        var backoff: ?u64 = null;
        var po: usize = 0;
        while (po < nv.value.len) {
            const pk = try w.decodeFieldKey(nv.value[po..]);
            po += pk.len;
            const ld_cap: usize = switch (pk.field_number) {
                1 => lim.max_topic_str_bytes,
                else => lim.max_control_entry_bytes,
            };
            const pv = if (pk.wire_type == .length_delimited)
                try w.nextFieldValueLimited(nv.value[po..], pk.wire_type, ld_cap)
            else
                try w.nextFieldValue(nv.value[po..], pk.wire_type);
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

/// One `PeerInfo` entry carried inside `ControlPrune.peers` (libp2p gossipsub v1.1 PX).
///
/// We currently surface only the `peerID` (field 1) bytes; the optional
/// `signedPeerRecord` (field 2) is preserved verbatim so callers that
/// understand it can pass it through to a libp2p TLS verifier.
pub const PeerInfoOwned = struct {
    peer_id: ?[]u8 = null,
    signed_peer_record: ?[]u8 = null,
};

pub const PruneWithPeersOwned = struct {
    topic: []u8,
    backoff_seconds: ?u64 = null,
    peers: []PeerInfoOwned,
};

pub fn deinitPeerInfoOwned(allocator: std.mem.Allocator, p: *PeerInfoOwned) void {
    if (p.peer_id) |x| allocator.free(x);
    if (p.signed_peer_record) |x| allocator.free(x);
    p.* = .{};
}

pub fn deinitPruneWithPeersOwned(allocator: std.mem.Allocator, p: *PruneWithPeersOwned) void {
    allocator.free(p.topic);
    for (p.peers) |*pi| deinitPeerInfoOwned(allocator, pi);
    allocator.free(p.peers);
    p.* = undefined;
}

/// Encode a single nested `PeerInfo` value (just the field-1/field-2 fragments, no outer key).
fn appendPeerInfoNested(list: *std.ArrayList(u8), allocator: std.mem.Allocator, p: PeerInfoOwned) (Error || std.mem.Allocator.Error)!void {
    if (p.peer_id) |b| {
        try checkMessageIdLen(b.len); // peer_id fits comfortably within the message-id cap
        try w.appendLengthDelimited(list, allocator, 1, b);
    }
    if (p.signed_peer_record) |b| {
        if (b.len > lim.max_control_entry_bytes) return error.PayloadTooLarge;
        try w.appendLengthDelimited(list, allocator, 2, b);
    }
}

/// `repeated ControlPrune prune = 4` with topic, optional backoff, and optional PX peers list.
pub fn encodePruneWithPeers(
    allocator: std.mem.Allocator,
    topic_id: []const u8,
    backoff_seconds: ?u64,
    peers: []const PeerInfoOwned,
) (Error || std.mem.Allocator.Error)![]u8 {
    try checkTopicLen(topic_id.len);
    if (peers.len > lim.max_message_ids_per_entry) return error.PayloadTooLarge;

    var prune = std.ArrayList(u8).empty;
    defer prune.deinit(allocator);
    try w.appendLengthDelimited(&prune, allocator, 1, topic_id);
    for (peers) |p| {
        var nested = std.ArrayList(u8).empty;
        defer nested.deinit(allocator);
        try appendPeerInfoNested(&nested, allocator, p);
        try w.appendLengthDelimited(&prune, allocator, 2, nested.items);
    }
    if (backoff_seconds) |b| {
        try w.appendFieldKey(&prune, allocator, 3, .varint);
        try w.appendVarUInt64(&prune, allocator, b);
    }

    var ctl = std.ArrayList(u8).empty;
    defer ctl.deinit(allocator);
    try w.appendLengthDelimited(&ctl, allocator, 4, prune.items);
    return try ctl.toOwnedSlice(allocator);
}

fn decodePeerInfo(allocator: std.mem.Allocator, blob: []const u8) (Error || std.mem.Allocator.Error)!PeerInfoOwned {
    var out: PeerInfoOwned = .{};
    errdefer deinitPeerInfoOwned(allocator, &out);

    var off: usize = 0;
    while (off < blob.len) {
        const key = try w.decodeFieldKey(blob[off..]);
        off += key.len;
        const ld_cap: usize = switch (key.field_number) {
            1 => lim.max_message_id_bytes,
            2 => lim.max_control_entry_bytes,
            else => lim.max_control_entry_bytes,
        };
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(blob[off..], key.wire_type, ld_cap)
        else
            try w.nextFieldValue(blob[off..], key.wire_type);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedWireType;
                if (out.peer_id != null) continue;
                out.peer_id = try allocator.dupe(u8, nv.value);
            },
            2 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedWireType;
                if (out.signed_peer_record != null) continue;
                out.signed_peer_record = try allocator.dupe(u8, nv.value);
            },
            else => {},
        }
    }
    return out;
}

/// First `ControlPrune` entry including PX `peers`, or null. Variant of [`decodeFirstPrune`].
pub fn decodeFirstPruneWithPeers(allocator: std.mem.Allocator, control: []const u8) (Error || std.mem.Allocator.Error)!?PruneWithPeersOwned {
    var off: usize = 0;
    while (off < control.len) {
        const key = try w.decodeFieldKey(control[off..]);
        off += key.len;
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(control[off..], key.wire_type, lim.max_control_entry_bytes)
        else
            try w.nextFieldValue(control[off..], key.wire_type);
        off += nv.total;

        if (key.field_number != 4 or key.wire_type != .length_delimited) continue;

        var topic: ?[]const u8 = null;
        var backoff: ?u64 = null;
        var peers = std.ArrayList(PeerInfoOwned).empty;
        defer {
            for (peers.items) |*p| deinitPeerInfoOwned(allocator, p);
            peers.deinit(allocator);
        }

        var po: usize = 0;
        while (po < nv.value.len) {
            const pk = try w.decodeFieldKey(nv.value[po..]);
            po += pk.len;
            const ld_cap: usize = switch (pk.field_number) {
                1 => lim.max_topic_str_bytes,
                2 => lim.max_control_entry_bytes,
                else => lim.max_control_entry_bytes,
            };
            const pv = if (pk.wire_type == .length_delimited)
                try w.nextFieldValueLimited(nv.value[po..], pk.wire_type, ld_cap)
            else
                try w.nextFieldValue(nv.value[po..], pk.wire_type);
            po += pv.total;
            switch (pk.field_number) {
                1 => {
                    if (pk.wire_type != .length_delimited) return error.UnsupportedWireType;
                    topic = pv.value;
                },
                2 => {
                    if (pk.wire_type != .length_delimited) return error.UnsupportedWireType;
                    if (peers.items.len >= lim.max_message_ids_per_entry) return error.PayloadTooLarge;
                    var pi = try decodePeerInfo(allocator, pv.value);
                    errdefer deinitPeerInfoOwned(allocator, &pi);
                    try peers.append(allocator, pi);
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
        const owned_peers = try peers.toOwnedSlice(allocator);
        errdefer {
            for (owned_peers) |*p| deinitPeerInfoOwned(allocator, p);
            allocator.free(owned_peers);
        }
        return PruneWithPeersOwned{
            .topic = try allocator.dupe(u8, top),
            .backoff_seconds = backoff,
            .peers = owned_peers,
        };
    }
    return null;
}

/// Subset of `ControlExtensions` from [rpc.proto](https://github.com/libp2p/go-libp2p-pubsub/blob/master/pb/rpc.proto):
/// `optional bool partialMessages = 10` only. Experimental fields (e.g. 6492434) are skipped on decode.
pub const ControlExtensionsView = struct {
    partial_messages: ?bool = null,
};

/// Encode `ControlExtensions` protobuf bytes (field 10 when set).
pub fn encodeControlExtensions(allocator: std.mem.Allocator, view: ControlExtensionsView) (Error || std.mem.Allocator.Error)![]u8 {
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    if (view.partial_messages) |b| {
        try w.appendFieldKey(&inner, allocator, 10, .varint);
        try w.appendVarUInt64(&inner, allocator, if (b) 1 else 0);
    }
    return try inner.toOwnedSlice(allocator);
}

/// Encode a `ControlMessage` containing only `optional ControlExtensions extensions = 6`.
pub fn encodeControlMessageExtensionsOnly(allocator: std.mem.Allocator, view: ControlExtensionsView) (Error || std.mem.Allocator.Error)![]u8 {
    const payload = try encodeControlExtensions(allocator, view);
    defer allocator.free(payload);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try w.appendLengthDelimited(&out, allocator, 6, payload);
    return try out.toOwnedSlice(allocator);
}

/// First `extensions` entry in a `ControlMessage` wire blob, or null.
pub fn decodeFirstControlExtensions(control: []const u8) Error!?ControlExtensionsView {
    var off: usize = 0;
    while (off < control.len) {
        const key = try w.decodeFieldKey(control[off..]);
        off += key.len;
        const nv = if (key.wire_type == .length_delimited)
            try w.nextFieldValueLimited(control[off..], key.wire_type, lim.max_control_extensions_blob_bytes)
        else
            try w.nextFieldValue(control[off..], key.wire_type);
        off += nv.total;

        if (key.field_number != 6 or key.wire_type != .length_delimited) continue;

        var view = ControlExtensionsView{};
        var io: usize = 0;
        while (io < nv.value.len) {
            const ik = try w.decodeFieldKey(nv.value[io..]);
            io += ik.len;
            const iv = if (ik.wire_type == .length_delimited)
                try w.nextFieldValueLimited(nv.value[io..], ik.wire_type, lim.max_control_extensions_blob_bytes)
            else
                try w.nextFieldValue(nv.value[io..], ik.wire_type);
            io += iv.total;
            switch (ik.field_number) {
                10 => {
                    if (ik.wire_type != .varint) return error.UnsupportedWireType;
                    const vv = try w.decodeVarUInt64(iv.value);
                    view.partial_messages = vv.value != 0;
                },
                else => {},
            }
        }
        return view;
    }
    return null;
}

test "ihave topic and message ids round trip" {
    const a = std.testing.allocator;
    const mids: []const []const u8 = &.{ "id-a", "id-b" };
    const wire = try encodeIHave(a, "/t/have", mids);
    defer a.free(wire);
    var got = (try decodeFirstIHave(a, wire)).?;
    defer deinitIHaveOwned(a, &got);
    try std.testing.expectEqualStrings("/t/have", got.topic);
    try std.testing.expectEqual(@as(usize, 2), got.message_ids.len);
    try std.testing.expectEqualStrings("id-a", got.message_ids[0]);
    try std.testing.expectEqualStrings("id-b", got.message_ids[1]);
}

test "ihave empty message id list" {
    const a = std.testing.allocator;
    const wire = try encodeIHave(a, "topic-only", &[_][]const u8{});
    defer a.free(wire);
    var got = (try decodeFirstIHave(a, wire)).?;
    defer deinitIHaveOwned(a, &got);
    try std.testing.expectEqualStrings("topic-only", got.topic);
    try std.testing.expectEqual(@as(usize, 0), got.message_ids.len);
}

test "iwant message ids round trip" {
    const a = std.testing.allocator;
    const mids: []const []const u8 = &.{ "\x00\x01", "want-b" };
    const wire = try encodeIWant(a, mids);
    defer a.free(wire);
    var got = (try decodeFirstIWant(a, wire)).?;
    defer deinitIWantOwned(a, &got);
    try std.testing.expectEqual(@as(usize, 2), got.message_ids.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 1 }, got.message_ids[0]);
    try std.testing.expectEqualStrings("want-b", got.message_ids[1]);
}

test "iwant empty" {
    const a = std.testing.allocator;
    const wire = try encodeIWant(a, &[_][]const u8{});
    defer a.free(wire);
    var got = (try decodeFirstIWant(a, wire)).?;
    defer deinitIWantOwned(a, &got);
    try std.testing.expectEqual(@as(usize, 0), got.message_ids.len);
}

test "idontwant message ids round trip" {
    const a = std.testing.allocator;
    const mids: []const []const u8 = &.{ "a", "\xff\x00" };
    const wire = try encodeIDontWant(a, mids);
    defer a.free(wire);
    var got = (try decodeFirstIDontWant(a, wire)).?;
    defer deinitIDontWantOwned(a, &got);
    try std.testing.expectEqual(@as(usize, 2), got.message_ids.len);
    try std.testing.expectEqualStrings("a", got.message_ids[0]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xff, 0 }, got.message_ids[1]);
}

test "idontwant empty" {
    const a = std.testing.allocator;
    const wire = try encodeIDontWant(a, &[_][]const u8{});
    defer a.free(wire);
    var got = (try decodeFirstIDontWant(a, wire)).?;
    defer deinitIDontWantOwned(a, &got);
    try std.testing.expectEqual(@as(usize, 0), got.message_ids.len);
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

test "ihave rejects oversized topic" {
    const a = std.testing.allocator;
    const big = try a.alloc(u8, lim.max_topic_str_bytes + 1);
    defer a.free(big);
    @memset(big, 'z');

    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(a);
    try w.appendLengthDelimited(&inner, a, 1, big);
    var ctl = std.ArrayList(u8).empty;
    defer ctl.deinit(a);
    try w.appendLengthDelimited(&ctl, a, 1, inner.items);

    try std.testing.expectError(error.LengthDelimitedTooLong, decodeFirstIHave(a, ctl.items));
}

test "ihave rejects excess message id count" {
    const a = std.testing.allocator;
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(a);
    try w.appendLengthDelimited(&inner, a, 1, "t");
    var i: usize = 0;
    while (i < lim.max_message_ids_per_entry + 1) : (i += 1) {
        try w.appendLengthDelimited(&inner, a, 2, "");
    }
    var ctl = std.ArrayList(u8).empty;
    defer ctl.deinit(a);
    try w.appendLengthDelimited(&ctl, a, 1, inner.items);

    try std.testing.expectError(error.PayloadTooLarge, decodeFirstIHave(a, ctl.items));
}

test "iwant rejects oversized message id" {
    const a = std.testing.allocator;
    const big = try a.alloc(u8, lim.max_message_id_bytes + 1);
    defer a.free(big);
    @memset(big, 0);

    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(a);
    try w.appendLengthDelimited(&inner, a, 1, big);
    var ctl = std.ArrayList(u8).empty;
    defer ctl.deinit(a);
    try w.appendLengthDelimited(&ctl, a, 2, inner.items);

    try std.testing.expectError(error.LengthDelimitedTooLong, decodeFirstIWant(a, ctl.items));
}

test "control extensions partialMessages round trip" {
    const a = std.testing.allocator;
    for ([_]bool{ true, false }) |b| {
        const wire = try encodeControlMessageExtensionsOnly(a, .{ .partial_messages = b });
        defer a.free(wire);
        const got = (try decodeFirstControlExtensions(wire)).?;
        try std.testing.expectEqual(@as(?bool, b), got.partial_messages);
    }
}

test "control extensions empty message" {
    const a = std.testing.allocator;
    const wire = try encodeControlMessageExtensionsOnly(a, .{});
    defer a.free(wire);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x32, 0x00 }, wire);
    const got = (try decodeFirstControlExtensions(wire)).?;
    try std.testing.expectEqual(@as(?bool, null), got.partial_messages);
}

test "control extensions wire matches manual key for field 10 true" {
    const a = std.testing.allocator;
    const wire = try encodeControlMessageExtensionsOnly(a, .{ .partial_messages = true });
    defer a.free(wire);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x32, 0x02, 0x50, 0x01 }, wire);
}

// ---------------------------------------------------------------------------
// PRUNE peer exchange (PX, #75 major)
// ---------------------------------------------------------------------------

test "prune with PX peers round trip carries topic, backoff, peer ids" {
    const a = std.testing.allocator;
    const peer1_id = "peer-id-bytes-1";
    const peer2_id = "peer-id-bytes-2";
    const peers = [_]PeerInfoOwned{
        .{ .peer_id = @constCast(peer1_id) },
        .{ .peer_id = @constCast(peer2_id), .signed_peer_record = @constCast("signed-record-blob") },
    };
    const wire = try encodePruneWithPeers(a, "t", 45, &peers);
    defer a.free(wire);

    var got = (try decodeFirstPruneWithPeers(a, wire)).?;
    defer deinitPruneWithPeersOwned(a, &got);
    try std.testing.expectEqualStrings("t", got.topic);
    try std.testing.expectEqual(@as(?u64, 45), got.backoff_seconds);
    try std.testing.expectEqual(@as(usize, 2), got.peers.len);
    try std.testing.expectEqualStrings(peer1_id, got.peers[0].peer_id.?);
    try std.testing.expectEqual(@as(?[]u8, null), got.peers[0].signed_peer_record);
    try std.testing.expectEqualStrings(peer2_id, got.peers[1].peer_id.?);
    try std.testing.expectEqualStrings("signed-record-blob", got.peers[1].signed_peer_record.?);
}

test "prune with empty PX peers list still decodes" {
    const a = std.testing.allocator;
    const wire = try encodePruneWithPeers(a, "t", null, &[_]PeerInfoOwned{});
    defer a.free(wire);
    var got = (try decodeFirstPruneWithPeers(a, wire)).?;
    defer deinitPruneWithPeersOwned(a, &got);
    try std.testing.expectEqualStrings("t", got.topic);
    try std.testing.expectEqual(@as(?u64, null), got.backoff_seconds);
    try std.testing.expectEqual(@as(usize, 0), got.peers.len);
}

test "decodeFirstPrune is backwards compatible with PX-bearing wire" {
    const a = std.testing.allocator;
    const peers = [_]PeerInfoOwned{.{ .peer_id = @constCast("peer-id-bytes-1") }};
    const wire = try encodePruneWithPeers(a, "t", 10, &peers);
    defer a.free(wire);
    // Old decoder ignores the unknown PX field but still surfaces topic + backoff.
    var legacy = (try decodeFirstPrune(a, wire)).?;
    defer deinitPruneView(a, &legacy);
    try std.testing.expectEqualStrings("t", legacy.topic);
    try std.testing.expectEqual(@as(?u64, 10), legacy.backoff_seconds);
}

test "decodeFirstPruneWithPeers handles missing optional fields" {
    const a = std.testing.allocator;
    // Hand-build a PRUNE with only topic (no backoff, no peers) to mirror old encoder output.
    const wire = try encodePrune(a, "alpha", null);
    defer a.free(wire);
    var got = (try decodeFirstPruneWithPeers(a, wire)).?;
    defer deinitPruneWithPeersOwned(a, &got);
    try std.testing.expectEqualStrings("alpha", got.topic);
    try std.testing.expectEqual(@as(?u64, null), got.backoff_seconds);
    try std.testing.expectEqual(@as(usize, 0), got.peers.len);
}
