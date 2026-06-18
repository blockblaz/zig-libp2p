//! kad-dht protobuf wire codec and length-prefixed framing (#93).
//!
//! Spec: https://github.com/libp2p/specs/tree/master/kad-dht

const std = @import("std");
const Io = std.Io;
const proto = @import("../../primitives/protobuf/wire.zig");
const varint = @import("../../primitives/varint.zig");

pub const protocol_line: []const u8 = "/ipfs/kad/1.0.0\n";
pub const protocol_id: []const u8 = std.mem.trimEnd(u8, protocol_line, "\n");
pub const lan_protocol_line: []const u8 = "/lan/kad/1.0.0\n";

pub const Error = proto.Error || error{
    MessageTooLarge,
    UnsupportedField,
    InvalidMessageType,
    InvalidConnectionType,
    MissingRequiredField,
    TooManyPeers,
    TooManyAddrs,
} || std.mem.Allocator.Error;

pub const Limits = struct {
    max_frame_bytes: usize = 64 * 1024,
    max_key_bytes: usize = 256,
    max_value_bytes: usize = 16 * 1024,
    max_peer_id_bytes: usize = 128,
    max_addr_bytes: usize = 1024,
    max_peers: usize = 32,
    max_addrs_per_peer: usize = 16,
    max_string_field_bytes: usize = 128,

    pub const standard: Limits = .{};
};

pub const MessageType = enum(u32) {
    put_value = 0,
    get_value = 1,
    add_provider = 2,
    get_providers = 3,
    find_node = 4,
    ping = 5,
};

pub const ConnectionType = enum(u32) {
    not_connected = 0,
    connected = 1,
    can_connect = 2,
    cannot_connect = 3,
};

pub const RecordView = struct {
    key: ?[]const u8 = null,
    value: ?[]const u8 = null,
    time_received: ?[]const u8 = null,
};

pub const RecordOwned = struct {
    key: ?[]u8 = null,
    value: ?[]u8 = null,
    time_received: ?[]u8 = null,

    pub fn deinit(self: *RecordOwned, allocator: std.mem.Allocator) void {
        if (self.key) |k| allocator.free(k);
        if (self.value) |v| allocator.free(v);
        if (self.time_received) |t| allocator.free(t);
        self.* = .{};
    }
};

pub const PeerView = struct {
    id: ?[]const u8 = null,
    addrs: []const []const u8 = &.{},
    connection: ConnectionType = .not_connected,
};

pub const PeerOwned = struct {
    id: ?[]u8 = null,
    addrs: [][]u8 = &[_][]u8{},
    connection: ConnectionType = .not_connected,

    pub fn deinit(self: *PeerOwned, allocator: std.mem.Allocator) void {
        if (self.id) |x| allocator.free(x);
        for (self.addrs) |a| allocator.free(a);
        allocator.free(self.addrs);
        self.* = .{};
    }
};

pub const MessageView = struct {
    msg_type: MessageType,
    key: ?[]const u8 = null,
    record: ?RecordView = null,
    closer_peers: []const PeerView = &.{},
    provider_peers: []const PeerView = &.{},
};

pub const MessageOwned = struct {
    msg_type: MessageType,
    key: ?[]u8 = null,
    record: ?RecordOwned = null,
    closer_peers: []PeerOwned = &[_]PeerOwned{},
    provider_peers: []PeerOwned = &[_]PeerOwned{},

    pub fn deinit(self: *MessageOwned, allocator: std.mem.Allocator) void {
        if (self.key) |k| allocator.free(k);
        if (self.record) |*r| r.deinit(allocator);
        for (self.closer_peers) |*p| p.deinit(allocator);
        allocator.free(self.closer_peers);
        for (self.provider_peers) |*p| p.deinit(allocator);
        allocator.free(self.provider_peers);
        self.* = .{ .msg_type = .ping };
    }
};

fn decodeMessageType(v: u64) Error!MessageType {
    return switch (v) {
        0 => .put_value,
        1 => .get_value,
        2 => .add_provider,
        3 => .get_providers,
        4 => .find_node,
        5 => .ping,
        else => error.InvalidMessageType,
    };
}

fn decodeConnectionType(v: u64) Error!ConnectionType {
    return switch (v) {
        0 => .not_connected,
        1 => .connected,
        2 => .can_connect,
        3 => .cannot_connect,
        else => error.InvalidConnectionType,
    };
}

fn appendRecord(list: *std.ArrayList(u8), allocator: std.mem.Allocator, rec: RecordView) std.mem.Allocator.Error!void {
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    if (rec.key) |k| try proto.appendLengthDelimited(&inner, allocator, 1, k);
    if (rec.value) |v| try proto.appendLengthDelimited(&inner, allocator, 2, v);
    if (rec.time_received) |t| try proto.appendLengthDelimited(&inner, allocator, 5, t);
    const blob = try inner.toOwnedSlice(allocator);
    defer allocator.free(blob);
    try proto.appendLengthDelimited(list, allocator, 3, blob);
}

fn appendPeer(list: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, peer: PeerView) std.mem.Allocator.Error!void {
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    if (peer.id) |id| try proto.appendLengthDelimited(&inner, allocator, 1, id);
    for (peer.addrs) |a| try proto.appendLengthDelimited(&inner, allocator, 2, a);
    try proto.appendFieldKey(&inner, allocator, 3, .varint);
    try proto.appendVarUInt64(&inner, allocator, @intFromEnum(peer.connection));
    const blob = try inner.toOwnedSlice(allocator);
    defer allocator.free(blob);
    try proto.appendLengthDelimited(list, allocator, field, blob);
}

pub fn encode(allocator: std.mem.Allocator, msg: MessageView) Error![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);
    try proto.appendFieldKey(&list, allocator, 1, .varint);
    try proto.appendVarUInt64(&list, allocator, @intFromEnum(msg.msg_type));
    if (msg.key) |k| {
        if (k.len > Limits.standard.max_key_bytes) return error.MessageTooLarge;
        try proto.appendLengthDelimited(&list, allocator, 2, k);
    }
    if (msg.record) |r| try appendRecord(&list, allocator, r);
    for (msg.closer_peers) |p| try appendPeer(&list, allocator, 8, p);
    for (msg.provider_peers) |p| try appendPeer(&list, allocator, 9, p);
    return try list.toOwnedSlice(allocator);
}

fn decodeRecordOwned(allocator: std.mem.Allocator, blob: []const u8, limits: Limits) Error!RecordOwned {
    var out: RecordOwned = .{};
    var off: usize = 0;
    while (off < blob.len) {
        const key = try proto.decodeFieldKey(blob[off..]);
        off += key.len;
        const val_buf = blob[off..];
        const nv = try proto.nextFieldValueLimited(val_buf, key.wire_type, limits.max_value_bytes);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                if (nv.value.len > limits.max_key_bytes) return error.MessageTooLarge;
                out.key = try allocator.dupe(u8, nv.value);
            },
            2 => {
                if (nv.value.len > limits.max_value_bytes) return error.MessageTooLarge;
                out.value = try allocator.dupe(u8, nv.value);
            },
            5 => {
                if (nv.value.len > limits.max_string_field_bytes) return error.MessageTooLarge;
                out.time_received = try allocator.dupe(u8, nv.value);
            },
            else => {},
        }
    }
    return out;
}

fn decodePeerOwned(allocator: std.mem.Allocator, blob: []const u8, limits: Limits) Error!PeerOwned {
    var out: PeerOwned = .{};
    var addrs = std.ArrayList([]u8).empty;
    errdefer {
        for (addrs.items) |a| allocator.free(a);
        addrs.deinit(allocator);
    }
    var off: usize = 0;
    while (off < blob.len) {
        const key = try proto.decodeFieldKey(blob[off..]);
        off += key.len;
        const val_buf = blob[off..];
        const cap: usize = switch (key.field_number) {
            1 => limits.max_peer_id_bytes,
            2 => limits.max_addr_bytes,
            else => limits.max_frame_bytes,
        };
        const nv = try proto.nextFieldValueLimited(val_buf, key.wire_type, cap);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                out.id = try allocator.dupe(u8, nv.value);
            },
            2 => {
                if (addrs.items.len >= limits.max_addrs_per_peer) return error.TooManyAddrs;
                try addrs.append(allocator, try allocator.dupe(u8, nv.value));
            },
            3 => {
                const d = try proto.decodeVarUInt64(nv.value);
                out.connection = try decodeConnectionType(d.value);
            },
            else => {},
        }
    }
    out.addrs = try addrs.toOwnedSlice(allocator);
    return out;
}

pub fn decodeOwned(allocator: std.mem.Allocator, wire_bytes: []const u8, limits: Limits) Error!MessageOwned {
    if (wire_bytes.len > limits.max_frame_bytes) return error.MessageTooLarge;
    var out: MessageOwned = .{ .msg_type = .ping };
    var closer = std.ArrayList(PeerOwned).empty;
    errdefer closer.deinit(allocator);
    var providers = std.ArrayList(PeerOwned).empty;
    errdefer providers.deinit(allocator);

    var off: usize = 0;
    var msg_type_set = false;
    while (off < wire_bytes.len) {
        const key = try proto.decodeFieldKey(wire_bytes[off..]);
        off += key.len;
        const val_buf = wire_bytes[off..];
        const cap: usize = switch (key.field_number) {
            2 => limits.max_key_bytes,
            3 => limits.max_frame_bytes,
            8, 9 => limits.max_frame_bytes,
            else => limits.max_frame_bytes,
        };
        const nv = try proto.nextFieldValueLimited(val_buf, key.wire_type, cap);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                const d = try proto.decodeVarUInt64(nv.value);
                out.msg_type = try decodeMessageType(d.value);
                msg_type_set = true;
            },
            2 => out.key = try allocator.dupe(u8, nv.value),
            3 => out.record = try decodeRecordOwned(allocator, nv.value, limits),
            8 => {
                if (closer.items.len >= limits.max_peers) return error.TooManyPeers;
                try closer.append(allocator, try decodePeerOwned(allocator, nv.value, limits));
            },
            9 => {
                if (providers.items.len >= limits.max_peers) return error.TooManyPeers;
                try providers.append(allocator, try decodePeerOwned(allocator, nv.value, limits));
            },
            else => {},
        }
    }
    if (!msg_type_set) return error.MissingRequiredField;
    out.closer_peers = try closer.toOwnedSlice(allocator);
    out.provider_peers = try providers.toOwnedSlice(allocator);
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

test "find_node round trip" {
    const a = std.testing.allocator;
    const key = "target-peer-id-bytes";
    const wire = try encode(a, .{
        .msg_type = .find_node,
        .key = key,
    });
    defer a.free(wire);
    var decoded = try decodeOwned(a, wire, .standard);
    defer decoded.deinit(a);
    try std.testing.expect(decoded.msg_type == .find_node);
    try std.testing.expectEqualStrings(key, decoded.key.?);
}

test "find_node response with closer peers" {
    const a = std.testing.allocator;
    const addrs = [_][]const u8{"/ip4/203.0.113.1/udp/4001/quic-v1"};
    const wire = try encode(a, .{
        .msg_type = .find_node,
        .key = "target",
        .closer_peers = &.{
            .{ .id = "peer1", .addrs = &addrs, .connection = .connected },
        },
    });
    defer a.free(wire);
    var decoded = try decodeOwned(a, wire, .standard);
    defer decoded.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), decoded.closer_peers.len);
    try std.testing.expectEqualStrings("peer1", decoded.closer_peers[0].id.?);
}
