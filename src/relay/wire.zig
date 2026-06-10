//! Circuit Relay v2 protobuf wire codec (#91).
//!
//! Spec: https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md

const std = @import("std");
const Io = std.Io;
const proto = @import("../protobuf/wire.zig");
const varint = @import("../varint.zig");

pub const hop_protocol_line: []const u8 = "/libp2p/circuit/relay/0.2.0/hop\n";
pub const hop_protocol_id: []const u8 = std.mem.trimEnd(u8, hop_protocol_line, "\n");

pub const stop_protocol_line: []const u8 = "/libp2p/circuit/relay/0.2.0/stop\n";
pub const stop_protocol_id: []const u8 = std.mem.trimEnd(u8, stop_protocol_line, "\n");

pub const Error = proto.Error || error{
    MessageTooLarge,
    UnsupportedField,
    InvalidMessageType,
    MissingRequiredField,
    TooManyAddrs,
} || std.mem.Allocator.Error;

pub const Limits = struct {
    max_frame_bytes: usize = 64 * 1024,
    max_peer_id_bytes: usize = 128,
    max_addrs: usize = 32,
    max_addr_bytes: usize = 1024,
    max_voucher_bytes: usize = 4096,

    pub const standard: Limits = .{};
};

pub const Status = enum(u32) {
    unused = 0,
    ok = 100,
    reservation_refused = 200,
    resource_limit_exceeded = 201,
    permission_denied = 202,
    connection_failed = 203,
    no_reservation = 204,
    malformed_message = 400,
    unexpected_message = 401,
};

pub const HopType = enum(u32) {
    reserve = 0,
    connect = 1,
    status = 2,
};

pub const StopType = enum(u32) {
    connect = 0,
    status = 1,
};

pub const LimitView = struct {
    duration_sec: ?u32 = null,
    data_bytes: ?u64 = null,
};

pub const PeerView = struct {
    id: ?[]const u8 = null,
    addrs: []const []const u8 = &.{},
};

pub const ReservationView = struct {
    expire_unix: u64 = 0,
    addrs: []const []const u8 = &.{},
    voucher: ?[]const u8 = null,
};

pub const HopMessageView = struct {
    msg_type: HopType,
    peer: ?PeerView = null,
    reservation: ?ReservationView = null,
    limit: ?LimitView = null,
    status: ?Status = null,
};

pub const StopMessageView = struct {
    msg_type: StopType,
    peer: ?PeerView = null,
    limit: ?LimitView = null,
    status: ?Status = null,
};

pub const PeerOwned = struct {
    id: ?[]u8 = null,
    addrs: [][]u8 = &[_][]u8{},

    pub fn deinit(self: *PeerOwned, allocator: std.mem.Allocator) void {
        if (self.id) |x| allocator.free(x);
        for (self.addrs) |a| allocator.free(a);
        if (self.addrs.len > 0) allocator.free(self.addrs);
        self.* = .{};
    }
};

pub const ReservationOwned = struct {
    expire_unix: u64 = 0,
    addrs: [][]u8 = &[_][]u8{},
    voucher: ?[]u8 = null,

    pub fn deinit(self: *ReservationOwned, allocator: std.mem.Allocator) void {
        for (self.addrs) |a| allocator.free(a);
        if (self.addrs.len > 0) allocator.free(self.addrs);
        if (self.voucher) |v| allocator.free(v);
        self.* = .{};
    }
};

pub const LimitOwned = struct {
    duration_sec: ?u32 = null,
    data_bytes: ?u64 = null,
};

pub const HopMessageOwned = struct {
    msg_type: HopType,
    peer: ?PeerOwned = null,
    reservation: ?ReservationOwned = null,
    limit: ?LimitOwned = null,
    status: ?Status = null,

    pub fn deinit(self: *HopMessageOwned, allocator: std.mem.Allocator) void {
        if (self.peer) |*p| p.deinit(allocator);
        if (self.reservation) |*r| r.deinit(allocator);
        self.* = .{ .msg_type = .status };
    }
};

pub const StopMessageOwned = struct {
    msg_type: StopType,
    peer: ?PeerOwned = null,
    limit: ?LimitOwned = null,
    status: ?Status = null,

    pub fn deinit(self: *StopMessageOwned, allocator: std.mem.Allocator) void {
        if (self.peer) |*p| p.deinit(allocator);
        self.* = .{ .msg_type = .status };
    }
};

fn decodeHopType(v: u64) Error!HopType {
    return switch (v) {
        0 => .reserve,
        1 => .connect,
        2 => .status,
        else => error.InvalidMessageType,
    };
}

fn decodeStopType(v: u64) Error!StopType {
    return switch (v) {
        0 => .connect,
        1 => .status,
        else => error.InvalidMessageType,
    };
}

fn decodeStatus(v: u64) Error!Status {
    return switch (v) {
        0 => .unused,
        100 => .ok,
        200 => .reservation_refused,
        201 => .resource_limit_exceeded,
        202 => .permission_denied,
        203 => .connection_failed,
        204 => .no_reservation,
        400 => .malformed_message,
        401 => .unexpected_message,
        else => error.InvalidMessageType,
    };
}

fn appendLimitBlob(list: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, lim: LimitView) !void {
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    if (lim.duration_sec) |d| {
        try proto.appendFieldKey(&inner, allocator, 1, .varint);
        try proto.appendVarUInt64(&inner, allocator, d);
    }
    if (lim.data_bytes) |d| {
        try proto.appendFieldKey(&inner, allocator, 2, .varint);
        try proto.appendVarUInt64(&inner, allocator, d);
    }
    const blob = try inner.toOwnedSlice(allocator);
    defer allocator.free(blob);
    try proto.appendLengthDelimited(list, allocator, field, blob);
}

fn appendPeerBlob(list: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, peer: PeerView) !void {
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    if (peer.id) |id| try proto.appendLengthDelimited(&inner, allocator, 1, id);
    for (peer.addrs) |a| try proto.appendLengthDelimited(&inner, allocator, 2, a);
    const blob = try inner.toOwnedSlice(allocator);
    defer allocator.free(blob);
    try proto.appendLengthDelimited(list, allocator, field, blob);
}

fn appendReservationBlob(list: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, res: ReservationView) !void {
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    try proto.appendFieldKey(&inner, allocator, 1, .varint);
    try proto.appendVarUInt64(&inner, allocator, res.expire_unix);
    for (res.addrs) |a| try proto.appendLengthDelimited(&inner, allocator, 2, a);
    if (res.voucher) |v| try proto.appendLengthDelimited(&inner, allocator, 3, v);
    const blob = try inner.toOwnedSlice(allocator);
    defer allocator.free(blob);
    try proto.appendLengthDelimited(list, allocator, field, blob);
}

pub fn encodeHop(allocator: std.mem.Allocator, msg: HopMessageView) ![]u8 {
    var list = std.ArrayList(u8).empty;
    errdefer list.deinit(allocator);
    try proto.appendFieldKey(&list, allocator, 1, .varint);
    try proto.appendVarUInt64(&list, allocator, @intFromEnum(msg.msg_type));
    if (msg.peer) |p| try appendPeerBlob(&list, allocator, 2, p);
    if (msg.reservation) |r| try appendReservationBlob(&list, allocator, 3, r);
    if (msg.limit) |l| try appendLimitBlob(&list, allocator, 4, l);
    if (msg.status) |s| {
        try proto.appendFieldKey(&list, allocator, 5, .varint);
        try proto.appendVarUInt64(&list, allocator, @intFromEnum(s));
    }
    return try list.toOwnedSlice(allocator);
}

pub fn encodeStop(allocator: std.mem.Allocator, msg: StopMessageView) ![]u8 {
    var list = std.ArrayList(u8).empty;
    errdefer list.deinit(allocator);
    try proto.appendFieldKey(&list, allocator, 1, .varint);
    try proto.appendVarUInt64(&list, allocator, @intFromEnum(msg.msg_type));
    if (msg.peer) |p| try appendPeerBlob(&list, allocator, 2, p);
    if (msg.limit) |l| try appendLimitBlob(&list, allocator, 3, l);
    if (msg.status) |s| {
        try proto.appendFieldKey(&list, allocator, 4, .varint);
        try proto.appendVarUInt64(&list, allocator, @intFromEnum(s));
    }
    return try list.toOwnedSlice(allocator);
}

fn decodeLimitOwned(wire: []const u8) Error!LimitOwned {
    var out: LimitOwned = .{};
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, 8);
        off += nv.total;
        if (key.field_number == 1 and key.wire_type == .varint) {
            const d = try proto.decodeVarUInt64(nv.value);
            out.duration_sec = @intCast(d.value);
        } else if (key.field_number == 2 and key.wire_type == .varint) {
            const d = try proto.decodeVarUInt64(nv.value);
            out.data_bytes = d.value;
        }
    }
    return out;
}

fn decodePeerOwned(allocator: std.mem.Allocator, wire: []const u8, limits: Limits) Error!PeerOwned {
    var out: PeerOwned = .{};
    var addrs = std.ArrayList([]u8).empty;
    errdefer {
        for (addrs.items) |a| allocator.free(a);
        addrs.deinit(allocator);
    }
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const cap: usize = if (key.field_number == 1) limits.max_peer_id_bytes else limits.max_addr_bytes;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, cap);
        off += nv.total;
        switch (key.field_number) {
            1 => out.id = try allocator.dupe(u8, nv.value),
            2 => {
                if (addrs.items.len >= limits.max_addrs) return error.TooManyAddrs;
                try addrs.append(allocator, try allocator.dupe(u8, nv.value));
            },
            else => {},
        }
    }
    out.addrs = try addrs.toOwnedSlice(allocator);
    return out;
}

fn decodeReservationOwned(allocator: std.mem.Allocator, wire: []const u8, limits: Limits) Error!ReservationOwned {
    var out: ReservationOwned = .{};
    var addrs = std.ArrayList([]u8).empty;
    errdefer {
        for (addrs.items) |a| allocator.free(a);
        addrs.deinit(allocator);
    }
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const cap: usize = switch (key.field_number) {
            1 => 8,
            2 => limits.max_addr_bytes,
            3 => limits.max_voucher_bytes,
            else => limits.max_frame_bytes,
        };
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, cap);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                const d = try proto.decodeVarUInt64(nv.value);
                out.expire_unix = d.value;
            },
            2 => {
                if (addrs.items.len >= limits.max_addrs) return error.TooManyAddrs;
                try addrs.append(allocator, try allocator.dupe(u8, nv.value));
            },
            3 => out.voucher = try allocator.dupe(u8, nv.value),
            else => {},
        }
    }
    out.addrs = try addrs.toOwnedSlice(allocator);
    return out;
}

pub fn decodeHopOwned(allocator: std.mem.Allocator, wire_bytes: []const u8, limits: Limits) Error!HopMessageOwned {
    if (wire_bytes.len > limits.max_frame_bytes) return error.MessageTooLarge;
    var out: HopMessageOwned = .{ .msg_type = .status };
    var type_set = false;
    var off: usize = 0;
    while (off < wire_bytes.len) {
        const key = try proto.decodeFieldKey(wire_bytes[off..]);
        off += key.len;
        const cap: usize = switch (key.field_number) {
            2, 3 => limits.max_frame_bytes,
            else => limits.max_frame_bytes,
        };
        const nv = try proto.nextFieldValueLimited(wire_bytes[off..], key.wire_type, cap);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                const d = try proto.decodeVarUInt64(nv.value);
                out.msg_type = try decodeHopType(d.value);
                type_set = true;
            },
            2 => out.peer = try decodePeerOwned(allocator, nv.value, limits),
            3 => out.reservation = try decodeReservationOwned(allocator, nv.value, limits),
            4 => out.limit = try decodeLimitOwned(nv.value),
            5 => {
                const d = try proto.decodeVarUInt64(nv.value);
                out.status = try decodeStatus(d.value);
            },
            else => {},
        }
    }
    if (!type_set) return error.MissingRequiredField;
    return out;
}

pub fn decodeStopOwned(allocator: std.mem.Allocator, wire_bytes: []const u8, limits: Limits) Error!StopMessageOwned {
    if (wire_bytes.len > limits.max_frame_bytes) return error.MessageTooLarge;
    var out: StopMessageOwned = .{ .msg_type = .status };
    var type_set = false;
    var off: usize = 0;
    while (off < wire_bytes.len) {
        const key = try proto.decodeFieldKey(wire_bytes[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire_bytes[off..], key.wire_type, limits.max_frame_bytes);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                const d = try proto.decodeVarUInt64(nv.value);
                out.msg_type = try decodeStopType(d.value);
                type_set = true;
            },
            2 => out.peer = try decodePeerOwned(allocator, nv.value, limits),
            3 => out.limit = try decodeLimitOwned(nv.value),
            4 => {
                const d = try proto.decodeVarUInt64(nv.value);
                out.status = try decodeStatus(d.value);
            },
            else => {},
        }
    }
    if (!type_set) return error.MissingRequiredField;
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

test "hop reserve round trip" {
    const a = std.testing.allocator;
    const wire_bytes = try encodeHop(a, .{ .msg_type = .reserve });
    defer a.free(wire_bytes);
    var decoded = try decodeHopOwned(a, wire_bytes, .standard);
    defer decoded.deinit(a);
    try std.testing.expectEqual(HopType.reserve, decoded.msg_type);
}

test "hop status with reservation round trip" {
    const a = std.testing.allocator;
    const wire_bytes = try encodeHop(a, .{
        .msg_type = .status,
        .status = .ok,
        .reservation = .{
            .expire_unix = 1_700_000_000,
            .addrs = &.{"/ip4/1.2.3.4/udp/4001/quic-v1"},
            .voucher = "voucher-bytes",
        },
        .limit = .{ .duration_sec = 120, .data_bytes = 1_048_576 },
    });
    defer a.free(wire_bytes);
    var decoded = try decodeHopOwned(a, wire_bytes, .standard);
    defer decoded.deinit(a);
    try std.testing.expectEqual(HopType.status, decoded.msg_type);
    try std.testing.expectEqual(Status.ok, decoded.status.?);
    try std.testing.expectEqual(@as(u64, 1_700_000_000), decoded.reservation.?.expire_unix);
}

test "stop connect round trip" {
    const a = std.testing.allocator;
    const wire_bytes = try encodeStop(a, .{
        .msg_type = .connect,
        .peer = .{ .id = "initiator-peer-id" },
        .limit = .{ .duration_sec = 60 },
    });
    defer a.free(wire_bytes);
    var decoded = try decodeStopOwned(a, wire_bytes, .standard);
    defer decoded.deinit(a);
    try std.testing.expectEqual(StopType.connect, decoded.msg_type);
    try std.testing.expectEqualStrings("initiator-peer-id", decoded.peer.?.id.?);
}
