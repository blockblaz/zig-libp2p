//! AutoNAT v1 + v2 protobuf wire codecs and length-prefixed framing.
//!
//! Specs:
//! - v1: https://github.com/libp2p/specs/blob/master/autonat/autonat-v1.md
//! - v2: https://github.com/libp2p/specs/blob/master/autonat/autonat-v2.md

const std = @import("std");
const Io = std.Io;
const proto = @import("../../primitives/protobuf/wire.zig");
const varint = @import("../../primitives/varint.zig");

pub const v1_protocol_line: []const u8 = "/libp2p/autonat/1.0.0\n";
pub const v1_multistream_protocol_id: []const u8 = std.mem.trimEnd(u8, v1_protocol_line, "\n");

pub const v2_dial_request_line: []const u8 = "/libp2p/autonat/2/dial-request\n";
pub const v2_dial_request_id: []const u8 = std.mem.trimEnd(u8, v2_dial_request_line, "\n");

pub const v2_dial_back_line: []const u8 = "/libp2p/autonat/2/dial-back\n";
pub const v2_dial_back_id: []const u8 = std.mem.trimEnd(u8, v2_dial_back_line, "\n");

pub const Error = proto.Error || error{
    MessageTooLarge,
    UnsupportedField,
    InvalidMessageType,
    MissingRequiredField,
    AmplificationDataTooLarge,
} || std.mem.Allocator.Error;

pub const Limits = struct {
    max_frame_bytes: usize = 64 * 1024,
    max_addrs: usize = 32,
    max_addr_bytes: usize = 1024,
    max_status_text_bytes: usize = 256,
    max_peer_id_bytes: usize = 128,
    /// v2 DialDataResponse.data field cap (spec: 4096 bytes).
    max_dial_data_chunk_bytes: usize = 4096,

    pub const standard: Limits = .{};
};

fn decodeV1MessageType(v: u64) Error!V1MessageType {
    return switch (v) {
        0 => .dial,
        1 => .dial_response,
        else => error.InvalidMessageType,
    };
}

fn decodeV1ResponseStatus(v: u64) Error!V1ResponseStatus {
    return switch (v) {
        0 => .ok,
        100 => .e_dial_error,
        101 => .e_dial_refused,
        200 => .e_bad_request,
        300 => .e_internal_error,
        else => error.InvalidMessageType,
    };
}

fn decodeV2ResponseStatus(v: u64) Error!V2ResponseStatus {
    return switch (v) {
        0 => .e_internal_error,
        100 => .e_request_rejected,
        101 => .e_dial_refused,
        200 => .ok,
        else => error.InvalidMessageType,
    };
}

fn decodeV2DialStatus(v: u64) Error!V2DialStatus {
    return switch (v) {
        0 => .unused,
        100 => .e_dial_error,
        101 => .e_dial_back_error,
        200 => .ok,
        else => error.InvalidMessageType,
    };
}

fn decodeV2DialBackStatus(v: u64) Error!V2DialBackStatus {
    return switch (v) {
        0 => .ok,
        else => error.InvalidMessageType,
    };
}

// ── v1 ───────────────────────────────────────────────────────────────────────

pub const V1MessageType = enum(u32) {
    dial = 0,
    dial_response = 1,
};

pub const V1ResponseStatus = enum(u32) {
    ok = 0,
    e_dial_error = 100,
    e_dial_refused = 101,
    e_bad_request = 200,
    e_internal_error = 300,
};

pub const V1Dial = struct {
    peer_id: ?[]const u8 = null,
    addrs: []const []const u8 = &.{},
};

pub const V1DialResponse = struct {
    status: V1ResponseStatus,
    status_text: ?[]const u8 = null,
    addr: ?[]const u8 = null,
};

pub const V1Message = union(enum) {
    dial: V1Dial,
    dial_response: V1DialResponse,
};

fn encodePeerInfo(list: *std.ArrayList(u8), allocator: std.mem.Allocator, peer_id: ?[]const u8, addrs: []const []const u8) !void {
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    if (peer_id) |id| try proto.appendLengthDelimited(&inner, allocator, 1, id);
    for (addrs) |a| try proto.appendLengthDelimited(&inner, allocator, 2, a);
    try proto.appendLengthDelimited(list, allocator, 1, inner.items);
}

pub fn encodeV1(allocator: std.mem.Allocator, msg: V1Message) Error![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);

    switch (msg) {
        .dial => |d| {
            try proto.appendFieldKey(&list, allocator, 1, .varint);
            try proto.appendVarUInt64(&list, allocator, @intFromEnum(V1MessageType.dial));
            var dial_inner = std.ArrayList(u8).empty;
            defer dial_inner.deinit(allocator);
            try encodePeerInfo(&dial_inner, allocator, d.peer_id, d.addrs);
            try proto.appendLengthDelimited(&list, allocator, 2, dial_inner.items);
        },
        .dial_response => |r| {
            try proto.appendFieldKey(&list, allocator, 1, .varint);
            try proto.appendVarUInt64(&list, allocator, @intFromEnum(V1MessageType.dial_response));
            var resp_inner = std.ArrayList(u8).empty;
            defer resp_inner.deinit(allocator);
            try proto.appendFieldKey(&resp_inner, allocator, 1, .varint);
            try proto.appendVarUInt64(&resp_inner, allocator, @intFromEnum(r.status));
            if (r.status_text) |t| try proto.appendLengthDelimited(&resp_inner, allocator, 2, t);
            if (r.addr) |a| try proto.appendLengthDelimited(&resp_inner, allocator, 3, a);
            try proto.appendLengthDelimited(&list, allocator, 3, resp_inner.items);
        },
    }
    return try list.toOwnedSlice(allocator);
}

pub fn decodeV1Owned(allocator: std.mem.Allocator, wire: []const u8, limits: Limits) Error!V1Message {
    if (wire.len > limits.max_frame_bytes) return error.MessageTooLarge;

    var msg_type: ?V1MessageType = null;
    var dial: V1Dial = .{};
    var dial_response: V1DialResponse = .{ .status = .e_internal_error };
    var addrs = std.ArrayList([]u8).empty;
    defer {
        for (addrs.items) |x| allocator.free(x);
        addrs.deinit(allocator);
    }
    var peer_id_owned: ?[]u8 = null;
    errdefer if (peer_id_owned) |x| allocator.free(x);
    var status_text_owned: ?[]u8 = null;
    errdefer if (status_text_owned) |x| allocator.free(x);
    var addr_owned: ?[]u8 = null;
    errdefer if (addr_owned) |x| allocator.free(x);

    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const cap: usize = switch (key.field_number) {
            1 => 16,
            2, 3 => limits.max_frame_bytes,
            else => 4096,
        };
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, cap);
        off += nv.total;

        switch (key.field_number) {
            1 => {
                if (key.wire_type != .varint) return error.UnsupportedField;
                const d = try proto.decodeVarUInt64(nv.value);
                msg_type = try decodeV1MessageType(d.value);
            },
            2 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedField;
                try decodeDialInner(allocator, nv.value, limits, &peer_id_owned, &addrs);
            },
            3 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedField;
                try decodeDialResponseInner(allocator, nv.value, limits, &dial_response, &status_text_owned, &addr_owned);
            },
            else => {},
        }
    }

    const t = msg_type orelse return error.MissingRequiredField;
    return switch (t) {
        .dial => blk: {
            dial.peer_id = peer_id_owned;
            peer_id_owned = null;
            dial.addrs = try addrs.toOwnedSlice(allocator);
            addrs = .empty;
            break :blk .{ .dial = dial };
        },
        .dial_response => blk: {
            dial_response.status_text = status_text_owned;
            status_text_owned = null;
            dial_response.addr = addr_owned;
            addr_owned = null;
            break :blk .{ .dial_response = dial_response };
        },
    };
}

fn decodeDialInner(
    allocator: std.mem.Allocator,
    wire: []const u8,
    limits: Limits,
    peer_id_out: *?[]u8,
    addrs_out: *std.ArrayList([]u8),
) Error!void {
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, limits.max_frame_bytes);
        off += nv.total;
        if (key.field_number == 1 and key.wire_type == .length_delimited) {
            try decodePeerInfoInner(allocator, nv.value, limits, peer_id_out, addrs_out);
        }
    }
}

fn decodePeerInfoInner(
    allocator: std.mem.Allocator,
    wire: []const u8,
    limits: Limits,
    peer_id_out: *?[]u8,
    addrs_out: *std.ArrayList([]u8),
) Error!void {
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, limits.max_addr_bytes);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                if (peer_id_out.*) |old| allocator.free(old);
                peer_id_out.* = try allocator.dupe(u8, nv.value);
            },
            2 => {
                if (addrs_out.items.len >= limits.max_addrs) return error.MessageTooLarge;
                try addrs_out.append(allocator, try allocator.dupe(u8, nv.value));
            },
            else => {},
        }
    }
}

fn decodeDialResponseInner(
    allocator: std.mem.Allocator,
    wire: []const u8,
    limits: Limits,
    resp: *V1DialResponse,
    status_text_out: *?[]u8,
    addr_out: *?[]u8,
) Error!void {
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const cap: usize = switch (key.field_number) {
            2 => limits.max_status_text_bytes,
            3 => limits.max_addr_bytes,
            else => 16,
        };
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, cap);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                if (key.wire_type != .varint) return error.UnsupportedField;
                const d = try proto.decodeVarUInt64(nv.value);
                resp.status = try decodeV1ResponseStatus(d.value);
            },
            2 => {
                if (status_text_out.*) |old| allocator.free(old);
                status_text_out.* = try allocator.dupe(u8, nv.value);
            },
            3 => {
                if (addr_out.*) |old| allocator.free(old);
                addr_out.* = try allocator.dupe(u8, nv.value);
            },
            else => {},
        }
    }
}

// ── v2 ───────────────────────────────────────────────────────────────────────

pub const V2DialStatus = enum(u32) {
    unused = 0,
    e_dial_error = 100,
    e_dial_back_error = 101,
    ok = 200,
};

pub const V2ResponseStatus = enum(u32) {
    e_internal_error = 0,
    e_request_rejected = 100,
    e_dial_refused = 101,
    ok = 200,
};

pub const V2DialBackStatus = enum(u32) {
    ok = 0,
};

pub const V2DialRequest = struct {
    addrs: []const []const u8 = &.{},
    nonce: u64,
};

pub const V2DialDataRequest = struct {
    addr_idx: u32,
    num_bytes: u64,
};

pub const V2DialResponse = struct {
    status: V2ResponseStatus,
    addr_idx: u32 = 0,
    dial_status: V2DialStatus = .unused,
};

pub const V2DialDataResponse = struct {
    data: []const u8,
};

pub const V2DialBack = struct {
    nonce: u64,
};

pub const V2DialBackResponse = struct {
    status: V2DialBackStatus = .ok,
};

pub const V2RequestMessage = union(enum) {
    dial_request: V2DialRequest,
    dial_response: V2DialResponse,
    dial_data_request: V2DialDataRequest,
    dial_data_response: V2DialDataResponse,
};

pub fn encodeV2RequestMessage(allocator: std.mem.Allocator, msg: V2RequestMessage) Error![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);

    switch (msg) {
        .dial_request => |dr| {
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            for (dr.addrs) |a| try proto.appendLengthDelimited(&inner, allocator, 1, a);
            try appendFixed64(&inner, allocator, 2, dr.nonce);
            try proto.appendLengthDelimited(&list, allocator, 1, inner.items);
        },
        .dial_response => |dr| {
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            try proto.appendFieldKey(&inner, allocator, 1, .varint);
            try proto.appendVarUInt64(&inner, allocator, @intFromEnum(dr.status));
            try proto.appendFieldKey(&inner, allocator, 2, .varint);
            try proto.appendVarUInt64(&inner, allocator, dr.addr_idx);
            try proto.appendFieldKey(&inner, allocator, 3, .varint);
            try proto.appendVarUInt64(&inner, allocator, @intFromEnum(dr.dial_status));
            try proto.appendLengthDelimited(&list, allocator, 2, inner.items);
        },
        .dial_data_request => |ddr| {
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            try proto.appendFieldKey(&inner, allocator, 1, .varint);
            try proto.appendVarUInt64(&inner, allocator, ddr.addr_idx);
            try proto.appendFieldKey(&inner, allocator, 2, .varint);
            try proto.appendVarUInt64(&inner, allocator, ddr.num_bytes);
            try proto.appendLengthDelimited(&list, allocator, 3, inner.items);
        },
        .dial_data_response => |ddr| {
            if (ddr.data.len > Limits.standard.max_dial_data_chunk_bytes) return error.AmplificationDataTooLarge;
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            try proto.appendLengthDelimited(&inner, allocator, 1, ddr.data);
            try proto.appendLengthDelimited(&list, allocator, 4, inner.items);
        },
    }
    return try list.toOwnedSlice(allocator);
}

pub fn encodeV2DialBack(allocator: std.mem.Allocator, msg: V2DialBack) Error![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);
    try appendFixed64(&list, allocator, 1, msg.nonce);
    return try list.toOwnedSlice(allocator);
}

pub fn encodeV2DialBackResponse(allocator: std.mem.Allocator, msg: V2DialBackResponse) Error![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);
    try proto.appendFieldKey(&list, allocator, 1, .varint);
    try proto.appendVarUInt64(&list, allocator, @intFromEnum(msg.status));
    return try list.toOwnedSlice(allocator);
}

fn appendFixed64(list: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, value: u64) !void {
    try proto.appendFieldKey(list, allocator, field, .fixed64);
    var le: [8]u8 = undefined;
    std.mem.writeInt(u64, &le, value, .little);
    try list.appendSlice(allocator, &le);
}

fn readFixed64(value: []const u8) Error!u64 {
    if (value.len != 8) return error.Truncated;
    return std.mem.readInt(u64, value[0..8], .little);
}

pub fn decodeV2RequestMessageOwned(allocator: std.mem.Allocator, wire: []const u8, limits: Limits) Error!V2RequestMessage {
    if (wire.len > limits.max_frame_bytes) return error.MessageTooLarge;

    var variant: ?enum { dial_request, dial_response, dial_data_request, dial_data_response } = null;
    var addrs = std.ArrayList([]u8).empty;
    defer {
        for (addrs.items) |x| allocator.free(x);
        addrs.deinit(allocator);
    }
    var nonce: u64 = 0;
    var dial_response: V2DialResponse = .{ .status = .e_internal_error };
    var dial_data_request: V2DialDataRequest = .{ .addr_idx = 0, .num_bytes = 0 };
    var dial_data: ?[]u8 = null;
    errdefer if (dial_data) |x| allocator.free(x);

    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, limits.max_frame_bytes);
        off += nv.total;

        switch (key.field_number) {
            1 => {
                variant = .dial_request;
                try decodeV2DialRequestInner(allocator, nv.value, limits, &addrs, &nonce);
            },
            2 => {
                variant = .dial_response;
                try decodeV2DialResponseInner(nv.value, &dial_response);
            },
            3 => {
                variant = .dial_data_request;
                try decodeV2DialDataRequestInner(nv.value, &dial_data_request);
            },
            4 => {
                variant = .dial_data_response;
                try decodeV2DialDataResponseInner(allocator, nv.value, limits, &dial_data);
            },
            else => {},
        }
    }

    const v = variant orelse return error.MissingRequiredField;
    return switch (v) {
        .dial_request => .{
            .dial_request = .{
                .addrs = try addrs.toOwnedSlice(allocator),
                .nonce = nonce,
            },
        },
        .dial_response => .{ .dial_response = dial_response },
        .dial_data_request => .{ .dial_data_request = dial_data_request },
        .dial_data_response => .{
            .dial_data_response = .{ .data = dial_data orelse &[_]u8{} },
        },
    };
}

fn decodeV2DialRequestInner(
    allocator: std.mem.Allocator,
    wire: []const u8,
    limits: Limits,
    addrs_out: *std.ArrayList([]u8),
    nonce_out: *u64,
) Error!void {
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, switch (key.field_number) {
            1 => limits.max_addr_bytes,
            2 => 8,
            else => 16,
        });
        off += nv.total;
        switch (key.field_number) {
            1 => {
                if (addrs_out.items.len >= limits.max_addrs) return error.MessageTooLarge;
                try addrs_out.append(allocator, try allocator.dupe(u8, nv.value));
            },
            2 => nonce_out.* = try readFixed64(nv.value),
            else => {},
        }
    }
}

fn decodeV2DialResponseInner(wire: []const u8, resp: *V2DialResponse) Error!void {
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, 16);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                const d = try proto.decodeVarUInt64(nv.value);
                resp.status = try decodeV2ResponseStatus(d.value);
            },
            2 => {
                const d = try proto.decodeVarUInt64(nv.value);
                resp.addr_idx = @intCast(d.value);
            },
            3 => {
                const d = try proto.decodeVarUInt64(nv.value);
                resp.dial_status = try decodeV2DialStatus(d.value);
            },
            else => {},
        }
    }
}

fn decodeV2DialDataRequestInner(wire: []const u8, req: *V2DialDataRequest) Error!void {
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, 16);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                const d = try proto.decodeVarUInt64(nv.value);
                req.addr_idx = @intCast(d.value);
            },
            2 => {
                const d = try proto.decodeVarUInt64(nv.value);
                req.num_bytes = d.value;
            },
            else => {},
        }
    }
}

fn decodeV2DialDataResponseInner(allocator: std.mem.Allocator, wire: []const u8, limits: Limits, data_out: *?[]u8) Error!void {
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, limits.max_dial_data_chunk_bytes);
        off += nv.total;
        if (key.field_number == 1) {
            if (data_out.*) |old| allocator.free(old);
            data_out.* = try allocator.dupe(u8, nv.value);
        }
    }
}

pub fn decodeV2DialBack(wire: []const u8) Error!V2DialBack {
    var nonce: u64 = 0;
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, 8);
        off += nv.total;
        if (key.field_number == 1 and key.wire_type == .fixed64) {
            nonce = try readFixed64(nv.value);
        }
    }
    return .{ .nonce = nonce };
}

pub fn decodeV2DialBackResponse(wire: []const u8) Error!V2DialBackResponse {
    var status: V2DialBackStatus = .ok;
    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, 8);
        off += nv.total;
        if (key.field_number == 1 and key.wire_type == .varint) {
            const d = try proto.decodeVarUInt64(nv.value);
            status = try decodeV2DialBackStatus(d.value);
        }
    }
    return .{ .status = status };
}

// ── length-prefixed framing ──────────────────────────────────────────────────

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

pub fn freeV1Owned(allocator: std.mem.Allocator, msg: V1Message) void {
    switch (msg) {
        .dial => |d| {
            if (d.peer_id) |p| allocator.free(p);
            for (d.addrs) |a| allocator.free(a);
            allocator.free(d.addrs);
        },
        .dial_response => |r| {
            if (r.status_text) |t| allocator.free(t);
            if (r.addr) |a| allocator.free(a);
        },
    }
}

pub fn freeV2RequestMessageOwned(allocator: std.mem.Allocator, msg: V2RequestMessage) void {
    switch (msg) {
        .dial_request => |dr| {
            for (dr.addrs) |a| allocator.free(a);
            allocator.free(dr.addrs);
        },
        .dial_data_response => |ddr| {
            if (ddr.data.len > 0) allocator.free(ddr.data);
        },
        else => {},
    }
}

test "v1 dial round trip" {
    const a = std.testing.allocator;
    const addrs = [_][]const u8{ "/ip4/1.2.3.4/udp/4001/quic-v1", "/ip4/5.6.7.8/tcp/4002" };
    const wire = try encodeV1(a, .{ .dial = .{ .peer_id = "peer", .addrs = &addrs } });
    defer a.free(wire);
    const decoded = try decodeV1Owned(a, wire, .standard);
    defer freeV1Owned(a, decoded);
    switch (decoded) {
        .dial => |d| {
            try std.testing.expectEqualStrings("peer", d.peer_id.?);
            try std.testing.expectEqual(@as(usize, 2), d.addrs.len);
        },
        else => try std.testing.expect(false),
    }
}

test "v2 dial request round trip" {
    const a = std.testing.allocator;
    const addrs = [_][]const u8{"/ip4/203.0.113.1/udp/4001/quic-v1"};
    const wire = try encodeV2RequestMessage(a, .{
        .dial_request = .{ .addrs = &addrs, .nonce = 0xDEADBEEFCAFEBABE },
    });
    defer a.free(wire);
    const decoded = try decodeV2RequestMessageOwned(a, wire, .standard);
    defer freeV2RequestMessageOwned(a, decoded);
    switch (decoded) {
        .dial_request => |dr| {
            try std.testing.expectEqual(@as(u64, 0xDEADBEEFCAFEBABE), dr.nonce);
            try std.testing.expectEqual(@as(usize, 1), dr.addrs.len);
        },
        else => try std.testing.expect(false),
    }
}
