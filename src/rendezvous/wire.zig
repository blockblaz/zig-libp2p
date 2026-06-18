//! Rendezvous protobuf wire codec and length-prefixed framing (#209).
//!
//! Spec: https://github.com/libp2p/specs/blob/master/rendezvous/README.md

const std = @import("std");
const Io = std.Io;
const proto = @import("../protobuf/wire.zig");
const varint = @import("../varint.zig");
const wall_time = @import("../wall_time.zig");

pub const protocol_line: []const u8 = "/rendezvous/1.0.0\n";
pub const protocol_id: []const u8 = std.mem.trimEnd(u8, protocol_line, "\n");

pub const default_ttl_s: u64 = 2 * 60 * 60;
pub const min_ttl_s: u64 = 2 * 60 * 60;
pub const max_ttl_s: u64 = 72 * 60 * 60;
pub const max_namespace_len: usize = 255;

pub const Error = proto.Error || error{
    MessageTooLarge,
    InvalidMessageType,
    InvalidResponseStatus,
    MissingRequiredField,
    TooManyRegistrations,
    InvalidCookie,
    InvalidNamespace,
} || std.mem.Allocator.Error;

pub const Limits = struct {
    max_frame_bytes: usize = 1024 * 1024,
    max_namespace_bytes: usize = max_namespace_len,
    max_signed_peer_record_bytes: usize = 8192,
    max_status_text_bytes: usize = 256,
    max_registrations_per_response: usize = 1000,

    pub const standard: Limits = .{};
};

pub const MessageType = enum(u32) {
    register = 0,
    register_response = 1,
    unregister = 2,
    discover = 3,
    discover_response = 4,
};

pub const ResponseStatus = enum(u32) {
    ok = 0,
    e_invalid_namespace = 100,
    e_invalid_signed_peer_record = 101,
    e_invalid_ttl = 102,
    e_invalid_cookie = 103,
    e_not_authorized = 200,
    e_internal_error = 300,
    e_unavailable = 400,
};

pub const RegisterView = struct {
    ns: ?[]const u8 = null,
    signed_peer_record: ?[]const u8 = null,
    ttl: ?u64 = null,
};

pub const RegisterOwned = struct {
    ns: ?[]u8 = null,
    signed_peer_record: ?[]u8 = null,
    ttl: ?u64 = null,

    pub fn deinit(self: *RegisterOwned, allocator: std.mem.Allocator) void {
        if (self.ns) |x| allocator.free(x);
        if (self.signed_peer_record) |x| allocator.free(x);
        self.* = .{};
    }
};

pub const RegisterResponseView = struct {
    status: ResponseStatus,
    status_text: ?[]const u8 = null,
    ttl: ?u64 = null,
};

pub const RegisterResponseOwned = struct {
    status: ResponseStatus,
    status_text: ?[]u8 = null,
    ttl: ?u64 = null,

    pub fn deinit(self: *RegisterResponseOwned, allocator: std.mem.Allocator) void {
        if (self.status_text) |x| allocator.free(x);
        self.* = .{ .status = .ok };
    }
};

pub const UnregisterView = struct {
    ns: ?[]const u8 = null,
};

pub const UnregisterOwned = struct {
    ns: ?[]u8 = null,

    pub fn deinit(self: *UnregisterOwned, allocator: std.mem.Allocator) void {
        if (self.ns) |x| allocator.free(x);
        self.* = .{};
    }
};

pub const DiscoverView = struct {
    ns: ?[]const u8 = null,
    limit: ?u64 = null,
    cookie: ?[]const u8 = null,
};

pub const DiscoverOwned = struct {
    ns: ?[]u8 = null,
    limit: ?u64 = null,
    cookie: ?[]u8 = null,

    pub fn deinit(self: *DiscoverOwned, allocator: std.mem.Allocator) void {
        if (self.ns) |x| allocator.free(x);
        if (self.cookie) |x| allocator.free(x);
        self.* = .{};
    }
};

pub const DiscoverResponseView = struct {
    registrations: []const RegisterView = &.{},
    cookie: ?[]const u8 = null,
    status: ?ResponseStatus = null,
    status_text: ?[]const u8 = null,
};

pub const DiscoverResponseOwned = struct {
    registrations: []RegisterOwned = &[_]RegisterOwned{},
    cookie: ?[]u8 = null,
    status: ?ResponseStatus = null,
    status_text: ?[]u8 = null,

    pub fn deinit(self: *DiscoverResponseOwned, allocator: std.mem.Allocator) void {
        for (self.registrations) |*r| r.deinit(allocator);
        allocator.free(self.registrations);
        if (self.cookie) |x| allocator.free(x);
        if (self.status_text) |x| allocator.free(x);
        self.* = .{ .registrations = &.{} };
    }
};

pub const MessageView = union(enum) {
    register: RegisterView,
    register_response: RegisterResponseView,
    unregister: UnregisterView,
    discover: DiscoverView,
    discover_response: DiscoverResponseView,
};

pub const MessageOwned = union(enum) {
    register: RegisterOwned,
    register_response: RegisterResponseOwned,
    unregister: UnregisterOwned,
    discover: DiscoverOwned,
    discover_response: DiscoverResponseOwned,

    pub fn deinit(self: *MessageOwned, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .register => |*r| r.deinit(allocator),
            .register_response => |*r| r.deinit(allocator),
            .unregister => |*r| r.deinit(allocator),
            .discover => |*r| r.deinit(allocator),
            .discover_response => |*r| r.deinit(allocator),
        }
        self.* = undefined;
    }
};

pub const Cookie = struct {
    id: u64,
    namespace: ?[]u8 = null,

    pub fn deinit(self: *Cookie, allocator: std.mem.Allocator) void {
        if (self.namespace) |x| allocator.free(x);
        self.* = .{ .id = 0 };
    }

    pub fn forNamespace(allocator: std.mem.Allocator, ns: []const u8) Error!Cookie {
        if (ns.len > max_namespace_len) return error.InvalidNamespace;
        var prng = std.Random.DefaultPrng.init(@intCast(@max(1, wall_time.unixTimestamp())));
        return .{
            .id = prng.random().int(u64),
            .namespace = try allocator.dupe(u8, ns),
        };
    }

    pub fn forAllNamespaces(_: std.mem.Allocator) Error!Cookie {
        var prng = std.Random.DefaultPrng.init(@intCast(@max(1, wall_time.unixTimestamp())));
        return .{ .id = prng.random().int(u64), .namespace = null };
    }

    pub fn encodeWire(self: *const Cookie, allocator: std.mem.Allocator) Error![]u8 {
        const ns_len = if (self.namespace) |n| n.len else 0;
        const out = try allocator.alloc(u8, 8 + ns_len);
        const id_be = std.mem.nativeToBig(u64, self.id);
        @memcpy(out[0..8], std.mem.asBytes(&id_be));
        if (self.namespace) |n| @memcpy(out[8..], n);
        return out;
    }

    pub fn decodeWire(allocator: std.mem.Allocator, wire_bytes: []const u8) Error!Cookie {
        if (wire_bytes.len < 8) return error.InvalidCookie;
        const id = std.mem.bigToNative(u64, @bitCast(wire_bytes[0..8].*));
        const ns_slice = wire_bytes[8..];
        if (ns_slice.len > max_namespace_len) return error.InvalidNamespace;
        return .{
            .id = id,
            .namespace = if (ns_slice.len > 0) try allocator.dupe(u8, ns_slice) else null,
        };
    }
};

fn decodeMessageType(v: u64) Error!MessageType {
    return switch (v) {
        0 => .register,
        1 => .register_response,
        2 => .unregister,
        3 => .discover,
        4 => .discover_response,
        else => error.InvalidMessageType,
    };
}

fn decodeResponseStatus(v: u64) Error!ResponseStatus {
    return switch (v) {
        0 => .ok,
        100 => .e_invalid_namespace,
        101 => .e_invalid_signed_peer_record,
        102 => .e_invalid_ttl,
        103 => .e_invalid_cookie,
        200 => .e_not_authorized,
        300 => .e_internal_error,
        400 => .e_unavailable,
        else => error.InvalidResponseStatus,
    };
}

pub fn validateNamespace(ns: []const u8) Error!void {
    if (ns.len == 0 or ns.len > max_namespace_len) return error.InvalidNamespace;
}

fn validateNamespaceInner(ns: []const u8) Error!void {
    return validateNamespace(ns);
}

fn encodeRegisterInner(list: *std.ArrayList(u8), allocator: std.mem.Allocator, reg: RegisterView) Error!void {
    if (reg.ns) |ns| {
        try validateNamespaceInner(ns);
        try proto.appendLengthDelimited(list, allocator, 1, ns);
    }
    if (reg.signed_peer_record) |spr| try proto.appendLengthDelimited(list, allocator, 2, spr);
    if (reg.ttl) |ttl| {
        try proto.appendFieldKey(list, allocator, 3, .varint);
        try proto.appendVarUInt64(list, allocator, ttl);
    }
}

pub fn encode(allocator: std.mem.Allocator, msg: MessageView) Error![]u8 {
    var list = std.ArrayList(u8).empty;
    errdefer list.deinit(allocator);

    switch (msg) {
        .register => |r| {
            try proto.appendFieldKey(&list, allocator, 1, .varint);
            try proto.appendVarUInt64(&list, allocator, @intFromEnum(MessageType.register));
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            try encodeRegisterInner(&inner, allocator, r);
            try proto.appendLengthDelimited(&list, allocator, 2, inner.items);
        },
        .register_response => |r| {
            try proto.appendFieldKey(&list, allocator, 1, .varint);
            try proto.appendVarUInt64(&list, allocator, @intFromEnum(MessageType.register_response));
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            try proto.appendFieldKey(&inner, allocator, 1, .varint);
            try proto.appendVarUInt64(&inner, allocator, @intFromEnum(r.status));
            if (r.status_text) |t| try proto.appendLengthDelimited(&inner, allocator, 2, t);
            if (r.ttl) |ttl| {
                try proto.appendFieldKey(&inner, allocator, 3, .varint);
                try proto.appendVarUInt64(&inner, allocator, ttl);
            }
            try proto.appendLengthDelimited(&list, allocator, 3, inner.items);
        },
        .unregister => |r| {
            try proto.appendFieldKey(&list, allocator, 1, .varint);
            try proto.appendVarUInt64(&list, allocator, @intFromEnum(MessageType.unregister));
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            if (r.ns) |ns| {
                try validateNamespaceInner(ns);
                try proto.appendLengthDelimited(&inner, allocator, 1, ns);
            }
            try proto.appendLengthDelimited(&list, allocator, 4, inner.items);
        },
        .discover => |d| {
            try proto.appendFieldKey(&list, allocator, 1, .varint);
            try proto.appendVarUInt64(&list, allocator, @intFromEnum(MessageType.discover));
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            if (d.ns) |ns| {
                try validateNamespaceInner(ns);
                try proto.appendLengthDelimited(&inner, allocator, 1, ns);
            }
            if (d.limit) |lim| {
                try proto.appendFieldKey(&inner, allocator, 2, .varint);
                try proto.appendVarUInt64(&inner, allocator, lim);
            }
            if (d.cookie) |c| try proto.appendLengthDelimited(&inner, allocator, 3, c);
            try proto.appendLengthDelimited(&list, allocator, 5, inner.items);
        },
        .discover_response => |d| {
            try proto.appendFieldKey(&list, allocator, 1, .varint);
            try proto.appendVarUInt64(&list, allocator, @intFromEnum(MessageType.discover_response));
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            for (d.registrations) |reg| {
                var reg_inner = std.ArrayList(u8).empty;
                defer reg_inner.deinit(allocator);
                try encodeRegisterInner(&reg_inner, allocator, reg);
                try proto.appendLengthDelimited(&inner, allocator, 1, reg_inner.items);
            }
            if (d.cookie) |c| try proto.appendLengthDelimited(&inner, allocator, 2, c);
            if (d.status) |st| {
                try proto.appendFieldKey(&inner, allocator, 3, .varint);
                try proto.appendVarUInt64(&inner, allocator, @intFromEnum(st));
            }
            if (d.status_text) |t| try proto.appendLengthDelimited(&inner, allocator, 4, t);
            try proto.appendLengthDelimited(&list, allocator, 6, inner.items);
        },
    }

    return try list.toOwnedSlice(allocator);
}

fn decodeRegisterOwned(allocator: std.mem.Allocator, wire_bytes: []const u8, limits: Limits) Error!RegisterOwned {
    var out: RegisterOwned = .{};
    var off: usize = 0;
    while (off < wire_bytes.len) {
        const key = try proto.decodeFieldKey(wire_bytes[off..]);
        off += key.len;
        const cap: usize = switch (key.field_number) {
            1 => limits.max_namespace_bytes,
            2 => limits.max_signed_peer_record_bytes,
            else => 8,
        };
        const nv = try proto.nextFieldValueLimited(wire_bytes[off..], key.wire_type, cap);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                if (out.ns != null) continue;
                out.ns = try allocator.dupe(u8, nv.value);
            },
            2 => {
                if (out.signed_peer_record != null) continue;
                out.signed_peer_record = try allocator.dupe(u8, nv.value);
            },
            3 => {
                const vv = try proto.decodeVarUInt64(nv.value);
                out.ttl = vv.value;
            },
            else => {},
        }
    }
    return out;
}

pub fn decodeOwned(allocator: std.mem.Allocator, wire_bytes: []const u8, limits: Limits) Error!MessageOwned {
    if (wire_bytes.len > limits.max_frame_bytes) return error.MessageTooLarge;

    var msg_type: ?MessageType = null;
    var register_bytes: ?[]const u8 = null;
    var register_response_bytes: ?[]const u8 = null;
    var unregister_bytes: ?[]const u8 = null;
    var discover_bytes: ?[]const u8 = null;
    var discover_response_bytes: ?[]const u8 = null;

    var off: usize = 0;
    while (off < wire_bytes.len) {
        const key = try proto.decodeFieldKey(wire_bytes[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire_bytes[off..], key.wire_type, limits.max_frame_bytes);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                const vv = try proto.decodeVarUInt64(nv.value);
                msg_type = try decodeMessageType(vv.value);
            },
            2 => register_bytes = nv.value,
            3 => register_response_bytes = nv.value,
            4 => unregister_bytes = nv.value,
            5 => discover_bytes = nv.value,
            6 => discover_response_bytes = nv.value,
            else => {},
        }
    }

    const mt = msg_type orelse return error.MissingRequiredField;
    return switch (mt) {
        .register => .{
            .register = try decodeRegisterOwned(allocator, register_bytes orelse return error.MissingRequiredField, limits),
        },
        .register_response => blk: {
            const inner = register_response_bytes orelse return error.MissingRequiredField;
            var out: RegisterResponseOwned = .{ .status = .e_internal_error };
            var ioff: usize = 0;
            while (ioff < inner.len) {
                const key = try proto.decodeFieldKey(inner[ioff..]);
                ioff += key.len;
                const nv = try proto.nextFieldValueLimited(inner[ioff..], key.wire_type, limits.max_status_text_bytes);
                ioff += nv.total;
                switch (key.field_number) {
                    1 => {
                        const vv = try proto.decodeVarUInt64(nv.value);
                        out.status = try decodeResponseStatus(vv.value);
                    },
                    2 => out.status_text = try allocator.dupe(u8, nv.value),
                    3 => {
                        const vv = try proto.decodeVarUInt64(nv.value);
                        out.ttl = vv.value;
                    },
                    else => {},
                }
            }
            break :blk .{ .register_response = out };
        },
        .unregister => blk: {
            const inner = unregister_bytes orelse return error.MissingRequiredField;
            var out: UnregisterOwned = .{};
            var ioff: usize = 0;
            while (ioff < inner.len) {
                const key = try proto.decodeFieldKey(inner[ioff..]);
                ioff += key.len;
                const nv = try proto.nextFieldValueLimited(inner[ioff..], key.wire_type, limits.max_namespace_bytes);
                ioff += nv.total;
                if (key.field_number == 1 and out.ns == null) out.ns = try allocator.dupe(u8, nv.value);
            }
            break :blk .{ .unregister = out };
        },
        .discover => blk: {
            const inner = discover_bytes orelse return error.MissingRequiredField;
            var out: DiscoverOwned = .{};
            var ioff: usize = 0;
            while (ioff < inner.len) {
                const key = try proto.decodeFieldKey(inner[ioff..]);
                ioff += key.len;
                const cap: usize = if (key.field_number == 3) limits.max_frame_bytes else limits.max_namespace_bytes;
                const nv = try proto.nextFieldValueLimited(inner[ioff..], key.wire_type, cap);
                ioff += nv.total;
                switch (key.field_number) {
                    1 => {
                        if (out.ns == null) out.ns = try allocator.dupe(u8, nv.value);
                    },
                    2 => {
                        const vv = try proto.decodeVarUInt64(nv.value);
                        out.limit = vv.value;
                    },
                    3 => {
                        if (out.cookie == null) out.cookie = try allocator.dupe(u8, nv.value);
                    },
                    else => {},
                }
            }
            break :blk .{ .discover = out };
        },
        .discover_response => blk: {
            const inner = discover_response_bytes orelse return error.MissingRequiredField;
            var regs = std.ArrayList(RegisterOwned).empty;
            errdefer {
                for (regs.items) |*r| r.deinit(allocator);
                regs.deinit(allocator);
            }
            var out: DiscoverResponseOwned = .{ .registrations = &.{} };
            var ioff: usize = 0;
            while (ioff < inner.len) {
                const key = try proto.decodeFieldKey(inner[ioff..]);
                ioff += key.len;
                const nv = try proto.nextFieldValueLimited(inner[ioff..], key.wire_type, limits.max_frame_bytes);
                ioff += nv.total;
                switch (key.field_number) {
                    1 => {
                        if (regs.items.len >= limits.max_registrations_per_response) return error.TooManyRegistrations;
                        try regs.append(allocator, try decodeRegisterOwned(allocator, nv.value, limits));
                    },
                    2 => out.cookie = try allocator.dupe(u8, nv.value),
                    3 => {
                        const vv = try proto.decodeVarUInt64(nv.value);
                        out.status = try decodeResponseStatus(vv.value);
                    },
                    4 => out.status_text = try allocator.dupe(u8, nv.value),
                    else => {},
                }
            }
            out.registrations = try regs.toOwnedSlice(allocator);
            break :blk .{ .discover_response = out };
        },
    };
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
        if (d.value > std.math.maxInt(usize)) return error.MessageTooLarge;
        const payload = try allocator.alloc(u8, @intCast(d.value));
        errdefer allocator.free(payload);
        var filled: usize = 0;
        while (filled < payload.len) {
            const n2 = try r.readSliceShort(payload[filled..]);
            if (n2 == 0) return error.Truncated;
            filled += n2;
        }
        return payload;
    }
    return error.Truncated;
}

test "cookie wire roundtrip matches rust layout" {
    const a = std.testing.allocator;
    var cookie = try Cookie.forNamespace(a, "foo");
    defer cookie.deinit(a);
    const wire_bytes = try cookie.encodeWire(a);
    defer a.free(wire_bytes);
    try std.testing.expectEqual(@as(usize, 11), wire_bytes.len);
    var parsed = try Cookie.decodeWire(a, wire_bytes);
    defer parsed.deinit(a);
    try std.testing.expectEqual(cookie.id, parsed.id);
    try std.testing.expectEqualStrings("foo", parsed.namespace.?);
}

test "register encode/decode roundtrip" {
    const a = std.testing.allocator;
    const spr = "signed-peer-record-blob";
    const bytes = try encode(a, .{
        .register = .{
            .ns = "my-app",
            .signed_peer_record = spr,
            .ttl = 7200,
        },
    });
    defer a.free(bytes);
    var msg = try decodeOwned(a, bytes, .standard);
    defer msg.deinit(a);
    try std.testing.expect(msg == .register);
    const reg = msg.register;
    try std.testing.expectEqualStrings("my-app", reg.ns.?);
    try std.testing.expectEqualStrings(spr, reg.signed_peer_record.?);
    try std.testing.expectEqual(@as(u64, 7200), reg.ttl.?);
}
