//! Minimal protobuf wire helpers (varints + length-delimited fields) for proto2
//! messages such as gossipsub `RPC`.

const std = @import("std");

pub const Error = error{
    Truncated,
    InvalidVarint,
    UnsupportedWireType,
    InvalidFieldNumber,
    /// Declared length-delimited payload is larger than the caller-supplied policy cap.
    LengthDelimitedTooLong,
    /// Declared length does not fit in `usize`, or `prefix + length` overflows `usize`.
    LengthDelimitedOverflow,
};

pub const WireType = enum(u3) {
    varint = 0,
    fixed64 = 1,
    length_delimited = 2,
    fixed32 = 5,
};

pub fn appendVarUInt64(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) std.mem.Allocator.Error!void {
    var v = value;
    while (v >= 0x80) {
        try list.append(allocator, @truncate((v & 0x7f) | 0x80));
        v >>= 7;
    }
    try list.append(allocator, @truncate(v));
}

pub fn decodeVarUInt64(buf: []const u8) Error!struct { value: u64, len: usize } {
    var s: u32 = 0;
    var x: u64 = 0;
    for (buf, 0..) |b, i| {
        if (i >= 10) return error.InvalidVarint;
        if (b < 0x80) {
            if (i == 9 and b > 1) return error.InvalidVarint;
            const v: u64 = b;
            return .{ .value = x | (v << @as(u6, @truncate(s))), .len = i + 1 };
        }
        const v: u64 = @as(u64, b & 0x7f);
        x |= v << @as(u6, @truncate(s));
        s += 7;
        if (s > 63) return error.InvalidVarint;
    }
    return error.Truncated;
}

pub fn appendFieldKey(list: *std.ArrayList(u8), allocator: std.mem.Allocator, field_number: u32, wire_type: WireType) std.mem.Allocator.Error!void {
    const key = (@as(u64, field_number) << 3) | @as(u64, @intFromEnum(wire_type));
    try appendVarUInt64(list, allocator, key);
}

pub fn appendLengthDelimited(list: *std.ArrayList(u8), allocator: std.mem.Allocator, field_number: u32, payload: []const u8) std.mem.Allocator.Error!void {
    try appendFieldKey(list, allocator, field_number, .length_delimited);
    try appendVarUInt64(list, allocator, @intCast(payload.len));
    try list.appendSlice(allocator, payload);
}

/// After a field key, `buf` starts at the value wire bytes. Returns the value
/// slice and total bytes consumed from `buf` (including length prefixes).
///
/// For `length_delimited`, only lengths representable as `usize` and a non-overflowing
/// end offset are accepted. Callers allocating from `value` should still enforce an
/// application-specific maximum via [`nextFieldValueLimited`].
pub fn nextFieldValue(buf: []const u8, wire_type: WireType) Error!struct { value: []const u8, total: usize } {
    return nextFieldValueLimited(buf, wire_type, std.math.maxInt(usize));
}

/// Like [`nextFieldValue`], but rejects `length_delimited` payloads whose declared
/// length is greater than `max_length_delimited` before indexing the buffer.
/// Other wire types ignore `max_length_delimited`.
pub fn nextFieldValueLimited(buf: []const u8, wire_type: WireType, max_length_delimited: usize) Error!struct { value: []const u8, total: usize } {
    return switch (wire_type) {
        .varint => blk: {
            const d = try decodeVarUInt64(buf);
            break :blk .{ .value = buf[0..d.len], .total = d.len };
        },
        .fixed64 => if (buf.len < 8) error.Truncated else .{ .value = buf[0..8], .total = 8 },
        .fixed32 => if (buf.len < 4) error.Truncated else .{ .value = buf[0..4], .total = 4 },
        .length_delimited => blk: {
            const ln = try decodeVarUInt64(buf);
            const len_u64 = ln.value;
            const n = std.math.cast(usize, len_u64) orelse return error.LengthDelimitedOverflow;
            if (n > max_length_delimited) return error.LengthDelimitedTooLong;
            const end = std.math.add(usize, ln.len, n) catch return error.LengthDelimitedOverflow;
            if (buf.len < end) return error.Truncated;
            break :blk .{ .value = buf[ln.len..end], .total = end };
        },
    };
}

pub fn decodeFieldKey(buf: []const u8) Error!struct { field_number: u32, wire_type: WireType, len: usize } {
    const dec = try decodeVarUInt64(buf);
    if (dec.value == 0) return error.InvalidFieldNumber;
    const field_number = @as(u32, @intCast(dec.value >> 3));
    if (field_number == 0) return error.InvalidFieldNumber;
    const wt = dec.value & 7;
    const wire_type: WireType = switch (wt) {
        0 => .varint,
        1 => .fixed64,
        2 => .length_delimited,
        5 => .fixed32,
        else => return error.UnsupportedWireType,
    };
    return .{ .field_number = field_number, .wire_type = wire_type, .len = dec.len };
}

test "varUInt64 round trip small values" {
    const a = std.testing.allocator;
    for ([_]u64{ 0, 1, 127, 128, 300, 0x7fff_ffff }) |v| {
        var list = std.ArrayList(u8).empty;
        defer list.deinit(a);
        try appendVarUInt64(&list, a, v);
        const dec = try decodeVarUInt64(list.items);
        try std.testing.expectEqual(v, dec.value);
        try std.testing.expectEqual(list.items.len, dec.len);
    }
}

test "nextFieldValueLimited length_delimited within cap" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).empty;
    defer list.deinit(a);
    try appendVarUInt64(&list, a, 4);
    try list.appendSlice(a, "abcd");
    const nv = try nextFieldValueLimited(list.items, .length_delimited, 16);
    try std.testing.expectEqualStrings("abcd", nv.value);
    try std.testing.expectEqual(@as(usize, 5), nv.total);
}

test "nextFieldValueLimited length_delimited rejects over cap" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).empty;
    defer list.deinit(a);
    try appendVarUInt64(&list, a, 10);
    try list.appendSlice(a, &[_]u8{0} ** 10);
    try std.testing.expectError(error.LengthDelimitedTooLong, nextFieldValueLimited(list.items, .length_delimited, 5));
}
