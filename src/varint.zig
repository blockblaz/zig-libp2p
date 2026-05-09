//! Unsigned protobuf-style varints (same wire as multiformats unsigned varint
//! used in Zeam req/resp length prefixes).

const std = @import("std");

pub const max_encoding_bytes: usize = (@bitSizeOf(usize) + 6) / 7;

pub const DecodeError = error{
    Overflow,
    Truncated,
};

pub fn encodeToScratch(scratch: *[max_encoding_bytes]u8, value: usize) []const u8 {
    var v = value;
    var i: usize = 0;
    while (v >= 0x80) : (i += 1) {
        scratch[i] = @truncate((v & 0x7f) | 0x80);
        v >>= 7;
    }
    scratch[i] = @truncate(v);
    return scratch[0 .. i + 1];
}

/// Decode a length-delimited unsigned varint (Go `ReadUvarint` rules, max 10 bytes on 64-bit).
pub fn decode(bytes: []const u8) DecodeError!struct { value: usize, len: usize } {
    var x: usize = 0;
    var s: u32 = 0;
    for (bytes, 0..) |b, i| {
        if (i >= max_encoding_bytes) return error.Overflow;
        if (b < 0x80) {
            if (i == max_encoding_bytes - 1 and b > 1) return error.Overflow;
            const v = @as(usize, b);
            const sh: std.math.Log2Int(usize) = @truncate(s);
            const r = x | (v << sh);
            if (r < x) return error.Overflow;
            return .{ .value = r, .len = i + 1 };
        }
        const v = @as(usize, b & 0x7f);
        const sh: std.math.Log2Int(usize) = @truncate(s);
        const r = x | (v << sh);
        if (r < x) return error.Overflow;
        x = r;
        s += 7;
        if (s > @bitSizeOf(usize) - 1) return error.Overflow;
    }
    return error.Truncated;
}

test "encode decode round trip" {
    var scratch: [max_encoding_bytes]u8 = undefined;
    for ([_]usize{ 0, 1, 127, 128, 16383, 16384, 1 << 40 }) |v| {
        const enc = encodeToScratch(&scratch, v);
        const dec = try decode(enc);
        try std.testing.expectEqual(v, dec.value);
        try std.testing.expectEqual(enc.len, dec.len);
    }
}

test "decode rejects overlong encoding" {
    const bad = [_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02 };
    try std.testing.expectError(error.Overflow, decode(&bad));
}
