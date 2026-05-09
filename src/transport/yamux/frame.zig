//! Yamux v0 frame header codec (per [libp2p yamux spec](https://github.com/libp2p/specs/blob/master/yamux/yamux.md)).
//!
//! Wire layout (big-endian, fixed 12 bytes; payload follows for `data` frames):
//!
//! ```text
//! +------+------+------+------+
//! | ver  | type | flags (u16) |
//! +------+------+-------------+
//! |        stream_id (u32)    |
//! +---------------------------+
//! |        length    (u32)    |
//! +---------------------------+
//! ```
//!
//! Per-frame semantics:
//! * `data`           — `length` is payload byte count; `length` bytes follow header.
//! * `window_update`  — `length` is the *delta* added to the peer's recv window for `stream_id`.
//! * `ping`           — `length` is the opaque ping value; `flags.syn` request, `flags.ack` reply; `stream_id` MUST be 0.
//! * `go_away`        — `length` is the error-code; `stream_id` MUST be 0; no further frames may be sent.
//!
//! All multi-byte fields are network-order (big-endian).  We keep this module
//! free of allocator / I/O concerns so it can be unit-tested in isolation and
//! reused by both the session state machine and any wire-level fuzzers.

const std = @import("std");

/// Yamux protocol version we speak.  The libp2p profile pins this to `0`.
pub const protocol_version: u8 = 0;

/// Fixed wire size of the header (no payload).
pub const header_len: usize = 12;

/// Frame types as encoded in the second header byte.
pub const Type = enum(u8) {
    data = 0,
    window_update = 1,
    ping = 2,
    go_away = 3,

    pub fn fromByte(b: u8) FrameError!Type {
        return switch (b) {
            0 => .data,
            1 => .window_update,
            2 => .ping,
            3 => .go_away,
            else => error.UnknownType,
        };
    }
};

/// Bit flags stored in `flags` (big-endian u16) — only the low byte is used.
pub const Flags = packed struct(u16) {
    syn: bool = false, // 0x0001 — open new stream / start of measurement (ping)
    ack: bool = false, // 0x0002 — acknowledge SYN / reply to ping
    fin: bool = false, // 0x0004 — half-close the sending side of `stream_id`
    rst: bool = false, // 0x0008 — abort `stream_id` immediately, discard buffers
    /// Reserved bits — MUST be zero on send and ignored on receive (per spec
    /// §3.2 "All other flags are reserved for future use and MUST NOT be set").
    /// We *reject* unknown flag bits to surface protocol violations early
    /// rather than silently discarding bytes the peer thought we'd honour.
    _reserved: u12 = 0,

    pub fn fromU16(v: u16) FrameError!Flags {
        const f: Flags = @bitCast(v);
        if (f._reserved != 0) return error.UnknownFlag;
        return f;
    }

    pub fn toU16(self: Flags) u16 {
        return @bitCast(self);
    }
};

/// Yamux session-level error codes carried in `go_away.length`.
pub const GoAwayCode = enum(u32) {
    normal = 0,
    protocol_error = 1,
    internal_error = 2,
    _,

    pub fn toU32(self: GoAwayCode) u32 {
        return @intFromEnum(self);
    }

    pub fn fromU32(v: u32) GoAwayCode {
        return @enumFromInt(v);
    }
};

pub const FrameError = error{
    UnknownVersion,
    UnknownType,
    UnknownFlag,
    /// Header buffer shorter than `header_len`.
    Truncated,
    /// `length` exceeds the configured per-frame cap (mitigates allocation
    /// amplification on the receive side).
    PayloadTooLarge,
};

/// Decoded frame header.  Payload bytes (when `kind == .data`) live elsewhere
/// and are addressed by `(length, stream_id)`.
pub const Header = struct {
    kind: Type,
    flags: Flags,
    stream_id: u32,
    length: u32,

    /// Decode `buf[0..header_len]`.  `max_length` is the largest payload size
    /// the caller will accept on a `data` frame; pass `std.math.maxInt(u32)` to
    /// disable the check.  All other frame types use `length` as a small
    /// number (delta / ping value / go-away code) so they bypass the cap.
    pub fn parse(buf: []const u8, max_length: u32) FrameError!Header {
        if (buf.len < header_len) return error.Truncated;
        if (buf[0] != protocol_version) return error.UnknownVersion;
        const kind = try Type.fromByte(buf[1]);
        const flags = try Flags.fromU16(std.mem.readInt(u16, buf[2..4], .big));
        const stream_id = std.mem.readInt(u32, buf[4..8], .big);
        const length = std.mem.readInt(u32, buf[8..12], .big);
        if (kind == .data and length > max_length) return error.PayloadTooLarge;
        return .{ .kind = kind, .flags = flags, .stream_id = stream_id, .length = length };
    }

    /// Encode into the first `header_len` bytes of `buf`.
    pub fn encode(self: Header, buf: []u8) error{BufferTooSmall}!void {
        if (buf.len < header_len) return error.BufferTooSmall;
        buf[0] = protocol_version;
        buf[1] = @intFromEnum(self.kind);
        std.mem.writeInt(u16, buf[2..4], self.flags.toU16(), .big);
        std.mem.writeInt(u32, buf[4..8], self.stream_id, .big);
        std.mem.writeInt(u32, buf[8..12], self.length, .big);
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

test "Header.parse: data frame round-trip" {
    const t = std.testing;
    var buf: [header_len]u8 = undefined;
    const h = Header{
        .kind = .data,
        .flags = .{ .syn = true },
        .stream_id = 1,
        .length = 42,
    };
    try h.encode(&buf);
    try t.expectEqual(@as(u8, 0), buf[0]);
    try t.expectEqual(@as(u8, 0), buf[1]); // type=data
    const round = try Header.parse(&buf, 1024);
    try t.expectEqual(h.kind, round.kind);
    try t.expectEqual(@as(u32, 1), round.stream_id);
    try t.expectEqual(@as(u32, 42), round.length);
    try t.expect(round.flags.syn);
    try t.expect(!round.flags.ack);
}

test "Header.parse: rejects unknown version" {
    const t = std.testing;
    var buf: [header_len]u8 = [_]u8{0} ** header_len;
    buf[0] = 1; // bad version
    try t.expectError(FrameError.UnknownVersion, Header.parse(&buf, 1024));
}

test "Header.parse: rejects unknown type" {
    const t = std.testing;
    var buf: [header_len]u8 = [_]u8{0} ** header_len;
    buf[1] = 7; // bad type
    try t.expectError(FrameError.UnknownType, Header.parse(&buf, 1024));
}

test "Header.parse: rejects reserved flag bits" {
    const t = std.testing;
    var buf: [header_len]u8 = [_]u8{0} ** header_len;
    // Set bit 0x0010 — reserved.
    buf[2] = 0; // high byte
    buf[3] = 0x10; // low byte: reserved bit
    try t.expectError(FrameError.UnknownFlag, Header.parse(&buf, 1024));
}

test "Header.parse: rejects truncated input" {
    const t = std.testing;
    const buf: [header_len - 1]u8 = [_]u8{0} ** (header_len - 1);
    try t.expectError(FrameError.Truncated, Header.parse(&buf, 1024));
}

test "Header.parse: enforces max_length on data frames" {
    const t = std.testing;
    var buf: [header_len]u8 = [_]u8{0} ** header_len;
    std.mem.writeInt(u32, buf[8..12], 2048, .big); // length=2048
    try t.expectError(FrameError.PayloadTooLarge, Header.parse(&buf, 1024));
    // Other types: length is small semantic value, max_length skipped.
    buf[1] = @intFromEnum(Type.window_update);
    _ = try Header.parse(&buf, 1024);
}

test "Header.encode: returns BufferTooSmall on short buffer" {
    const t = std.testing;
    var buf: [header_len - 1]u8 = undefined;
    const h = Header{ .kind = .ping, .flags = .{}, .stream_id = 0, .length = 0 };
    try t.expectError(error.BufferTooSmall, h.encode(&buf));
}

test "Flags: SYN+ACK round-trip" {
    const t = std.testing;
    const f = Flags{ .syn = true, .ack = true };
    const round = try Flags.fromU16(f.toU16());
    try t.expect(round.syn and round.ack and !round.fin and !round.rst);
}

test "GoAwayCode: round-trip preserves unknown values" {
    const t = std.testing;
    try t.expectEqual(@as(u32, 0), GoAwayCode.normal.toU32());
    try t.expectEqual(@as(u32, 1), GoAwayCode.protocol_error.toU32());
    // Unknown codes pass through opaque.
    const c = GoAwayCode.fromU32(99);
    try t.expectEqual(@as(u32, 99), c.toU32());
}
