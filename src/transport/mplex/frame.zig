//! Mplex (libp2p `/mplex/6.7.0`) frame codec.
//!
//! Wire format:
//!
//! ```text
//! +------------------+------------------+--------+
//! | header  (varint) | length  (varint) | data   |
//! +------------------+------------------+--------+
//! ```
//!
//! `header = (stream_id << 3) | flag`
//!
//! `flag` values (low 3 bits of the header varint):
//!
//! | value | meaning                                                |
//! |------:|--------------------------------------------------------|
//! | 0     | `new_stream`     — initiator opens a new stream        |
//! | 1     | `message_receiver` — receiver-side data                |
//! | 2     | `message_initiator` — initiator-side data              |
//! | 3     | `close_receiver`  — half-close from the receiver side  |
//! | 4     | `close_initiator` — half-close from the initiator side |
//! | 5     | `reset_receiver`  — abort from receiver side           |
//! | 6     | `reset_initiator` — abort from initiator side          |
//!
//! Frame `length` MUST NOT exceed the negotiated maximum (libp2p mplex spec
//! caps this at 1 MiB and it is hard-coded in every interop implementation).
//! `length` may legitimately be `0` for `close_*` / `reset_*` frames.
//!
//! Mplex has no flow control, no keep-alive, and no per-stream window —
//! framing is far simpler than Yamux but that means the transport itself is
//! responsible for back-pressure and DoS mitigation (we cap inbound bytes
//! per `Config.max_frame_payload`).

const std = @import("std");
const varint = @import("../../varint.zig");

/// Spec maximum payload, libp2p go-mplex / js-libp2p hard-coded value.
pub const default_max_frame_payload: u64 = 1024 * 1024;

/// Multistream-select id for negotiating mplex on top of a secured stream.
pub const multistream_protocol_id: []const u8 = "/mplex/6.7.0";

pub const Flag = enum(u8) {
    new_stream = 0,
    message_receiver = 1,
    message_initiator = 2,
    close_receiver = 3,
    close_initiator = 4,
    reset_receiver = 5,
    reset_initiator = 6,

    pub fn fromInt(v: u8) FrameError!Flag {
        return switch (v) {
            0 => .new_stream,
            1 => .message_receiver,
            2 => .message_initiator,
            3 => .close_receiver,
            4 => .close_initiator,
            5 => .reset_receiver,
            6 => .reset_initiator,
            else => error.UnknownFlag,
        };
    }

    /// True when the frame originates from the side that opened the stream.
    pub fn isInitiatorSide(self: Flag) bool {
        return switch (self) {
            .new_stream, .message_initiator, .close_initiator, .reset_initiator => true,
            else => false,
        };
    }

    pub fn isData(self: Flag) bool {
        return self == .message_initiator or self == .message_receiver;
    }

    pub fn isClose(self: Flag) bool {
        return self == .close_initiator or self == .close_receiver;
    }

    pub fn isReset(self: Flag) bool {
        return self == .reset_initiator or self == .reset_receiver;
    }
};

pub const FrameError = error{
    UnknownFlag,
    /// Header / length varint not a valid encoding.
    BadVarint,
    /// `length` exceeded the configured frame cap.
    PayloadTooLarge,
    /// Buffer ran out mid-frame; caller should keep accumulating bytes.
    Truncated,
    /// Header `stream_id` overflowed the 61-bit space (after shifting off 3
    /// flag bits).  Required to surface arithmetic safety problems.
    StreamIdOverflow,
};

pub const Header = struct {
    flag: Flag,
    stream_id: u64,
    length: u64,

    pub const ParseResult = struct {
        header: Header,
        consumed: usize,
    };

    /// Parse the header *and* length varints from the front of `bytes`.
    /// Returns `error.Truncated` when more bytes are needed (caller should
    /// accumulate and retry — this is the normal incremental case).  Returns
    /// `error.PayloadTooLarge` when `length > max_payload`.
    pub fn parse(bytes: []const u8, max_payload: u64) FrameError!ParseResult {
        const hd = decodeVarint(bytes) catch |err| return mapVarintErr(err);
        const flag_bits: u8 = @intCast(hd.value & 0x7);
        const flag = try Flag.fromInt(flag_bits);
        // `stream_id` is the upper bits.
        const stream_id = hd.value >> 3;

        if (bytes.len <= hd.len) return error.Truncated;
        const len_dec = decodeVarint(bytes[hd.len..]) catch |err| return mapVarintErr(err);
        if (len_dec.value > max_payload) return error.PayloadTooLarge;

        return .{
            .header = .{ .flag = flag, .stream_id = stream_id, .length = len_dec.value },
            .consumed = hd.len + len_dec.len,
        };
    }

    /// Encode header (no payload) into `out`, returning the byte count.
    /// `out` MUST be at least `2 * varint.max_encoding_bytes` long.
    pub fn encodeHeader(self: Header, out: []u8) error{BufferTooSmall}!usize {
        const need: usize = 2 * varint.max_encoding_bytes;
        if (out.len < need) return error.BufferTooSmall;
        // header word
        const overflow_check, const overflow = @shlWithOverflow(self.stream_id, 3);
        if (overflow != 0) return error.BufferTooSmall; // surfaced via type system
        const word = overflow_check | @intFromEnum(self.flag);
        // varint expects usize; on 64-bit zig that's u64.
        const word_us: usize = @intCast(word);
        const len_us: usize = @intCast(self.length);

        var hdr_scratch: [varint.max_encoding_bytes]u8 = undefined;
        var len_scratch: [varint.max_encoding_bytes]u8 = undefined;
        const hdr_bytes = varint.encodeToScratch(&hdr_scratch, word_us);
        const len_bytes = varint.encodeToScratch(&len_scratch, len_us);
        @memcpy(out[0..hdr_bytes.len], hdr_bytes);
        @memcpy(out[hdr_bytes.len .. hdr_bytes.len + len_bytes.len], len_bytes);
        return hdr_bytes.len + len_bytes.len;
    }
};

fn decodeVarint(bytes: []const u8) varint.DecodeError!struct { value: u64, len: usize } {
    const r = try varint.decode(bytes);
    return .{ .value = @intCast(r.value), .len = r.len };
}

fn mapVarintErr(err: varint.DecodeError) FrameError {
    return switch (err) {
        error.Truncated => error.Truncated,
        error.Overflow, error.TooLong, error.NonMinimal => error.BadVarint,
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const t = std.testing;

test "Header.parse: round-trip new_stream(id=5, len=0)" {
    var buf: [32]u8 = undefined;
    const h = Header{ .flag = .new_stream, .stream_id = 5, .length = 0 };
    const n = try h.encodeHeader(&buf);
    const r = try Header.parse(buf[0..n], default_max_frame_payload);
    try t.expectEqual(@as(u64, 5), r.header.stream_id);
    try t.expectEqual(Flag.new_stream, r.header.flag);
    try t.expectEqual(@as(u64, 0), r.header.length);
    try t.expectEqual(n, r.consumed);
}

test "Header.parse: round-trip message_initiator with payload length" {
    var buf: [32]u8 = undefined;
    const h = Header{ .flag = .message_initiator, .stream_id = 17, .length = 42 };
    const n = try h.encodeHeader(&buf);
    const r = try Header.parse(buf[0..n], default_max_frame_payload);
    try t.expectEqual(@as(u64, 17), r.header.stream_id);
    try t.expectEqual(Flag.message_initiator, r.header.flag);
    try t.expectEqual(@as(u64, 42), r.header.length);
}

test "Header.parse: rejects unknown flag" {
    // Flag 7 — reserved.
    const bytes = [_]u8{ 0x07, 0x00 }; // header=7 (sid=0, flag=7), length=0
    try t.expectError(FrameError.UnknownFlag, Header.parse(&bytes, default_max_frame_payload));
}

test "Header.parse: rejects oversize length" {
    // header=0 (new_stream, sid=0), length=2 MiB
    var buf: [32]u8 = undefined;
    const h = Header{ .flag = .message_initiator, .stream_id = 0, .length = 2 * 1024 * 1024 };
    const n = try h.encodeHeader(&buf);
    try t.expectError(FrameError.PayloadTooLarge, Header.parse(buf[0..n], default_max_frame_payload));
}

test "Header.parse: truncated header bytes return Truncated" {
    const bytes = [_]u8{0x80}; // varint continuation bit but no follow-up
    try t.expectError(FrameError.Truncated, Header.parse(&bytes, default_max_frame_payload));
}

test "Header.parse: truncated between header and length is Truncated" {
    // Encode just the header word for sid=1, flag=new_stream → byte 0x08
    // (1<<3 | 0). Drop the length varint entirely.
    const bytes = [_]u8{0x08};
    try t.expectError(FrameError.Truncated, Header.parse(&bytes, default_max_frame_payload));
}

test "Flag classifiers" {
    try t.expect(Flag.message_initiator.isInitiatorSide());
    try t.expect(!Flag.message_receiver.isInitiatorSide());
    try t.expect(Flag.message_initiator.isData());
    try t.expect(!Flag.close_initiator.isData());
    try t.expect(Flag.close_initiator.isClose());
    try t.expect(Flag.reset_receiver.isReset());
}
