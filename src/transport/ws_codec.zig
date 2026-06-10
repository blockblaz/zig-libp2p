//! RFC 6455 WebSocket frame codec — buffer-only, no I/O.
//!
//! This is the low-level layer: parse a single frame out of a byte buffer,
//! or emit a single frame into one. Higher layers ([`ws_handshake`] for the
//! HTTP/1.1 upgrade, [`ws`] for the transport face) build on this.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc6455#section-5.2>.
//!
//! Wire shape per frame:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |F|R|R|R| op    |M| payload len |   extended payload length     |
//! |I|S|S|S| code  |A|             |   (16/64-bit, if needed)      |
//! |N|V|V|V|       |S|             |                               |
//! | |1|2|3|       |K|             |                               |
//! +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//! |                   masking-key (4 octets, if MASK=1)           |
//! +---------------------------------------------------------------+
//! |                        payload data                           |
//! +---------------------------------------------------------------+
//! ```
//!
//! Constraints we enforce (the libp2p `/ws` transport never strays beyond
//! these):
//! - RSV1/2/3 MUST be zero — we have no extensions negotiated.
//! - Client→server frames MUST be masked; server→client frames MUST NOT be.
//! - Control frames (close/ping/pong) MUST have payload ≤ 125 bytes and FIN=1.
//! - We accept fragmented data frames but the caller reassembles.

const std = @import("std");

/// Frame opcodes per §5.2.
pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    // 0x3–0x7 reserved for further non-control frames.
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
    // 0xb–0xf reserved for further control frames.
    _,

    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }
};

pub const Mask = [4]u8;

/// Decoded frame header. The payload itself is a borrowed slice of the input
/// buffer, never copied here.
pub const Header = struct {
    fin: bool,
    opcode: Opcode,
    /// 4-byte XOR mask, present iff this frame was sent by a client.
    mask: ?Mask,
    /// Total frame length on the wire = `header_bytes` + `payload_len`.
    header_bytes: usize,
    payload_len: u64,
};

pub const ParseError = error{
    /// Need more bytes; caller retries after reading more.
    Incomplete,
    /// RSV1/2/3 set or reserved opcode used.
    ReservedBitSet,
    /// Control frame with FIN=0 or payload > 125 bytes (§5.5).
    InvalidControlFrame,
    /// Payload length declared above `max_payload_len`.
    PayloadTooLarge,
    /// 7-bit length field used `127` (8-byte extended) but the top bit is set
    /// per §5.2: "the most significant bit MUST be 0".
    InvalidExtendedLength,
};

/// Parse exactly one frame from the head of `bytes`. Returns the decoded
/// `Header` and leaves the payload sitting at `bytes[header.header_bytes..][0..payload_len]`.
///
/// `max_payload_len` lets the caller reject oversized inbound frames before
/// allocating. Pick something sensible (libp2p stream payloads are tiny —
/// 1 MiB is generous).
pub fn parseHeader(bytes: []const u8, max_payload_len: u64) ParseError!Header {
    if (bytes.len < 2) return error.Incomplete;

    const b0 = bytes[0];
    const b1 = bytes[1];

    const fin = (b0 & 0x80) != 0;
    if ((b0 & 0x70) != 0) return error.ReservedBitSet; // RSV1/2/3
    const opcode_raw: u4 = @truncate(b0 & 0x0f);
    const opcode: Opcode = @enumFromInt(opcode_raw);

    // Reject reserved opcodes (3–7 non-control, b–f control).
    switch (opcode_raw) {
        0x0, 0x1, 0x2, 0x8, 0x9, 0xa => {},
        else => return error.ReservedBitSet,
    }

    const masked = (b1 & 0x80) != 0;
    const len7: u7 = @truncate(b1 & 0x7f);

    var cursor: usize = 2;
    var payload_len: u64 = undefined;
    switch (len7) {
        0...125 => payload_len = len7,
        126 => {
            if (bytes.len < cursor + 2) return error.Incomplete;
            payload_len = std.mem.readInt(u16, bytes[cursor..][0..2], .big);
            cursor += 2;
        },
        127 => {
            if (bytes.len < cursor + 8) return error.Incomplete;
            const v = std.mem.readInt(u64, bytes[cursor..][0..8], .big);
            // §5.2: "the most significant bit MUST be 0".
            if ((v & (@as(u64, 1) << 63)) != 0) return error.InvalidExtendedLength;
            payload_len = v;
            cursor += 8;
        },
    }

    if (opcode.isControl()) {
        if (!fin or payload_len > 125) return error.InvalidControlFrame;
    }
    if (payload_len > max_payload_len) return error.PayloadTooLarge;

    var mask: ?Mask = null;
    if (masked) {
        if (bytes.len < cursor + 4) return error.Incomplete;
        var m: Mask = undefined;
        @memcpy(m[0..], bytes[cursor..][0..4]);
        mask = m;
        cursor += 4;
    }

    // Don't require the whole payload to be present — only the header.
    return .{
        .fin = fin,
        .opcode = opcode,
        .mask = mask,
        .header_bytes = cursor,
        .payload_len = payload_len,
    };
}

/// XOR `data` with `mask`. Endpoints call this twice: once to mask before
/// send (client) and once to unmask on receive (server).
pub fn maskPayload(data: []u8, mask: Mask) void {
    for (data, 0..) |*b, i| {
        b.* ^= mask[i & 0x3];
    }
}

pub const FrameOptions = struct {
    fin: bool = true,
    opcode: Opcode,
    /// If non-null, this frame is masked with these bytes (and the payload
    /// is XOR'd in place by the caller's contract — `writeHeader` does NOT
    /// touch the payload).
    mask: ?Mask = null,
};

pub const WriteHeaderError = error{
    /// `out` is too small to hold the header.
    BufferTooSmall,
    InvalidControlFrame,
};

/// Append the frame header bytes to `out`. Returns the number of bytes
/// written. Caller follows up by writing the payload bytes (masked already
/// if `opts.mask` is set).
pub fn writeHeader(out: []u8, opts: FrameOptions, payload_len: u64) WriteHeaderError!usize {
    if (opts.opcode.isControl()) {
        if (!opts.fin or payload_len > 125) return error.InvalidControlFrame;
    }
    const need = headerSize(payload_len, opts.mask != null);
    if (out.len < need) return error.BufferTooSmall;

    var cursor: usize = 0;
    out[cursor] = (if (opts.fin) @as(u8, 0x80) else 0) | @intFromEnum(opts.opcode);
    cursor += 1;

    const mask_bit: u8 = if (opts.mask != null) 0x80 else 0;
    if (payload_len < 126) {
        out[cursor] = mask_bit | @as(u8, @intCast(payload_len));
        cursor += 1;
    } else if (payload_len <= 0xffff) {
        out[cursor] = mask_bit | 126;
        cursor += 1;
        std.mem.writeInt(u16, out[cursor..][0..2], @intCast(payload_len), .big);
        cursor += 2;
    } else {
        out[cursor] = mask_bit | 127;
        cursor += 1;
        std.mem.writeInt(u64, out[cursor..][0..8], payload_len, .big);
        cursor += 8;
    }
    if (opts.mask) |m| {
        @memcpy(out[cursor..][0..4], m[0..]);
        cursor += 4;
    }
    return cursor;
}

/// Returns the exact number of header bytes needed for a frame of
/// `payload_len` bytes with or without a mask. Useful so callers can size
/// their write buffers without trial-and-error.
pub fn headerSize(payload_len: u64, masked: bool) usize {
    var n: usize = 2;
    if (payload_len >= 126 and payload_len <= 0xffff) {
        n += 2;
    } else if (payload_len > 0xffff) {
        n += 8;
    }
    if (masked) n += 4;
    return n;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseHeader: minimal unmasked binary frame" {
    // FIN=1, opcode=binary, MASK=0, len=5, payload "hello".
    const bytes = [_]u8{ 0x82, 0x05, 'h', 'e', 'l', 'l', 'o' };
    const h = try parseHeader(&bytes, 1024);
    try testing.expect(h.fin);
    try testing.expectEqual(Opcode.binary, h.opcode);
    try testing.expect(h.mask == null);
    try testing.expectEqual(@as(usize, 2), h.header_bytes);
    try testing.expectEqual(@as(u64, 5), h.payload_len);
}

test "parseHeader: masked client frame" {
    const mask = Mask{ 0xa1, 0xb2, 0xc3, 0xd4 };
    var bytes = [_]u8{ 0x82, 0x83, mask[0], mask[1], mask[2], mask[3], 0xaa, 0xbb, 0xcc };
    const h = try parseHeader(&bytes, 1024);
    try testing.expect(h.mask != null);
    try testing.expectEqualSlices(u8, &mask, &h.mask.?);
    try testing.expectEqual(@as(usize, 6), h.header_bytes);
    try testing.expectEqual(@as(u64, 3), h.payload_len);
}

test "parseHeader: 16-bit extended length" {
    var bytes: [4]u8 = undefined;
    bytes[0] = 0x82;
    bytes[1] = 126;
    std.mem.writeInt(u16, bytes[2..4], 1000, .big);
    const h = try parseHeader(&bytes, 4096);
    try testing.expectEqual(@as(u64, 1000), h.payload_len);
    try testing.expectEqual(@as(usize, 4), h.header_bytes);
}

test "parseHeader: 64-bit extended length" {
    var bytes: [10]u8 = undefined;
    bytes[0] = 0x82;
    bytes[1] = 127;
    std.mem.writeInt(u64, bytes[2..10], 100_000, .big);
    const h = try parseHeader(&bytes, 200_000);
    try testing.expectEqual(@as(u64, 100_000), h.payload_len);
    try testing.expectEqual(@as(usize, 10), h.header_bytes);
}

test "parseHeader: 64-bit extended length with high bit rejected" {
    var bytes: [10]u8 = undefined;
    bytes[0] = 0x82;
    bytes[1] = 127;
    std.mem.writeInt(u64, bytes[2..10], @as(u64, 1) << 63, .big);
    try testing.expectError(error.InvalidExtendedLength, parseHeader(&bytes, std.math.maxInt(u64)));
}

test "parseHeader: incomplete returns error.Incomplete" {
    try testing.expectError(error.Incomplete, parseHeader(&[_]u8{}, 1024));
    try testing.expectError(error.Incomplete, parseHeader(&[_]u8{0x82}, 1024));
    // 16-bit length missing one byte.
    try testing.expectError(error.Incomplete, parseHeader(&[_]u8{ 0x82, 126, 0x03 }, 4096));
}

test "parseHeader: rejects RSV bits" {
    // RSV1 set.
    try testing.expectError(error.ReservedBitSet, parseHeader(&[_]u8{ 0xc2, 0x00 }, 1024));
}

test "parseHeader: rejects reserved opcodes" {
    // opcode 0x3 (reserved data frame).
    try testing.expectError(error.ReservedBitSet, parseHeader(&[_]u8{ 0x83, 0x00 }, 1024));
    // opcode 0xb (reserved control frame).
    try testing.expectError(error.ReservedBitSet, parseHeader(&[_]u8{ 0x8b, 0x00 }, 1024));
}

test "parseHeader: control frame with FIN=0 rejected" {
    // ping with FIN=0.
    try testing.expectError(error.InvalidControlFrame, parseHeader(&[_]u8{ 0x09, 0x00 }, 1024));
}

test "parseHeader: control frame with payload > 125 rejected" {
    // close with 16-bit length 200.
    var bytes: [4]u8 = undefined;
    bytes[0] = 0x88; // FIN=1, close
    bytes[1] = 126;
    std.mem.writeInt(u16, bytes[2..4], 200, .big);
    try testing.expectError(error.InvalidControlFrame, parseHeader(&bytes, 4096));
}

test "parseHeader: rejects oversized payload" {
    var bytes: [4]u8 = undefined;
    bytes[0] = 0x82;
    bytes[1] = 126;
    std.mem.writeInt(u16, bytes[2..4], 2048, .big);
    try testing.expectError(error.PayloadTooLarge, parseHeader(&bytes, 1024));
}

test "maskPayload: XOR is self-inverse" {
    const mask = Mask{ 0x11, 0x22, 0x33, 0x44 };
    var data = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    const expected: [5]u8 = data;
    maskPayload(&data, mask);
    try testing.expect(!std.mem.eql(u8, &expected, &data));
    maskPayload(&data, mask);
    try testing.expectEqualSlices(u8, &expected, &data);
}

test "writeHeader: round-trip with parseHeader" {
    const cases = [_]struct { payload_len: u64, masked: bool, opcode: Opcode }{
        .{ .payload_len = 0, .masked = false, .opcode = .text },
        .{ .payload_len = 5, .masked = true, .opcode = .binary },
        .{ .payload_len = 125, .masked = false, .opcode = .binary },
        .{ .payload_len = 126, .masked = false, .opcode = .binary },
        .{ .payload_len = 65535, .masked = true, .opcode = .binary },
        .{ .payload_len = 65536, .masked = false, .opcode = .binary },
        .{ .payload_len = 1_000_000, .masked = false, .opcode = .binary },
    };
    for (cases) |c| {
        const mask: ?Mask = if (c.masked) Mask{ 0xde, 0xad, 0xbe, 0xef } else null;
        var buf: [16]u8 = undefined;
        const n = try writeHeader(&buf, .{ .opcode = c.opcode, .mask = mask }, c.payload_len);
        try testing.expectEqual(headerSize(c.payload_len, c.masked), n);

        const h = try parseHeader(buf[0..n], c.payload_len + 1);
        try testing.expect(h.fin);
        try testing.expectEqual(c.opcode, h.opcode);
        try testing.expectEqual(c.payload_len, h.payload_len);
        try testing.expectEqual(c.masked, h.mask != null);
    }
}

test "writeHeader: rejects oversized control frame" {
    var buf: [16]u8 = undefined;
    try testing.expectError(
        error.InvalidControlFrame,
        writeHeader(&buf, .{ .opcode = .close }, 200),
    );
    try testing.expectError(
        error.InvalidControlFrame,
        writeHeader(&buf, .{ .opcode = .ping, .fin = false }, 0),
    );
}

test "writeHeader: rejects undersized buffer" {
    var buf: [1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writeHeader(&buf, .{ .opcode = .binary }, 5));
}

test "headerSize: matches writeHeader output" {
    try testing.expectEqual(@as(usize, 2), headerSize(0, false));
    try testing.expectEqual(@as(usize, 6), headerSize(5, true));
    try testing.expectEqual(@as(usize, 4), headerSize(126, false));
    try testing.expectEqual(@as(usize, 8), headerSize(126, true));
    try testing.expectEqual(@as(usize, 10), headerSize(65536, false));
    try testing.expectEqual(@as(usize, 14), headerSize(65536, true));
}
