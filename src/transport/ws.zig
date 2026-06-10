//! libp2p WebSocket transport (`/ws`) — RFC 6455 framing on top of TCP.
//!
//! Why this lives in the transport layer:
//! `/ws` is just a thin wrapper that turns a TCP byte stream into a
//! frame stream after an HTTP/1.1 upgrade. The libp2p layers stacked on
//! top of it — multistream-select, Noise / TLS, the muxer — see the
//! wrapped stream the same way they see a raw `net.Stream`.
//!
//! This module exposes:
//! - [`Stream`]: a `Io.Reader`/`Io.Writer` pair that frames inbound /
//!   outbound bytes as WebSocket binary frames automatically. Inbound
//!   reassembles fragmented data frames and handles ping/pong/close
//!   control frames silently.
//! - [`dialUpgrade`]: client-side upgrade over a connected `net.Stream`.
//! - [`acceptUpgrade`]: server-side upgrade over an accepted `net.Stream`.
//!
//! The pure-TLS variant (`/wss`) is intentionally out of scope here — it
//! re-uses [`tcp_tls`](./tcp_tls.zig) to upgrade the socket to TLS, then
//! wraps the secure stream with this same [`Stream`]. See #94 for the
//! follow-up issue.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

const ws_codec = @import("ws_codec.zig");
const ws_handshake = @import("ws_handshake.zig");

/// Multiaddr token. Mirrors `/quic-v1`, `/tls/1.0.0`, `/tcp` style strings.
pub const multistream_protocol_id: []const u8 = "/ws";

/// Multiaddr `/ws` component tag (per <https://github.com/multiformats/multicodec/blob/master/table.csv>).
/// Embedders pin the same constant so parser and printer agree.
pub const multicodec: u32 = 0x01dd;

pub const Role = enum { client, server };

/// Hard upper bound for a single inbound frame's payload. Caller can raise
/// it on construction; this default matches the libp2p req/resp typical
/// frame ceiling and is generous for gossipsub / identify.
pub const default_max_frame_payload: usize = 1 * 1024 * 1024;

pub const StreamOptions = struct {
    role: Role,
    max_frame_payload: usize = default_max_frame_payload,
    /// Masking-bytes source. Client frames MUST be masked (§5.3); the
    /// caller threads a CSPRNG (typically via `Io.Threaded.rng()` or
    /// `std.Random.DefaultCsprng`). Tests pass a deterministic stub.
    /// Servers don't mask outbound frames, so any value (even an unseeded
    /// `std.Random{}`) is fine for them.
    random: std.Random,
};

/// Frame-by-frame read/write adapter on top of a paired (Reader, Writer).
///
/// One read call returns the next complete data-message payload (binary or
/// text, fragments reassembled). One write call emits exactly one binary
/// frame. Control frames are handled transparently:
/// - `ping` → reply with `pong` carrying the same payload.
/// - `pong` → drop.
/// - `close` → set [`closed`] and surface `error.EndOfStream` on subsequent
///   reads; caller is responsible for echoing a close frame and tearing
///   the underlying transport down.
pub const Stream = struct {
    role: Role,
    reader: *Io.Reader,
    writer: *Io.Writer,
    max_frame_payload: usize,
    random: std.Random,
    /// Set once a close frame has been observed (inbound) or sent
    /// (outbound). Further reads/writes are rejected.
    closed: bool = false,

    pub const ReadError = error{
        /// Peer-side framing was malformed (RSV set, reserved opcode,
        /// invalid control frame, etc.).
        Malformed,
        /// Inbound frame exceeded `max_frame_payload`.
        FrameTooLarge,
        /// Server received an unmasked client frame, or client received a
        /// masked server frame (§5.1).
        MaskingViolation,
        /// Caller's `out` buffer too small to hold the assembled message.
        BufferTooSmall,
        /// Peer sent a close frame; no further payload is available.
        EndOfStream,
        ReadFailed,
        WriteFailed,
    };

    pub const WriteError = error{
        Closed,
        WriteFailed,
    };

    /// Read the next data-message payload into `out`. Returns the number of
    /// bytes consumed. Spins past any number of control frames the peer
    /// interleaves before the next data message.
    pub fn read(self: *Stream, out: []u8) ReadError!usize {
        if (self.closed) return error.EndOfStream;
        var total: usize = 0;
        var saw_first: bool = false;
        while (true) {
            const h = try self.readHeader();
            switch (h.opcode) {
                .ping => {
                    // Echo as pong (§5.5.2). Read payload, mask it back if
                    // necessary, then write a pong frame with the same body.
                    var pong_buf: [125]u8 = undefined;
                    const n = try self.readPayload(h, pong_buf[0..h.payload_len]);
                    self.writeControl(.pong, pong_buf[0..n]) catch return error.WriteFailed;
                    continue;
                },
                .pong => {
                    // Drop. Spec allows unsolicited pongs as keepalive.
                    var sink: [125]u8 = undefined;
                    _ = try self.readPayload(h, sink[0..h.payload_len]);
                    continue;
                },
                .close => {
                    var sink: [125]u8 = undefined;
                    _ = try self.readPayload(h, sink[0..h.payload_len]);
                    self.closed = true;
                    return error.EndOfStream;
                },
                .continuation, .binary, .text => {
                    if (h.opcode == .continuation and !saw_first) return error.Malformed;
                    if (h.opcode != .continuation and saw_first) return error.Malformed;
                    saw_first = true;
                    if (total + h.payload_len > out.len) return error.BufferTooSmall;
                    const dst = out[total..][0..h.payload_len];
                    _ = try self.readPayload(h, dst);
                    total += h.payload_len;
                    if (h.fin) return total;
                },
                else => return error.Malformed,
            }
        }
    }

    /// Emit one binary frame with `payload`. The frame is masked iff this
    /// stream's role is `client` (§5.3).
    pub fn writeBinary(self: *Stream, payload: []const u8) WriteError!void {
        if (self.closed) return error.Closed;
        self.writeDataFrame(.binary, payload) catch return error.WriteFailed;
    }

    /// Emit a close frame and flag this stream as closed. Caller still has
    /// to close the underlying transport.
    pub fn close(self: *Stream) WriteError!void {
        if (self.closed) return;
        self.writeControl(.close, &[_]u8{}) catch return error.WriteFailed;
        self.closed = true;
    }

    // ── private ──────────────────────────────────────────────────────────

    fn readHeader(self: *Stream) ReadError!ws_codec.Header {
        // Peek-and-toss: ask the reader for incrementally more bytes until
        // parseHeader succeeds, then consume exactly `header.header_bytes`
        // off the reader's seek position. Reading more than the header
        // upfront would swallow payload bytes meant for [`readPayload`].
        var n: usize = 2;
        while (true) {
            const peeked = self.reader.peekGreedy(n) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                error.ReadFailed => return error.ReadFailed,
            };
            const result = ws_codec.parseHeader(peeked, @intCast(self.max_frame_payload));
            if (result) |h| {
                self.reader.toss(h.header_bytes);
                self.validateMasking(h) catch |e| return e;
                return h;
            } else |err| switch (err) {
                error.Incomplete => {
                    // Bump n by one byte and retry. The longest possible
                    // header is 14 bytes (2 + 8-byte extended length +
                    // 4-byte mask).
                    if (n >= 14) return error.Malformed;
                    n += 1;
                },
                error.PayloadTooLarge => return error.FrameTooLarge,
                error.ReservedBitSet, error.InvalidControlFrame, error.InvalidExtendedLength => return error.Malformed,
            }
        }
    }

    fn validateMasking(self: *Stream, h: ws_codec.Header) error{MaskingViolation}!void {
        switch (self.role) {
            .server => if (h.mask == null) return error.MaskingViolation,
            .client => if (h.mask != null) return error.MaskingViolation,
        }
    }

    /// Read exactly `dst.len == payload_len` bytes off the wire, unmasking
    /// in place if necessary.
    fn readPayload(self: *Stream, h: ws_codec.Header, dst: []u8) ReadError!usize {
        self.reader.readSliceAll(dst) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
        };
        if (h.mask) |m| ws_codec.maskPayload(dst, m);
        return dst.len;
    }

    fn writeDataFrame(self: *Stream, opcode: ws_codec.Opcode, payload: []const u8) !void {
        const mask: ?ws_codec.Mask = if (self.role == .client) blk: {
            var m: ws_codec.Mask = undefined;
            self.random.bytes(m[0..]);
            break :blk m;
        } else null;

        var hdr_buf: [14]u8 = undefined;
        const hdr_n = try ws_codec.writeHeader(&hdr_buf, .{
            .opcode = opcode,
            .mask = mask,
        }, @intCast(payload.len));
        try self.writer.writeAll(hdr_buf[0..hdr_n]);

        if (payload.len == 0) {
            try self.writer.flush();
            return;
        }
        if (mask) |m| {
            // Mask in a scratch copy so we don't corrupt the caller's bytes.
            // Reuse a small stack buffer in 1 KiB chunks for big payloads.
            var chunk_buf: [1024]u8 = undefined;
            var off: usize = 0;
            var counter: usize = 0;
            while (off < payload.len) {
                const n = @min(chunk_buf.len, payload.len - off);
                @memcpy(chunk_buf[0..n], payload[off..][0..n]);
                // mask is XORed with a 4-byte rolling key; offset matters.
                var rolling: ws_codec.Mask = m;
                if ((counter & 0x3) != 0) {
                    // shift mask so chunk i continues the same XOR pattern.
                    var shifted: ws_codec.Mask = undefined;
                    for (0..4) |i| shifted[i] = m[(i + counter) & 0x3];
                    rolling = shifted;
                }
                ws_codec.maskPayload(chunk_buf[0..n], rolling);
                try self.writer.writeAll(chunk_buf[0..n]);
                off += n;
                counter += n;
            }
        } else {
            try self.writer.writeAll(payload);
        }
        try self.writer.flush();
    }

    fn writeControl(self: *Stream, opcode: ws_codec.Opcode, payload: []const u8) !void {
        if (!opcode.isControl()) unreachable;
        try self.writeDataFrame(opcode, payload);
    }
};

pub fn newStream(opts: StreamOptions, reader: *Io.Reader, writer: *Io.Writer) Stream {
    return .{
        .role = opts.role,
        .reader = reader,
        .writer = writer,
        .max_frame_payload = opts.max_frame_payload,
        .random = opts.random,
    };
}

// ── HTTP/1.1 upgrade over (Reader, Writer) ──────────────────────────────

pub const HandshakeError = error{
    BufferTooSmall,
    Malformed,
    UpstreamRead,
    UpstreamWrite,
    HandshakeFailed,
    Incomplete,
};

/// Run the client side of the upgrade: send `GET / HTTP/1.1` with a fresh
/// 16-byte nonce, read the server's `101 Switching Protocols`, verify
/// `Sec-WebSocket-Accept`. On success, the caller wraps the same reader /
/// writer in [`Stream`].
pub fn dialUpgrade(
    reader: *Io.Reader,
    writer: *Io.Writer,
    host: []const u8,
    path: []const u8,
    nonce_source: ?std.Random,
) HandshakeError!void {
    var nonce: [16]u8 = undefined;
    (nonce_source orelse std.crypto.random).bytes(&nonce);

    var key_b64: [ws_handshake.key_b64_len]u8 = undefined;
    ws_handshake.encodeKeyB64(nonce, &key_b64);

    var req_buf: [512]u8 = undefined;
    const req_n = ws_handshake.writeClientRequest(&req_buf, host, path, &key_b64) catch |e| switch (e) {
        error.BufferTooSmall => return error.BufferTooSmall,
        else => return error.Malformed,
    };
    writer.writeAll(req_buf[0..req_n]) catch return error.UpstreamWrite;
    writer.flush() catch return error.UpstreamWrite;

    var resp_buf: [1024]u8 = undefined;
    const resp_slice = try readHttpHeader(reader, &resp_buf);
    ws_handshake.parseAndVerifyServerResponse(resp_slice, &key_b64) catch |e| switch (e) {
        error.Incomplete => return error.Incomplete,
        error.HandshakeFailed, error.BadStartLine, error.BadHeader, error.MissingOrInvalidHeader => return error.HandshakeFailed,
        else => return error.HandshakeFailed,
    };
}

/// Run the server side of the upgrade: read the client request, send back
/// `101 Switching Protocols` with the computed `Sec-WebSocket-Accept`. On
/// success, caller wraps `reader` / `writer` in [`Stream`].
pub fn acceptUpgrade(reader: *Io.Reader, writer: *Io.Writer) HandshakeError!void {
    var req_buf: [1024]u8 = undefined;
    const req_slice = try readHttpHeader(reader, &req_buf);
    const upgrade = ws_handshake.parseClientRequest(req_slice) catch |e| switch (e) {
        error.Incomplete => return error.Incomplete,
        error.HandshakeFailed, error.BadStartLine, error.BadHeader, error.MissingOrInvalidHeader => return error.HandshakeFailed,
        else => return error.HandshakeFailed,
    };

    var resp_buf: [256]u8 = undefined;
    const resp_n = ws_handshake.writeServerResponse(&resp_buf, upgrade.sec_websocket_key) catch return error.HandshakeFailed;
    writer.writeAll(resp_buf[0..resp_n]) catch return error.UpstreamWrite;
    writer.flush() catch return error.UpstreamWrite;
}

/// Read until we see the `\r\n\r\n` end-of-headers marker. Returns the
/// slice up to (and including) the marker; bytes past it stay in the
/// reader's buffer for the caller to drain.
fn readHttpHeader(reader: *Io.Reader, out: []u8) HandshakeError![]const u8 {
    var have: usize = 0;
    while (true) {
        const got = reader.readSliceShort(out[have..]) catch return error.UpstreamRead;
        if (got == 0) return error.Incomplete;
        have += got;
        if (std.mem.indexOf(u8, out[0..have], "\r\n\r\n")) |end| {
            return out[0 .. end + 4];
        }
        if (have == out.len) return error.BufferTooSmall;
    }
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

const FixedRandom = struct {
    bytes_: []const u8,
    cursor: usize = 0,

    fn fill(self_op: *anyopaque, out: []u8) void {
        const self: *FixedRandom = @ptrCast(@alignCast(self_op));
        for (out) |*b| {
            b.* = self.bytes_[self.cursor % self.bytes_.len];
            self.cursor += 1;
        }
    }
    fn random(self: *FixedRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

test "Stream: client→server binary round-trip via in-memory buffers" {
    // Client writes 'hello' as masked binary; server reads & assembles.
    var c2s_buf: [256]u8 = undefined;
    var c2s_w = Io.Writer.fixed(c2s_buf[0..]);

    var fr = FixedRandom{ .bytes_ = &[_]u8{ 0xa1, 0xb2, 0xc3, 0xd4 } };
    var dummy_reader_buf: [0]u8 = undefined;
    var dummy_reader = Io.Reader.fixed(dummy_reader_buf[0..]);
    var client = newStream(.{
        .role = .client,
        .random = fr.random(),
    }, &dummy_reader, &c2s_w);
    try client.writeBinary("hello");

    // Server side: feed `c2s_w.buffered()` to a reader and let Stream.read
    // pull the message.
    const wire = c2s_w.buffered();
    var s_reader = Io.Reader.fixed(wire);

    var dummy_writer_buf: [0]u8 = undefined;
    var dummy_writer = Io.Writer.fixed(dummy_writer_buf[0..]);
    var server = newStream(.{ .role = .server, .random = fr.random() }, &s_reader, &dummy_writer);
    var out: [16]u8 = undefined;
    const n = try server.read(&out);
    try testing.expectEqualStrings("hello", out[0..n]);
}

test "Stream: server→client unmasked binary" {
    var fr = FixedRandom{ .bytes_ = &[_]u8{0} };
    var s2c_buf: [256]u8 = undefined;
    var s2c_w = Io.Writer.fixed(s2c_buf[0..]);
    var nonce_reader_buf: [0]u8 = undefined;
    var nonce_reader = Io.Reader.fixed(nonce_reader_buf[0..]);
    var server = newStream(.{ .role = .server, .random = fr.random() }, &nonce_reader, &s2c_w);
    try server.writeBinary("world");

    var c_reader = Io.Reader.fixed(s2c_w.buffered());
    var dummy_writer_buf: [0]u8 = undefined;
    var dummy_writer = Io.Writer.fixed(dummy_writer_buf[0..]);
    var client = newStream(.{ .role = .client, .random = fr.random() }, &c_reader, &dummy_writer);
    var out: [16]u8 = undefined;
    const n = try client.read(&out);
    try testing.expectEqualStrings("world", out[0..n]);
}

test "Stream: client read rejects unmasked frame (server-shape from peer)" {
    // Frame fashioned as if a server sent it (unmasked) but the receiving
    // role is also client — masking-violation.
    const bytes = [_]u8{ 0x82, 0x03, 'x', 'y', 'z' };
    var r = Io.Reader.fixed(&bytes);
    var w_buf: [0]u8 = undefined;
    var w = Io.Writer.fixed(w_buf[0..]);
    var fr_ = FixedRandom{ .bytes_ = &[_]u8{0} };
    var s = newStream(.{ .role = .server, .random = fr_.random() }, &r, &w);
    var out: [8]u8 = undefined;
    try testing.expectError(error.MaskingViolation, s.read(&out));
}

test "Stream: ping is echoed as pong with same payload" {
    // Server receives a masked ping with payload 'pi', should respond with
    // an unmasked pong carrying 'pi'.
    var ping_buf: [8]u8 = undefined;
    ping_buf[0] = 0x89; // FIN=1, ping
    ping_buf[1] = 0x82; // MASK=1, len=2
    const mask: ws_codec.Mask = .{ 0x11, 0x22, 0x33, 0x44 };
    @memcpy(ping_buf[2..6], mask[0..]);
    ping_buf[6] = 'p' ^ mask[0];
    ping_buf[7] = 'i' ^ mask[1];

    // Need a follow-on binary frame so server.read() has something to
    // return after handling the ping (otherwise it would loop on EOF).
    var follow_buf: [9]u8 = undefined;
    follow_buf[0] = 0x82; // FIN=1, binary
    follow_buf[1] = 0x83; // MASK=1, len=3
    @memcpy(follow_buf[2..6], mask[0..]);
    follow_buf[6] = 'a' ^ mask[0];
    follow_buf[7] = 'b' ^ mask[1];
    follow_buf[8] = 'c' ^ mask[2];

    var combined: [17]u8 = undefined;
    @memcpy(combined[0..8], ping_buf[0..]);
    @memcpy(combined[8..17], follow_buf[0..]);
    var r = Io.Reader.fixed(&combined);

    var out_buf: [64]u8 = undefined;
    var w = Io.Writer.fixed(out_buf[0..]);
    var fr_ = FixedRandom{ .bytes_ = &[_]u8{0} };
    var s = newStream(.{ .role = .server, .random = fr_.random() }, &r, &w);
    var out: [8]u8 = undefined;
    const n = try s.read(&out);
    try testing.expectEqualStrings("abc", out[0..n]);
    // Pong frame on the wire: FIN=1, opcode=pong, no mask, len=2, "pi".
    try testing.expectEqualSlices(u8, &[_]u8{ 0x8a, 0x02, 'p', 'i' }, w.buffered());
}

test "Stream: close surfaces EndOfStream" {
    // Server receives a close frame followed by nothing.
    var close_buf: [6]u8 = undefined;
    close_buf[0] = 0x88; // FIN=1, close
    close_buf[1] = 0x80; // MASK=1, len=0
    const mask: ws_codec.Mask = .{ 0, 0, 0, 0 };
    @memcpy(close_buf[2..6], mask[0..]);

    var r = Io.Reader.fixed(&close_buf);
    var w_buf: [0]u8 = undefined;
    var w = Io.Writer.fixed(w_buf[0..]);
    var fr_ = FixedRandom{ .bytes_ = &[_]u8{0} };
    var s = newStream(.{ .role = .server, .random = fr_.random() }, &r, &w);
    var out: [8]u8 = undefined;
    try testing.expectError(error.EndOfStream, s.read(&out));
    try testing.expect(s.closed);
}

test "Stream: fragmented data frames reassembled" {
    const mask: ws_codec.Mask = .{ 0x10, 0x20, 0x30, 0x40 };
    // Two fragments: binary FIN=0 "he" then continuation FIN=1 "llo".
    var frame1: [8]u8 = undefined;
    frame1[0] = 0x02; // FIN=0, binary
    frame1[1] = 0x82; // MASK=1, len=2
    @memcpy(frame1[2..6], mask[0..]);
    frame1[6] = 'h' ^ mask[0];
    frame1[7] = 'e' ^ mask[1];

    var frame2: [9]u8 = undefined;
    frame2[0] = 0x80; // FIN=1, continuation
    frame2[1] = 0x83; // MASK=1, len=3
    @memcpy(frame2[2..6], mask[0..]);
    frame2[6] = 'l' ^ mask[0];
    frame2[7] = 'l' ^ mask[1];
    frame2[8] = 'o' ^ mask[2];

    var combined: [17]u8 = undefined;
    @memcpy(combined[0..8], frame1[0..]);
    @memcpy(combined[8..17], frame2[0..]);
    var r = Io.Reader.fixed(&combined);
    var w_buf: [0]u8 = undefined;
    var w = Io.Writer.fixed(w_buf[0..]);
    var fr_ = FixedRandom{ .bytes_ = &[_]u8{0} };
    var s = newStream(.{ .role = .server, .random = fr_.random() }, &r, &w);
    var out: [16]u8 = undefined;
    const n = try s.read(&out);
    try testing.expectEqualStrings("hello", out[0..n]);
}

test "dialUpgrade + acceptUpgrade staged round-trip via paired buffers" {
    // True round-trip requires concurrent I/O (client sends → server reads
    // → server sends → client reads). With in-memory buffers we stage it:
    // build the client request, hand it to acceptUpgrade, then verify the
    // server's response by parsing it with the same key.
    var fr = FixedRandom{ .bytes_ = &[_]u8{ 0xde, 0xad, 0xbe, 0xef } };

    var nonce: [16]u8 = undefined;
    fr.random().bytes(&nonce);
    var key_b64: [ws_handshake.key_b64_len]u8 = undefined;
    ws_handshake.encodeKeyB64(nonce, &key_b64);

    var c2s_buf: [1024]u8 = undefined;
    var c2s_w = Io.Writer.fixed(c2s_buf[0..]);
    var req_buf: [512]u8 = undefined;
    const req_n = try ws_handshake.writeClientRequest(&req_buf, "x.example", "/", &key_b64);
    try c2s_w.writeAll(req_buf[0..req_n]);

    var s2c_buf: [1024]u8 = undefined;
    var s2c_w = Io.Writer.fixed(s2c_buf[0..]);
    var s_reader = Io.Reader.fixed(c2s_w.buffered());
    try acceptUpgrade(&s_reader, &s2c_w);

    try ws_handshake.parseAndVerifyServerResponse(s2c_w.buffered(), &key_b64);
}
