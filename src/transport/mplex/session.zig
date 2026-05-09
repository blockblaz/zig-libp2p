//! Mplex (`/mplex/6.7.0`) session — pure-Zig, allocator-driven, I/O-free.
//!
//! ## Architecture
//!
//! Mirror of `transport/yamux/session.zig` with a much smaller blast radius
//! since mplex has no flow control or keep-alive.  The session owns two
//! stream maps (one for each direction, because mplex stream ids are *not*
//! globally unique — each side numbers its own outbound streams) plus an
//! inbound parser and an outbound byte queue.
//!
//! Edge cases handled:
//!
//! - Frames split across multiple `feed()` calls — we buffer until both the
//!   header *and* the length varint plus the full payload are present.
//! - Bad varint or unknown flag closes the session (caller should treat the
//!   transport as poisoned and tear it down — mplex has no GoAway frame so
//!   we surface it as `error.ProtocolError`).
//! - Frame `length` exceeding `max_frame_payload` (default 1 MiB) is a
//!   protocol error.
//! - Frames addressing an unknown stream id are *silently dropped* per spec
//!   — the peer is allowed a brief race after we close.
//! - `new_stream` for an id we already have on the inbound side is a
//!   protocol error.
//! - `close` half-closes the originating side; both close → fully closed.
//!   `close` after `reset` is a no-op.
//! - `reset` discards both buffers immediately and silences subsequent
//!   frames on that stream.
//! - Local `Stream.write` after local close / reset returns
//!   `error.StreamClosed`.
//! - Local `Stream.read` returns buffered data first; when the buffer is
//!   empty *and* the remote has half-closed, returns `error.StreamClosed`.

const std = @import("std");
const frame = @import("frame.zig");
const varint = @import("../../varint.zig");

pub const Flag = frame.Flag;
pub const Header = frame.Header;

/// Whose perspective opened the stream — *from the local node's POV*.
pub const Direction = enum { outbound, inbound };

pub const Config = struct {
    /// Maximum payload bytes accepted on a single frame.  Spec / interop
    /// implementations cap at 1 MiB; surfaced here so embedders can lower.
    max_frame_payload: u64 = frame.default_max_frame_payload,
    /// Maximum concurrent open streams (sum of inbound + outbound).
    /// Excess inbound `new_stream` frames are replied to with reset.
    max_streams: u32 = 1024,
};

pub const SessionError = error{
    ProtocolError,
    SessionClosed,
    StreamLimitExceeded,
    OutOfMemory,
};

const StreamState = enum { open, closed_local, closed_remote, closed, reset };

pub const Stream = struct {
    id: u64,
    direction: Direction,
    session: *Session,
    state: StreamState = .open,
    recv_buf: std.ArrayList(u8) = .empty,

    pub const ReadError = error{StreamClosed};
    pub const WriteError = error{ StreamClosed, OutOfMemory };

    /// Drain up to `out.len` bytes.  Non-blocking — returns 0 when the
    /// buffer is empty but the stream is still receivable.  Returns
    /// `error.StreamClosed` once the buffer is empty *and* the remote has
    /// closed (or the stream was reset).
    pub fn read(self: *Stream, out: []u8) ReadError!usize {
        if (self.state == .reset) return error.StreamClosed;
        if (self.recv_buf.items.len == 0) {
            if (self.state == .closed or self.state == .closed_remote) return error.StreamClosed;
            return 0;
        }
        const n = @min(out.len, self.recv_buf.items.len);
        @memcpy(out[0..n], self.recv_buf.items[0..n]);
        const remaining = self.recv_buf.items.len - n;
        if (remaining > 0) std.mem.copyForwards(u8, self.recv_buf.items[0..remaining], self.recv_buf.items[n..]);
        self.recv_buf.shrinkRetainingCapacity(remaining);
        return n;
    }

    /// Append `bytes` to the outbound queue.  Mplex has no flow control so
    /// we always emit a single data frame chunked at `max_frame_payload`.
    pub fn write(self: *Stream, bytes: []const u8) WriteError!usize {
        if (self.state == .reset or self.state == .closed_local or self.state == .closed) {
            return error.StreamClosed;
        }
        try self.session.queueStreamData(self, bytes);
        return bytes.len;
    }

    /// Send `close` on our side.  Idempotent.
    pub fn close(self: *Stream) WriteError!void {
        if (self.state == .reset) return;
        if (self.state == .closed_local or self.state == .closed) return;
        try self.session.queueStreamClose(self);
    }

    /// Send `reset`.  Idempotent.
    pub fn reset(self: *Stream) WriteError!void {
        if (self.state == .reset) return;
        try self.session.queueStreamReset(self);
    }

    pub fn isClosed(self: *const Stream) bool {
        return self.state == .closed or self.state == .reset;
    }

    pub fn readBufferedLen(self: *const Stream) usize {
        return self.recv_buf.items.len;
    }
};

const StreamMap = std.AutoHashMapUnmanaged(u64, *Stream);

pub const Session = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// Streams we opened (we are initiator); keyed by our local id.
    outbound: StreamMap = .empty,
    /// Streams the peer opened (we are receiver); keyed by peer's id.
    inbound: StreamMap = .empty,
    out: std.ArrayList(u8) = .empty,
    in: std.ArrayList(u8) = .empty,
    accept_queue: std.ArrayList(*Stream) = .empty,
    next_outbound_id: u64 = 0,
    closed: bool = false,

    fn streamMap(self: *Session, dir: Direction) *StreamMap {
        return switch (dir) {
            .outbound => &self.outbound,
            .inbound => &self.inbound,
        };
    }

    fn streamMapConst(self: *const Session, dir: Direction) *const StreamMap {
        return switch (dir) {
            .outbound => &self.outbound,
            .inbound => &self.inbound,
        };
    }

    pub fn init(allocator: std.mem.Allocator, config: Config) Session {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *Session) void {
        var oit = self.outbound.iterator();
        while (oit.next()) |entry| {
            const s = entry.value_ptr.*;
            s.recv_buf.deinit(self.allocator);
            self.allocator.destroy(s);
        }
        var iit = self.inbound.iterator();
        while (iit.next()) |entry| {
            const s = entry.value_ptr.*;
            s.recv_buf.deinit(self.allocator);
            self.allocator.destroy(s);
        }
        self.outbound.deinit(self.allocator);
        self.inbound.deinit(self.allocator);
        self.out.deinit(self.allocator);
        self.in.deinit(self.allocator);
        self.accept_queue.deinit(self.allocator);
    }

    fn totalStreams(self: *const Session) u32 {
        return @intCast(self.outbound.count() + self.inbound.count());
    }

    // ── outbound surface ────────────────────────────────────────────────

    pub fn pendingOutbound(self: *const Session) []const u8 {
        return self.out.items;
    }

    pub fn consumeOutbound(self: *Session, n: usize) void {
        std.debug.assert(n <= self.out.items.len);
        const remaining = self.out.items.len - n;
        if (remaining > 0) std.mem.copyForwards(u8, self.out.items[0..remaining], self.out.items[n..]);
        self.out.shrinkRetainingCapacity(remaining);
    }

    // ── stream open / accept ────────────────────────────────────────────

    pub fn openStream(self: *Session) SessionError!*Stream {
        if (self.closed) return error.SessionClosed;
        if (self.totalStreams() >= self.config.max_streams) return error.StreamLimitExceeded;

        const id = self.next_outbound_id;
        self.next_outbound_id += 1;

        const s = try self.allocator.create(Stream);
        errdefer self.allocator.destroy(s);
        s.* = .{
            .id = id,
            .direction = .outbound,
            .session = self,
        };

        try self.outbound.put(self.allocator, id, s);
        try self.appendFrame(.{ .flag = .new_stream, .stream_id = id, .length = 0 }, &.{});
        return s;
    }

    pub fn acceptStream(self: *Session) ?*Stream {
        if (self.accept_queue.items.len == 0) return null;
        const s = self.accept_queue.items[0];
        const remaining = self.accept_queue.items.len - 1;
        if (remaining > 0) std.mem.copyForwards(*Stream, self.accept_queue.items[0..remaining], self.accept_queue.items[1..]);
        self.accept_queue.shrinkRetainingCapacity(remaining);
        return s;
    }

    pub fn streamCount(self: *const Session) u32 {
        return self.totalStreams();
    }

    // ── inbound feed ────────────────────────────────────────────────────

    pub fn feed(self: *Session, bytes: []const u8) SessionError!void {
        try self.in.appendSlice(self.allocator, bytes);
        while (true) {
            if (self.in.items.len == 0) return;
            const r = Header.parse(self.in.items, self.config.max_frame_payload) catch |err| switch (err) {
                error.Truncated => return,
                error.UnknownFlag, error.BadVarint, error.PayloadTooLarge, error.StreamIdOverflow => {
                    self.closed = true;
                    return error.ProtocolError;
                },
            };
            const total = r.consumed + @as(usize, @intCast(r.header.length));
            if (self.in.items.len < total) return; // wait for body
            const body = self.in.items[r.consumed..total];
            try self.handleFrame(r.header, body);
            const remaining = self.in.items.len - total;
            if (remaining > 0) std.mem.copyForwards(u8, self.in.items[0..remaining], self.in.items[total..]);
            self.in.shrinkRetainingCapacity(remaining);
        }
    }

    // ── private: frame builders ─────────────────────────────────────────

    fn appendFrame(self: *Session, h: Header, payload: []const u8) error{OutOfMemory}!void {
        var hdr_buf: [2 * varint.max_encoding_bytes]u8 = undefined;
        const n = h.encodeHeader(&hdr_buf) catch unreachable;
        try self.out.appendSlice(self.allocator, hdr_buf[0..n]);
        if (payload.len > 0) try self.out.appendSlice(self.allocator, payload);
    }

    fn dataFlag(s: *const Stream) Flag {
        // From our POV: outbound stream → we are the initiator → message_initiator.
        // Inbound stream → we are the receiver → message_receiver.
        return switch (s.direction) {
            .outbound => .message_initiator,
            .inbound => .message_receiver,
        };
    }

    fn closeFlag(s: *const Stream) Flag {
        return switch (s.direction) {
            .outbound => .close_initiator,
            .inbound => .close_receiver,
        };
    }

    fn resetFlag(s: *const Stream) Flag {
        return switch (s.direction) {
            .outbound => .reset_initiator,
            .inbound => .reset_receiver,
        };
    }

    fn queueStreamData(self: *Session, s: *Stream, bytes: []const u8) error{OutOfMemory}!void {
        var off: usize = 0;
        const cap = self.config.max_frame_payload;
        while (off < bytes.len) {
            const remaining = bytes.len - off;
            const chunk_len: usize = @intCast(@min(@as(u64, @intCast(remaining)), cap));
            try self.appendFrame(
                .{ .flag = dataFlag(s), .stream_id = s.id, .length = @intCast(chunk_len) },
                bytes[off .. off + chunk_len],
            );
            off += chunk_len;
        }
    }

    fn queueStreamClose(self: *Session, s: *Stream) error{OutOfMemory}!void {
        try self.appendFrame(.{ .flag = closeFlag(s), .stream_id = s.id, .length = 0 }, &.{});
        switch (s.state) {
            .open, .closed_remote => s.state = if (s.state == .closed_remote) .closed else .closed_local,
            else => {},
        }
    }

    fn queueStreamReset(self: *Session, s: *Stream) error{OutOfMemory}!void {
        s.state = .reset;
        s.recv_buf.clearRetainingCapacity();
        try self.appendFrame(.{ .flag = resetFlag(s), .stream_id = s.id, .length = 0 }, &.{});
    }

    // ── private: frame handlers ─────────────────────────────────────────

    fn handleFrame(self: *Session, h: Header, body: []const u8) SessionError!void {
        // Flag tells us which side of the stream the peer is acting as.  If
        // the peer marks itself as initiator → from our POV the stream is
        // *inbound*.  If receiver → outbound.
        const peer_is_initiator = h.flag.isInitiatorSide();
        const local_dir: Direction = if (peer_is_initiator) .inbound else .outbound;

        switch (h.flag) {
            .new_stream => return self.handleNewStream(h, body, local_dir),
            .message_initiator, .message_receiver => return self.handleMessage(h, body, local_dir),
            .close_initiator, .close_receiver => return self.handleClose(h, local_dir),
            .reset_initiator, .reset_receiver => return self.handleReset(h, local_dir),
        }
    }

    fn handleNewStream(self: *Session, h: Header, body: []const u8, local_dir: Direction) SessionError!void {
        std.debug.assert(local_dir == .inbound);
        _ = body; // optional human-readable name — ignored
        if (self.inbound.contains(h.stream_id)) {
            self.closed = true;
            return error.ProtocolError; // dup new_stream
        }
        if (self.totalStreams() >= self.config.max_streams) {
            // Reply with reset; do not open the stream.
            try self.appendFrame(.{ .flag = .reset_receiver, .stream_id = h.stream_id, .length = 0 }, &.{});
            return;
        }
        const s = try self.allocator.create(Stream);
        errdefer self.allocator.destroy(s);
        s.* = .{ .id = h.stream_id, .direction = .inbound, .session = self };
        try self.inbound.put(self.allocator, h.stream_id, s);
        try self.accept_queue.append(self.allocator, s);
    }

    fn handleMessage(self: *Session, h: Header, body: []const u8, local_dir: Direction) SessionError!void {
        const s_opt = self.streamMap(local_dir).get(h.stream_id);
        const s = s_opt orelse return; // unknown / closed stream — silently drop
        if (s.state == .reset) return;
        if (s.state == .closed_remote or s.state == .closed) {
            // Peer sent data after we received their close — protocol error.
            self.closed = true;
            return error.ProtocolError;
        }
        if (h.length > 0) try s.recv_buf.appendSlice(self.allocator, body);
    }

    fn handleClose(self: *Session, h: Header, local_dir: Direction) SessionError!void {
        const s_opt = self.streamMap(local_dir).get(h.stream_id);
        const s = s_opt orelse return;
        if (s.state == .reset) return;
        switch (s.state) {
            .open => s.state = .closed_remote,
            .closed_local => s.state = .closed,
            else => {}, // already closed_remote / closed: silently dedupe
        }
    }

    fn handleReset(self: *Session, h: Header, local_dir: Direction) SessionError!void {
        const s_opt = self.streamMap(local_dir).get(h.stream_id);
        const s = s_opt orelse return;
        s.state = .reset;
        s.recv_buf.clearRetainingCapacity();
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn pump(a: *Session, b: *Session) !void {
    try b.feed(a.pendingOutbound());
    a.consumeOutbound(a.pendingOutbound().len);
    try a.feed(b.pendingOutbound());
    b.consumeOutbound(b.pendingOutbound().len);
}

test "Session: open + accept + bidirectional data" {
    var d = Session.init(testing.allocator, .{});
    defer d.deinit();
    var l = Session.init(testing.allocator, .{});
    defer l.deinit();

    const ds = try d.openStream();
    try testing.expectEqual(@as(u64, 0), ds.id);
    _ = try ds.write("hello");
    try pump(&d, &l);

    const ls = l.acceptStream() orelse return error.NoStream;
    try testing.expectEqual(@as(u64, 0), ls.id);
    try testing.expectEqual(Direction.inbound, ls.direction);
    var buf: [16]u8 = undefined;
    const n = try ls.read(&buf);
    try testing.expectEqualStrings("hello", buf[0..n]);

    _ = try ls.write("world");
    try pump(&l, &d);
    const m = try ds.read(&buf);
    try testing.expectEqualStrings("world", buf[0..m]);
}

test "Session: close half-closes; subsequent write fails; read drains then EOF" {
    var d = Session.init(testing.allocator, .{});
    defer d.deinit();
    var l = Session.init(testing.allocator, .{});
    defer l.deinit();

    const ds = try d.openStream();
    _ = try ds.write("bye");
    try ds.close();
    try testing.expectError(Stream.WriteError.StreamClosed, ds.write("more"));
    try pump(&d, &l);

    const ls = l.acceptStream() orelse return error.NoStream;
    var buf: [16]u8 = undefined;
    const n = try ls.read(&buf);
    try testing.expectEqualStrings("bye", buf[0..n]);
    try testing.expectError(error.StreamClosed, ls.read(&buf));
}

test "Session: reset discards buffers and silences further frames" {
    var d = Session.init(testing.allocator, .{});
    defer d.deinit();
    var l = Session.init(testing.allocator, .{});
    defer l.deinit();

    const ds = try d.openStream();
    _ = try ds.write("data");
    try ds.reset();
    try pump(&d, &l);

    const ls = l.acceptStream() orelse return error.NoStream;
    try testing.expectEqual(StreamState.reset, ls.state);
    try testing.expectEqual(@as(usize, 0), ls.recv_buf.items.len);
    try testing.expectError(error.StreamClosed, ls.read(&[_]u8{}));
}

test "Session: data after peer-close is protocol error" {
    var l = Session.init(testing.allocator, .{});
    defer l.deinit();

    // Peer is initiator on stream id 7: send new_stream, then close, then data.
    var hbuf: [32]u8 = undefined;
    const n1 = try (Header{ .flag = .new_stream, .stream_id = 7, .length = 0 }).encodeHeader(&hbuf);
    try l.feed(hbuf[0..n1]);
    const n2 = try (Header{ .flag = .close_initiator, .stream_id = 7, .length = 0 }).encodeHeader(&hbuf);
    try l.feed(hbuf[0..n2]);
    var d_hdr: [32]u8 = undefined;
    const n3 = try (Header{ .flag = .message_initiator, .stream_id = 7, .length = 1 }).encodeHeader(&d_hdr);
    var dframe: [17]u8 = undefined;
    @memcpy(dframe[0..n3], d_hdr[0..n3]);
    dframe[n3] = 'x';
    try testing.expectError(SessionError.ProtocolError, l.feed(dframe[0 .. n3 + 1]));
}

test "Session: duplicate new_stream → protocol error" {
    var l = Session.init(testing.allocator, .{});
    defer l.deinit();

    var hbuf: [32]u8 = undefined;
    const n1 = try (Header{ .flag = .new_stream, .stream_id = 1, .length = 0 }).encodeHeader(&hbuf);
    try l.feed(hbuf[0..n1]);
    try testing.expectError(SessionError.ProtocolError, l.feed(hbuf[0..n1]));
}

test "Session: stream limit reached → reset reply, no new state" {
    var l = Session.init(testing.allocator, .{ .max_streams = 1 });
    defer l.deinit();

    var hbuf: [32]u8 = undefined;
    const n1 = try (Header{ .flag = .new_stream, .stream_id = 1, .length = 0 }).encodeHeader(&hbuf);
    try l.feed(hbuf[0..n1]);
    try testing.expectEqual(@as(u32, 1), l.streamCount());

    const n2 = try (Header{ .flag = .new_stream, .stream_id = 3, .length = 0 }).encodeHeader(&hbuf);
    try l.feed(hbuf[0..n2]); // does NOT raise — replies reset
    try testing.expectEqual(@as(u32, 1), l.streamCount());

    const out = l.pendingOutbound();
    try testing.expect(out.len > 0);
    const r = try Header.parse(out, frame.default_max_frame_payload);
    try testing.expectEqual(Flag.reset_receiver, r.header.flag);
    try testing.expectEqual(@as(u64, 3), r.header.stream_id);
}

test "Session: split feed across header/length/body" {
    var l = Session.init(testing.allocator, .{});
    defer l.deinit();
    var hdr: [32]u8 = undefined;
    const nh = try (Header{ .flag = .new_stream, .stream_id = 9, .length = 0 }).encodeHeader(&hdr);
    try l.feed(hdr[0..nh]);

    // Split data frame over multiple feeds.
    var dh: [32]u8 = undefined;
    const nd = try (Header{ .flag = .message_initiator, .stream_id = 9, .length = 5 }).encodeHeader(&dh);
    try l.feed(dh[0..1]); // partial header
    try l.feed(dh[1..nd]); // rest of header
    try l.feed("hel"); // partial body
    try l.feed("lo"); // rest

    const ls = l.acceptStream() orelse return error.NoStream;
    var buf: [16]u8 = undefined;
    const n = try ls.read(&buf);
    try testing.expectEqualStrings("hello", buf[0..n]);
}

test "Session: oversize frame → protocol error" {
    var l = Session.init(testing.allocator, .{ .max_frame_payload = 16 });
    defer l.deinit();
    // Encode a header claiming length=32 (>cap).  Even without the body
    // present yet, parse() rejects on the length varint.
    var hdr: [32]u8 = undefined;
    const n = try (Header{ .flag = .message_initiator, .stream_id = 3, .length = 32 }).encodeHeader(&hdr);
    try testing.expectError(SessionError.ProtocolError, l.feed(hdr[0..n]));
}

test "Session: unknown stream id silently ignored (peer race after reset)" {
    var l = Session.init(testing.allocator, .{});
    defer l.deinit();
    var hdr: [48]u8 = undefined;
    const n = try (Header{ .flag = .message_initiator, .stream_id = 99, .length = 3 }).encodeHeader(&hdr);
    @memcpy(hdr[n..][0..3], "xyz");
    try l.feed(hdr[0 .. n + 3]); // no error
    try testing.expectEqual(@as(u32, 0), l.streamCount());
}

test "Session: write chunked at max_frame_payload boundary" {
    var d = Session.init(testing.allocator, .{ .max_frame_payload = 4 });
    defer d.deinit();
    const ds = try d.openStream();
    _ = try ds.write("0123456789");
    // 1 new_stream + ceil(10/4) = 3 data frames.
    var remaining = d.pendingOutbound();
    var frames: usize = 0;
    while (remaining.len > 0) {
        const r = try Header.parse(remaining, frame.default_max_frame_payload);
        const total = r.consumed + @as(usize, @intCast(r.header.length));
        try testing.expect(remaining.len >= total);
        if (r.header.flag.isData()) try testing.expect(r.header.length <= 4);
        remaining = remaining[total..];
        frames += 1;
    }
    try testing.expectEqual(@as(usize, 4), frames);
}

test "Session: close after both sides closed is no-op" {
    var d = Session.init(testing.allocator, .{});
    defer d.deinit();
    var l = Session.init(testing.allocator, .{});
    defer l.deinit();

    const ds = try d.openStream();
    try ds.close();
    try pump(&d, &l);
    const ls = l.acceptStream() orelse return error.NoStream;
    try ls.close();
    try pump(&l, &d);

    try testing.expectEqual(StreamState.closed, ds.state);
    try testing.expectEqual(StreamState.closed, ls.state);
    // close() again — no error, no extra wire bytes.
    const out_before = d.pendingOutbound().len;
    try ds.close();
    try testing.expectEqual(out_before, d.pendingOutbound().len);
}

test "Session: openStream after session-closed fails" {
    var d = Session.init(testing.allocator, .{});
    defer d.deinit();
    d.closed = true;
    try testing.expectError(SessionError.SessionClosed, d.openStream());
}

test "Session: bad varint flag closes session" {
    var l = Session.init(testing.allocator, .{});
    defer l.deinit();
    const bytes = [_]u8{ 0x07, 0x00 }; // flag 7
    try testing.expectError(SessionError.ProtocolError, l.feed(&bytes));
    try testing.expect(l.closed);
}
