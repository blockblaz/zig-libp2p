//! Yamux v0 session state machine — pure-Zig, allocator-driven, I/O-free.
//!
//! ## Architecture
//!
//! `Session` owns a map of `Stream`s plus an inbound parser and an outbound
//! ring of bytes.  It is **completely I/O-free**: the embedder feeds inbound
//! bytes via `feed()` and drains the encoded frames from `pendingOutbound()`
//! / `consumeOutbound()` onto whatever socket abstraction it owns (TCP,
//! WebSocket, in-memory pipe, …).  This mirrors how `multistream_negotiate`
//! and the gossipsub runtime are wired in this repo.
//!
//! ## Edge cases handled
//!
//! - Stream-id parity per role (initiator → odd, responder → even) is enforced
//!   on every inbound SYN.  Mismatches close the session with
//!   `protocol_error`.
//! - `data` frames whose `length` exceeds the per-stream recv window or the
//!   configured per-frame cap close the session with `protocol_error`.
//! - Frames on stream-id 0 are restricted to `ping` and `go_away` — anything
//!   else is rejected.
//! - Receiving `RST` flushes both buffers and marks the stream `reset`; later
//!   frames on the same id (data, FIN, window-update) are silently dropped.
//! - `FIN` may piggy-back on a `data` frame.  We consume the payload first,
//!   then transition the stream's recv side.
//! - `WindowUpdate` for an unknown / closed stream is ignored — the peer is
//!   allowed a brief race after we tear down a stream.
//! - The per-stream send buffer is unbounded by design — outbound writes
//!   block at the API layer when the peer's recv window is exhausted, so
//!   memory pressure is bounded by the application.
//! - Hitting the configured `max_streams` cap immediately replies with `RST`
//!   on the offending SYN rather than allocating; the stream id is not
//!   recorded.
//! - `GoAway` received → no further `openStream` calls succeed; existing
//!   streams continue to drain.
//! - Keep-alive ping is scheduled by `tick(now_ms)`; missing pong beyond the
//!   configured timeout closes the session with `internal_error`.

const std = @import("std");
const frame = @import("frame.zig");

pub const Header = frame.Header;
pub const Flags = frame.Flags;
pub const FrameType = frame.Type;
pub const GoAwayCode = frame.GoAwayCode;

pub const Role = enum {
    /// Dialer.  Owns *odd* stream ids starting at 1.
    initiator,
    /// Listener.  Owns *even* stream ids starting at 2.
    responder,
};

pub const Config = struct {
    /// Initial recv window per stream, in bytes.  Spec default 256 KiB.
    initial_stream_window: u32 = 256 * 1024,
    /// Maximum concurrent streams (sum of inbound + outbound).  Past this we
    /// reply RST to peer SYN and refuse local `openStream` calls.
    max_streams: u32 = 256,
    /// Maximum payload bytes accepted on a single `data` frame.  Defends
    /// against allocation amplification on the receive side.  Spec lets us
    /// pick — match HashiCorp Yamux's default of 1 MiB.
    max_data_frame_payload: u32 = 1 * 1024 * 1024,
    /// Cadence of outbound keep-alive `ping(SYN)` frames.  `0` disables
    /// keep-alive (e.g. on top of QUIC, which has its own keep-alive).
    keep_alive_interval_ms: i64 = 30_000,
    /// If a keep-alive `ping(SYN)` is not echoed back within this window we
    /// declare the session dead.  Default is 2× the interval.
    keep_alive_timeout_ms: i64 = 60_000,
};

pub const SessionError = error{
    /// Peer broke the wire format.  Session is now dead.
    ProtocolError,
    /// Local API error: e.g. opening a stream after `shutdown`.
    SessionClosed,
    /// We've hit `Config.max_streams`.
    StreamLimitExceeded,
    /// Allocation failure.
    OutOfMemory,
};

const StreamState = enum {
    /// Local stream created, SYN not yet flushed.
    init,
    /// SYN sent (initiator) or received (responder) — half-open.
    syn_sent,
    syn_received,
    /// Both sides exchanged at least one frame.  Ordinary data flow.
    established,
    /// Either side has been closed.  We track the FIN booleans separately so
    /// we still know which direction is open.
    closed_local,
    closed_remote,
    /// Both FINs seen — the stream id is finalised but not yet GC'd.
    closed,
    /// `RST` happened; recv/send buffers discarded; no further frames
    /// processed.
    reset,
};

pub const Stream = struct {
    id: u32,
    session: *Session,
    state: StreamState,
    /// Bytes the peer is still allowed to send before we must issue a
    /// WindowUpdate.  Decreases on inbound data, increases when the app
    /// drains `recv_buf` past the half-window mark.
    recv_window_remaining: u32,
    /// Bytes we may still send before peer must issue a WindowUpdate.
    /// Decreases on outbound data, increases on inbound WindowUpdate.
    send_window_remaining: u32,
    /// Bytes received but not yet read by app.
    recv_buf: std.ArrayList(u8) = .empty,
    /// Bytes the app handed us via `write()` that didn't fit in the peer's
    /// current recv window.  Drained on `WindowUpdate`.
    send_pending: std.ArrayList(u8) = .empty,
    recv_fin: bool = false,
    send_fin: bool = false,

    pub const ReadError = error{StreamClosed};
    pub const WriteError = error{ StreamClosed, OutOfMemory };

    /// Drain up to `out.len` bytes from the recv buffer.  Returns the byte
    /// count copied (may be `0` if the buffer is empty even when the stream
    /// is still open).  Returns `error.StreamClosed` once the stream is fully
    /// closed (FIN both sides or reset) and no buffered data remains.
    pub fn read(self: *Stream, out: []u8) ReadError!usize {
        if (self.state == .reset) return error.StreamClosed;
        if (self.recv_buf.items.len == 0) {
            if (self.state == .closed or
                (self.recv_fin and self.state == .closed_remote))
            {
                return error.StreamClosed;
            }
            return 0;
        }
        const n = @min(out.len, self.recv_buf.items.len);
        @memcpy(out[0..n], self.recv_buf.items[0..n]);
        // Drain.  ArrayList's "shift" pattern: keep the tail, drop the head.
        const remaining = self.recv_buf.items.len - n;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.recv_buf.items[0..remaining], self.recv_buf.items[n..]);
        }
        self.recv_buf.shrinkRetainingCapacity(remaining);
        // Maybe send a WindowUpdate.  Spec recommends auto-update when peer's
        // half of the window has been consumed.  Best-effort: if we OOM
        // queueing the update, the next read will retry — read itself does
        // not fail because of it.
        self.session.maybeSendWindowUpdate(self) catch |err| switch (err) {
            error.OutOfMemory => {},
        };
        return n;
    }

    /// Append `bytes` to the outbound queue.  Returns the byte count accepted
    /// (always equal to `bytes.len` on success — backpressure is absorbed by
    /// the per-stream send buffer).  Returns `error.StreamClosed` if the
    /// stream has been closed locally or reset.
    pub fn write(self: *Stream, bytes: []const u8) WriteError!usize {
        if (self.state == .reset or self.send_fin) return error.StreamClosed;
        if (self.state == .closed or self.state == .closed_local) return error.StreamClosed;
        try self.session.queueStreamData(self, bytes);
        return bytes.len;
    }

    /// Send `FIN` after any pending writes have been flushed.  Idempotent.
    pub fn close(self: *Stream) WriteError!void {
        if (self.state == .reset) return;
        if (self.send_fin) return;
        try self.session.queueStreamFin(self);
    }

    /// Send `RST` — peer SHOULD discard buffers immediately.  Idempotent.
    pub fn reset(self: *Stream) WriteError!void {
        if (self.state == .reset) return;
        try self.session.queueStreamReset(self);
    }

    pub fn isClosed(self: *const Stream) bool {
        return self.state == .closed or self.state == .reset;
    }

    /// Bytes ready to read (does not block).
    pub fn readBufferedLen(self: *const Stream) usize {
        return self.recv_buf.items.len;
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    config: Config,
    role: Role,
    streams: std.AutoHashMapUnmanaged(u32, *Stream) = .empty,
    /// Encoded frames waiting to go onto the wire.  The embedder drains via
    /// `pendingOutbound` + `consumeOutbound`.  Sized loosely — keeps the I/O
    /// loop simple at the cost of a bounded extra copy.
    out: std.ArrayList(u8) = .empty,
    /// Inbound byte buffer.  Frames cross packet boundaries so we keep a
    /// rolling buffer rather than requiring the embedder to deliver whole
    /// frames.
    in: std.ArrayList(u8) = .empty,

    /// Next local stream id.  Initiator starts at 1, responder at 2.  Always
    /// advanced by 2 to preserve parity invariants.
    next_local_stream_id: u32,
    /// Highest peer stream id we've seen.  Spec: ids must be monotonically
    /// increasing — repeating an old one is a protocol error.
    highest_peer_stream_id: u32 = 0,
    /// Streams pending `acceptStream`.  Pointers, not copies — `streams`
    /// owns the storage.
    accept_queue: std.ArrayList(*Stream) = .empty,

    /// Set once we send GoAway.  No further outbound frames are produced
    /// except RST/Ping/GoAway echoes.  Existing streams may still be drained.
    sent_go_away: bool = false,
    /// Set once we receive GoAway from peer.  No new outbound streams.
    recv_go_away: bool = false,

    /// Keep-alive bookkeeping.  `0` (the default zero-init) means no ping is
    /// outstanding.
    next_ping_at_ms: i64 = 0,
    last_ping_value: u32 = 0,
    last_ping_sent_at_ms: i64 = 0,
    keep_alive_armed: bool = false,

    /// Last error code we sent in GoAway.  Surfaced to embedders that want
    /// to distinguish a clean shutdown from a protocol abort.
    closed_with_code: ?GoAwayCode = null,

    pub fn init(allocator: std.mem.Allocator, config: Config, role: Role) Session {
        const next_id: u32 = switch (role) {
            .initiator => 1,
            .responder => 2,
        };
        return .{
            .allocator = allocator,
            .config = config,
            .role = role,
            .next_local_stream_id = next_id,
        };
    }

    pub fn deinit(self: *Session) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.*;
            s.recv_buf.deinit(self.allocator);
            s.send_pending.deinit(self.allocator);
            self.allocator.destroy(s);
        }
        self.streams.deinit(self.allocator);
        self.out.deinit(self.allocator);
        self.in.deinit(self.allocator);
        self.accept_queue.deinit(self.allocator);
    }

    // ── outbound surface ────────────────────────────────────────────────

    pub fn pendingOutbound(self: *const Session) []const u8 {
        return self.out.items;
    }

    pub fn consumeOutbound(self: *Session, n: usize) void {
        std.debug.assert(n <= self.out.items.len);
        const remaining = self.out.items.len - n;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.out.items[0..remaining], self.out.items[n..]);
        }
        self.out.shrinkRetainingCapacity(remaining);
    }

    // ── stream open / accept ────────────────────────────────────────────

    pub fn openStream(self: *Session) SessionError!*Stream {
        if (self.sent_go_away or self.recv_go_away) return error.SessionClosed;
        if (self.streams.count() >= self.config.max_streams) return error.StreamLimitExceeded;

        const id = self.next_local_stream_id;
        self.next_local_stream_id += 2; // preserve parity

        const s = try self.allocator.create(Stream);
        errdefer self.allocator.destroy(s);
        s.* = .{
            .id = id,
            .session = self,
            .state = .syn_sent,
            .recv_window_remaining = self.config.initial_stream_window,
            .send_window_remaining = self.config.initial_stream_window,
        };

        try self.streams.put(self.allocator, id, s);
        try self.appendFrame(.{
            .kind = .data,
            .flags = .{ .syn = true },
            .stream_id = id,
            .length = 0,
        }, &.{});
        return s;
    }

    pub fn acceptStream(self: *Session) ?*Stream {
        if (self.accept_queue.items.len == 0) return null;
        const s = self.accept_queue.items[0];
        const remaining = self.accept_queue.items.len - 1;
        if (remaining > 0) {
            std.mem.copyForwards(*Stream, self.accept_queue.items[0..remaining], self.accept_queue.items[1..]);
        }
        self.accept_queue.shrinkRetainingCapacity(remaining);
        return s;
    }

    pub fn streamCount(self: *const Session) u32 {
        return @intCast(self.streams.count());
    }

    pub fn shutdown(self: *Session, code: GoAwayCode) SessionError!void {
        if (self.sent_go_away) return;
        self.sent_go_away = true;
        self.closed_with_code = code;
        try self.appendFrame(.{
            .kind = .go_away,
            .flags = .{},
            .stream_id = 0,
            .length = code.toU32(),
        }, &.{});
    }

    // ── timer tick ──────────────────────────────────────────────────────

    pub fn tick(self: *Session, now_ms: i64) SessionError!void {
        if (self.sent_go_away) return;
        if (self.config.keep_alive_interval_ms == 0) return;

        // Pong-timeout enforcement.
        if (self.keep_alive_armed and (now_ms - self.last_ping_sent_at_ms) > self.config.keep_alive_timeout_ms) {
            try self.shutdown(.internal_error);
            return;
        }

        if (now_ms >= self.next_ping_at_ms) {
            self.last_ping_value +%= 1;
            self.last_ping_sent_at_ms = now_ms;
            self.next_ping_at_ms = now_ms + self.config.keep_alive_interval_ms;
            self.keep_alive_armed = true;
            try self.appendFrame(.{
                .kind = .ping,
                .flags = .{ .syn = true },
                .stream_id = 0,
                .length = self.last_ping_value,
            }, &.{});
        }
    }

    // ── inbound feed ────────────────────────────────────────────────────

    pub const FeedError = SessionError;

    pub fn feed(self: *Session, bytes: []const u8) FeedError!void {
        try self.in.appendSlice(self.allocator, bytes);
        while (true) {
            if (self.in.items.len < frame.header_len) return;
            const h = frame.Header.parse(self.in.items, self.config.max_data_frame_payload) catch |err| switch (err) {
                frame.FrameError.Truncated => return, // need more bytes
                else => {
                    try self.shutdown(.protocol_error);
                    return error.ProtocolError;
                },
            };
            const payload_len: usize = if (h.kind == .data) h.length else 0;
            const total = frame.header_len + payload_len;
            if (self.in.items.len < total) return; // wait for body

            const body = self.in.items[frame.header_len..total];
            try self.handleFrame(h, body);

            // Shift consumed bytes off the front.
            const remaining = self.in.items.len - total;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.in.items[0..remaining], self.in.items[total..]);
            }
            self.in.shrinkRetainingCapacity(remaining);
        }
    }

    // ── private: frame builders ─────────────────────────────────────────

    fn appendFrame(self: *Session, h: Header, payload: []const u8) error{OutOfMemory}!void {
        var hbuf: [frame.header_len]u8 = undefined;
        h.encode(&hbuf) catch unreachable; // hbuf is sized correctly
        try self.out.appendSlice(self.allocator, &hbuf);
        if (payload.len > 0) try self.out.appendSlice(self.allocator, payload);
    }

    fn queueStreamData(self: *Session, s: *Stream, bytes: []const u8) error{OutOfMemory}!void {
        try s.send_pending.appendSlice(self.allocator, bytes);
        try self.flushStreamPending(s);
    }

    fn queueStreamFin(self: *Session, s: *Stream) error{OutOfMemory}!void {
        s.send_fin = true;
        try self.flushStreamPending(s);
        // If pending is now empty, the FIN was attached to the last frame
        // already (see flushStreamPending below).  Otherwise FIN piggybacks
        // on the next eligible frame.
    }

    fn queueStreamReset(self: *Session, s: *Stream) error{OutOfMemory}!void {
        s.state = .reset;
        s.recv_buf.clearRetainingCapacity();
        s.send_pending.clearRetainingCapacity();
        try self.appendFrame(.{
            .kind = .data,
            .flags = .{ .rst = true },
            .stream_id = s.id,
            .length = 0,
        }, &.{});
    }

    /// Drain `s.send_pending` into Data frames bounded by `send_window_remaining`
    /// and `max_data_frame_payload`.  Carries SYN/ACK/FIN flags as appropriate.
    fn flushStreamPending(self: *Session, s: *Stream) error{OutOfMemory}!void {
        // Determine SYN/ACK flags for the *first* frame on this stream.
        var first_frame_flags: Flags = .{};
        switch (s.state) {
            .syn_sent => {
                // SYN already in `out` from openStream; subsequent frames carry no SYN.
            },
            .syn_received => {
                first_frame_flags.ack = true;
            },
            else => {},
        }

        var emitted: usize = 0;
        while (s.send_pending.items.len > 0) {
            if (s.send_window_remaining == 0) break; // peer-side backpressure
            const window: u32 = s.send_window_remaining;
            const cap = @min(window, self.config.max_data_frame_payload);
            const chunk_len: u32 = @intCast(@min(cap, s.send_pending.items.len));
            const chunk = s.send_pending.items[0..chunk_len];

            var flags: Flags = .{};
            if (emitted == 0) flags = first_frame_flags;
            const drains_pending = chunk_len == s.send_pending.items.len;
            if (drains_pending and s.send_fin) flags.fin = true;

            try self.appendFrame(.{
                .kind = .data,
                .flags = flags,
                .stream_id = s.id,
                .length = chunk_len,
            }, chunk);

            s.send_window_remaining -= chunk_len;
            // Drop the head of pending buffer.
            const rem = s.send_pending.items.len - chunk_len;
            if (rem > 0) std.mem.copyForwards(u8, s.send_pending.items[0..rem], s.send_pending.items[chunk_len..]);
            s.send_pending.shrinkRetainingCapacity(rem);
            emitted += 1;

            // Promote responder syn_received → established once we ACK.
            if (s.state == .syn_received) s.state = .established;
        }

        // Empty-payload FIN if pending was already empty when close() was
        // called.  Use SYN/ACK on first frame; otherwise plain FIN.
        if (s.send_pending.items.len == 0 and s.send_fin and emitted == 0) {
            var flags: Flags = first_frame_flags;
            flags.fin = true;
            try self.appendFrame(.{
                .kind = .data,
                .flags = flags,
                .stream_id = s.id,
                .length = 0,
            }, &.{});
            if (s.state == .syn_received) s.state = .established;
        }

        if (s.send_fin and s.send_pending.items.len == 0) {
            switch (s.state) {
                .established, .syn_sent, .syn_received => s.state = .closed_local,
                .closed_remote => s.state = .closed,
                else => {},
            }
        }
    }

    fn maybeSendWindowUpdate(self: *Session, s: *Stream) error{OutOfMemory}!void {
        const initial = self.config.initial_stream_window;
        if (s.recv_window_remaining * 2 >= initial) return; // > half window left
        const delta = initial - s.recv_window_remaining;
        if (delta == 0) return;
        try self.appendFrame(.{
            .kind = .window_update,
            .flags = .{},
            .stream_id = s.id,
            .length = delta,
        }, &.{});
        s.recv_window_remaining += delta;
    }

    // ── private: frame handlers ─────────────────────────────────────────

    fn handleFrame(self: *Session, h: Header, body: []const u8) SessionError!void {
        switch (h.kind) {
            .ping => return self.handlePing(h),
            .go_away => return self.handleGoAway(h),
            .window_update => return self.handleWindowUpdate(h),
            .data => return self.handleData(h, body),
        }
    }

    fn handlePing(self: *Session, h: Header) SessionError!void {
        if (h.stream_id != 0) {
            try self.shutdown(.protocol_error);
            return error.ProtocolError;
        }
        if (h.flags.syn) {
            // Peer is asking for a pong.  Echo back with ACK.
            try self.appendFrame(.{
                .kind = .ping,
                .flags = .{ .ack = true },
                .stream_id = 0,
                .length = h.length,
            }, &.{});
        } else if (h.flags.ack) {
            if (self.keep_alive_armed and h.length == self.last_ping_value) {
                self.keep_alive_armed = false;
            }
        } else {
            try self.shutdown(.protocol_error);
            return error.ProtocolError;
        }
    }

    fn handleGoAway(self: *Session, h: Header) SessionError!void {
        if (h.stream_id != 0) {
            try self.shutdown(.protocol_error);
            return error.ProtocolError;
        }
        self.recv_go_away = true;
        self.closed_with_code = GoAwayCode.fromU32(h.length);
    }

    fn handleWindowUpdate(self: *Session, h: Header) SessionError!void {
        const s_opt = self.streams.get(h.stream_id);
        const s = s_opt orelse return; // unknown / closed stream → ignore
        if (s.state == .reset) return;
        const new_win, const overflow = @addWithOverflow(s.send_window_remaining, h.length);
        if (overflow != 0) {
            try self.shutdown(.protocol_error);
            return error.ProtocolError;
        }
        s.send_window_remaining = new_win;
        // Try to flush any pending writes that were waiting on credit.
        try self.flushStreamPending(s);
    }

    fn handleData(self: *Session, h: Header, body: []const u8) SessionError!void {
        if (h.stream_id == 0) {
            try self.shutdown(.protocol_error);
            return error.ProtocolError;
        }

        var s_ptr = self.streams.get(h.stream_id);
        // Re-using an existing id with SYN is a protocol violation.
        if (s_ptr != null and h.flags.syn) {
            try self.shutdown(.protocol_error);
            return error.ProtocolError;
        }
        if (s_ptr == null) {
            // Must be a SYN to legitimately open a new stream.
            if (!h.flags.syn) {
                // Unknown stream + not SYN → stale frames after RST.  Spec
                // says ignore (peer race) — but only when not also FIN/data.
                if (h.flags.rst) return; // no-op
                if (h.length == 0 and h.flags.fin) return;
                // Otherwise treat as protocol error.
                try self.shutdown(.protocol_error);
                return error.ProtocolError;
            }
            // Validate parity: peer-initiated streams must use the *opposite*
            // role's parity from us.
            const peer_parity_ok = switch (self.role) {
                .initiator => (h.stream_id % 2) == 0, // peer is responder, even ids
                .responder => (h.stream_id % 2) == 1, // peer is initiator, odd ids
            };
            if (!peer_parity_ok) {
                try self.shutdown(.protocol_error);
                return error.ProtocolError;
            }
            // Monotonic id check.
            if (h.stream_id <= self.highest_peer_stream_id) {
                try self.shutdown(.protocol_error);
                return error.ProtocolError;
            }
            self.highest_peer_stream_id = h.stream_id;
            // Stream-limit gate: refuse with RST instead of GoAway.
            if (self.streams.count() >= self.config.max_streams) {
                try self.appendFrame(.{
                    .kind = .data,
                    .flags = .{ .rst = true },
                    .stream_id = h.stream_id,
                    .length = 0,
                }, &.{});
                return;
            }
            const s = try self.allocator.create(Stream);
            errdefer self.allocator.destroy(s);
            s.* = .{
                .id = h.stream_id,
                .session = self,
                .state = .syn_received,
                .recv_window_remaining = self.config.initial_stream_window,
                .send_window_remaining = self.config.initial_stream_window,
            };
            try self.streams.put(self.allocator, h.stream_id, s);
            try self.accept_queue.append(self.allocator, s);
            s_ptr = s;
        }

        const s = s_ptr.?;
        if (s.state == .reset) return; // post-reset frames discarded

        // ACK on a previously-sent SYN.
        if (h.flags.ack and s.state == .syn_sent) s.state = .established;

        // RST takes precedence — discard buffers and mark reset.
        if (h.flags.rst) {
            s.state = .reset;
            s.recv_buf.clearRetainingCapacity();
            s.send_pending.clearRetainingCapacity();
            return;
        }

        // Window enforcement.
        if (h.length > s.recv_window_remaining) {
            try self.shutdown(.protocol_error);
            return error.ProtocolError;
        }
        if (h.length > 0) {
            try s.recv_buf.appendSlice(self.allocator, body);
            s.recv_window_remaining -= h.length;
        }

        // FIN ends the recv side.
        if (h.flags.fin) {
            s.recv_fin = true;
            switch (s.state) {
                .established, .syn_sent, .syn_received => s.state = .closed_remote,
                .closed_local => s.state = .closed,
                else => {},
            }
        }

        // First peer frame after our SYN can also serve as ACK promotion.
        if (s.state == .syn_sent and (h.flags.syn or h.flags.ack or h.length > 0 or h.flags.fin)) {
            s.state = .established;
        }
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn dialSetup() struct { dialer: Session, listener: Session } {
    return .{
        .dialer = Session.init(testing.allocator, .{}, .initiator),
        .listener = Session.init(testing.allocator, .{}, .responder),
    };
}

fn pump(a: *Session, b: *Session) !void {
    // a → b
    try b.feed(a.pendingOutbound());
    a.consumeOutbound(a.pendingOutbound().len);
    // b → a
    try a.feed(b.pendingOutbound());
    b.consumeOutbound(b.pendingOutbound().len);
}

test "Session: openStream + acceptStream + data round-trip" {
    var d = Session.init(testing.allocator, .{}, .initiator);
    defer d.deinit();
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();

    const ds = try d.openStream();
    try testing.expectEqual(@as(u32, 1), ds.id);
    _ = try ds.write("hello");
    try pump(&d, &l);

    const ls = l.acceptStream() orelse return error.NoStream;
    try testing.expectEqual(@as(u32, 1), ls.id);

    var buf: [16]u8 = undefined;
    const n = try ls.read(&buf);
    try testing.expectEqualStrings("hello", buf[0..n]);

    // Reverse direction.
    _ = try ls.write("world");
    try pump(&l, &d);
    const m = try ds.read(&buf);
    try testing.expectEqualStrings("world", buf[0..m]);
}

test "Session: backpressure when peer recv window is exhausted" {
    var d = Session.init(testing.allocator, .{ .initial_stream_window = 16 }, .initiator);
    defer d.deinit();
    var l = Session.init(testing.allocator, .{ .initial_stream_window = 16 }, .responder);
    defer l.deinit();

    const ds = try d.openStream();
    // Write 32 bytes — only 16 should fit on the wire; rest queues locally.
    _ = try ds.write("0123456789abcdef0123456789abcdef");
    try testing.expectEqual(@as(u32, 0), ds.send_window_remaining);
    try testing.expectEqual(@as(usize, 16), ds.send_pending.items.len);
    try pump(&d, &l);

    const ls = l.acceptStream() orelse return error.NoStream;
    var buf: [64]u8 = undefined;
    const first = try ls.read(&buf);
    try testing.expectEqual(@as(usize, 16), first);
    try testing.expectEqualStrings("0123456789abcdef", buf[0..first]);

    // Reading drained the window → WindowUpdate flows back, draining the
    // dialer's pending 16 bytes onto the wire.
    try pump(&l, &d);
    try testing.expectEqual(@as(usize, 0), ds.send_pending.items.len);
    try pump(&d, &l);
    const second = try ls.read(&buf);
    try testing.expectEqual(@as(usize, 16), second);
    try testing.expectEqualStrings("0123456789abcdef", buf[0..second]);
}

test "Session: FIN on close, read returns StreamClosed after drain" {
    var d = Session.init(testing.allocator, .{}, .initiator);
    defer d.deinit();
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();

    const ds = try d.openStream();
    _ = try ds.write("bye");
    try ds.close();
    try pump(&d, &l);

    var ls = l.acceptStream() orelse return error.NoStream;
    var buf: [16]u8 = undefined;
    const n = try ls.read(&buf);
    try testing.expectEqualStrings("bye", buf[0..n]);
    // Next read after FIN drain must return StreamClosed.
    try testing.expectError(error.StreamClosed, ls.read(&buf));
}

test "Session: RST discards buffers and stops further frames" {
    var d = Session.init(testing.allocator, .{}, .initiator);
    defer d.deinit();
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();

    const ds = try d.openStream();
    _ = try ds.write("data");
    try ds.reset();
    try pump(&d, &l);
    const ls = l.acceptStream() orelse return error.NoStream;
    try testing.expectEqual(StreamState.reset, ls.state);
    // Late writes on either side become no-ops or errors.
    try testing.expectError(error.StreamClosed, ds.write("x"));
}

test "Session: protocol error closes session" {
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();
    // Initiator-side parity from a peer claiming responder role: even ids.
    // We feed an *odd* id with SYN, which is correct (peer is dialer).
    // Then we feed a second SYN with the SAME id — monotonic violation.
    var f1: [12]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 1, .length = 0 }).encode(&f1) catch unreachable;
    try l.feed(&f1);
    try testing.expect(l.streams.contains(1));

    var f2: [12]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 1, .length = 0 }).encode(&f2) catch unreachable;
    try testing.expectError(SessionError.ProtocolError, l.feed(&f2));
    try testing.expect(l.sent_go_away);
    try testing.expectEqual(GoAwayCode.protocol_error, l.closed_with_code.?);
}

test "Session: stream id parity violation aborts" {
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();
    // Responder expects peer-odd ids.  Feed an *even* SYN.
    var f: [12]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 2, .length = 0 }).encode(&f) catch unreachable;
    try testing.expectError(SessionError.ProtocolError, l.feed(&f));
}

test "Session: stream limit reached → RST reply (not GoAway)" {
    var l = Session.init(testing.allocator, .{ .max_streams = 1 }, .responder);
    defer l.deinit();
    var f1: [12]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 1, .length = 0 }).encode(&f1) catch unreachable;
    try l.feed(&f1);
    var f3: [12]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 3, .length = 0 }).encode(&f3) catch unreachable;
    try l.feed(&f3); // should NOT error — RST is sent as response

    try testing.expect(!l.sent_go_away);
    // Last outbound frame should be RST on stream 3.
    const out = l.pendingOutbound();
    try testing.expect(out.len >= frame.header_len);
    const last = out[out.len - frame.header_len ..];
    const lh = try Header.parse(last, std.math.maxInt(u32));
    try testing.expect(lh.flags.rst);
    try testing.expectEqual(@as(u32, 3), lh.stream_id);
}

test "Session: ping echo with same opaque value" {
    var s = Session.init(testing.allocator, .{}, .responder);
    defer s.deinit();
    var f: [12]u8 = undefined;
    (Header{ .kind = .ping, .flags = .{ .syn = true }, .stream_id = 0, .length = 0xdeadbeef }).encode(&f) catch unreachable;
    try s.feed(&f);
    const out = s.pendingOutbound();
    try testing.expectEqual(@as(usize, frame.header_len), out.len);
    const reply = try Header.parse(out, std.math.maxInt(u32));
    try testing.expectEqual(FrameType.ping, reply.kind);
    try testing.expect(reply.flags.ack);
    try testing.expectEqual(@as(u32, 0xdeadbeef), reply.length);
}

test "Session: keep-alive ping fires on tick after interval" {
    var s = Session.init(testing.allocator, .{ .keep_alive_interval_ms = 1000 }, .initiator);
    defer s.deinit();
    try s.tick(0);
    try testing.expect(s.keep_alive_armed);
    try testing.expectEqual(@as(usize, frame.header_len), s.pendingOutbound().len);
    s.consumeOutbound(s.pendingOutbound().len);
    // Pong arrives with matching value.
    var f: [12]u8 = undefined;
    (Header{ .kind = .ping, .flags = .{ .ack = true }, .stream_id = 0, .length = s.last_ping_value }).encode(&f) catch unreachable;
    try s.feed(&f);
    try testing.expect(!s.keep_alive_armed);
}

test "Session: keep-alive timeout shuts session down" {
    var s = Session.init(testing.allocator, .{ .keep_alive_interval_ms = 100, .keep_alive_timeout_ms = 100 }, .initiator);
    defer s.deinit();
    try s.tick(0);
    try testing.expect(s.keep_alive_armed);
    // No pong — past timeout window.
    try s.tick(500);
    try testing.expect(s.sent_go_away);
    try testing.expectEqual(GoAwayCode.internal_error, s.closed_with_code.?);
}

test "Session: data exceeding recv window is protocol error" {
    var s = Session.init(testing.allocator, .{ .initial_stream_window = 4 }, .responder);
    defer s.deinit();
    var f: [16]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 1, .length = 5 }).encode(f[0..12]) catch unreachable;
    @memcpy(f[12..16], "AAAA"); // only 4 bytes payload — header.length=5 inflates body
    // We need exactly `length=5` bytes to make the parse succeed but window check fail.
    // Build the right payload size:
    var f2: [17]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 1, .length = 5 }).encode(f2[0..12]) catch unreachable;
    @memcpy(f2[12..17], "AAAAA");
    try testing.expectError(SessionError.ProtocolError, s.feed(&f2));
}

test "Session: write across multiple frames respects max_data_frame_payload" {
    var d = Session.init(testing.allocator, .{ .initial_stream_window = 1 << 20, .max_data_frame_payload = 4 }, .initiator);
    defer d.deinit();
    const ds = try d.openStream();
    _ = try ds.write("0123456789");
    // Expect 1 SYN (empty data) + 3 data frames of 4/4/2 bytes.
    var remaining = d.pendingOutbound();
    var frames: usize = 0;
    while (remaining.len >= frame.header_len) {
        const h = try Header.parse(remaining, std.math.maxInt(u32));
        const total = frame.header_len + (if (h.kind == .data) h.length else 0);
        try testing.expect(remaining.len >= total);
        if (h.kind == .data and h.length > 0) try testing.expect(h.length <= 4);
        remaining = remaining[total..];
        frames += 1;
    }
    try testing.expect(frames >= 4); // SYN + 3 chunks
}

test "Session: shutdown emits GoAway and refuses new streams" {
    var s = Session.init(testing.allocator, .{}, .initiator);
    defer s.deinit();
    try s.shutdown(.normal);
    try testing.expect(s.sent_go_away);
    try testing.expectError(SessionError.SessionClosed, s.openStream());
    const out = s.pendingOutbound();
    const h = try Header.parse(out, std.math.maxInt(u32));
    try testing.expectEqual(FrameType.go_away, h.kind);
    try testing.expectEqual(@as(u32, 0), h.stream_id);
    try testing.expectEqual(@as(u32, 0), h.length);
}

test "Session: feed handles frames split across multiple chunks" {
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();
    var hdr: [frame.header_len]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 1, .length = 5 }).encode(&hdr) catch unreachable;
    // Feed header in 3 byte chunks; feed body byte-at-a-time.
    try l.feed(hdr[0..3]);
    try l.feed(hdr[3..7]);
    try l.feed(hdr[7..frame.header_len]);
    const body = "hello";
    for (body) |b| try l.feed(&[_]u8{b});

    const ls = l.acceptStream() orelse return error.NoStream;
    var buf: [8]u8 = undefined;
    const n = try ls.read(&buf);
    try testing.expectEqualStrings("hello", buf[0..n]);
}

test "Session: data frame on stream id 0 is protocol error" {
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();
    var f: [frame.header_len]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 0, .length = 0 }).encode(&f) catch unreachable;
    try testing.expectError(SessionError.ProtocolError, l.feed(&f));
    try testing.expectEqual(GoAwayCode.protocol_error, l.closed_with_code.?);
}

test "Session: data on unknown stream without SYN is protocol error" {
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();
    var f: [frame.header_len + 4]u8 = undefined;
    (Header{ .kind = .data, .flags = .{}, .stream_id = 7, .length = 4 }).encode(f[0..frame.header_len]) catch unreachable;
    @memcpy(f[frame.header_len..][0..4], "ABCD");
    try testing.expectError(SessionError.ProtocolError, l.feed(&f));
}

test "Session: window-update wrap-around is protocol error" {
    var l = Session.init(testing.allocator, .{ .initial_stream_window = std.math.maxInt(u32) }, .responder);
    defer l.deinit();
    // Establish stream first.
    var f1: [frame.header_len]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 1, .length = 0 }).encode(&f1) catch unreachable;
    try l.feed(&f1);
    // Now send a WindowUpdate that overflows send_window_remaining (already maxInt).
    var f2: [frame.header_len]u8 = undefined;
    (Header{ .kind = .window_update, .flags = .{}, .stream_id = 1, .length = 1 }).encode(&f2) catch unreachable;
    try testing.expectError(SessionError.ProtocolError, l.feed(&f2));
}

test "Session: ping ack with wrong value does not clear keep-alive" {
    var s = Session.init(testing.allocator, .{ .keep_alive_interval_ms = 1000 }, .initiator);
    defer s.deinit();
    try s.tick(0);
    try testing.expect(s.keep_alive_armed);
    s.consumeOutbound(s.pendingOutbound().len);
    var f: [frame.header_len]u8 = undefined;
    (Header{ .kind = .ping, .flags = .{ .ack = true }, .stream_id = 0, .length = s.last_ping_value +% 1 }).encode(&f) catch unreachable;
    try s.feed(&f);
    try testing.expect(s.keep_alive_armed);
}

test "Session: GoAway received → no new streams (existing keep working)" {
    var d = Session.init(testing.allocator, .{}, .initiator);
    defer d.deinit();
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();

    const ds = try d.openStream();
    _ = try ds.write("hi");
    try pump(&d, &l);
    const ls = l.acceptStream() orelse return error.NoStream;

    try l.shutdown(.normal);
    try pump(&l, &d);
    try testing.expect(d.recv_go_away);
    try testing.expectError(SessionError.SessionClosed, d.openStream());

    // Existing stream still drains.
    var buf: [8]u8 = undefined;
    const n = try ls.read(&buf);
    try testing.expectEqualStrings("hi", buf[0..n]);
}

test "Session: multiple parallel streams" {
    var d = Session.init(testing.allocator, .{}, .initiator);
    defer d.deinit();
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();

    const a = try d.openStream();
    const b = try d.openStream();
    const c = try d.openStream();
    try testing.expectEqual(@as(u32, 1), a.id);
    try testing.expectEqual(@as(u32, 3), b.id);
    try testing.expectEqual(@as(u32, 5), c.id);
    _ = try a.write("aaa");
    _ = try b.write("bb");
    _ = try c.write("c");
    try pump(&d, &l);

    var ids = std.ArrayList(u32).empty;
    defer ids.deinit(testing.allocator);
    while (l.acceptStream()) |sptr| try ids.append(testing.allocator, sptr.id);
    // Listener observed all three SYNs.
    try testing.expectEqual(@as(usize, 3), ids.items.len);
}

test "Session: oversized data frame parsed but rejected via header.parse" {
    // Independently verify max_data_frame_payload guard at parse layer.
    const cfg = Config{ .max_data_frame_payload = 1024 };
    var l = Session.init(testing.allocator, cfg, .responder);
    defer l.deinit();
    var hdr: [frame.header_len]u8 = undefined;
    (Header{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 1, .length = 2048 }).encode(&hdr) catch unreachable;
    try testing.expectError(SessionError.ProtocolError, l.feed(&hdr));
}

test "Session: read on empty established stream returns 0" {
    var d = Session.init(testing.allocator, .{}, .initiator);
    defer d.deinit();
    var l = Session.init(testing.allocator, .{}, .responder);
    defer l.deinit();
    _ = try d.openStream();
    try pump(&d, &l);
    const ls = l.acceptStream() orelse return error.NoStream;
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try ls.read(&buf));
}
