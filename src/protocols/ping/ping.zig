//! libp2p ping 1.0.0 (`/ipfs/ping/1.0.0`) — RTT payload exchange and optional keepalive policy.

const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const errors = @import("../../primitives/errors.zig");
const wall_time = @import("../../primitives/wall_time.zig");

/// Multistream negotiation line including newline.
pub const protocol_line: []const u8 = "/ipfs/ping/1.0.0\n";

/// Protocol id passed to multistream-select (no trailing newline), same logical name as [`protocol_line`].
pub const multistream_protocol_id: []const u8 = std.mem.trimEnd(u8, protocol_line, "\n");

/// Payload size for each ping or pong datagram on the stream.
pub const payload_len: usize = 32;

/// Ping stream failures use the same layer as req/resp stream I/O (#45).
pub const WireError = errors.ReqRespError;

fn mapReaderErr(err: Io.Reader.Error) errors.ReqRespError {
    return switch (err) {
        error.ReadFailed => error.IoError,
        error.EndOfStream => error.IncompleteStream,
    };
}

fn mapWriterErr(err: Io.Writer.Error) errors.ReqRespError {
    return switch (err) {
        error.WriteFailed => error.IoError,
    };
}

/// Fill `payload` with random bytes suitable for a ping datagram.
pub fn randomPayload(payload: *[payload_len]u8) void {
    if (builtin.link_libc) {
        std.c.arc4random_buf(payload.ptr, payload.len);
        return;
    }
    if (builtin.os.tag == .linux) {
        var off: usize = 0;
        while (off < payload.len) {
            const rc = std.os.linux.getrandom(payload.ptr + off, payload.len - off, 0);
            const e = std.posix.errno(rc);
            if (e == .SUCCESS) {
                off += @intCast(rc);
            } else if (e == .INTR) {
                continue;
            } else {
                @panic("getrandom failed");
            }
        }
        return;
    }
    @compileError("randomPayload requires libc (e.g. arc4random_buf) or Linux getrandom");
}

/// Write one ping/pong payload and flush.
pub fn writePayload(w: *Io.Writer, payload: *const [payload_len]u8) WireError!void {
    Io.Writer.writeAll(w, payload) catch |e| return mapWriterErr(e);
    Io.Writer.flush(w) catch |e| return mapWriterErr(e);
}

/// Read exactly one payload from the stream.
pub fn readPayload(r: *Io.Reader, payload_out: *[payload_len]u8) WireError!void {
    Io.Reader.readSliceAll(r, payload_out) catch |e| return mapReaderErr(e);
}

/// Responder: read one payload and write it back (echo).
pub fn handleInbound(r: *Io.Reader, w: *Io.Writer) WireError!void {
    try handleInboundPrefixed(&.{}, r, w);
}

/// Like [`handleInbound`], but the first bytes of the payload may already sit in `prefix`
/// (e.g. read ahead during multistream-select when the peer flushes handshake + data).
pub fn handleInboundPrefixed(prefix: []const u8, r: *Io.Reader, w: *Io.Writer) WireError!void {
    var buf: [payload_len]u8 = undefined;
    if (prefix.len >= payload_len) {
        @memcpy(buf[0..payload_len], prefix[0..payload_len]);
    } else {
        @memcpy(buf[0..prefix.len], prefix);
        Io.Reader.readSliceAll(r, buf[prefix.len..]) catch |e| return mapReaderErr(e);
    }
    try writePayload(w, &buf);
}

/// Initiator: send `payload`, read echo, ensure it matches. Returns wall-clock RTT in milliseconds.
pub fn initiatorRoundTripMs(r: *Io.Reader, w: *Io.Writer, payload: *[payload_len]u8) WireError!u64 {
    randomPayload(payload);
    const t0: u64 = @intCast(wall_time.milliTimestamp());
    try writePayload(w, payload);
    var echo: [payload_len]u8 = undefined;
    try readPayload(r, &echo);
    const t1: u64 = @intCast(wall_time.milliTimestamp());
    if (!std.mem.eql(u8, payload, &echo)) return error.InvalidData;
    return t1 - t0;
}

/// Default interval between ping attempts (milliseconds).
pub const default_interval_ms: u64 = 15_000;
/// Default time to wait for a pong before counting a miss (milliseconds).
pub const default_timeout_ms: u64 = 20_000;
/// Default consecutive failed round-trips before the embedder should close the connection.
pub const default_max_missed_pings: u8 = 2;

/// Tunables for [`Ping`].
pub const PingConfig = struct {
    interval_ms: u64 = default_interval_ms,
    timeout_ms: u64 = default_timeout_ms,
    max_missed_pings: u8 = default_max_missed_pings,
};

/// What [`Ping.poll`] requests from the embedder.
pub const PingPoll = union(enum) {
    none,
    /// Open or use a ping substream and send a 32-byte payload (see [`initiatorRoundTripMs`]).
    send_ping,
    /// Missed-ping policy says the connection should be closed.
    close_connection,
};

/// Time-based ping scheduling and miss counting. The embedder must drive I/O and call
/// [`handleOutboundResult`] on success or [`notifyOutboundFailure`] on timeout / stream errors.
pub const Ping = struct {
    config: PingConfig,
    missed: u8 = 0,
    /// When set, a ping is in flight until pong or deadline.
    deadline_ms: ?u64 = null,
    /// Next time a ping may be sent (when no deadline is active).
    next_ping_ms: ?u64 = null,

    pub fn init(config: PingConfig) Ping {
        return .{ .config = config };
    }

    /// Arm the first ping (or reset after reconnect). Same as starting the libp2p ping behaviour.
    pub fn schedulePing(self: *Ping, now_ms: u64) void {
        self.deadline_ms = null;
        self.next_ping_ms = now_ms + self.config.interval_ms;
    }

    fn onMiss(self: *Ping, now_ms: u64) PingPoll {
        self.deadline_ms = null;
        self.missed +|= 1;
        if (self.missed >= self.config.max_missed_pings) {
            return .close_connection;
        }
        self.next_ping_ms = now_ms + self.config.interval_ms;
        return .none;
    }

    /// Advance timers; may request a new ping or a connection close.
    pub fn poll(self: *Ping, now_ms: u64) PingPoll {
        if (self.deadline_ms) |d| {
            if (now_ms >= d) {
                return self.onMiss(now_ms);
            }
            return .none;
        }
        if (self.next_ping_ms) |t| {
            if (now_ms >= t) {
                self.next_ping_ms = null;
                self.deadline_ms = now_ms + self.config.timeout_ms;
                return .send_ping;
            }
        }
        return .none;
    }

    /// Call after a successful round-trip (RTT is for metrics only).
    pub fn handleOutboundResult(self: *Ping, now_ms: u64, rtt_ms: u64) void {
        _ = rtt_ms;
        self.missed = 0;
        self.deadline_ms = null;
        self.next_ping_ms = now_ms + self.config.interval_ms;
    }

    /// Call when the ping stream times out or returns an I/O error while a ping is in flight.
    pub fn notifyOutboundFailure(self: *Ping, now_ms: u64) PingPoll {
        if (self.deadline_ms == null) return .none;
        return self.onMiss(now_ms);
    }
};

test "protocol_line ends with newline" {
    try std.testing.expect(std.mem.endsWith(u8, protocol_line, "\n"));
}

test "multistream_protocol_id matches protocol_line without newline" {
    try std.testing.expectEqualStrings("/ipfs/ping/1.0.0", multistream_protocol_id);
}

test "ping responder echoes payload" {
    var inbound: [payload_len]u8 = undefined;
    @memset(&inbound, 0xC5);
    var r = Io.Reader.fixed(&inbound);
    var outbound: [payload_len]u8 = undefined;
    var w = Io.Writer.fixed(&outbound);
    try handleInbound(&r, &w);
    try std.testing.expectEqualSlices(u8, &inbound, &outbound);
}

test "ping initiator write then read" {
    var pay: [payload_len]u8 = undefined;
    @memset(&pay, 0x2A);
    var echo: [payload_len]u8 = undefined;
    @memcpy(&echo, &pay);
    var r = Io.Reader.fixed(&echo);
    var written: [payload_len]u8 = undefined;
    var w = Io.Writer.fixed(&written);
    try writePayload(&w, &pay);
    try std.testing.expectEqualSlices(u8, &pay, &written);
    var got: [payload_len]u8 = undefined;
    try readPayload(&r, &got);
    try std.testing.expectEqualSlices(u8, &pay, &got);
}

test "Ping poll schedules send then close after misses" {
    var p = Ping.init(.{
        .interval_ms = 100,
        .timeout_ms = 50,
        .max_missed_pings = 2,
    });
    p.schedulePing(1_000);
    try std.testing.expectEqual(PingPoll.none, p.poll(1_050));
    try std.testing.expectEqual(PingPoll.send_ping, p.poll(1_100));
    try std.testing.expect(p.deadline_ms != null);
    try std.testing.expectEqual(PingPoll.none, p.poll(1_120));
    // Timeout at 1_100 + 50 = 1_150
    try std.testing.expectEqual(PingPoll.none, p.poll(1_149));
    try std.testing.expectEqual(PingPoll.none, p.poll(1_150)); // first miss, schedule next
    try std.testing.expectEqual(@as(u8, 1), p.missed);
    try std.testing.expectEqual(PingPoll.none, p.poll(1_240));
    try std.testing.expectEqual(PingPoll.send_ping, p.poll(1_250)); // next ping at 1_150+100
    try std.testing.expectEqual(PingPoll.none, p.poll(1_299)); // deadline 1_250+50
    try std.testing.expectEqual(PingPoll.close_connection, p.poll(1_300)); // second miss
}

test "Ping handleOutboundResult clears miss state" {
    var p = Ping.init(.{ .interval_ms = 10, .timeout_ms = 20, .max_missed_pings = 2 });
    p.schedulePing(0);
    try std.testing.expectEqual(PingPoll.send_ping, p.poll(10));
    p.handleOutboundResult(12, 4);
    try std.testing.expectEqual(@as(u8, 0), p.missed);
    try std.testing.expectEqual(@as(?u64, 22), p.next_ping_ms);
}
