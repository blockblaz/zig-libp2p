//! Libp2p **QUIC v1** transport endpoint on bundled [zquic](https://github.com/ch4r10t33r/zquic): listen,
//! dial, non-blocking UDP [`drive`], and [`QuicListener.pollAccept`] for application-level acceptance (#15).
//!
//! TLS uses the libp2p ALPN and raw application streams via [`quic_v1.libp2pZquicServerConfig`] /
//! [`quic_v1.libp2pZquicClientConfig`] (see [`quic`]). Multistream-select runs on each raw bidi stream
//! using [`stream_multistream`] / [`quic_raw_stream_io`]; embedders may pump until enough bytes are
//! buffered (see [`stream_multistream.initiatorFirstWriteWireLen`]) so a single thread can alternate
//! [`drive`] with protocol steps without blocking on an empty QUIC recv buffer.
//!
//! **IPv4:** client dial matches [`quic.Libp2pQuicClientDialError`] (`ZquicClientIpv4Only` for IPv6 targets).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// `MSG_DONTWAIT` for `recvfrom` (drain all datagrams already queued after `poll`).
const recv_flags_dontwait: u32 = switch (builtin.target.os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos => 0x80,
    else => 0x40,
};
const Io = std.Io;
const multiaddr = @import("multiaddr");
const zquic = @import("zquic");
const ZIo = zquic.transport.io;
const feed_addr = @import("zquic_feed_addr.zig");

const quic = @import("quic.zig");
const quic_posix_udp = @import("quic_posix_udp.zig");
const wall_time = @import("../wall_time.zig");
const quic_v1 = quic.quic_v1;
const quic_raw_stream_io = @import("quic_raw_stream_io.zig");
const stream_multistream = @import("stream_multistream.zig");
const ping = @import("../ping.zig");

/// zquic `compat.Address` (not re-exported); layout matches [`feed_addr.Address`].
const ZquicAddress = blk: {
    const info = @typeInfo(@TypeOf(ZIo.Server.feedPacket)).@"fn";
    break :blk info.params[2].type.?;
};

fn zquicAddr(a: feed_addr.Address) ZquicAddress {
    return @bitCast(a);
}

pub const QuicListener = struct {
    allocator: std.mem.Allocator,
    server: *ZIo.Server,
    /// Per-slot: already surfaced by [`pollAccept`] for the current connection occupying the slot.
    seen_connected: [ZIo.MAX_CONNECTIONS]bool,

    /// Bind from a `/udp/.../quic-v1` multiaddr (port may be `0`; use [`boundUdpPortIpv4`] after listen).
    pub fn listen(
        allocator: std.mem.Allocator,
        ma: multiaddr.Multiaddr,
        options: quic_v1.Libp2pZquicServerOptions,
    ) !*QuicListener {
        const srv = try quic.initLibp2pQuicServerFromMultiaddr(allocator, ma, options);
        const self = try allocator.create(QuicListener);
        self.* = .{
            .allocator = allocator,
            .server = srv,
            .seen_connected = .{false} ** ZIo.MAX_CONNECTIONS,
        };
        return self;
    }

    pub fn deinit(self: *QuicListener) void {
        self.server.deinit();
        self.allocator.destroy(self);
    }

    /// UDP port the listening IPv4 socket is bound to (after OS assignment when multiaddr used port `0`).
    pub fn boundUdpPortIpv4(self: *QuicListener) posix.GetSockNameError!u16 {
        var sa: posix.sockaddr.in = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        try quic_posix_udp.getsockname(self.server.sock, @ptrCast(&sa), &len);
        return std.mem.bigToNative(u16, sa.port);
    }

    fn syncSeenFlags(self: *QuicListener) void {
        for (0..ZIo.MAX_CONNECTIONS) |i| {
            if (self.server.conns[i] == null) self.seen_connected[i] = false;
        }
    }

    /// Poll UDP (up to `poll_timeout_ms`), feed zquic, run loss recovery / flush. Call from your reactor.
    pub fn drive(self: *QuicListener, recv_buf: []u8, poll_timeout_ms: u32) DriveError!void {
        self.syncSeenFlags();
        var fds = [1]posix.pollfd{.{
            .fd = self.server.sock,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        _ = posix.poll(&fds, @intCast(poll_timeout_ms)) catch return error.PollFailed;
        if (fds[0].revents & posix.POLL.IN != 0) {
            while (true) {
                var sa: posix.sockaddr.storage = undefined;
                var sl: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
                const n = feed_addr.recvfrom(self.server.sock, recv_buf, recv_flags_dontwait, @ptrCast(&sa), &sl) catch |err| switch (err) {
                    error.WouldBlock => break,
                    else => |e| return e,
                };
                const addr: feed_addr.Address = .{ .any = @as(*const posix.sockaddr, @ptrCast(&sa)).* };
                self.server.feedPacket(recv_buf[0..n], zquicAddr(addr));
            }
        }
        self.server.processPendingWork();
    }

    pub const AcceptedConn = struct {
        slot: usize,
        conn: *ZIo.ConnState,
    };

    /// First connection in [`ConnPhase.connected`] not yet returned here. Clears automatically when the slot is freed.
    pub fn pollAccept(self: *QuicListener) ?AcceptedConn {
        self.syncSeenFlags();
        for (0..ZIo.MAX_CONNECTIONS) |i| {
            if (self.server.conns[i]) |*c| {
                if (c.phase == .connected and !self.seen_connected[i]) {
                    self.seen_connected[i] = true;
                    return .{ .slot = i, .conn = c };
                }
            }
        }
        return null;
    }
};

pub const QuicOutbound = struct {
    allocator: std.mem.Allocator,
    /// Heap-allocated: [`ZIo.Client`] is very large; embedding it here overflows typical stacks.
    client: *ZIo.Client,
    server_addr: feed_addr.Address,

    /// Parse `/udp/.../quic-v1` (IPv4), create zquic client, and send the Initial to `server_addr`.
    pub fn dial(
        allocator: std.mem.Allocator,
        ma: multiaddr.Multiaddr,
        dial_opts: quic.Libp2pZquicClientDialOptions,
    ) !QuicOutbound {
        const client = blk: {
            const p = try allocator.create(ZIo.Client);
            errdefer allocator.destroy(p);
            p.* = try quic.initLibp2pQuicClientFromMultiaddr(allocator, ma, dial_opts);
            break :blk p;
        };
        errdefer {
            client.deinit();
            allocator.destroy(client);
        }
        const ep = try quic.parseQuicV1Endpoint(ma);
        const server_addr = try compatAddressFromIp(ep.address);
        try client.startHandshake(zquicAddr(server_addr));
        return .{ .allocator = allocator, .client = client, .server_addr = server_addr };
    }

    pub fn deinit(self: *QuicOutbound) void {
        self.client.deinit();
        self.allocator.destroy(self.client);
    }

    pub fn drive(self: *QuicOutbound, recv_buf: []u8, poll_timeout_ms: u32) DriveError!void {
        var fds = [1]posix.pollfd{.{
            .fd = self.client.sock,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        _ = posix.poll(&fds, @intCast(poll_timeout_ms)) catch return error.PollFailed;
        if (fds[0].revents & posix.POLL.IN != 0) {
            while (true) {
                var sa: posix.sockaddr.storage = undefined;
                var sl: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
                const n = feed_addr.recvfrom(self.client.sock, recv_buf, recv_flags_dontwait, @ptrCast(&sa), &sl) catch |err| switch (err) {
                    error.WouldBlock => break,
                    else => |e| return e,
                };
                self.client.feedPacket(recv_buf[0..n]);
            }
        }
        self.client.processPendingWork(zquicAddr(self.server_addr));
        // zquic defers ACKs until a recv-drain boundary; embedders must flush so
        // the server gets ACKs and continues 1-RTT transmission (see Client.flushDeferredAck).
        self.client.flushDeferredAck();
    }

    pub fn waitConnected(self: *QuicOutbound, recv_buf: []u8, deadline_ms: i64) error{Timeout}!void {
        while (wall_time.milliTimestamp() < deadline_ms) {
            if (self.client.conn.phase == .connected) return;
            self.drive(recv_buf, 50) catch {};
        }
        return error.Timeout;
    }

    pub fn nextLocalBidiStream(self: *QuicOutbound) ZIo.OpenLocalStreamError!u64 {
        return ZIo.rawAllocateNextLocalBidiStream(&self.client.conn);
    }
};

pub const DriveError = feed_addr.RecvFromError || error{PollFailed};

fn compatAddressFromIp(addr: std.Io.net.IpAddress) quic.Libp2pQuicClientDialError!feed_addr.Address {
    return switch (addr) {
        .ip4 => |v| feed_addr.Address.initIp4(v.bytes, v.port),
        .ip6 => error.ZquicClientIpv4Only,
    };
}

fn pumpBoth(
    ln: *QuicListener,
    out: *QuicOutbound,
    recv_buf: []u8,
) DriveError!void {
    try ln.drive(recv_buf, 0);
    try out.drive(recv_buf, 0);
}

/// Deterministic single-threaded loopback: multistream + one ping on stream 0. Used by tests; requires `cert.pem` / `key.pem`.
pub fn loopbackPingOnce(
    allocator: std.mem.Allocator,
    cert_path: []const u8,
    key_path: []const u8,
) !void {
    var ma_listen = try multiaddr.Multiaddr.fromString(allocator, "/ip4/127.0.0.1/udp/0/quic-v1");
    defer ma_listen.deinit();

    var listener = try QuicListener.listen(allocator, ma_listen, .{
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer listener.deinit();

    const port = try listener.boundUdpPortIpv4();
    const dial_str = try std.fmt.allocPrint(allocator, "/ip4/127.0.0.1/udp/{d}/quic-v1", .{port});
    defer allocator.free(dial_str);
    var ma_dial = try multiaddr.Multiaddr.fromString(allocator, dial_str);
    defer ma_dial.deinit();

    var outbound = try QuicOutbound.dial(allocator, ma_dial, .{});
    defer outbound.deinit();

    var recv_buf: [65536]u8 = undefined;
    const deadline_ms = wall_time.milliTimestamp() + 20_000;

    var accepted: ?*ZIo.ConnState = null;
    var quic_ready = false;
    while (wall_time.milliTimestamp() < deadline_ms) {
        try pumpBoth(listener, &outbound, &recv_buf);
        if (accepted == null) {
            if (listener.pollAccept()) |a| accepted = a.conn;
        }
        if (accepted != null and outbound.client.conn.phase == .connected) {
            quic_ready = true;
            break;
        }
    }
    if (!quic_ready) return error.Timeout;
    const conn = accepted.?;

    const sid = try outbound.nextLocalBidiStream();
    const init_wlen = try stream_multistream.initiatorFirstWriteWireLen(ping.multistream_protocol_id);
    const resp_wlen = try stream_multistream.responderSuccessReplyWireLen(ping.multistream_protocol_id);

    var raw_c = quic_raw_stream_io.RawAppBidiClient{
        .client = outbound.client,
        .stream_id = sid,
    };
    var raw_s = quic_raw_stream_io.RawAppBidiServer{
        .server = listener.server,
        .conn = conn,
        .stream_id = sid,
    };

    {
        var pre = std.ArrayList(u8).empty;
        defer pre.deinit(allocator);
        try stream_multistream.appendFirstStreamInitiatorHandshake(&pre, allocator, ping.multistream_protocol_id);
        var w = raw_c.writer();
        Io.Writer.writeAll(&w, pre.items) catch return error.IoError;
        Io.Writer.flush(&w) catch return error.IoError;
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        try pumpBoth(listener, &outbound, &recv_buf);
        if (raw_s.unreadRecvLen() >= init_wlen) break;
    } else return error.Timeout;

    {
        var r = raw_s.reader();
        var w = raw_s.writer();
        try stream_multistream.responderHandshakeMultistream(&r, &w, ping.multistream_protocol_id, allocator);
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        try pumpBoth(listener, &outbound, &recv_buf);
        if (raw_c.unreadRecvLen() >= resp_wlen) break;
    } else return error.Timeout;

    {
        var r = raw_c.reader();
        var w = raw_c.writer();
        try stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, ping.multistream_protocol_id, allocator);
    }

    var pay: [ping.payload_len]u8 = undefined;
    ping.randomPayload(&pay);
    {
        var w = raw_c.writer();
        try ping.writePayload(&w, &pay);
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        try pumpBoth(listener, &outbound, &recv_buf);
        if (raw_s.unreadRecvLen() >= ping.payload_len) break;
    } else return error.Timeout;

    {
        var r = raw_s.reader();
        var w = raw_s.writer();
        try ping.handleInbound(&r, &w);
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        try pumpBoth(listener, &outbound, &recv_buf);
        if (raw_c.unreadRecvLen() >= ping.payload_len) break;
    } else return error.Timeout;

    {
        var r = raw_c.reader();
        var echo: [ping.payload_len]u8 = undefined;
        try ping.readPayload(&r, &echo);
        if (!std.mem.eql(u8, &pay, &echo)) return error.InvalidData;
    }
}

test "stream_multistream wire lens match negotiate buffers" {
    const a = std.testing.allocator;
    const proto = ping.multistream_protocol_id;
    var w = std.ArrayList(u8).empty;
    defer w.deinit(a);
    try stream_multistream.appendFirstStreamInitiatorHandshake(&w, a, proto);
    try std.testing.expectEqual(try stream_multistream.initiatorFirstWriteWireLen(proto), w.items.len);

    var rsp = std.ArrayList(u8).empty;
    defer rsp.deinit(a);
    try quic_v1.appendFirstBidiStreamInitiatorHandshake(&rsp, a, proto);
    try std.testing.expectEqual(w.items.len, rsp.items.len);
}

test "quic endpoint loopback ping (single-threaded)" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    const cert = "test/fixtures/quic_loopback/cert.pem";
    const key = "test/fixtures/quic_loopback/key.pem";
    try loopbackPingOnce(a, cert, key);
}
