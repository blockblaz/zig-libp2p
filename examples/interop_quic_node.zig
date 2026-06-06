//! zig-libp2p QUIC interop endpoint (Phase B1 minimal).
//!
//! Single binary that runs as either client or server, parameterised by
//! environment variables.  Used by the QUIC interop runner to spin up one
//! side of an interop test in its own container (or process).
//!
//! Environment variables:
//!
//!   ROLE           — "server" (listen) or "client" (dial)
//!   TESTCASE       — "handshake", "ping", "gossipsub" (B3 stub on zig side),
//!                    or "reqresp" (B4 — echo over a libp2p stream)
//!   RR_PAYLOAD_LEN — bytes per request/response on the reqresp testcase
//!                    (default 256). Length is known to both sides via env;
//!                    on the wire it's a raw byte run, no length prefix.
//!   LISTEN_PORT    — UDP port for server (default 4001)
//!   SERVER_HOST    — dial target IPv4 dotted-decimal (default "127.0.0.1")
//!   SERVER_PORT    — dial target port for client (default 4001)
//!   CERT_PATH      — PEM cert path (default /certs/cert.pem)
//!   KEY_PATH       — PEM EC key path (default /certs/key.pem)
//!   DEADLINE_MS    — overall test deadline (default 30000)
//!   REMOTE_PEER_ID — base58btc-encoded peer id of the dial target. When set
//!                    on the client, dialExtended is used and the TLS leaf
//!                    must produce a matching libp2p peer id (cross-impl
//!                    interop with go-libp2p). Unset → legacy dial path.
//!
//! Exit codes:
//!   0  success
//!   1  failure (timeout / decode / mismatch)
//!   2  bad config (unknown ROLE / TESTCASE)
//!   3  testcase not yet implemented on this side (B3 zig gossipsub stub)

const std = @import("std");
const zl = @import("zig_libp2p");
const multiaddr = @import("multiaddr");
const zquic = @import("zquic");

const ZIoConnState = zquic.transport.io.ConnState;

const QuicListener = zl.transport.quic_endpoint.QuicListener;
const QuicOutbound = zl.transport.quic_endpoint.QuicOutbound;
const dialExtended = zl.transport.quic_endpoint.dialExtended;
const QuicOutboundDialOptions = zl.transport.quic_endpoint.QuicOutboundDialOptions;
const PeerId = zl.peer_id.PeerId;
const RawAppBidiClient = zl.transport.quic_raw_stream_io.RawAppBidiClient;
const RawAppBidiServer = zl.transport.quic_raw_stream_io.RawAppBidiServer;
const stream_multistream = zl.transport.stream_multistream;
const ping = zl.ping;
const wall_time = zl.wall_time;
const Io = std.Io;

const default_listen_port: u16 = 4001;
const default_deadline_ms: i64 = 30_000;

/// B4 req-resp testcase protocol id.  Pinned here so both impls reference
/// the same string and the env contract stays tight; no version skew across
/// runners.
const reqresp_protocol_id: []const u8 = "/interop/b4/echo/1.0.0";
const default_reqresp_payload_len: usize = 256;

fn getEnv(key: []const u8) ?[]const u8 {
    // zig 0.16 dropped std.posix.getenv; use C getenv directly.  Always
    // available on the linux runtime image we ship.
    var buf: [256]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{key}) catch return null;
    const c_ptr = std.c.getenv(z.ptr) orelse return null;
    return std.mem.span(c_ptr);
}

fn envOr(key: []const u8, fallback: []const u8) []const u8 {
    return getEnv(key) orelse fallback;
}

fn envInt(comptime T: type, key: []const u8, fallback: T) T {
    const s = getEnv(key) orelse return fallback;
    return std.fmt.parseInt(T, s, 10) catch fallback;
}

pub fn main() !u8 {
    const a = std.heap.page_allocator;

    const role = envOr("ROLE", "server");
    const testcase = envOr("TESTCASE", "handshake");
    const cert_path = envOr("CERT_PATH", "/certs/cert.pem");
    const key_path = envOr("KEY_PATH", "/certs/key.pem");
    const deadline_ms = envInt(i64, "DEADLINE_MS", default_deadline_ms);

    std.debug.print("interop_quic_node: role={s} testcase={s}\n", .{ role, testcase });

    // The B3 gossipsub testcase needs the QUIC inbound-stream pipeline
    // to dispatch /meshsub/1.1.0 frames through `Host.handleGossipRpc`;
    // wiring isn't in this binary yet (tracked as a follow-up to land the
    // same path zeam-network's EthLibp2pV2 will use). For now return
    // exit code 3 (distinct from 1 / 2) so the matrix runner can report
    // a TAP "skip" without confusing it with a real failure.
    if (std.mem.eql(u8, testcase, "gossipsub")) {
        std.debug.print("interop_quic_node[{s}]: gossipsub testcase not yet wired on zig side; skipping\n", .{role});
        return 3;
    }

    if (std.mem.eql(u8, role, "server")) {
        const port = envInt(u16, "LISTEN_PORT", default_listen_port);
        return runServer(a, cert_path, key_path, port, testcase, deadline_ms);
    } else if (std.mem.eql(u8, role, "client")) {
        const host = envOr("SERVER_HOST", "127.0.0.1");
        const port = envInt(u16, "SERVER_PORT", default_listen_port);
        return runClient(a, cert_path, key_path, host, port, testcase, deadline_ms);
    } else {
        std.debug.print("interop_quic_node: unknown ROLE={s}\n", .{role});
        return 2;
    }
}

fn runServer(
    a: std.mem.Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    port: u16,
    testcase: []const u8,
    deadline_ms: i64,
) !u8 {
    const ma_str = try std.fmt.allocPrint(a, "/ip4/0.0.0.0/udp/{d}/quic-v1", .{port});
    defer a.free(ma_str);
    var ma = try multiaddr.Multiaddr.fromString(a, ma_str);
    defer ma.deinit();

    var listener = try QuicListener.listen(a, ma, .{
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer listener.deinit();

    std.debug.print("interop_quic_node[server]: listening on udp/{d}\n", .{port});

    var recv_buf: [65536]u8 = undefined;
    const dl = wall_time.milliTimestamp() + deadline_ms;
    var accepted: ?*ZIoConnState = null;
    while (wall_time.milliTimestamp() < dl) {
        listener.drive(&recv_buf, 5) catch {};
        if (listener.pollAccept()) |acc| {
            accepted = acc.conn;
            break;
        }
    }
    if (accepted == null) {
        std.debug.print("interop_quic_node[server]: accept timeout\n", .{});
        return 1;
    }
    std.debug.print("interop_quic_node[server]: connection accepted\n", .{});

    if (std.mem.eql(u8, testcase, "handshake")) {
        const settle = wall_time.milliTimestamp() + 1_000;
        while (wall_time.milliTimestamp() < settle) listener.drive(&recv_buf, 5) catch {};
        std.debug.print("interop_quic_node[server]: handshake ok\n", .{});
        return 0;
    }

    if (std.mem.eql(u8, testcase, "ping")) {
        return serveOnePingResponder(a, listener, accepted.?, &recv_buf, dl);
    }

    if (std.mem.eql(u8, testcase, "reqresp")) {
        const payload_len = envInt(usize, "RR_PAYLOAD_LEN", default_reqresp_payload_len);
        return serveOneReqRespResponder(a, listener, accepted.?, &recv_buf, dl, payload_len);
    }

    std.debug.print("interop_quic_node[server]: unknown TESTCASE={s}\n", .{testcase});
    return 2;
}

/// B4 server: accept one inbound stream, multistream-select
/// `/interop/b4/echo/1.0.0`, read RR_PAYLOAD_LEN bytes, echo them back.
fn serveOneReqRespResponder(
    a: std.mem.Allocator,
    listener: *QuicListener,
    conn: *ZIoConnState,
    recv_buf: *[65536]u8,
    deadline_ms: i64,
    payload_len: usize,
) !u8 {
    const Ctx = struct {
        sid: ?u64 = null,
        fn cb(self_op: ?*anyopaque, _: *QuicListener, _: usize, _: *ZIoConnState, sid: u64) void {
            const ctx_p: *@This() = @ptrCast(@alignCast(self_op.?));
            if (ctx_p.sid == null) ctx_p.sid = sid;
        }
    };
    var ctx = Ctx{};
    listener.lifecycle.ctx = &ctx;
    listener.lifecycle.on_inbound_stream_ready = Ctx.cb;

    while (wall_time.milliTimestamp() < deadline_ms and ctx.sid == null) {
        listener.drive(recv_buf, 5) catch {};
    }
    const sid = ctx.sid orelse {
        std.debug.print("interop_quic_node[server]: reqresp: stream timeout\n", .{});
        return 1;
    };
    std.debug.print("interop_quic_node[server]: reqresp: got stream sid={d}\n", .{sid});

    var raw = RawAppBidiServer{
        .server = listener.server,
        .conn = conn,
        .stream_id = sid,
    };

    const init_wlen = try stream_multistream.initiatorFirstWriteWireLen(reqresp_protocol_id);
    while (wall_time.milliTimestamp() < deadline_ms) {
        listener.drive(recv_buf, 5) catch {};
        if (raw.unreadRecvLen() >= init_wlen) break;
    } else return 1;

    {
        var r = raw.reader();
        var w = raw.writer();
        try stream_multistream.responderHandshakeMultistream(&r, &w, reqresp_protocol_id, a);
    }

    // Drain RR_PAYLOAD_LEN request bytes — allocate on heap since this is
    // a runtime-size buffer (ping has a comptime fixed 32).
    const buf = try a.alloc(u8, payload_len);
    defer a.free(buf);

    while (wall_time.milliTimestamp() < deadline_ms) {
        listener.drive(recv_buf, 5) catch {};
        if (raw.unreadRecvLen() >= payload_len) break;
    } else return 1;

    {
        var r = raw.reader();
        try Io.Reader.readSliceAll(&r, buf);
    }

    // Echo back the exact same bytes; matches the deterministic payload
    // the client builds (see `clientOneReqRespInitiator`).
    {
        var w = raw.writer();
        Io.Writer.writeAll(&w, buf) catch return 1;
        Io.Writer.flush(&w) catch return 1;
    }

    const flush_until = wall_time.milliTimestamp() + 500;
    while (wall_time.milliTimestamp() < flush_until) listener.drive(recv_buf, 5) catch {};

    std.debug.print("interop_quic_node[server]: reqresp ok ({d} bytes)\n", .{payload_len});
    return 0;
}

fn serveOnePingResponder(
    a: std.mem.Allocator,
    listener: *QuicListener,
    conn: *ZIoConnState,
    recv_buf: *[65536]u8,
    deadline_ms: i64,
) !u8 {
    const Ctx = struct {
        sid: ?u64 = null,
        fn cb(self_op: ?*anyopaque, _: *QuicListener, _: usize, _: *ZIoConnState, sid: u64) void {
            const ctx_p: *@This() = @ptrCast(@alignCast(self_op.?));
            if (ctx_p.sid == null) ctx_p.sid = sid;
        }
    };
    var ctx = Ctx{};
    listener.lifecycle.ctx = &ctx;
    listener.lifecycle.on_inbound_stream_ready = Ctx.cb;

    while (wall_time.milliTimestamp() < deadline_ms and ctx.sid == null) {
        listener.drive(recv_buf, 5) catch {};
    }
    const sid = ctx.sid orelse {
        std.debug.print("interop_quic_node[server]: ping: stream timeout\n", .{});
        return 1;
    };
    std.debug.print("interop_quic_node[server]: ping: got stream sid={d}\n", .{sid});

    var raw = RawAppBidiServer{
        .server = listener.server,
        .conn = conn,
        .stream_id = sid,
    };

    const init_wlen = try stream_multistream.initiatorFirstWriteWireLen(ping.multistream_protocol_id);
    while (wall_time.milliTimestamp() < deadline_ms) {
        listener.drive(recv_buf, 5) catch {};
        if (raw.unreadRecvLen() >= init_wlen) break;
    } else return 1;

    {
        var r = raw.reader();
        var w = raw.writer();
        try stream_multistream.responderHandshakeMultistream(&r, &w, ping.multistream_protocol_id, a);
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        listener.drive(recv_buf, 5) catch {};
        if (raw.unreadRecvLen() >= ping.payload_len) break;
    } else return 1;

    {
        var r = raw.reader();
        var w = raw.writer();
        try ping.handleInbound(&r, &w);
    }

    const flush_until = wall_time.milliTimestamp() + 500;
    while (wall_time.milliTimestamp() < flush_until) listener.drive(recv_buf, 5) catch {};

    std.debug.print("interop_quic_node[server]: ping ok\n", .{});
    return 0;
}

fn runClient(
    a: std.mem.Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    host: []const u8,
    port: u16,
    testcase: []const u8,
    deadline_ms: i64,
) !u8 {
    const ma_str = try std.fmt.allocPrint(a, "/ip4/{s}/udp/{d}/quic-v1", .{ host, port });
    defer a.free(ma_str);
    var ma = try multiaddr.Multiaddr.fromString(a, ma_str);
    defer ma.deinit();

    const remote_peer_str = getEnv("REMOTE_PEER_ID");
    var expected_peer: ?PeerId = null;
    if (remote_peer_str) |s| {
        expected_peer = try PeerId.fromBase58(a, s);
        std.debug.print("interop_quic_node[client]: expecting remote peer={s}\n", .{s});
    }

    std.debug.print("interop_quic_node[client]: dialing {s}:{d}\n", .{ host, port });

    var recv_buf: [65536]u8 = undefined;
    const dl = wall_time.milliTimestamp() + deadline_ms;

    var outbound = if (expected_peer != null) blk: {
        // dialExtended pumps to .connected internally + runs TLS leaf
        // verification against expected_peer (libp2p RFC 0001).
        const dial_opts = QuicOutboundDialOptions{
            .libp2p = .{
                .client_cert_path = cert_path,
                .client_key_path = key_path,
            },
            .connect_timeout_ms = @intCast(deadline_ms),
            .expected_peer = expected_peer,
        };
        break :blk dialExtended(a, ma, dial_opts) catch |err| {
            std.debug.print("interop_quic_node[client]: dialExtended err={s}\n", .{@errorName(err)});
            return 1;
        };
    } else QuicOutbound.dial(a, ma, .{
        .client_cert_path = cert_path,
        .client_key_path = key_path,
    }) catch |err| {
        std.debug.print("interop_quic_node[client]: dial err={s}\n", .{@errorName(err)});
        return 1;
    };
    defer outbound.deinit();

    if (expected_peer == null) {
        while (wall_time.milliTimestamp() < dl) {
            outbound.drive(&recv_buf, 5) catch {};
            if (outbound.client.conn.phase == .connected) break;
        }
        if (outbound.client.conn.phase != .connected) {
            std.debug.print("interop_quic_node[client]: connect timeout\n", .{});
            return 1;
        }
    }
    std.debug.print("interop_quic_node[client]: connected\n", .{});

    if (std.mem.eql(u8, testcase, "handshake")) {
        std.debug.print("interop_quic_node[client]: handshake ok\n", .{});
        return 0;
    }

    if (std.mem.eql(u8, testcase, "ping")) {
        return clientOnePingInitiator(a, &outbound, &recv_buf, dl);
    }

    if (std.mem.eql(u8, testcase, "reqresp")) {
        const payload_len = envInt(usize, "RR_PAYLOAD_LEN", default_reqresp_payload_len);
        return clientOneReqRespInitiator(a, &outbound, &recv_buf, dl, payload_len);
    }

    std.debug.print("interop_quic_node[client]: unknown TESTCASE={s}\n", .{testcase});
    return 2;
}

/// B4 client: open one bidi stream, multistream-select
/// `/interop/b4/echo/1.0.0`, send RR_PAYLOAD_LEN deterministic bytes,
/// read echo, assert match.
fn clientOneReqRespInitiator(
    a: std.mem.Allocator,
    outbound: *QuicOutbound,
    recv_buf: *[65536]u8,
    deadline_ms: i64,
    payload_len: usize,
) !u8 {
    const sid = try outbound.nextLocalBidiStream();
    var raw = RawAppBidiClient{
        .client = outbound.client,
        .stream_id = sid,
    };

    {
        var pre = std.ArrayList(u8).empty;
        defer pre.deinit(a);
        try stream_multistream.appendFirstStreamInitiatorHandshake(&pre, a, reqresp_protocol_id);
        var w = raw.writer();
        Io.Writer.writeAll(&w, pre.items) catch return 1;
        Io.Writer.flush(&w) catch return 1;
    }

    const resp_wlen = try stream_multistream.responderSuccessReplyWireLen(reqresp_protocol_id);
    while (wall_time.milliTimestamp() < deadline_ms) {
        outbound.drive(recv_buf, 5) catch {};
        if (raw.unreadRecvLen() >= resp_wlen) break;
    } else return 1;

    {
        var r = raw.reader();
        var w = raw.writer();
        try stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, reqresp_protocol_id, a);
    }

    // Deterministic payload: low-byte counter so any impl can mint the
    // same bytes for assertion. Keeps the wire byte-stable across runs.
    const req = try a.alloc(u8, payload_len);
    defer a.free(req);
    for (req, 0..) |*b, i| b.* = @intCast(i & 0xff);

    {
        var w = raw.writer();
        Io.Writer.writeAll(&w, req) catch return 1;
        Io.Writer.flush(&w) catch return 1;
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        outbound.drive(recv_buf, 5) catch {};
        if (raw.unreadRecvLen() >= payload_len) break;
    } else return 1;

    const echo = try a.alloc(u8, payload_len);
    defer a.free(echo);
    {
        var r = raw.reader();
        try Io.Reader.readSliceAll(&r, echo);
    }
    if (!std.mem.eql(u8, req, echo)) {
        std.debug.print("interop_quic_node[client]: reqresp payload mismatch\n", .{});
        return 1;
    }

    std.debug.print("interop_quic_node[client]: reqresp ok ({d} bytes)\n", .{payload_len});
    return 0;
}

fn clientOnePingInitiator(
    a: std.mem.Allocator,
    outbound: *QuicOutbound,
    recv_buf: *[65536]u8,
    deadline_ms: i64,
) !u8 {
    const sid = try outbound.nextLocalBidiStream();
    var raw = RawAppBidiClient{
        .client = outbound.client,
        .stream_id = sid,
    };

    {
        var pre = std.ArrayList(u8).empty;
        defer pre.deinit(a);
        try stream_multistream.appendFirstStreamInitiatorHandshake(&pre, a, ping.multistream_protocol_id);
        var w = raw.writer();
        Io.Writer.writeAll(&w, pre.items) catch return 1;
        Io.Writer.flush(&w) catch return 1;
    }

    const resp_wlen = try stream_multistream.responderSuccessReplyWireLen(ping.multistream_protocol_id);
    while (wall_time.milliTimestamp() < deadline_ms) {
        outbound.drive(recv_buf, 5) catch {};
        if (raw.unreadRecvLen() >= resp_wlen) break;
    } else return 1;

    {
        var r = raw.reader();
        var w = raw.writer();
        try stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, ping.multistream_protocol_id, a);
    }

    var pay: [ping.payload_len]u8 = undefined;
    ping.randomPayload(&pay);
    {
        var w = raw.writer();
        try ping.writePayload(&w, &pay);
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        outbound.drive(recv_buf, 5) catch {};
        if (raw.unreadRecvLen() >= ping.payload_len) break;
    } else return 1;

    var echo: [ping.payload_len]u8 = undefined;
    {
        var r = raw.reader();
        try ping.readPayload(&r, &echo);
    }
    if (!std.mem.eql(u8, &pay, &echo)) {
        std.debug.print("interop_quic_node[client]: ping payload mismatch\n", .{});
        return 1;
    }

    std.debug.print("interop_quic_node[client]: ping ok\n", .{});
    return 0;
}
