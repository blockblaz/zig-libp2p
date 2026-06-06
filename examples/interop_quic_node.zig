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
//! gossipsub-specific:
//!   GS_TOPIC       — pubsub topic both sides subscribe to (default "/interop/b3")
//!   GS_COUNT       — number of messages the server publishes (default 5)
//!   GS_PAYLOAD_LEN — bytes per message; deterministic content
//!
//! Exit codes:
//!   0  success
//!   1  failure (timeout / decode / mismatch)
//!   2  bad config (unknown ROLE / TESTCASE)

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

const Host = zl.host.Host;
const QuicRuntime = zl.transport.quic_runtime.QuicRuntime;
const libp2p_tls_cert = zl.security.libp2p_tls_cert;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const swarm_mod = zl.swarm;

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

    if (std.mem.eql(u8, testcase, "gossipsub")) {
        return runGossipsubInterop(a, role, cert_path, key_path, deadline_ms);
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

// ── B3 gossipsub testcase ─────────────────────────────────────────────────
//
// Wired on Host + QuicRuntime. Both sides:
//   - mint a Host with `local_peer_id` derived from SEED_HEX (same scheme
//     gen-libp2p-cert uses to mint the cert), so the peer-id on the wire
//     matches what the matrix runner exported as REMOTE_PEER_ID;
//   - spin up a QuicRuntime which owns the QUIC listener, multistream-
//     select for `/meshsub/1.1.0`, and the bidirectional pump between
//     QUIC streams and `Host.gossipsub`.
//
// Server:
//   1. Subscribe to GS_TOPIC.
//   2. Wait for a peer-connected event from the swarm event channel.
//   3. Publish GS_COUNT deterministic payloads via `host.publish`.
//   4. Stay alive briefly so the client can drain the mesh.
//
// Client:
//   1. registerKnownPeer with the server multiaddr (this is what the
//      ConnectionManager turns into a swarm `.dial` → QuicRuntime hook
//      → outbound connection).
//   2. Subscribe to GS_TOPIC.
//   3. Drain swarm events; count `gossip_message` events with payloads
//      that match the deterministic set the server publishes.

const gs_default_topic: []const u8 = "/interop/b3";
const gs_default_count: usize = 5;
const gs_default_payload_len: usize = 64;

fn gsPayload(buf: []u8, idx: usize) void {
    var header_buf: [32]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "msg-{d:0>5}:", .{idx}) catch unreachable;
    // Fill with 0x2A then overlay the header — same scheme as the go and
    // rust impls so all three speak identical bytes.
    @memset(buf, 0x2A);
    const n = @min(header.len, buf.len);
    @memcpy(buf[0..n], header[0..n]);
}

/// Derive the libp2p PeerId from a PEM cert on disk (this binary's own
/// CERT_PATH). The cert was minted with the libp2p RFC 0001 extension
/// (`gen-libp2p-cert`), so the embedded host-key signature recovers a
/// canonical peer-id. Using the cert as the source of truth means both
/// the Host's `local_peer_id` and what the matrix runner exports as
/// REMOTE_PEER_ID agree without threading SEED_HEX through every step.
fn derivePeerFromCert(a: std.mem.Allocator, cert_path: []const u8) !zl.peer_id.PeerId {
    const pem = try readFileAlloc(a, cert_path);
    defer a.free(pem);
    const der = try pemFirstCertDer(a, pem);
    defer a.free(der);
    const now_sec = @divTrunc(wall_time.milliTimestamp(), 1000);
    return try zl.security.libp2p_tls.peerIdFromVerifiedCertificate(a, der, now_sec);
}

fn readFileAlloc(a: std.mem.Allocator, path: []const u8) ![]u8 {
    // std 0.16 moved fs.cwd().readFileAlloc behind Io.Threaded — fall
    // back to libc open/read so this binary stays small.
    var path_buf: [1024]u8 = undefined;
    const z = try std.fmt.bufPrintZ(&path_buf, "{s}", .{path});
    const mode: std.c.mode_t = 0;
    const fd = std.c.open(z.ptr, .{ .ACCMODE = .RDONLY }, mode);
    if (fd < 0) return error.OpenFailed;
    defer _ = std.c.close(fd);
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(a);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = std.c.read(fd, &chunk, chunk.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try buf.appendSlice(a, chunk[0..@intCast(n)]);
    }
    return try buf.toOwnedSlice(a);
}

fn pemFirstCertDer(a: std.mem.Allocator, pem: []const u8) ![]u8 {
    const begin = std.mem.indexOf(u8, pem, "-----BEGIN CERTIFICATE-----") orelse
        return error.PemNoBegin;
    const after_begin = begin + "-----BEGIN CERTIFICATE-----".len;
    const end_rel = std.mem.indexOf(u8, pem[after_begin..], "-----END CERTIFICATE-----") orelse
        return error.PemNoEnd;
    const b64_block = pem[after_begin .. after_begin + end_rel];
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const upper = decoder.calcSizeUpperBound(b64_block.len);
    const out = try a.alloc(u8, upper);
    errdefer a.free(out);
    const n = try decoder.decode(out, b64_block);
    return try a.realloc(out, n);
}

fn runGossipsubInterop(
    a: std.mem.Allocator,
    role: []const u8,
    cert_path: []const u8,
    key_path: []const u8,
    deadline_ms: i64,
) !u8 {
    const topic = envOr("GS_TOPIC", gs_default_topic);
    const count = envInt(usize, "GS_COUNT", gs_default_count);
    const plen = envInt(usize, "GS_PAYLOAD_LEN", gs_default_payload_len);
    const is_server = std.mem.eql(u8, role, "server");
    const is_client = std.mem.eql(u8, role, "client");
    if (!is_server and !is_client) {
        std.debug.print("interop_quic_node: unknown ROLE={s}\n", .{role});
        return 2;
    }

    const me = try derivePeerFromCert(a, cert_path);
    var me_b58_buf: [128]u8 = undefined;
    const me_b58 = try me.toBase58(&me_b58_buf);
    std.debug.print("interop_quic_node[{s}]: gossipsub local_peer={s}\n", .{ role, me_b58 });

    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();
    try host.startBackground();
    if (!host.waitUntilReady(5_000)) {
        std.debug.print("interop_quic_node[{s}]: gossipsub host not ready\n", .{role});
        return 1;
    }

    // Listen on the configured port (server) or ephemeral (client) so
    // both sides can use QuicRuntime's accept + dial path uniformly.
    const listen_port: u16 = if (is_server)
        envInt(u16, "LISTEN_PORT", default_listen_port)
    else
        0;
    const listen_ma = try std.fmt.allocPrint(a, "/ip4/0.0.0.0/udp/{d}/quic-v1", .{listen_port});
    defer a.free(listen_ma);

    var rt = try QuicRuntime.create(.{
        .allocator = a,
        .host = host,
        .tls_pem = .{ .paths = .{ .cert_path = cert_path, .key_path = key_path } },
        .listen_multiaddr = listen_ma,
    });
    defer rt.destroy();
    try rt.start();

    try host.subscribe(topic);

    const dl = wall_time.milliTimestamp() + deadline_ms;

    if (is_client) {
        // Dial via ConnectionManager → swarm.dial → QuicRuntime hook.
        const server_host = envOr("SERVER_HOST", "127.0.0.1");
        const server_port = envInt(u16, "SERVER_PORT", default_listen_port);
        const remote_pid_str = getEnv("REMOTE_PEER_ID") orelse {
            std.debug.print("interop_quic_node[client]: gossipsub requires REMOTE_PEER_ID\n", .{});
            return 2;
        };
        const remote_pid = try zl.peer_id.PeerId.fromBase58(a, remote_pid_str);
        const server_ma_str = try std.fmt.allocPrint(
            a,
            "/ip4/{s}/udp/{d}/quic-v1/p2p/{s}",
            .{ server_host, server_port, remote_pid_str },
        );
        defer a.free(server_ma_str);
        var server_ma = try multiaddr.Multiaddr.fromString(a, server_ma_str);
        defer server_ma.deinit();
        try rt.registerKnownPeer(&server_ma, remote_pid);
    }

    // Role split, asymmetric vs. the go-libp2p impl:
    //
    //   QuicRuntime's `onPublishCommand` fans publishes out to every
    //   currently *outbound* peer (the dialed side of each conn). The
    //   listener side has no outbound peers and so `host.publish` from
    //   that role produces no wire traffic. To exercise gossipsub
    //   end-to-end against this codebase today, the dialer publishes
    //   and the listener subscribes. Cross-impl with go-libp2p stays
    //   gated behind the upstream zquic TLS gaps anyway, so the
    //   role-swap doesn't change today's CI surface; tracked in
    //   src/transport/quic_runtime.zig as a follow-up (let publishes
    //   reach inbound peers via `listener.server` stream open).
    //
    //   ROLE=server → subscribe, count gossip_message events, exit 0
    //   ROLE=client → subscribe, dial, wait for peer-connected +
    //                 gossipsub heartbeat, publish N msgs, exit 0
    const payload_buf = try a.alloc(u8, plen);
    defer a.free(payload_buf);

    if (is_client) {
        // Wait for the outbound conn to land before publishing — otherwise
        // QuicRuntime has no outbound_by_peer entry yet and the publish
        // fans out to an empty set.
        var saw_peer = false;
        while (wall_time.milliTimestamp() < dl and !saw_peer) {
            var ev = host.nextEvent(100) catch |err| switch (err) {
                error.Timeout => continue,
                else => return 1,
            };
            defer ev.deinit(a);
            if (std.meta.activeTag(ev) == .peer_connected) saw_peer = true;
        }
        if (!saw_peer) {
            std.debug.print("interop_quic_node[client]: gossipsub: no peer connected before deadline\n", .{});
            return 1;
        }
        // Let the gossipsub heartbeat run a couple cycles so the GRAFT
        // exchange finishes and we have a mesh edge before publishing.
        const settle_until = wall_time.milliTimestamp() + 2_000;
        while (wall_time.milliTimestamp() < settle_until) {
            var ev = host.nextEvent(100) catch |err| switch (err) {
                error.Timeout => continue,
                else => return 1,
            };
            ev.deinit(a);
        }

        var i: usize = 0;
        while (i < count) : (i += 1) {
            gsPayload(payload_buf, i);
            host.publish(topic, payload_buf) catch |err| {
                std.debug.print("interop_quic_node[client]: gossipsub publish #{d} err={s}\n", .{ i, @errorName(err) });
                return 1;
            };
        }
        std.debug.print("interop_quic_node[client]: gossipsub published {d} msgs on {s}\n", .{ count, topic });
        // Stay alive long enough for the server to drain the mesh.
        const drain_until = wall_time.milliTimestamp() + 3_000;
        while (wall_time.milliTimestamp() < drain_until) {
            var ev = host.nextEvent(100) catch |err| switch (err) {
                error.Timeout => continue,
                else => return 1,
            };
            ev.deinit(a);
        }
        std.debug.print("interop_quic_node[client]: gossipsub ok\n", .{});
        return 0;
    }

    // Server path: drain swarm events, count gossip_message arrivals
    // whose data matches one of the deterministic payloads the client
    // sends. The matcher tracks which indices have been observed to
    // tolerate dup deliveries from the gossipsub forwarding layer.
    var seen = try a.alloc(bool, count);
    defer a.free(seen);
    @memset(seen, false);
    var seen_count: usize = 0;

    while (wall_time.milliTimestamp() < dl and seen_count < count) {
        var ev = host.nextEvent(200) catch |err| switch (err) {
            error.Timeout => continue,
            else => return 1,
        };
        defer ev.deinit(a);
        switch (ev) {
            .gossip_message => |m| {
                if (!std.mem.eql(u8, m.topic, topic)) continue;
                if (m.data.len != plen) continue;
                // Find which index this is by reconstructing payloads.
                var idx: usize = 0;
                while (idx < count) : (idx += 1) {
                    gsPayload(payload_buf, idx);
                    if (std.mem.eql(u8, payload_buf, m.data)) {
                        if (!seen[idx]) {
                            seen[idx] = true;
                            seen_count += 1;
                        }
                        break;
                    }
                }
            },
            else => {},
        }
    }
    if (seen_count < count) {
        std.debug.print("interop_quic_node[server]: gossipsub got {d}/{d} msgs\n", .{ seen_count, count });
        return 1;
    }
    std.debug.print("interop_quic_node[server]: gossipsub got {d}/{d} msgs\n", .{ seen_count, count });
    std.debug.print("interop_quic_node[server]: gossipsub ok\n", .{});
    return 0;
}
