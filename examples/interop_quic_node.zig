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
//!                    "reqresp" (B4 — echo over a libp2p stream), "relay"
//!                    (circuit-v2 HOP RESERVE round-trip), or "dcutr" (CONNECT/SYNC
//!                    exchange smoke — zig self-pair only in relay_test.sh)
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

const ZIo = zquic.transport.io;
const ZIoConnState = ZIo.ConnState;

const QuicListener = zl.transport.quic_endpoint.QuicListener;
const QuicOutbound = zl.transport.quic_endpoint.QuicOutbound;
const dialExtended = zl.transport.quic_endpoint.dialExtended;
const QuicOutboundDialOptions = zl.transport.quic_endpoint.QuicOutboundDialOptions;
const PeerId = zl.peer_id.PeerId;
const RawAppBidiClient = zl.transport.quic_raw_stream_io.RawAppBidiClient;
const RawAppBidiServer = zl.transport.quic_raw_stream_io.RawAppBidiServer;
const stream_multistream = zl.transport.stream_multistream;
const ping = zl.ping;
const identify_mod = zl.identify;
const libp2p_tls = zl.security.libp2p_tls;
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

/// go-libp2p runs identify (`/ipfs/id/1.0.0`) on every new connection before app streams.
const go_identify_protocol_id: []const u8 = std.mem.trimEnd(u8, identify_mod.protocol_line, "\n");

fn appendProtobufDelimited(a: std.mem.Allocator, msg: []const u8) ![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(a);
    var v: u64 = @intCast(msg.len);
    while (v >= 0x80) {
        try list.append(a, @truncate((v & 0x7f) | 0x80));
        v >>= 7;
    }
    try list.append(a, @truncate(v));
    try list.appendSlice(a, msg);
    return try list.toOwnedSlice(a);
}

fn hostPublicKeyProtoFromCert(a: std.mem.Allocator, cert_path: []const u8) ![]const u8 {
    const pem = try readFileAlloc(a, cert_path);
    defer a.free(pem);
    const der = try pemFirstCertDer(a, pem);
    defer a.free(der);
    const ext = try libp2p_tls.findLibp2pExtensionExtValue(der);
    const sk = try libp2p_tls.parseSignedKey(ext);
    return try a.dupe(u8, sk.public_key_pb);
}

fn buildDelimitedIdentifyPayload(a: std.mem.Allocator, cert_path: []const u8) ![]u8 {
    const host_pk = try hostPublicKeyProtoFromCert(a, cert_path);
    defer a.free(host_pk);
    const protos = [_][]const u8{ go_identify_protocol_id, ping.multistream_protocol_id };
    const msg = identify_mod.MessageView{
        .public_key = host_pk,
        .protocols = &protos,
    };
    const raw = try identify_mod.encode(a, msg);
    defer a.free(raw);
    return try appendProtobufDelimited(a, raw);
}

/// Answer remote-initiated bidi streams on the client side. Handles both
/// `/ipfs/id/1.0.0` (writes our identify payload + FIN) and
/// `/ipfs/ping/1.0.0` (reads 32B, echoes, FIN). Required for cross-impl pairs
/// where the remote also opens identify / ping streams against us:
///   - go-libp2p opens identify on connection establishment.
///   - rust-libp2p `ping::Behaviour` opens outbound `/ipfs/ping/1.0.0` so its
///     own RTT measurement succeeds; without an answer the rust side
///     considers ping failed (#174).
///
/// Stateful: keeps a `RawAppBidiClient` per server-initiated bidi sid so
/// `send_offset` / `read_cursor` persist across calls. Non-blocking per call;
/// the parent re-invokes on each iteration of its own read loop, so we never
/// burn the caller's deadline spinning on already-answered streams.
const ServerBidiSids = [_]u64{ 1, 5, 9, 13, 17, 21, 25, 29 };

const InboundSlotPhase = enum { idle, ping_payload, done };
const InboundSlot = struct {
    raw: RawAppBidiClient,
    phase: InboundSlotPhase = .idle,
    ping_have: usize = 0,
    ping_payload: [ping.payload_len]u8 = undefined,
};
const InboundSlots = struct {
    slots: [ServerBidiSids.len]InboundSlot,
    initialized: bool = false,

    fn initIfNeeded(self: *InboundSlots, client: *QuicOutbound) void {
        if (self.initialized) return;
        self.initialized = true;
        for (ServerBidiSids, 0..) |sid, i| {
            self.slots[i] = .{
                .raw = .{ .client = client.client, .stream_id = sid },
            };
        }
    }
};

fn respondInboundIdentifyStreamsClient(
    outbound: *QuicOutbound,
    recv_buf: *[65536]u8,
    skip_sid: u64,
    a: std.mem.Allocator,
    identify_payload: []const u8,
    state: *InboundSlots,
) void {
    state.initIfNeeded(outbound);
    const cands = [_][]const u8{ go_identify_protocol_id, ping.multistream_protocol_id };
    outbound.drive(recv_buf, 5) catch {};
    for (ServerBidiSids, 0..) |sid, i| {
        if (sid == skip_sid) continue;
        const slot = &state.slots[i];
        if (slot.phase == .done) continue;
        if (outbound.client.rawAppRecvBuffer(sid) == null) continue;

        if (slot.phase == .idle) {
            var tail = std.ArrayList(u8).empty;
            defer tail.deinit(a);
            var r = slot.raw.reader();
            var w = slot.raw.writer();
            const which = stream_multistream.responderHandshakeMultistreamAmong(&r, &w, &cands, a, &tail) catch |err| {
                switch (err) {
                    error.DialFailed => continue, // need more bytes; try next pass
                    else => {
                        slot.phase = .done; // na sent or hard error
                        continue;
                    },
                }
            };
            if (which == 0) {
                slot.raw.writeAllFin(identify_payload);
                outbound.drive(recv_buf, 5) catch {};
                slot.phase = .done;
                return;
            }
            // ping. Stash any prefetched payload bytes.
            const have = @min(tail.items.len, ping.payload_len);
            if (have > 0) @memcpy(slot.ping_payload[0..have], tail.items[0..have]);
            slot.ping_have = have;
            slot.phase = .ping_payload;
        }

        if (slot.phase == .ping_payload) {
            // Collect the remaining bytes of the 32-byte ping payload.
            while (slot.ping_have < ping.payload_len) {
                const avail = slot.raw.unreadRecvLen();
                if (avail == 0) return; // wait for more bytes on next pass
                const need = ping.payload_len - slot.ping_have;
                const n = @min(avail, need);
                var rr = slot.raw.reader();
                Io.Reader.readSliceAll(&rr, slot.ping_payload[slot.ping_have..][0..n]) catch {
                    slot.phase = .done;
                    return;
                };
                slot.ping_have += n;
            }
            slot.raw.writeAllFin(&slot.ping_payload);
            outbound.drive(recv_buf, 5) catch {};
            slot.phase = .done;
            return;
        }
    }
}

/// Answer go-libp2p server-initiated identify streams until `until_ms`.
fn serveInboundIdentifyUntil(
    a: std.mem.Allocator,
    listener: *QuicListener,
    conn: *ZIoConnState,
    recv_buf: *[65536]u8,
    until_ms: i64,
    cert_path: []const u8,
) !void {
    const identify_payload = try buildDelimitedIdentifyPayload(a, cert_path);
    defer a.free(identify_payload);

    const Ctx = struct {
        a: std.mem.Allocator,
        pending: std.ArrayList(u64),
        fn cb(self_op: ?*anyopaque, _: *QuicListener, _: usize, _: *ZIoConnState, sid: u64) void {
            const ctx_p: *@This() = @ptrCast(@alignCast(self_op.?));
            ctx_p.pending.append(ctx_p.a, sid) catch {};
        }
    };
    var ctx = Ctx{ .a = a, .pending = .empty };
    defer ctx.pending.deinit(a);
    listener.lifecycle.ctx = &ctx;
    listener.lifecycle.on_inbound_stream_ready = Ctx.cb;

    const cands = [_][]const u8{go_identify_protocol_id};

    while (wall_time.milliTimestamp() < until_ms) {
        while (ctx.pending.items.len == 0 and wall_time.milliTimestamp() < until_ms) {
            listener.drive(recv_buf, 5) catch {};
        }
        if (ctx.pending.items.len == 0) continue;
        const sid = ctx.pending.orderedRemove(0);

        var raw = RawAppBidiServer{
            .server = listener.server,
            .conn = conn,
            .stream_id = sid,
        };

        var r = raw.reader();
        var w = raw.writer();
        negotiate: while (wall_time.milliTimestamp() < until_ms) {
            listener.drive(recv_buf, 5) catch {};
            _ = stream_multistream.responderHandshakeMultistreamAmong(&r, &w, &cands, a, null) catch |err| {
                switch (err) {
                    error.DialFailed => continue,
                    else => break :negotiate,
                }
            };
            raw.writeAllFin(identify_payload);
            const flush_until = wall_time.milliTimestamp() + 200;
            while (wall_time.milliTimestamp() < flush_until) listener.drive(recv_buf, 5) catch {};
            break;
        }
    }
}

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
        const settle = wall_time.milliTimestamp() + 2_000;
        try serveInboundIdentifyUntil(a, listener, accepted.?, &recv_buf, settle, cert_path);
        std.debug.print("interop_quic_node[server]: handshake ok\n", .{});
        return 0;
    }

    if (std.mem.eql(u8, testcase, "ping")) {
        return serveOnePingResponder(a, listener, accepted.?, &recv_buf, dl, cert_path);
    }

    if (std.mem.eql(u8, testcase, "reqresp")) {
        const payload_len = envInt(usize, "RR_PAYLOAD_LEN", default_reqresp_payload_len);
        return serveOneReqRespResponder(a, listener, accepted.?, &recv_buf, dl, payload_len);
    }

    if (std.mem.eql(u8, testcase, "relay")) {
        return serveRelayHopReserve(a, listener, accepted.?, &recv_buf, dl);
    }

    if (std.mem.eql(u8, testcase, "dcutr")) {
        return serveDcutrConnect(a, listener, accepted.?, &recv_buf, dl);
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
    // Cross-impl clients (rust-libp2p, go-libp2p) auto-open identify /
    // ping / gossipsub streams alongside the reqresp stream, and the
    // arrival order is not deterministic. Accumulate every inbound sid
    // and walk them: the first sid that negotiates
    // `/interop/b4/echo/1.0.0` wins; others get `na`. Other testcases
    // single-shot the first stream — they don't have this race because
    // the only stream the same-impl client opens IS the testcase
    // protocol.
    const ReqCtx = struct {
        a: std.mem.Allocator,
        pending: std.ArrayList(u64),
        fn cb(self_op: ?*anyopaque, _: *QuicListener, _: usize, _: *ZIoConnState, sid: u64) void {
            const ctx_p: *@This() = @ptrCast(@alignCast(self_op.?));
            ctx_p.pending.append(ctx_p.a, sid) catch {};
        }
    };
    var ctx = ReqCtx{ .a = a, .pending = .empty };
    defer ctx.pending.deinit(a);
    listener.lifecycle.ctx = &ctx;
    listener.lifecycle.on_inbound_stream_ready = ReqCtx.cb;

    const cands = [_][]const u8{reqresp_protocol_id};
    const buf = try a.alloc(u8, payload_len);
    defer a.free(buf);

    stream_loop: while (wall_time.milliTimestamp() < deadline_ms) {
        while (ctx.pending.items.len == 0 and wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
        }
        if (ctx.pending.items.len == 0) break;
        const sid = ctx.pending.orderedRemove(0);

        // Keep `raw` (and its send_offset / read_cursor) alive for the
        // entire negotiate → read → echo → flush pipeline on this sid.
        // Don't copy it out of this scope — the writer's
        // `@fieldParentPtr(&writer_buf)` is sensitive to the address.
        var raw = RawAppBidiServer{
            .server = listener.server,
            .conn = conn,
            .stream_id = sid,
        };

        var tail = std.ArrayList(u8).empty;
        defer tail.deinit(a);

        negotiate: while (wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
            var r = raw.reader();
            var w = raw.writer();
            _ = stream_multistream.responderHandshakeMultistreamAmong(&r, &w, &cands, a, &tail) catch |err| {
                switch (err) {
                    error.DialFailed => continue :negotiate, // need more bytes
                    error.ProtocolNegotiationFailed => {
                        // Send `na` (already done by the responder) then FIN
                        // our half of the stream so the peer gets a clean
                        // half-close from us. Without the FIN, the stream
                        // stays half-open and rust-libp2p / quinn treat
                        // later STREAM frames on other sids as
                        // FINAL_SIZE_ERROR-related (#184).
                        raw.writeAllFin(&.{});
                        listener.drive(recv_buf, 5) catch {};
                        continue :stream_loop;
                    },
                    else => {
                        raw.writeAllFin(&.{});
                        listener.drive(recv_buf, 5) catch {};
                        continue :stream_loop;
                    },
                }
            };
            break :negotiate;
        }
        if (wall_time.milliTimestamp() >= deadline_ms) return 1;
        std.debug.print("interop_quic_node[server]: reqresp: got stream sid={d}\n", .{sid});

        // Drain payload — copy any prefetched bytes from `tail` first,
        // then read the remainder off the wire.
        const have_in_tail = @min(tail.items.len, payload_len);
        if (have_in_tail > 0) @memcpy(buf[0..have_in_tail], tail.items[0..have_in_tail]);
        var remaining = payload_len - have_in_tail;
        while (remaining > 0 and wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
            const avail = raw.unreadRecvLen();
            if (avail == 0) continue;
            const n = @min(avail, remaining);
            var r = raw.reader();
            try Io.Reader.readSliceAll(&r, buf[payload_len - remaining ..][0..n]);
            remaining -= n;
        }
        if (remaining != 0) return 1;

        // Echo + FIN. rust-libp2p's `request_response::Codec` reads with
        // `read_to_end`, so the response is only delivered after FIN.
        raw.writeAllFin(buf);

        const flush_until = wall_time.milliTimestamp() + 3_000;
        while (wall_time.milliTimestamp() < flush_until) listener.drive(recv_buf, 5) catch {};

        std.debug.print("interop_quic_node[server]: reqresp ok ({d} bytes)\n", .{payload_len});
        return 0;
    }
    std.debug.print("interop_quic_node[server]: reqresp: no matching inbound stream\n", .{});
    return 1;
}

fn serveOnePingResponder(
    a: std.mem.Allocator,
    listener: *QuicListener,
    conn: *ZIoConnState,
    recv_buf: *[65536]u8,
    deadline_ms: i64,
    cert_path: []const u8,
) !u8 {
    const identify_payload = try buildDelimitedIdentifyPayload(a, cert_path);
    defer a.free(identify_payload);

    const Ctx = struct {
        a: std.mem.Allocator,
        pending: std.ArrayList(u64),
        fn cb(self_op: ?*anyopaque, _: *QuicListener, _: usize, _: *ZIoConnState, sid: u64) void {
            const ctx_p: *@This() = @ptrCast(@alignCast(self_op.?));
            ctx_p.pending.append(ctx_p.a, sid) catch {};
        }
    };
    var ctx = Ctx{ .a = a, .pending = .empty };
    defer ctx.pending.deinit(a);
    listener.lifecycle.ctx = &ctx;
    listener.lifecycle.on_inbound_stream_ready = Ctx.cb;

    const ping_cands = [_][]const u8{ go_identify_protocol_id, ping.multistream_protocol_id };

    stream_loop: while (wall_time.milliTimestamp() < deadline_ms) {
        while (ctx.pending.items.len == 0 and wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
        }
        if (ctx.pending.items.len == 0) break;
        const sid = ctx.pending.orderedRemove(0);
        std.debug.print("interop_quic_node[server]: ping: got stream sid={d}\n", .{sid});

        var raw = RawAppBidiServer{
            .server = listener.server,
            .conn = conn,
            .stream_id = sid,
        };

        var tail = std.ArrayList(u8).empty;
        defer tail.deinit(a);
        {
            var r = raw.reader();
            var w = raw.writer();
            var matched: ?usize = null;
            negotiate: while (wall_time.milliTimestamp() < deadline_ms) {
                listener.drive(recv_buf, 5) catch {};
                matched = stream_multistream.responderHandshakeMultistreamAmong(&r, &w, &ping_cands, a, &tail) catch |err| {
                    switch (err) {
                        error.DialFailed => continue,
                        error.ProtocolNegotiationFailed => {
                            std.debug.print("interop_quic_node[server]: ping: skip sid={d} (not ping/identify)\n", .{sid});
                            continue :stream_loop;
                        },
                        else => return 1,
                    }
                };
                break :negotiate;
            } else continue :stream_loop;

            if (matched.? == 0) {
                raw.writeAllFin(identify_payload);
                const flush_until = wall_time.milliTimestamp() + 200;
                while (wall_time.milliTimestamp() < flush_until) listener.drive(recv_buf, 5) catch {};
                std.debug.print("interop_quic_node[server]: ping: answered identify on sid={d}\n", .{sid});
                continue :stream_loop;
            }
        }

        while (wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
            if (tail.items.len + raw.unreadRecvLen() >= ping.payload_len) break;
        } else return 1;

        {
            var r = raw.reader();
            var w = raw.writer();
            ping.handleInboundPrefixed(tail.items, &r, &w) catch return 1;
        }

        const flush_until = wall_time.milliTimestamp() + 500;
        while (wall_time.milliTimestamp() < flush_until) listener.drive(recv_buf, 5) catch {};

        std.debug.print("interop_quic_node[server]: ping ok\n", .{});
        return 0;
    }
    std.debug.print("interop_quic_node[server]: ping: deadline waiting for ping stream\n", .{});
    return 1;
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
        const cross_impl = expected_peer != null;
        return clientOnePingInitiator(a, &outbound, &recv_buf, dl, cert_path, cross_impl);
    }

    if (std.mem.eql(u8, testcase, "reqresp")) {
        const payload_len = envInt(usize, "RR_PAYLOAD_LEN", default_reqresp_payload_len);
        const cross_impl = expected_peer != null;
        return clientOneReqRespInitiator(a, &outbound, &recv_buf, dl, payload_len, cross_impl);
    }

    if (std.mem.eql(u8, testcase, "relay")) {
        const relay_peer = expected_peer orelse return 2;
        return clientRelayReserve(a, &outbound, &recv_buf, dl, relay_peer);
    }

    if (std.mem.eql(u8, testcase, "dcutr")) {
        return clientDcutrExchange(a, &outbound, &recv_buf, dl);
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
    cross_impl: bool,
) !u8 {
    const sid = try outbound.nextLocalBidiStream();
    var raw = RawAppBidiClient{
        .client = outbound.client,
        .stream_id = sid,
    };

    {
        var pre = std.ArrayList(u8).empty;
        defer pre.deinit(a);
        if (cross_impl) {
            try stream_multistream.appendFirstStreamInitiatorHandshakeFramed(&pre, a, reqresp_protocol_id, zl.transport.multistream_negotiate.Framing.delimited);
        } else {
            try stream_multistream.appendFirstStreamInitiatorHandshake(&pre, a, reqresp_protocol_id);
        }
        var w = raw.writer();
        Io.Writer.writeAll(&w, pre.items) catch return 1;
        Io.Writer.flush(&w) catch return 1;
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        outbound.drive(recv_buf, 5) catch {};
        var r = raw.reader();
        var w = raw.writer();
        stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, reqresp_protocol_id, a, null) catch |err| {
            switch (err) {
                error.ProtocolNegotiationFailed, error.DialFailed => continue,
                else => return 1,
            }
        };
        break;
    } else return 1;

    // Deterministic payload: low-byte counter so any impl can mint the
    // same bytes for assertion. Keeps the wire byte-stable across runs.
    const req = try a.alloc(u8, payload_len);
    defer a.free(req);
    for (req, 0..) |*b, i| b.* = @intCast(i & 0xff);

    // FIN after the request — rust-libp2p's `request_response::Codec`
    // `read_request` is `read_to_end`, so it never returns until the
    // initiator half-closes.
    raw.writeAllFin(req);

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
    cert_path: []const u8,
    cross_impl: bool,
) !u8 {
    const identify_payload = try buildDelimitedIdentifyPayload(a, cert_path);
    defer a.free(identify_payload);

    const sid = try outbound.nextLocalBidiStream();
    var inbound_slots: InboundSlots = .{ .slots = undefined };
    respondInboundIdentifyStreamsClient(outbound, recv_buf, sid, a, identify_payload, &inbound_slots);
    var raw = RawAppBidiClient{
        .client = outbound.client,
        .stream_id = sid,
    };

    {
        var pre = std.ArrayList(u8).empty;
        defer pre.deinit(a);
        if (cross_impl) {
            try stream_multistream.appendFirstStreamInitiatorHandshakeFramed(&pre, a, ping.multistream_protocol_id, zl.transport.multistream_negotiate.Framing.delimited);
        } else {
            try stream_multistream.appendFirstStreamInitiatorHandshake(&pre, a, ping.multistream_protocol_id);
        }
        var w = raw.writer();
        Io.Writer.writeAll(&w, pre.items) catch return 1;
        Io.Writer.flush(&w) catch return 1;
    }
    outbound.drive(recv_buf, 5) catch {};

    while (wall_time.milliTimestamp() < deadline_ms) {
        outbound.drive(recv_buf, 5) catch {};
        respondInboundIdentifyStreamsClient(outbound, recv_buf, sid, a, identify_payload, &inbound_slots);
        var r = raw.reader();
        var w = raw.writer();
        stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, ping.multistream_protocol_id, a, null) catch |err| {
            switch (err) {
                error.ProtocolNegotiationFailed, error.DialFailed => continue,
                else => {
                    std.debug.print("interop_quic_node[client]: ping multistream ack parse failed: {s}\n", .{@errorName(err)});
                    return 1;
                },
            }
        };
        break;
    } else {
        std.debug.print("interop_quic_node[client]: ping multistream ack timeout\n", .{});
        return 1;
    }

    var pay: [ping.payload_len]u8 = undefined;
    ping.randomPayload(&pay);
    {
        var w = raw.writer();
        try ping.writePayload(&w, &pay);
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        outbound.drive(recv_buf, 5) catch {};
        respondInboundIdentifyStreamsClient(outbound, recv_buf, sid, a, identify_payload, &inbound_slots);
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

    // Role convention (all impls agree): dialer publishes, listener counts.
    // The zig client publishes its N deterministic payloads after a 2 s
    // settle for GRAFT; the zig server simply counts matching arrivals.
    const payload_buf = try a.alloc(u8, plen);
    defer a.free(payload_buf);

    if (is_client) {
        // Wait for outbound conn so QuicRuntime has an `outbound_by_peer`
        // entry to fan publishes out through.
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
        // 2 s settle so the gossipsub heartbeat lays the mesh edge.
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
        // Stay alive long enough for the listener to drain.
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
    // sends.
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

fn serveRelayHopReserve(
    a: std.mem.Allocator,
    listener: *QuicListener,
    conn: *ZIoConnState,
    recv_buf: *[65536]u8,
    deadline_ms: i64,
) !u8 {
    const Ctx = struct {
        a: std.mem.Allocator,
        pending: std.ArrayList(u64),
        fn cb(self_op: ?*anyopaque, _: *QuicListener, _: usize, _: *ZIoConnState, sid: u64) void {
            const ctx_p: *@This() = @ptrCast(@alignCast(self_op.?));
            ctx_p.pending.append(ctx_p.a, sid) catch {};
        }
    };
    var ctx = Ctx{ .a = a, .pending = .empty };
    defer ctx.pending.deinit(a);
    listener.lifecycle.ctx = &ctx;
    listener.lifecycle.on_inbound_stream_ready = Ctx.cb;

    const hop_cands = [_][]const u8{zl.relay.wire.hop_protocol_id};
    const OpenStub = struct {
        fn open(ctx_op: ?*anyopaque, target: zl.identity.PeerId, initiator: []const u8, limit: ?zl.relay.wire.LimitView) zl.relay.OpenStopResult {
            _ = ctx_op;
            _ = target;
            _ = initiator;
            _ = limit;
            return .ok;
        }
    };
    const relay_id = try zl.identity.PeerId.random();
    var srv = zl.relay.Server.init(a, .{
        .relay_addrs = &.{"/ip4/127.0.0.1/udp/4001/quic-v1"},
    }, relay_id, OpenStub.open);
    defer srv.deinit();

    while (wall_time.milliTimestamp() < deadline_ms) {
        while (ctx.pending.items.len == 0 and wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
        }
        if (ctx.pending.items.len == 0) return 1;
        const sid = ctx.pending.orderedRemove(0);
        var raw = RawAppBidiServer{ .server = listener.server, .conn = conn, .stream_id = sid };

        negotiate: while (wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
            if (raw.unreadRecvLen() < 2) continue;
            var r = raw.reader();
            var w = raw.writer();
            _ = stream_multistream.responderHandshakeMultistreamAmong(&r, &w, &hop_cands, a, null) catch continue;
            break :negotiate;
        } else return 1;

        while (wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
            if (raw.unreadRecvLen() < 4) continue;
            var r = raw.reader();
            var out_buf: [4096]u8 = undefined;
            var w_out = Io.Writer.fixed(&out_buf);
            const hop_peer = try zl.identity.PeerId.random();
            try srv.handleHopStream(&r, &w_out, hop_peer, false);
            var w = raw.writer();
            try Io.Writer.writeAll(&w, out_buf[0..w_out.end]);
            try Io.Writer.flush(&w);
            std.debug.print("interop_quic_node[server]: relay reserve ok\n", .{});
            return 0;
        }
    }
    return 1;
}

fn serveDcutrConnect(
    a: std.mem.Allocator,
    listener: *QuicListener,
    conn: *ZIoConnState,
    recv_buf: *[65536]u8,
    deadline_ms: i64,
) !u8 {
    const Ctx = struct {
        a: std.mem.Allocator,
        pending: std.ArrayList(u64),
        fn cb(self_op: ?*anyopaque, _: *QuicListener, _: usize, _: *ZIoConnState, sid: u64) void {
            const ctx_p: *@This() = @ptrCast(@alignCast(self_op.?));
            ctx_p.pending.append(ctx_p.a, sid) catch {};
        }
    };
    var ctx = Ctx{ .a = a, .pending = .empty };
    defer ctx.pending.deinit(a);
    listener.lifecycle.ctx = &ctx;
    listener.lifecycle.on_inbound_stream_ready = Ctx.cb;

    const cands = [_][]const u8{zl.dcutr.wire.protocol_id};
    var coord = zl.dcutr.Coordinator.init(a, .{}, .responder);
    defer coord.deinit();
    const obs = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};

    while (wall_time.milliTimestamp() < deadline_ms) {
        while (ctx.pending.items.len == 0 and wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
        }
        if (ctx.pending.items.len == 0) return 1;
        const sid = ctx.pending.orderedRemove(0);
        var raw = RawAppBidiServer{ .server = listener.server, .conn = conn, .stream_id = sid };

        negotiate: while (wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
            if (raw.unreadRecvLen() < 2) continue;
            var r = raw.reader();
            var w = raw.writer();
            _ = stream_multistream.responderHandshakeMultistreamAmong(&r, &w, &cands, a, null) catch continue;
            break :negotiate;
        } else return 1;

        while (wall_time.milliTimestamp() < deadline_ms) {
            listener.drive(recv_buf, 5) catch {};
            if (raw.unreadRecvLen() < 4) continue;
            var r = raw.reader();
            const frame = try zl.dcutr.wire.readLengthPrefixedAlloc(&r, a, zl.dcutr.wire.Limits.standard.max_frame_bytes);
            defer a.free(frame);
            const reply = try coord.onRemoteConnect(frame, &obs);
            defer a.free(reply);
            var w = raw.writer();
            try zl.dcutr.wire.writeLengthPrefixed(&w, reply);
            try Io.Writer.flush(&w);
            std.debug.print("interop_quic_node[server]: dcutr connect ok\n", .{});
            return 0;
        }
    }
    return 1;
}

fn clientRelayReserve(
    a: std.mem.Allocator,
    outbound: *QuicOutbound,
    recv_buf: *[65536]u8,
    deadline_ms: i64,
    relay_peer: PeerId,
) !u8 {
    const sid = try outbound.nextLocalBidiStream();
    var raw = RawAppBidiClient{ .client = outbound.client, .stream_id = sid };
    var client = zl.relay.Client.init(a, .{});
    defer client.deinit();

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try stream_multistream.appendFirstStreamInitiatorHandshake(&out, a, zl.relay.wire.hop_protocol_id);
    var w = raw.writer();
    try Io.Writer.writeAll(&w, out.items);
    try Io.Writer.flush(&w);

    const need = try stream_multistream.responderSuccessReplyWireLen(zl.relay.wire.hop_protocol_id);
    while (wall_time.milliTimestamp() < deadline_ms) {
        outbound.drive(recv_buf, 5) catch {};
        if (raw.unreadRecvLen() >= need) break;
    }
    var r = raw.reader();
    try stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, zl.relay.wire.hop_protocol_id, a, null);
    try client.reserveOnStream(&r, &w, relay_peer);
    std.debug.print("interop_quic_node[client]: relay reserve ok\n", .{});
    return 0;
}

fn clientDcutrExchange(
    a: std.mem.Allocator,
    outbound: *QuicOutbound,
    recv_buf: *[65536]u8,
    deadline_ms: i64,
) !u8 {
    const sid = try outbound.nextLocalBidiStream();
    var raw = RawAppBidiClient{ .client = outbound.client, .stream_id = sid };
    var coord = zl.dcutr.Coordinator.init(a, .{}, .initiator);
    defer coord.deinit();
    const obs = [_][]const u8{"/ip4/127.0.0.1/udp/4002/quic-v1"};

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try stream_multistream.appendFirstStreamInitiatorHandshake(&out, a, zl.dcutr.wire.protocol_id);
    var w = raw.writer();
    try Io.Writer.writeAll(&w, out.items);
    try Io.Writer.flush(&w);

    const need = try stream_multistream.responderSuccessReplyWireLen(zl.dcutr.wire.protocol_id);
    while (wall_time.milliTimestamp() < deadline_ms) {
        outbound.drive(recv_buf, 5) catch {};
        if (raw.unreadRecvLen() >= need) break;
    }
    var r = raw.reader();
    try stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, zl.dcutr.wire.protocol_id, a, null);
    _ = try coord.runInitiatorExchange(&r, &w, &obs);
    std.debug.print("interop_quic_node[client]: dcutr exchange ok\n", .{});
    return 0;
}
