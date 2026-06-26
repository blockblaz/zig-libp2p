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
//!
//! Issue [#37](https://github.com/ch4r10t33r/zig-libp2p/issues/37): heap dial with connect timeout + optional `/p2p` consistency
//! ([`dialMultiaddr`], [`dialExtended`]), optional [`QuicLifecycleHooks`] on [`QuicListener`], and
//! [`stream_multistream.responderHandshakeMultistreamAmong`] for per-stream multistream on the responder.
//! Issue [#16](https://github.com/ch4r10t33r/zig-libp2p/issues/16): [`dialExtended`] verifies the **server** leaf by default
//! ([`quic_peer_identity.verifiedPeerIdFromLibp2pQuicClient`]); set [`quic.Libp2pZquicClientDialOptions.client_cert_path`] / `client_key_path`
//! so mutual TLS completes. Inbound peer id: [`quic_peer_identity.verifiedPeerIdFromLibp2pQuicServerConn`].

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const peer_id_mod = @import("peer_id");

/// `MSG_DONTWAIT` for `recvfrom` (drain all datagrams already queued after `poll`).
const recv_flags_dontwait: u32 = switch (builtin.target.os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos => 0x80,
    else => 0x40,
};

/// Fairness bound on a single drive-loop recv drain. The socket recv loops below
/// previously drained `while (true)` until WouldBlock, so one connection
/// receiving a burst (a block-sync transfer, or a high-rate gossip mesh) could
/// monopolize the single drive thread for hundreds of ms — during which NO ACKs
/// are sent to any other peer, who then declare this node lost (live: outbound
/// drive phase = ~700ms/iter, all in one busy conn; peers churn). Cap the drain
/// per call; the kernel buffer (SO_RCVBUF=8MB) holds the remainder until the
/// next iteration. Well above the steady-state per-conn rate (~550 pkt/s), so it
/// only bounds bursts, never normal traffic.
const max_recv_drain_per_call: usize = 1024;
const Io = std.Io;
const shard_ring = @import("shard_ring.zig");
const multiaddr = @import("multiaddr");
const zquic = @import("zquic");
const ZIo = zquic.transport.io;
const feed_addr = @import("../zquic_feed_addr.zig");

/// Batched UDP receiver (recvmmsg). Callers allocate one per socket-reading
/// thread and pass it to `drive`/`pumpInbound`/`pollAndRouteToRings`.
pub const RecvBatch = feed_addr.RecvBatch;

const quic = @import("quic.zig");
const quic_posix_udp = @import("posix_udp.zig");
const wall_time = @import("../../primitives/wall_time.zig");
const quic_v1 = quic.quic_v1;
const quic_raw_stream_io = @import("raw_stream_io.zig");
const stream_multistream = @import("../stream_multistream.zig");
const quic_peer_identity = @import("peer_identity.zig");
const ping = @import("../../protocols/ping/ping.zig");
const libp2p_tls_cert = @import("../../security/libp2p_tls_cert.zig");

/// zquic `compat.Address` (not re-exported); layout matches [`feed_addr.Address`].
const ZquicAddress = blk: {
    const info = @typeInfo(@TypeOf(ZIo.Server.feedPacket)).@"fn";
    break :blk info.params[2].type.?;
};

fn zquicAddr(a: feed_addr.Address) ZquicAddress {
    return @bitCast(a);
}

/// Historical cap on the per-connection reported-bitset. RETAINED only as the
/// type parameter for the `over_cap` policy machinery and the legacy
/// `StaticBitSet` fields that other call sites still pass; the inbound-stream
/// discovery sweeps below no longer cap surfacing by absolute stream id — they
/// dedup with [`SurfacedStreamSet`], which is bounded by *concurrently-active*
/// streams (≤ the 64-slot raw_app recv table), not by lifetime stream id.
pub const max_tracked_peer_bidi_streams = 256;

/// Dedup state for inbound-stream discovery, bounded by the number of
/// concurrently-active server-/peer-initiated streams rather than by absolute
/// stream id. A stream only needs to be surfaced ONCE while it is live in the
/// zquic recv table (`conn.raw_app_streams` / `client.raw_app_recv`); once the
/// embedder reaps it (releasing the slot) it can never reappear in a scan, so
/// its surfaced-marker is pruned. This removes the 256-stream lifetime cap that
/// permanently buried later server-initiated req/resp streams (stream id ≥ 1024)
/// on a long-lived inbound-leg connection — the dominant secondary boundary
/// behind the live status-RPC timeout. Handles out-of-slot-order arrival because
/// membership is keyed by stream id, not slot index.
pub const SurfacedStreamSet = struct {
    ids: std.AutoHashMapUnmanaged(u64, void) = .empty,

    pub fn deinit(self: *SurfacedStreamSet, allocator: std.mem.Allocator) void {
        self.ids.deinit(allocator);
    }

    pub fn isSet(self: *const SurfacedStreamSet, stream_id: u64) bool {
        return self.ids.contains(stream_id);
    }

    /// Mark `stream_id` surfaced. Best-effort: on OOM the id is treated as
    /// un-surfaced (it may be re-reported on a later scan, which the inbound
    /// handler dedups on its own slot table) rather than failing the sweep.
    pub fn set(self: *SurfacedStreamSet, allocator: std.mem.Allocator, stream_id: u64) void {
        self.ids.put(allocator, stream_id, {}) catch {};
    }

    /// Drop every surfaced id that is no longer present among the currently
    /// active streams (`live`), so the set stays bounded by active streams.
    fn pruneToLive(self: *SurfacedStreamSet, live: []const u64) void {
        if (self.ids.count() == 0) return;
        var stale: [128]u64 = undefined;
        var n: usize = 0;
        var it = self.ids.keyIterator();
        outer: while (it.next()) |k| {
            for (live) |l| {
                if (l == k.*) continue :outer;
            }
            if (n < stale.len) {
                stale[n] = k.*;
                n += 1;
            }
        }
        for (stale[0..n]) |sid| _ = self.ids.remove(sid);
    }

    pub fn clear(self: *SurfacedStreamSet) void {
        self.ids.clearRetainingCapacity();
    }
};

/// Outcome of one stream-discovery sweep over `conn.raw_app_streams`.
///
/// `over_cap` is retained for API/observability compatibility but is now always
/// zero: inbound-stream surfacing is no longer capped by absolute stream id (see
/// [`SurfacedStreamSet`]). Embedders can still observe per-window pressure via
/// the over-cap policy on the listener.
pub const InboundStreamScan = struct {
    stream_id: ?u64 = null,
    over_cap: u32 = 0,
};

/// Next peer-initiated raw bidi stream on `conn` that has not yet been reported to
/// [`QuicLifecycleHooks.on_inbound_stream_ready`].
///
/// Use this for **listener (server-side)** connections where the remote is the QUIC client:
/// client-initiated bidi streams have IDs `0, 4, 8, …` (type bits = 00). Surfacing is
/// deduped via [`SurfacedStreamSet`] (bounded by active streams), NOT by absolute stream
/// id, so a long-lived connection that opens thousands of streams over its lifetime never
/// silently buries later ones. `over_cap` is always 0 now.
pub fn popNextUnreportedPeerBidiStream(
    allocator: std.mem.Allocator,
    conn: *ZIo.ConnState,
    reported: *SurfacedStreamSet,
) InboundStreamScan {
    var live: [64]u64 = undefined;
    var live_n: usize = 0;
    for (&conn.raw_app_streams) |*slot| {
        if (!slot.active) continue;
        if (slot.stream_id % 4 != 0) continue;
        if (live_n < live.len) {
            live[live_n] = slot.stream_id;
            live_n += 1;
        }
    }
    reported.pruneToLive(live[0..live_n]);

    for (live[0..live_n]) |sid| {
        if (reported.isSet(sid)) continue;
        reported.set(allocator, sid);
        return .{ .stream_id = sid, .over_cap = 0 };
    }
    return .{ .stream_id = null, .over_cap = 0 };
}

/// Next server-initiated raw bidi stream on a **client-side** QUIC connection that has not
/// yet been dispatched to the application.
///
/// Use this for **outbound (client-side)** connections where the remote is the QUIC server:
/// server-initiated bidi streams have IDs `1, 5, 9, …` (type bits = 01). This mirrors
/// [`popNextUnreportedPeerBidiStream`] but selects the opposite parity so that remote-opened
/// gossipsub streams on a zeam-dialled connection — and the server-initiated req/resp streams
/// of the inbound-leg fallback — are surfaced to the inbound-stream handler.
///
/// Note: STREAM frames received by a [`ZIo.Client`] land in `Client.raw_app_recv` (a
/// separate slot table from the server-side `conn.raw_app_streams`), so this helper must
/// iterate the client-side recv table — using `conn.raw_app_streams` here would never see
/// any server-initiated streams. This was the silent miss behind ethlambda → zeam gossip
/// being dropped entirely. Surfacing is deduped via [`SurfacedStreamSet`] (bounded by active
/// streams), NOT by absolute stream id, so the inbound-leg fallback's repeated
/// server-initiated streams (ids climbing past 1024) are never buried. `over_cap` is 0 now.
pub fn popNextUnreportedServerBidiStream(
    allocator: std.mem.Allocator,
    client: *ZIo.Client,
    reported: *SurfacedStreamSet,
) InboundStreamScan {
    var live: [64]u64 = undefined;
    var live_n: usize = 0;
    for (&client.raw_app_recv) |*slot| {
        if (!slot.active) continue;
        if (slot.stream_id % 4 != 1) continue; // server-initiated bidi: type bits = 01
        if (live_n < live.len) {
            live[live_n] = slot.stream_id;
            live_n += 1;
        }
    }
    reported.pruneToLive(live[0..live_n]);

    for (live[0..live_n]) |sid| {
        if (reported.isSet(sid)) continue;
        reported.set(allocator, sid);
        return .{ .stream_id = sid, .over_cap = 0 };
    }
    return .{ .stream_id = null, .over_cap = 0 };
}

/// Optional callbacks after [`QuicListener.drive`] / [`QuicListener.pollAccept`] (single-threaded embedder assumption).
pub const QuicLifecycleHooks = struct {
    ctx: ?*anyopaque = null,
    on_connection_established: ?*const fn (ctx: ?*anyopaque, slot: usize, conn: *ZIo.ConnState) void = null,
    on_connection_closed: ?*const fn (ctx: ?*anyopaque, slot: usize) void = null,
    /// Fires at most once per inbound stream id (see [`popNextUnreportedPeerBidiStream`]) after each [`QuicListener.drive`].
    on_inbound_stream_ready: ?*const fn (ctx: ?*anyopaque, listener: *QuicListener, slot: usize, conn: *ZIo.ConnState, stream_id: u64) void = null,
    /// Fires when over-cap inbound streams (those beyond the per-slot bitset) exceed
    /// [`OverCapPolicy.threshold`] inside [`OverCapPolicy.window_ms`] for a slot (#75 / #105).
    /// Embedders should close the connection on this signal — the listener itself only
    /// recommends; it does not own the transport close.
    on_inbound_stream_over_cap_breach: ?*const fn (ctx: ?*anyopaque, slot: usize, recent_skips: u32) void = null,
};

const over_cap_mod = @import("../over_cap.zig");

/// Re-export of [`over_cap_mod.Policy`] so callers configure the listener without
/// importing the helper module directly.
pub const OverCapPolicy = over_cap_mod.Policy;

pub const QuicListener = struct {
    allocator: std.mem.Allocator,
    server: *ZIo.Server,
    /// Per-slot: already surfaced by [`pollAccept`] for the current connection occupying the slot.
    seen_connected: [ZIo.MAX_CONNECTIONS]bool,
    lifecycle: QuicLifecycleHooks,
    inbound_stream_reported: [ZIo.MAX_CONNECTIONS]SurfacedStreamSet,
    /// Total inbound streams handed to [`QuicLifecycleHooks.on_inbound_stream_ready`].
    inbound_streams_reported_total: u64,
    /// Total inbound streams ignored because their id is beyond the per-slot bitset capacity
    /// (i.e. `stream_id / 4 >= max_tracked_peer_bidi_streams`). Observability for backpressure
    /// against peers that try to open more streams than we can track on a single connection.
    silently_skipped_inbound_streams_total: u64,
    /// Rate-policy state per slot — running count and the wall-clock millisecond at which
    /// the count last reset. Driven by [`OverCapPolicy`] (#105).
    over_cap_count: [ZIo.MAX_CONNECTIONS]u32,
    over_cap_window_start_ms: [ZIo.MAX_CONNECTIONS]i64,
    /// Active over-cap policy. When `threshold == 0` the policy is off.
    over_cap_policy: OverCapPolicy,
    /// Total times [`QuicLifecycleHooks.on_inbound_stream_over_cap_breach`] has fired.
    over_cap_breaches_total: u64,

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
            .lifecycle = .{},
            .inbound_stream_reported = [_]SurfacedStreamSet{.{}} ** ZIo.MAX_CONNECTIONS,
            .inbound_streams_reported_total = 0,
            .silently_skipped_inbound_streams_total = 0,
            .over_cap_count = .{0} ** ZIo.MAX_CONNECTIONS,
            .over_cap_window_start_ms = .{0} ** ZIo.MAX_CONNECTIONS,
            .over_cap_policy = .{},
            .over_cap_breaches_total = 0,
        };
        return self;
    }

    /// Build an additional listener for a multi-shard drive loop that shares an
    /// already-bound listen socket (`sock`, owned by shard 0's Server). The
    /// wrapped Server is created with `take_ownership = false`, so this
    /// listener's `deinit` closes only its own Server allocation, never the fd.
    /// Call `self.server.setShard(index, mask)` afterwards so the CIDs it mints
    /// route inbound packets back to this shard.
    pub fn listenSharingSocket(
        allocator: std.mem.Allocator,
        sock: posix.socket_t,
        port: u16,
        options: quic_v1.Libp2pZquicServerOptions,
    ) !*QuicListener {
        const srv = try quic.initLibp2pQuicServerSharingSocket(allocator, sock, port, options);
        const self = try allocator.create(QuicListener);
        self.* = .{
            .allocator = allocator,
            .server = srv,
            .seen_connected = .{false} ** ZIo.MAX_CONNECTIONS,
            .lifecycle = .{},
            .inbound_stream_reported = [_]SurfacedStreamSet{.{}} ** ZIo.MAX_CONNECTIONS,
            .inbound_streams_reported_total = 0,
            .silently_skipped_inbound_streams_total = 0,
            .over_cap_count = .{0} ** ZIo.MAX_CONNECTIONS,
            .over_cap_window_start_ms = .{0} ** ZIo.MAX_CONNECTIONS,
            .over_cap_policy = .{},
            .over_cap_breaches_total = 0,
        };
        return self;
    }

    /// Configure the rate-based over-cap policy (#105). `OverCapPolicy { .threshold = 0 }`
    /// (the default) disables it; any positive threshold enables the breach callback.
    pub fn setOverCapPolicy(self: *QuicListener, policy: OverCapPolicy) void {
        self.over_cap_policy = policy;
        self.over_cap_count = .{0} ** ZIo.MAX_CONNECTIONS;
        self.over_cap_window_start_ms = .{0} ** ZIo.MAX_CONNECTIONS;
    }

    /// Total breach callbacks emitted (#105).
    pub fn overCapBreachCount(self: *const QuicListener) u64 {
        return self.over_cap_breaches_total;
    }

    /// Total inbound stream-ready callbacks dispatched since listener init (#75).
    pub fn inboundStreamsReportedCount(self: *const QuicListener) u64 {
        return self.inbound_streams_reported_total;
    }

    /// Inbound streams whose id exceeded the per-slot tracking bitset (#75). A non-zero,
    /// monotonically growing value indicates a peer (or peers) opening more bidi streams
    /// than we can track on a single connection; either tune embedder logic to close streams
    /// promptly or treat this as a sign of abuse.
    pub fn silentlySkippedInboundStreamsCount(self: *const QuicListener) u64 {
        return self.silently_skipped_inbound_streams_total;
    }

    /// Per-connection structural cap on simultaneously-trackable peer-initiated bidi streams (#75).
    pub fn pendingInboundStreamCap(_: *const QuicListener) usize {
        return max_tracked_peer_bidi_streams;
    }

    pub fn deinit(self: *QuicListener) void {
        for (&self.inbound_stream_reported) |*r| r.deinit(self.allocator);
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
            if (self.server.conns[i] == null) {
                if (self.seen_connected[i]) {
                    if (self.lifecycle.on_connection_closed) |cb| {
                        cb(self.lifecycle.ctx, i);
                    }
                    self.inbound_stream_reported[i].clear();
                }
                self.seen_connected[i] = false;
            }
        }
    }

    fn dispatchInboundStreamCallbacks(self: *QuicListener) void {
        const cb = self.lifecycle.on_inbound_stream_ready;
        const now_ms = wall_time.milliTimestamp();
        for (0..ZIo.MAX_CONNECTIONS) |i| {
            if (!self.seen_connected[i]) continue;
            if (self.server.conns[i]) |c| {
                while (true) {
                    const scan = popNextUnreportedPeerBidiStream(self.allocator, c, &self.inbound_stream_reported[i]);
                    self.silently_skipped_inbound_streams_total += scan.over_cap;
                    if (scan.over_cap > 0) self.recordOverCap(i, scan.over_cap, now_ms);
                    const sid = scan.stream_id orelse break;
                    if (cb) |hook| {
                        hook(self.lifecycle.ctx, self, i, c, sid);
                    }
                    self.inbound_streams_reported_total += 1;
                }
            }
        }
    }

    /// Per-slot sliding-window tally for the over-cap policy. Bookkeeping math
    /// lives in [`over_cap.step`] so it is testable without a live listener.
    fn recordOverCap(self: *QuicListener, slot: usize, delta: u32, now_ms: i64) void {
        const cur = over_cap_mod.State{
            .count = self.over_cap_count[slot],
            .window_start_ms = self.over_cap_window_start_ms[slot],
        };
        const step = over_cap_mod.step(cur, delta, now_ms, self.over_cap_policy);
        self.over_cap_count[slot] = step.state.count;
        self.over_cap_window_start_ms[slot] = step.state.window_start_ms;
        if (step.breach) {
            self.over_cap_breaches_total +%= 1;
            if (self.lifecycle.on_inbound_stream_over_cap_breach) |cb| {
                cb(self.lifecycle.ctx, slot, delta);
            }
        }
    }

    /// Poll UDP (up to `poll_timeout_ms`), feed zquic, run loss recovery / flush. Call from your reactor.
    /// `rb` is a caller-owned `RecvBatch` (one per socket-reading thread); the
    /// batched `recvmmsg` drain keeps the kernel buffer from overflowing under load.
    pub fn drive(self: *QuicListener, rb: *feed_addr.RecvBatch, poll_timeout_ms: u32) DriveError!void {
        self.syncSeenFlags();
        var fds = [1]posix.pollfd{.{
            .fd = self.server.sock,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        _ = posix.poll(&fds, @intCast(poll_timeout_ms)) catch return error.PollFailed;
        if (fds[0].revents & posix.POLL.IN != 0) {
            var recv_n: usize = 0;
            while (recv_n < max_recv_drain_per_call) {
                const got = rb.recv(self.server.sock);
                if (got == 0) break;
                for (0..got) |i| {
                    const s = rb.slot(i);
                    self.server.feedPacket(s.data, zquicAddr(s.addr));
                }
                recv_n += got;
            }
        }
        self.server.processPendingWork();
        self.dispatchInboundStreamCallbacks();
    }

    // ── Sharded recv path (multi-shard drive loop) ─────────────────────────
    // The demux thread reads the shared listen socket and queues datagrams into
    // an InboundRing; the drive thread consumes them. The demux thread touches
    // only the socket + ring (never Server/ConnState), so all QUIC state stays
    // single-threaded on the drive thread. These are the ring-fed analogues of
    // `drive`/`pumpInbound`.

    /// Demux-thread side: poll the shared listen socket and copy any waiting
    /// datagrams into `ring` (drop-newest on overflow). `scratch` is a
    /// caller-owned datagram staging buffer (>= shard_ring.max_datagram_bytes).
    pub fn pollAndDrainToRing(self: *QuicListener, ring: *shard_ring.InboundRing, rb: *feed_addr.RecvBatch, poll_timeout_ms: u32) DriveError!void {
        var fds = [1]posix.pollfd{.{ .fd = self.server.sock, .events = posix.POLL.IN, .revents = 0 }};
        _ = posix.poll(&fds, @intCast(poll_timeout_ms)) catch return error.PollFailed;
        if (fds[0].revents & posix.POLL.IN == 0) return;
        var recv_n: usize = 0;
        while (recv_n < max_recv_drain_per_call) {
            const got = rb.recv(self.server.sock);
            if (got == 0) break;
            for (0..got) |i| {
                const s = rb.slot(i);
                _ = ring.push(s.data, s.addr);
            }
            recv_n += got;
        }
    }

    /// Demux-thread side, multi-shard: poll the shared listen socket and route
    /// each waiting datagram to the ring of the shard that owns its connection
    /// (`shard_ring.shardForDatagram` — short-header by tagged DCID byte, long-
    /// header by source-address hash). `rings.len` must be the shard count and
    /// `mask` = `rings.len - 1` (power of two). Drop-newest per ring on overflow.
    /// The demux thread touches only the socket + rings (never any Server), so
    /// all QUIC state stays single-threaded on each shard's drive thread.
    pub fn pollAndRouteToRings(
        self: *QuicListener,
        rings: []const *shard_ring.InboundRing,
        rb: *feed_addr.RecvBatch,
        mask: u8,
        poll_timeout_ms: u32,
    ) DriveError!void {
        var fds = [1]posix.pollfd{.{ .fd = self.server.sock, .events = posix.POLL.IN, .revents = 0 }};
        _ = posix.poll(&fds, @intCast(poll_timeout_ms)) catch return error.PollFailed;
        if (fds[0].revents & posix.POLL.IN == 0) return;
        var recv_n: usize = 0;
        while (recv_n < max_recv_drain_per_call) {
            const got = rb.recv(self.server.sock);
            if (got == 0) break;
            for (0..got) |i| {
                const s = rb.slot(i);
                const src_hash = std.hash.Wyhash.hash(0, std.mem.asBytes(&s.addr.any));
                const idx = shard_ring.shardForDatagram(s.data, src_hash, mask);
                _ = rings[idx].push(s.data, s.addr);
            }
            recv_n += got;
        }
    }

    /// Drive-thread side: consume up to `max` queued datagrams, feed each to the
    /// Server, then run pending work + surface inbound streams. Ring-fed
    /// analogue of `drive`.
    pub fn driveFromRing(self: *QuicListener, ring: *shard_ring.InboundRing, max: usize) void {
        self.syncSeenFlags();
        var n: usize = 0;
        while (n < max) : (n += 1) {
            const slot = ring.peek() orelse break;
            self.server.feedPacket(slot.buf[0..slot.len], zquicAddr(slot.addr));
            ring.pop();
        }
        self.server.processPendingWork();
        self.dispatchInboundStreamCallbacks();
    }

    /// Drive-thread side: feed up to `max` queued datagrams to the Server with no
    /// pending-work pass — ring-fed analogue of `pumpInbound`, for the
    /// interleaved inbound drains inside long phases. Returns the count drained.
    pub fn pumpFromRing(self: *QuicListener, ring: *shard_ring.InboundRing, max: usize) usize {
        var n: usize = 0;
        while (n < max) : (n += 1) {
            const slot = ring.peek() orelse break;
            self.server.feedPacket(slot.buf[0..slot.len], zquicAddr(slot.addr));
            ring.pop();
        }
        return n;
    }

    /// Non-blocking drain of the inbound UDP socket into zquic — recv +
    /// `feedPacket` only, NOT the (relatively expensive, O(conns))
    /// `processPendingWork` / callback sweep. Cheap to call repeatedly within
    /// one `driveLoop` iteration to keep the kernel receive buffer from
    /// overflowing under high inbound packet rate. On a busy 31-peer gossip
    /// mesh the single drive thread spends most of an iteration on outbound
    /// conns + stream advancement; without interleaved draining the inbound
    /// buffer (even at SO_RCVBUF=8MB) saturates and the kernel drops datagrams
    /// — including peers' ACKs — which manifests as "no ACK for 60s" teardowns
    /// and mesh churn. Recorded ACK ranges are flushed by the next `drive`'s
    /// `processPendingWork`. Returns the number of datagrams drained.
    pub fn pumpInbound(self: *QuicListener, rb: *feed_addr.RecvBatch) DriveError!usize {
        var drained: usize = 0;
        while (drained < max_recv_drain_per_call) {
            const got = rb.recv(self.server.sock);
            if (got == 0) break;
            for (0..got) |i| {
                const s = rb.slot(i);
                self.server.feedPacket(s.data, zquicAddr(s.addr));
            }
            drained += got;
        }
        return drained;
    }

    pub const AcceptedConn = struct {
        slot: usize,
        conn: *ZIo.ConnState,
    };

    /// First connection in [`ConnPhase.connected`] not yet returned here. Clears automatically when the slot is freed.
    pub fn pollAccept(self: *QuicListener) ?AcceptedConn {
        self.syncSeenFlags();
        for (0..ZIo.MAX_CONNECTIONS) |i| {
            if (self.server.conns[i]) |c| {
                if (c.phase == .connected and !self.seen_connected[i]) {
                    self.seen_connected[i] = true;
                    if (self.lifecycle.on_connection_established) |cb| {
                        cb(self.lifecycle.ctx, i, c);
                    }
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
    /// Heap-allocated batched receiver (recvmmsg) for this conn's client socket
    /// — same reason as `client`: too large to embed (QuicOutbound is sometimes
    /// stack-allocated). Gossip from peers WE dialed arrives on this outbound
    /// socket, not the listen socket; batching keeps the drive thread from
    /// falling behind and letting the kernel buffer overflow (drops -> cwnd
    /// collapse -> stalled sends).
    recv_batch: *feed_addr.RecvBatch,

    /// Parse `/udp/.../quic-v1` (IPv4), create zquic client, and send the Initial to `server_addr`.
    pub fn dial(
        allocator: std.mem.Allocator,
        ma: multiaddr.Multiaddr,
        dial_opts: quic.Libp2pZquicClientDialOptions,
    ) !QuicOutbound {
        const client = blk: {
            const p = try allocator.create(ZIo.Client);
            errdefer allocator.destroy(p);
            const ep = try quic.parseQuicV1Endpoint(ma);
            try quic.initLibp2pQuicClientInPlace(allocator, ep, dial_opts, p);
            break :blk p;
        };
        errdefer {
            client.deinit();
            allocator.destroy(client);
        }
        const ep = try quic.parseQuicV1Endpoint(ma);
        const server_addr = try compatAddressFromIp(ep.address);
        try client.startHandshake(zquicAddr(server_addr));
        const recv_batch = try allocator.create(feed_addr.RecvBatch);
        recv_batch.* = .{};
        return .{ .allocator = allocator, .client = client, .server_addr = server_addr, .recv_batch = recv_batch };
    }

    pub fn deinit(self: *QuicOutbound) void {
        self.client.deinit();
        self.allocator.destroy(self.client);
        self.allocator.destroy(self.recv_batch);
    }

    pub fn drive(self: *QuicOutbound, recv_buf: []u8, poll_timeout_ms: u32) DriveError!void {
        _ = recv_buf; // superseded by the per-conn batched receiver
        var fds = [1]posix.pollfd{.{
            .fd = self.client.sock,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        _ = posix.poll(&fds, @intCast(poll_timeout_ms)) catch return error.PollFailed;
        if (fds[0].revents & posix.POLL.IN != 0) {
            var recv_n: usize = 0;
            while (recv_n < max_recv_drain_per_call) {
                const got = self.recv_batch.recv(self.client.sock);
                if (got == 0) break;
                for (0..got) |i| {
                    self.client.feedPacket(self.recv_batch.slot(i).data);
                }
                recv_n += got;
            }
        }
        self.client.processPendingWork(zquicAddr(self.server_addr));
        // zquic defers ACKs until a recv-drain boundary; embedders must flush so
        // the server gets ACKs and continues 1-RTT transmission (see Client.flushDeferredAck).
        self.client.flushDeferredAck();
    }

    /// Recv-only drain of this conn's client socket (no poll, no pending-work
    /// pass) — the interleaved-pump analogue of `QuicListener.pumpInbound`.
    /// Keeps the outbound socket from overflowing during long drive-loop phases
    /// when the full `drive()` isn't reached often enough (gossip from a peer we
    /// dialed arrives here). `rb` is a caller-owned batch so this never aliases
    /// the conn's own `recv_batch` used by `drive()`. Flushes ACKs for the drained
    /// packets so the server keeps transmitting.
    pub fn pumpRecv(self: *QuicOutbound, rb: *feed_addr.RecvBatch) void {
        var drained: usize = 0;
        while (drained < max_recv_drain_per_call) {
            const got = rb.recv(self.client.sock);
            if (got == 0) break;
            for (0..got) |i| self.client.feedPacket(rb.slot(i).data);
            drained += got;
        }
        if (drained > 0) self.client.flushDeferredAck();
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

    /// Close the underlying QUIC connection (sends CONNECTION_CLOSE).
    pub fn closeConnection(self: *QuicOutbound) void {
        if (self.client.conn.phase != .closed) {
            self.client.closeConnection(0, "local close");
        }
    }

    /// Remote [`PeerId`](`peer_id_mod.PeerId`) from the TLS server leaf (caller owns via [`PeerId.deinit`]).
    pub fn verifiedRemotePeerId(
        self: *const QuicOutbound,
        allocator: std.mem.Allocator,
        expected_peer: ?peer_id_mod.PeerId,
        now_sec: i64,
    ) quic_peer_identity.VerifiedPeerIdFromQuicError!peer_id_mod.PeerId {
        return quic_peer_identity.verifiedPeerIdFromLibp2pQuicClient(self.client, allocator, expected_peer, now_sec);
    }

    /// Free a value produced by [`dialMultiaddr`].
    pub fn destroyAllocated(self: *QuicOutbound) void {
        const a = self.allocator;
        self.deinit();
        a.destroy(self);
    }
};

/// Options for [`dialExtended`] (connect timeout + optional PeerId consistency with multiaddr `/p2p`).
pub const QuicOutboundDialOptions = struct {
    libp2p: quic.Libp2pZquicClientDialOptions = .{},
    /// `0` means 20_000 ms.
    connect_timeout_ms: u32 = 20_000,
    /// When the multiaddr includes `/p2p`, this must match when non-null. TLS leaf verification: [#16].
    expected_peer: ?peer_id_mod.PeerId = null,
};

/// [`QuicOutbound.dial`] then block until connected or deadline (stack `recv_buf` for pumping).
pub fn dialExtended(
    allocator: std.mem.Allocator,
    ma: multiaddr.Multiaddr,
    opts: QuicOutboundDialOptions,
) !QuicOutbound {
    const ep = try quic.parseQuicV1Endpoint(ma);
    if (opts.expected_peer) |p| {
        if (ep.expected_peer) |e| {
            if (!e.eql(&p)) return error.PeerIdMismatch;
        }
    }
    var out = try QuicOutbound.dial(allocator, ma, opts.libp2p);
    errdefer out.deinit();
    var buf: [65536]u8 = undefined;
    const timeout = if (opts.connect_timeout_ms == 0) 20_000 else opts.connect_timeout_ms;
    const deadline = wall_time.milliTimestamp() + @as(i64, @intCast(timeout));
    try out.waitConnected(&buf, deadline);

    const now_sec = @divTrunc(wall_time.milliTimestamp(), 1000);
    const expected: ?peer_id_mod.PeerId = if (opts.expected_peer) |p| p else ep.expected_peer;
    _ = try quic_peer_identity.verifiedPeerIdFromLibp2pQuicClient(out.client, allocator, expected, now_sec);
    return out;
}

/// Heap-allocated [`QuicOutbound`] after QUIC is connected (issue #37 dial helper).
pub fn dialMultiaddr(allocator: std.mem.Allocator, ma: multiaddr.Multiaddr, opts: QuicOutboundDialOptions) !*QuicOutbound {
    var o = opts;
    if (o.connect_timeout_ms == 0) o.connect_timeout_ms = 20_000;
    o.connect_timeout_ms = @min(o.connect_timeout_ms, std.math.maxInt(u32));
    const p = try allocator.create(QuicOutbound);
    errdefer allocator.destroy(p);
    p.* = try dialExtended(allocator, ma, o);
    return p;
}

/// Heap [`QuicListener`] from multiaddr (alias of [`QuicListener.listen`] for issue #37 naming).
pub fn listenMultiaddr(
    allocator: std.mem.Allocator,
    ma: multiaddr.Multiaddr,
    options: quic_v1.Libp2pZquicServerOptions,
) !*QuicListener {
    return QuicListener.listen(allocator, ma, options);
}

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
    var rb: RecvBatch = .{};
    try ln.drive(&rb, 0);
    try out.drive(recv_buf, 0);
}

fn quicLoopbackOnePingOnStream(
    allocator: std.mem.Allocator,
    listener: *QuicListener,
    outbound: *QuicOutbound,
    conn: *ZIo.ConnState,
    recv_buf: []u8,
    stream_id: u64,
    deadline_ms: i64,
    responder_among: bool,
) !void {
    const init_wlen = try stream_multistream.initiatorFirstWriteWireLen(ping.multistream_protocol_id);
    const resp_wlen = try stream_multistream.responderSuccessReplyWireLen(ping.multistream_protocol_id);

    var raw_c = quic_raw_stream_io.RawAppBidiClient{
        .client = outbound.client,
        .stream_id = stream_id,
    };
    var raw_s = quic_raw_stream_io.RawAppBidiServer{
        .server = listener.server,
        .conn = conn,
        .stream_id = stream_id,
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
        try pumpBoth(listener, outbound, recv_buf);
        if (raw_s.unreadRecvLen() >= init_wlen) break;
    } else return error.Timeout;

    {
        var r = raw_s.reader();
        var w = raw_s.writer();
        if (responder_among) {
            const cands: []const []const u8 = &.{
                "/meshsub/1.1.0",
                ping.multistream_protocol_id,
            };
            const ix = try stream_multistream.responderHandshakeMultistreamAmong(&r, &w, cands, allocator, null);
            if (ix != 1) return error.InvalidData;
        } else {
            try stream_multistream.responderHandshakeMultistream(&r, &w, ping.multistream_protocol_id, allocator, null);
        }
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        try pumpBoth(listener, outbound, recv_buf);
        if (raw_c.unreadRecvLen() >= resp_wlen) break;
    } else return error.Timeout;

    {
        var r = raw_c.reader();
        var w = raw_c.writer();
        try stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, ping.multistream_protocol_id, allocator, null, null);
    }

    var pay: [ping.payload_len]u8 = undefined;
    ping.randomPayload(&pay);
    {
        var w = raw_c.writer();
        try ping.writePayload(&w, &pay);
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        try pumpBoth(listener, outbound, recv_buf);
        if (raw_s.unreadRecvLen() >= ping.payload_len) break;
    } else return error.Timeout;

    {
        var r = raw_s.reader();
        var w = raw_s.writer();
        try ping.handleInbound(&r, &w);
    }

    while (wall_time.milliTimestamp() < deadline_ms) {
        try pumpBoth(listener, outbound, recv_buf);
        if (raw_c.unreadRecvLen() >= ping.payload_len) break;
    } else return error.Timeout;

    {
        var r = raw_c.reader();
        var echo: [ping.payload_len]u8 = undefined;
        try ping.readPayload(&r, &echo);
        if (!std.mem.eql(u8, &pay, &echo)) return error.InvalidData;
    }
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

    var outbound = try QuicOutbound.dial(allocator, ma_dial, .{
        .client_cert_path = cert_path,
        .client_key_path = key_path,
    });
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
    try quicLoopbackOnePingOnStream(allocator, listener, &outbound, conn, &recv_buf, sid, deadline_ms, false);
}

/// Two local bidi streams on one QUIC connection, each with independent multistream + ping (#37).
pub fn loopbackPingTwoStreams(
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

    var outbound = try QuicOutbound.dial(allocator, ma_dial, .{
        .client_cert_path = cert_path,
        .client_key_path = key_path,
    });
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

    const s0 = try outbound.nextLocalBidiStream();
    if (s0 != 0) return error.InvalidData;
    try quicLoopbackOnePingOnStream(allocator, listener, &outbound, conn, &recv_buf, s0, deadline_ms, false);

    const s1 = try outbound.nextLocalBidiStream();
    if (s1 != 4) return error.InvalidData;
    try quicLoopbackOnePingOnStream(allocator, listener, &outbound, conn, &recv_buf, s1, deadline_ms, true);
}

const LoopbackTlsBundle = struct {
    cert_pem: []u8,
    key_pem: []u8,
    peer: peer_id_mod.PeerId,

    fn deinit(self: *LoopbackTlsBundle, a: std.mem.Allocator) void {
        a.free(self.cert_pem);
        a.free(self.key_pem);
    }
};

const LoopbackHostSigner = struct {
    kp: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
    fn sign(ctx: ?*anyopaque, message: []const u8, out_sig: []u8, out_sig_len: *usize) anyerror!void {
        const self: *LoopbackHostSigner = @ptrCast(@alignCast(ctx.?));
        const sig = try self.kp.sign(message, null);
        var buf: [std.crypto.sign.ecdsa.EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
        const der = sig.toDer(&buf);
        if (der.len > out_sig.len) return error.NoSpaceLeft;
        @memcpy(out_sig[0..der.len], der);
        out_sig_len.* = der.len;
    }
};

fn buildLoopbackLibp2pTlsCertBundle(a: std.mem.Allocator, seed: u8) !LoopbackTlsBundle {
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const host_seed = [_]u8{seed} ** 32;
    const cert_seed = [_]u8{seed +% 1} ** 32;
    const now_sec = @divTrunc(wall_time.milliTimestamp(), 1000);

    const host_kp = try EcdsaP256.KeyPair.generateDeterministic(host_seed);
    var signer = LoopbackHostSigner{ .kp = host_kp };
    const host_pub_sec1: [65]u8 = host_kp.public_key.toUncompressedSec1();

    var gen = try libp2p_tls_cert.generate(a, .{
        .host_identity = .{
            .ecdsa_p256 = .{
                .public_key_sec1_uncompressed = host_pub_sec1,
                .sign = LoopbackHostSigner.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now_sec - 3600,
        .not_after_sec = now_sec + 365 * 24 * 3600,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    const cert_pem = try libp2p_tls_cert.certDerToPem(a, gen.cert_der);
    errdefer a.free(cert_pem);
    const key_pem = try libp2p_tls_cert.ecdsaP256SeedToPem(a, gen.cert_key_seed);
    errdefer a.free(key_pem);

    const host_pub_proto = try libp2p_tls_cert.encodeEcdsaPublicKeyProto(a, host_pub_sec1);
    defer a.free(host_pub_proto);
    const reader = try peer_id_mod.PublicKeyReader.init(host_pub_proto);
    const spki_bytes = reader.getData();
    var host_pk = peer_id_mod.PublicKey{ .type = .ECDSA, .data = spki_bytes };
    const peer = try peer_id_mod.PeerId.fromPublicKey(a, &host_pk);

    return .{ .cert_pem = cert_pem, .key_pem = key_pem, .peer = peer };
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
    const cert = "fixtures/quic_loopback/cert.pem";
    const key = "fixtures/quic_loopback/key.pem";
    try loopbackPingOnce(a, cert, key);
}

test "quic endpoint loopback two streams ping (single-threaded)" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    const cert = "fixtures/quic_loopback/cert.pem";
    const key = "fixtures/quic_loopback/key.pem";
    try loopbackPingTwoStreams(a, cert, key);
}

test "quic tls remote peer id matches listener key" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var bundle = try buildLoopbackLibp2pTlsCertBundle(a, 0x51);
    defer bundle.deinit(a);

    var ma_listen = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/0/quic-v1");
    defer ma_listen.deinit();

    var listener = try QuicListener.listen(a, ma_listen, .{
        .cert_pem = bundle.cert_pem,
        .key_pem = bundle.key_pem,
    });
    defer listener.deinit();

    const port = try listener.boundUdpPortIpv4();
    const dial_str = try std.fmt.allocPrint(a, "/ip4/127.0.0.1/udp/{d}/quic-v1", .{port});
    defer a.free(dial_str);
    var ma_dial = try multiaddr.Multiaddr.fromString(a, dial_str);
    defer ma_dial.deinit();

    var outbound = try QuicOutbound.dial(a, ma_dial, .{
        .client_cert_pem = bundle.cert_pem,
        .client_key_pem = bundle.key_pem,
    });
    defer outbound.deinit();

    var recv_buf: [65536]u8 = undefined;
    var rb: RecvBatch = .{};
    const deadline_ms = wall_time.milliTimestamp() + 20_000;

    var accepted = false;
    while (wall_time.milliTimestamp() < deadline_ms) {
        try listener.drive(&rb, 50);
        try outbound.drive(&recv_buf, 50);
        if (listener.pollAccept() != null) accepted = true;
        if (accepted and outbound.client.conn.phase == .connected) break;
    } else return error.Timeout;
    try outbound.waitConnected(&recv_buf, deadline_ms);

    const want = bundle.peer;
    const now_sec = @divTrunc(wall_time.milliTimestamp(), 1000);
    const got = try outbound.verifiedRemotePeerId(a, null, now_sec);
    try std.testing.expect(got.eql(&want));
}

// Tests for [`overCapStep`] live in `wire_boundaries.zig` so they're picked up
// by the root test analyzer (this file itself is not in the test-discovery set
// because it pulls in transport modules with 0.16 drift bugs that are queued
// for a separate cleanup).
