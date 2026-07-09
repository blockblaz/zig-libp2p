//! Known-peer dial scheduling, reconnect backoff, and peer lifecycle events (#38).
//!
//! Embedders call [`ConnectionManager.tick`] with a monotonic clock and forward transport
//! callbacks into [`onConnectionEstablished`], [`onConnectionClosed`], and [`onDialFailure`].
//! Dial commands use multiaddrs with `/p2p` stripped so the transport dials by address only.
//!
//! Optional: set [`ConnectionManager.setReqResp`] so [`onConnectionClosed`] invokes
//! [`req_resp.runtime.ReqResp.onPeerDisconnected`] when the last session to a peer ends.

const std = @import("std");
const multiaddr = @import("multiaddr");
const identity = @import("../primitives/identity.zig");
const peer_events = @import("peer_events.zig");
const req_resp_runtime = @import("../protocols/req_resp/runtime.zig");
const swarm_mod = @import("swarm.zig");
const circuit_addr = @import("../protocols/relay/circuit_addr.zig");
const wall_time = @import("../primitives/wall_time.zig");

const log = std.log.scoped(.connection_manager);

pub const ConnectionId = u64;

pub const ConnectionEstablishedOptions = struct {
    via_relay: bool = false,
};

/// At most this many consecutive failures (failed dials or non-local closes) before giving up.
pub const max_reconnect_failures: u8 = 5;

const backoff_ms: [max_reconnect_failures]i64 = .{
    5000, 10000, 20000, 40000, 80000,
};

pub const PeerIdContext = struct {
    pub fn hash(_: PeerIdContext, key: identity.PeerId) u64 {
        var buf: [128]u8 = undefined;
        const b = key.toBytes(&buf) catch return 0;
        return std.hash.Wyhash.hash(0, b);
    }
    pub fn eql(_: PeerIdContext, a: identity.PeerId, b: identity.PeerId) bool {
        return a.eql(&b);
    }
};

fn reconnectDelayMs(failure_count: u8, peer: identity.PeerId) i64 {
    // Clamp to the last backoff bucket: a known peer is retried forever (we never
    // abandon a configured peer — see `tick`), so `failure_count` can exceed the
    // table length. Beyond the ramp we hold at the slowest interval (80 s).
    const idx = @min(@as(usize, failure_count) - 1, backoff_ms.len - 1);
    const base = backoff_ms[idx];
    var prng = std.Random.DefaultPrng.init(PeerIdContext.hash(.{}, peer) ^ failure_count);
    const jitter_span = @divTrunc(base, 4);
    const jitter = if (jitter_span == 0)
        @as(i64, 0)
    else
        prng.random().intRangeAtMost(i64, -jitter_span, jitter_span);
    return base + jitter;
}

const KnownState = struct {
    dial_str: []const u8,
    next_dial_deadline_ms: i64,
    /// Counts failures since the last fully established session; capped by scheduling logic.
    failure_count: u8,
    dial_inflight: bool,
    /// Set once we observe this peer deduplicating a simultaneous open (it
    /// graceful-closed our freshly-established leg — see [`onConnectionClosed`]).
    /// When set AND the tie-break makes the peer the designated dialer, [`tick`]
    /// stops racing dials against it and waits for its inbound instead, so the
    /// two ends converge on one connection without churn.
    dedups: bool = false,
};

const ConnEntry = struct {
    peer: identity.PeerId,
    direction: peer_events.Direction,
    /// Monotonic insertion order — used to pick the oldest connection during trimming (#90).
    seq: u64,
    /// Wall-clock ms when this leg established — lets [`onConnectionClosed`]
    /// recognize a peer's simultaneous-open dedup close (a graceful remote close
    /// very soon after establishing). See [`dedup_close_window_ms`].
    established_ms: i64,
};

/// A peer that closes our freshly-established leg within this window (a graceful
/// remote close) is deduplicating a duplicate connection (go/rust-libp2p and
/// lantern all do this). We stop fighting it — see [`onConnectionClosed`] and the
/// dial gate in [`tick`].
const dedup_close_window_ms: i64 = 5_000;

/// When a dedup-ing peer is the tie-break's designated dialer we normally wait
/// for its inbound instead of dialing. This is the slow safety re-arm so a peer
/// that crashed / never dials us eventually gets retried rather than stranded.
const dedup_listener_retry_ms: i64 = 60_000;

/// libp2p simultaneous-open tie-break (matches go/rust-libp2p and lantern's
/// c-lean-libp2p `connection_tie_break_prefers_inbound`): compare the two peer
/// ids as their canonical binary (multihash) byte strings, shorter-first, with
/// length as the final tiebreak. The peer with the LARGER id keeps its INBOUND
/// leg; the peer with the SMALLER id keeps its OUTBOUND leg. Both ends therefore
/// converge on keeping the single connection dialed by the smaller-id peer.
///
/// The byte encoding MUST match the peer's: `PeerId.toBytes` emits the same
/// CIDv0 multihash bytes lantern compares with `memcmp`, so both sides reach the
/// identical decision and close the same leg.
fn keepInboundOnTieBreak(local: identity.PeerId, remote: identity.PeerId) bool {
    var lbuf: [128]u8 = undefined;
    var rbuf: [128]u8 = undefined;
    const lb = local.toBytes(&lbuf) catch return false;
    const rb = remote.toBytes(&rbuf) catch return false;
    const min_len = @min(lb.len, rb.len);
    return switch (std.mem.order(u8, lb[0..min_len], rb[0..min_len])) {
        .gt => true,
        .lt => false,
        .eq => lb.len > rb.len,
    };
}

/// Connection-limit knobs (libp2p connection manager profile, #90).
///
/// `null` for any field disables the corresponding policy. The default keeps the
/// old un-capped behaviour so this is opt-in.
pub const ConnectionLimits = struct {
    /// Maximum concurrent connections to a single peer; excess connections are
    /// surfaced as [`swarm.Event.connection_trim_recommended`] with
    /// [`swarm.TrimReason.over_per_peer_cap`].
    max_per_peer: ?u32 = null,
    /// Hard cap on the total active connections kept open. The manager only
    /// emits trim recommendations *after* `high_watermark` is crossed; the
    /// embedder remains responsible for actual close.
    max_total: ?u32 = null,
    /// Trimming wakes up when `total >= high_watermark` …
    high_watermark: ?u32 = null,
    /// … and stops once we've shaved enough oldest connections to bring total
    /// back to `low_watermark`. Must be ≤ `high_watermark`.
    low_watermark: ?u32 = null,
    /// How long a trim recommendation blocks re-recommendation for the same
    /// connection before the grace window expires ([#210](https://github.com/blockblaz/zig-libp2p/issues/210)).
    trim_grace_ms: i64 = 30_000,
};

/// Snapshot of dial scheduling state for a known peer (tests and diagnostics, #38).
pub const KnownPeerDialStatus = struct {
    failure_count: u8,
    next_dial_deadline_ms: i64,
    dial_inflight: bool,
};

pub const ConnectionManager = struct {
    allocator: std.mem.Allocator,
    swarm: *swarm_mod.Swarm,
    /// When set, [`onConnectionClosed`] calls [`req_resp.runtime.ReqResp.onPeerDisconnected`] if the
    /// peer drops to zero active connections.
    req_resp: ?*req_resp_runtime.ReqResp = null,
    /// Connection-limit policy (#90).
    limits: ConnectionLimits = .{},

    known: std.HashMap(identity.PeerId, KnownState, PeerIdContext, std.hash_map.default_max_load_percentage),
    conns: std.AutoHashMap(ConnectionId, ConnEntry),
    peer_active: std.HashMap(identity.PeerId, u32, PeerIdContext, std.hash_map.default_max_load_percentage),
    /// Monotonic counter assigned to each [`onConnectionEstablished`]; used to pick
    /// the oldest connection for trim recommendations (#90).
    next_seq: u64 = 0,
    /// Peers exempt from trim recommendations (bootnodes, direct peers) ([#210](https://github.com/blockblaz/zig-libp2p/issues/210)).
    protected_peers: std.HashMap(identity.PeerId, void, PeerIdContext, std.hash_map.default_max_load_percentage),
    /// Conns with an outstanding trim recommendation and when that flag expires ([#210](https://github.com/blockblaz/zig-libp2p/issues/210)).
    trim_recommended: std.AutoHashMap(ConnectionId, i64),
    /// Total trim recommendations emitted across both reason codes (#90 observability).
    trim_recommendations_total: u64 = 0,

    /// Our own peer id. Required for the simultaneous-open dedup tie-break
    /// ([`keepInboundOnTieBreak`]); when null the dial gate is disabled (no
    /// decision can be made without knowing which side we are).
    local_peer: ?identity.PeerId = null,

    pub fn init(allocator: std.mem.Allocator, s: *swarm_mod.Swarm) ConnectionManager {
        return .{
            .allocator = allocator,
            .swarm = s,
            .known = .init(allocator),
            .conns = .init(allocator),
            .peer_active = .init(allocator),
            .protected_peers = .init(allocator),
            .trim_recommended = .init(allocator),
        };
    }

    /// Set our own peer id, enabling the simultaneous-open dedup dial gate. Call
    /// once at setup.
    pub fn setLocalPeer(self: *ConnectionManager, peer: identity.PeerId) void {
        self.local_peer = peer;
    }

    /// Mark `peer` exempt from trim recommendations until [`unprotect`].
    pub fn protect(self: *ConnectionManager, peer: identity.PeerId) !void {
        try self.protected_peers.put(peer, {});
    }

    /// Clear trim protection previously set via [`protect`].
    pub fn unprotect(self: *ConnectionManager, peer: identity.PeerId) void {
        _ = self.protected_peers.remove(peer);
    }

    fn isProtected(self: *const ConnectionManager, peer: identity.PeerId) bool {
        return self.protected_peers.contains(peer);
    }

    fn trimRecommendedActive(self: *const ConnectionManager, cid: ConnectionId, now_ms: i64) bool {
        const expires_at = self.trim_recommended.get(cid) orelse return false;
        return expires_at > now_ms;
    }

    fn sweepTrimGrace(self: *ConnectionManager, now_ms: i64) void {
        var expired = std.ArrayList(ConnectionId).empty;
        defer expired.deinit(self.allocator);
        var it = self.trim_recommended.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* <= now_ms) {
                expired.append(self.allocator, e.key_ptr.*) catch {
                    _ = self.trim_recommended.remove(e.key_ptr.*);
                };
            }
        }
        for (expired.items) |cid| _ = self.trim_recommended.remove(cid);
    }

    fn recommendTrim(
        self: *ConnectionManager,
        cid: ConnectionId,
        peer: identity.PeerId,
        reason: swarm_mod.TrimReason,
        now_ms: i64,
    ) !void {
        try self.trim_recommended.put(cid, now_ms + self.limits.trim_grace_ms);
        self.trim_recommendations_total += 1;
        try self.swarm.queueEvent(.{ .connection_trim_recommended = .{
            .peer = peer,
            .conn_id = cid,
            .reason = reason,
        } });
    }

    pub fn setLimits(self: *ConnectionManager, limits: ConnectionLimits) void {
        self.limits = limits;
    }

    /// Total active connections currently tracked (#90).
    pub fn activeConnectionCount(self: *const ConnectionManager) usize {
        return self.conns.count();
    }

    /// Number of trim recommendations emitted since init (#90).
    pub fn trimRecommendationCount(self: *const ConnectionManager) u64 {
        return self.trim_recommendations_total;
    }

    pub fn deinit(self: *ConnectionManager) void {
        var it = self.known.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.value_ptr.dial_str);
        }
        self.known.deinit();
        self.conns.deinit();
        self.peer_active.deinit();
        self.protected_peers.deinit();
        self.trim_recommended.deinit();
    }

    pub fn setReqResp(self: *ConnectionManager, rr: ?*req_resp_runtime.ReqResp) void {
        self.req_resp = rr;
    }

    fn peerActiveCount(self: *ConnectionManager, peer: identity.PeerId) u32 {
        return self.peer_active.get(peer) orelse 0;
    }

    pub fn hasActiveConnection(self: *ConnectionManager, peer: identity.PeerId) bool {
        return self.peerActiveCount(peer) > 0;
    }

    /// Invoke `cb` for each peer with at least one active connection (#202).
    pub fn forEachConnectedPeer(
        self: *const ConnectionManager,
        ctx: anytype,
        comptime cb: fn (ctx: @TypeOf(ctx), peer: identity.PeerId) void,
    ) void {
        var it = self.peer_active.keyIterator();
        while (it.next()) |kp| cb(ctx, kp.*);
    }

    /// Append all currently connected peers to `out` (#202).
    pub fn collectConnectedPeers(
        self: *const ConnectionManager,
        out: *std.ArrayList(identity.PeerId),
    ) std.mem.Allocator.Error!void {
        var it = self.peer_active.keyIterator();
        while (it.next()) |kp| try out.append(self.allocator, kp.*);
    }

    /// Inferred from [`multiaddrDialString`] plus the local error tags. The dependency's
    /// `ProtocolIterator.next` error set drifted in Zig 0.16, so we let the compiler
    /// infer it rather than spell out every transitively-added variant.
    pub const RegisterError = error{
        PeerIdMismatch,
        KnownPeerRequiresPeerId,
    } || @typeInfo(@typeInfo(@TypeOf(multiaddrDialString)).@"fn".return_type.?).error_union.error_set;

    /// Registers interest in a peer. The dial string is the multiaddr without any `/p2p` segment.
    /// Either the multiaddr must end with `/p2p/<id>` or `peer_override` must be set.
    ///
    /// Submits the first dial **synchronously** when the peer isn't already connected
    /// so the first mesh formation isn't gated on the next periodic tick (~100ms in the
    /// reference reactor). Subsequent failed dials are still rate-limited by
    /// [`backoff_ms`] on the [`onDialFailure`] path.
    pub fn registerKnownPeer(
        self: *ConnectionManager,
        ma: *const multiaddr.Multiaddr,
        peer_override: ?identity.PeerId,
    ) RegisterError!void {
        const from_addr = peerIdFromMultiaddr(ma);
        if (peer_override) |o| {
            if (from_addr) |f| {
                if (!o.eql(&f)) return error.PeerIdMismatch;
            }
        }
        const effective = peer_override orelse from_addr orelse return error.KnownPeerRequiresPeerId;

        const dial_str = try multiaddrDialString(self.allocator, ma);
        errdefer self.allocator.free(dial_str);

        const gop = try self.known.getOrPut(effective);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.dial_str);
        }
        gop.value_ptr.* = .{
            .dial_str = dial_str,
            .next_dial_deadline_ms = 0,
            .failure_count = 0,
            .dial_inflight = false,
        };
        if (self.peerActiveCount(effective) > 0) {
            gop.value_ptr.next_dial_deadline_ms = std.math.maxInt(i64);
            return;
        }

        // Eager first dial: don't wait for the next periodic tick. On a fresh
        // bootnode registration this shaves ~100ms (one reactor cycle) off
        // cold-start mesh-formation latency, which matters when block proposal
        // can fire as early as slot 0+0s. Submit failures (queue full /
        // shutting down) are non-fatal — the peer stays in `known` with
        // deadline=0 and the next `tick` will retry. We deliberately do NOT
        // propagate submit errors out of `registerKnownPeer` so a transient
        // queue-full does not undo a successful peer registration.
        self.swarm.submit(.{ .dial = .{ .addr = gop.value_ptr.dial_str, .expected_peer = effective } }) catch return;
        gop.value_ptr.dial_inflight = true;
        gop.value_ptr.next_dial_deadline_ms = std.math.maxInt(i64);
    }

    /// Submits [`swarm_mod.SwarmCommand.dial`] for due peers. `now_ms` must be comparable
    /// deadlines from [`onDialFailure`] / [`onConnectionClosed`].
    pub fn knownPeerStatus(self: *const ConnectionManager, peer: identity.PeerId) ?KnownPeerDialStatus {
        const st = self.known.get(peer) orelse return null;
        return .{
            .failure_count = st.failure_count,
            .next_dial_deadline_ms = st.next_dial_deadline_ms,
            .dial_inflight = st.dial_inflight,
        };
    }

    pub fn tick(self: *ConnectionManager, now_ms: i64) swarm_mod.SubmitError!void {
        self.sweepTrimGrace(now_ms);

        if (self.limits.high_watermark) |hi| {
            const low = self.limits.low_watermark orelse hi;
            if (self.conns.count() >= hi) {
                try self.trimOldestDownTo(low, now_ms);
            }
        }

        var it = self.known.iterator();
        while (it.next()) |e| {
            const peer = e.key_ptr.*;
            const st = e.value_ptr;
            if (self.peerActiveCount(peer) > 0) continue;
            if (st.dial_inflight) continue;
            // No abandonment for known (configured) peers. The validator/bootstrap
            // set is static, so a peer we never reach is a peer we must keep
            // chasing: on a fleet-wide restart every node dials every other at
            // once, the QUIC Initial handshakes time out under contention, and a
            // hard cap (formerly `failure_count >= max_reconnect_failures`) would
            // permanently drop ~a third of the mesh right as congestion clears —
            // sinking it below the 2/3 attestation quorum. Backoff still throttles
            // (capped at the slowest bucket via `reconnectDelayMs`).
            if (st.next_dial_deadline_ms > now_ms) continue;

            // Simultaneous-open dedup gate: if this peer deduplicates (it
            // fast-closed our leg before — see `onConnectionClosed`) AND the
            // tie-break makes IT the designated dialer (peer id < ours → it keeps
            // its outbound = our inbound), stop racing dials against it. Dialing
            // would just recreate the duplicate it closes, churning forever; we
            // wait for its inbound instead. Both ends run the identical tie-break,
            // so exactly one side dials → one stable connection. A slow safety
            // re-arm still retries eventually if the peer never dials us.
            if (st.dedups) {
                if (self.local_peer) |lp| {
                    if (keepInboundOnTieBreak(lp, peer)) {
                        st.next_dial_deadline_ms = now_ms + dedup_listener_retry_ms;
                        continue;
                    }
                }
            }

            try self.swarm.submit(.{ .dial = .{ .addr = st.dial_str, .expected_peer = peer } });
            st.dial_inflight = true;
            st.next_dial_deadline_ms = std.math.maxInt(i64);
        }
    }

    pub fn onDialFailure(
        self: *ConnectionManager,
        now_ms: i64,
        conn_id: ConnectionId,
        peer: ?identity.PeerId,
        direction: peer_events.Direction,
        result: peer_events.ConnectionFailureResult,
    ) !void {
        _ = conn_id;
        try self.swarm.queueEvent(.{ .peer_connection_failed = .{
            .peer = peer,
            .direction = direction,
            .result = result,
        } });

        if (peer) |p| {
            if (self.known.getPtr(p)) |st| {
                st.dial_inflight = false;
                st.failure_count +|= 1;
                // Always re-arm: known peers are retried forever (capped backoff).
                st.next_dial_deadline_ms = now_ms + reconnectDelayMs(st.failure_count, p);
            }
        }
    }

    pub fn onConnectionEstablished(
        self: *ConnectionManager,
        conn_id: ConnectionId,
        peer: identity.PeerId,
        direction: peer_events.Direction,
        opts: ConnectionEstablishedOptions,
    ) !void {
        if (self.known.getPtr(peer)) |st| {
            st.dial_inflight = false;
            st.failure_count = 0;
            st.next_dial_deadline_ms = std.math.maxInt(i64);
        }

        const now_ms = wall_time.milliTimestamp();
        const seq = self.next_seq;
        self.next_seq += 1;
        try self.conns.put(conn_id, .{
            .peer = peer,
            .direction = direction,
            .seq = seq,
            .established_ms = now_ms,
        });

        const gop = try self.peer_active.getOrPut(peer);
        const prev = if (gop.found_existing) gop.value_ptr.* else 0;
        gop.value_ptr.* = prev + 1;
        if (prev == 0) {
            try self.swarm.queueEvent(.{ .peer_connected = .{
                .peer = peer,
                .direction = direction,
                .via_relay = opts.via_relay,
            } });
        }

        // Per-peer cap: if this connection puts us over `max_per_peer`, recommend
        // closing the oldest connection to that peer (#90).
        if (self.limits.max_per_peer) |cap| {
            if (gop.value_ptr.* > cap) {
                try self.recommendOldestForPeer(peer, .over_per_peer_cap, now_ms);
            }
        }

        // Global watermark: once `high_watermark` is breached, trim oldest down to
        // `low_watermark`.
        if (self.limits.high_watermark) |hi| {
            const low = self.limits.low_watermark orelse hi;
            if (self.conns.count() >= hi) {
                try self.trimOldestDownTo(low, now_ms);
            }
        }
    }

    fn recommendOldestForPeer(self: *ConnectionManager, peer: identity.PeerId, reason: swarm_mod.TrimReason, now_ms: i64) !void {
        if (self.isProtected(peer)) return;
        var pick_id: ?ConnectionId = null;
        var pick_seq: u64 = std.math.maxInt(u64);
        var it = self.conns.iterator();
        while (it.next()) |e| {
            const cid = e.key_ptr.*;
            const ent = e.value_ptr.*;
            if (!ent.peer.eql(&peer)) continue;
            if (self.trimRecommendedActive(cid, now_ms)) continue;
            if (ent.seq < pick_seq) {
                pick_seq = ent.seq;
                pick_id = cid;
            }
        }
        const cid = pick_id orelse return;
        try self.recommendTrim(cid, peer, reason, now_ms);
    }

    fn trimOldestDownTo(self: *ConnectionManager, target: u32, now_ms: i64) !void {
        // We may issue several recommendations per breach; cap the loop by the
        // current live conn count to avoid runaway.
        var safety: usize = self.conns.count();
        while (safety > 0) : (safety -= 1) {
            const live_unrecommended = blk: {
                var n: usize = 0;
                var it = self.conns.iterator();
                while (it.next()) |e| {
                    const ent = e.value_ptr.*;
                    if (self.isProtected(ent.peer)) continue;
                    if (self.trimRecommendedActive(e.key_ptr.*, now_ms)) continue;
                    n += 1;
                }
                break :blk n;
            };
            if (live_unrecommended <= target) return;

            // Pick globally-oldest non-recommended, non-protected conn.
            var pick_id: ?ConnectionId = null;
            var pick_peer: identity.PeerId = undefined;
            var pick_seq: u64 = std.math.maxInt(u64);
            var it = self.conns.iterator();
            while (it.next()) |e| {
                const ent = e.value_ptr.*;
                if (self.isProtected(ent.peer)) continue;
                if (self.trimRecommendedActive(e.key_ptr.*, now_ms)) continue;
                if (ent.seq < pick_seq) {
                    pick_seq = ent.seq;
                    pick_id = e.key_ptr.*;
                    pick_peer = ent.peer;
                }
            }
            const cid = pick_id orelse {
                log.warn("trimOldestDownTo: all live connections are protected or grace-flagged; cannot trim further", .{});
                return;
            };
            try self.recommendTrim(cid, pick_peer, .over_global_watermark, now_ms);
        }
    }

    /// Returns `true` iff this close removed the peer's LAST connection (the
    /// peer is now fully disconnected, `peer_active` reached 0). The Host gates
    /// peer-level teardown (gossipsub.onPeerDisconnected, peer_protocols, kad)
    /// on this — a single leg closing while another leg is still up must NOT
    /// wipe peer-level state (e.g. gossipsub `remote_interest`), or sparse
    /// subnet meshes permanently bleed members on every leg flap.
    pub fn onConnectionClosed(
        self: *ConnectionManager,
        now_ms: i64,
        conn_id: ConnectionId,
        reason: peer_events.DisconnectReason,
    ) !bool {
        const ent = self.conns.fetchRemove(conn_id) orelse {
            // Defensive: a close arrived for a conn we never recorded (or
            // already removed via a prior close). Without this log, a
            // double-close races silently and the embedder sees a wedged
            // publish path with no clue why no `peer_disconnected` ever
            // fired (the gossip-asymmetry bug observed against quinn).
            log.warn(
                "onConnectionClosed: unknown conn_id={d} reason={s} (already closed or never registered)",
                .{ conn_id, @tagName(reason) },
            );
            return false;
        };
        const peer = ent.value.peer;
        const direction = ent.value.direction;
        _ = self.trim_recommended.remove(conn_id);

        const pr = self.peer_active.getPtr(peer) orelse {
            log.warn(
                "onConnectionClosed: conn_id={d} dir={s} but peer not in peer_active map (skew)",
                .{ conn_id, @tagName(direction) },
            );
            return false;
        };
        if (pr.* == 0) {
            // Would underflow — peer_active was already 0 when we still had
            // a `conns` entry. Means the maps are out of sync, log and
            // bail rather than wrapping to u32_max.
            log.warn(
                "onConnectionClosed: conn_id={d} dir={s} peer_active already 0 (map skew); removing entry",
                .{ conn_id, @tagName(direction) },
            );
            _ = self.peer_active.remove(peer);
            return false;
        }
        pr.* -= 1;
        const count = pr.*;
        log.info(
            "onConnectionClosed: conn_id={d} dir={s} reason={s} peer_active_after={d}",
            .{ conn_id, @tagName(direction), @tagName(reason), count },
        );

        // Simultaneous-open dedup detection: a graceful REMOTE close of a leg we
        // established only moments ago is the signature of a peer deduplicating a
        // duplicate connection (go/rust-libp2p and lantern all do this). Mark the
        // peer so [`tick`] stops racing dials against it and lets the tie-break's
        // designated dialer own the single surviving connection — otherwise we
        // redial straight back into the same race and churn forever
        // (issue_lantern_dedup_simopen_not_cert). zeam↔zeam is unaffected: peers
        // that keep both legs never fast-close ours, so `dedups` stays false and
        // the multi-leg behavior is preserved.
        if (self.local_peer != null and reason == .remote_close and
            (now_ms - ent.value.established_ms) < dedup_close_window_ms)
        {
            if (self.known.getPtr(peer)) |st| {
                if (!st.dedups) {
                    st.dedups = true;
                    log.info(
                        "onConnectionClosed: peer dedups (remote close {d}ms after establish); dial now tie-break-gated",
                        .{now_ms - ent.value.established_ms},
                    );
                }
            }
        }

        if (count == 0) {
            _ = self.peer_active.remove(peer);
            try self.swarm.queueEvent(.{ .peer_disconnected = .{
                .peer = peer,
                .direction = direction,
                .reason = reason,
            } });

            if (self.req_resp) |rr| {
                try rr.onPeerDisconnected(peer);
            }

            if (reason != .local_close) {
                if (self.known.getPtr(peer)) |st| {
                    st.dial_inflight = false;
                    st.failure_count +|= 1;
                    // Always re-arm: known peers are retried forever (capped backoff).
                    st.next_dial_deadline_ms = now_ms + reconnectDelayMs(st.failure_count, peer);
                }
            }
        } else if (direction == .outbound and reason != .local_close) {
            // Outbound leg died but an inbound leg is still up (count > 0).
            // Since zig-libp2p#214 the persistent /meshsub publish stream falls
            // back to the inbound connection
            // (`quic_runtime.ensurePersistentGossipStream`), so losing the
            // outbound no longer breaks gossip publish to this peer — we must
            // NOT eagerly resubmit the dial. Doing so recreated a duplicate
            // connection that the peer immediately remote-closed, looping
            // indefinitely (the duplicate-connection churn this issue fixes).
            // The peer stays reachable over the inbound leg; if it later drops
            // too, the `count == 0` branch above applies the normal reconnect
            // backoff.
            log.debug(
                "onConnectionClosed: outbound died for known peer (inbound still up, count={d}); publish falls back to inbound, no redial",
                .{count},
            );
        }
        return count == 0;
    }
};

fn peerIdFromMultiaddr(ma: *const multiaddr.Multiaddr) ?identity.PeerId {
    var iter = ma.iterator();
    var last: ?identity.PeerId = null;
    while (iter.next() catch return null) |proto| {
        switch (proto) {
            .P2P => |id| last = id,
            else => {},
        }
    }
    return last;
}

fn multiaddrDialString(allocator: std.mem.Allocator, ma: *const multiaddr.Multiaddr) ![]u8 {
    if (circuit_addr.isCircuit(ma)) {
        var split = try circuit_addr.splitCircuit(allocator, ma);
        defer split.deinit();
        return try split.toString(allocator);
    }
    var out = multiaddr.Multiaddr.init(allocator);
    defer out.deinit();
    var iter = ma.iterator();
    while (try iter.next()) |proto| {
        if (proto == .P2P) continue;
        try out.push(proto);
    }
    return try out.toString(allocator);
}

test "strip p2p from dial string" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    const s = try multiaddrDialString(a, &ma);
    defer a.free(s);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/udp/4001/quic-v1", s);
}

test "circuit multiaddr dial string preserves p2p-circuit path" {
    const a = std.testing.allocator;
    const relay = try identity.PeerId.random();
    const target = try identity.PeerId.random();
    var relay_ma = try multiaddr.Multiaddr.fromString(a, "/ip4/203.0.113.1/udp/4001/quic-v1");
    defer relay_ma.deinit();
    try relay_ma.push(.{ .P2P = relay });
    var circuit_ma = try circuit_addr.RelayedAddr.build(a, &relay_ma, target);
    defer circuit_ma.deinit();
    const s = try multiaddrDialString(a, &circuit_ma);
    defer a.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "/p2p-circuit") != null);
}

test "forEachConnectedPeer and collectConnectedPeers" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();

    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();

    const peer_a = try identity.PeerId.random();
    const peer_b = try identity.PeerId.random();
    try cm.onConnectionEstablished(1, peer_a, .outbound, .{});
    try cm.onConnectionEstablished(2, peer_b, .inbound, .{});

    var count: usize = 0;
    const Ctx = struct {
        var n: *usize = undefined;
        fn cb(ctx: *usize, _: identity.PeerId) void {
            ctx.* += 1;
        }
    };
    Ctx.n = &count;
    cm.forEachConnectedPeer(&count, Ctx.cb);
    try std.testing.expectEqual(@as(usize, 2), count);

    var peers: std.ArrayList(identity.PeerId) = .empty;
    defer peers.deinit(a);
    try cm.collectConnectedPeers(&peers);
    try std.testing.expectEqual(@as(usize, 2), peers.items.len);
}

test "connection manager emits single peer_connected for two conns" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();

    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();

    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    try cm.registerKnownPeer(&ma, null);

    const peer = peerIdFromMultiaddr(&ma).?;

    try cm.onConnectionEstablished(1, peer, .outbound, .{});
    try cm.onConnectionEstablished(2, peer, .inbound, .{});

    var ev1 = try swarm.nextEvent(100);
    defer ev1.deinit(a);
    try std.testing.expectEqual(@as(std.meta.Tag(swarm_mod.Event), .peer_connected), std.meta.activeTag(ev1));
    try std.testing.expect(ev1.peer_connected.peer.eql(&peer));
    try std.testing.expectEqual(@as(peer_events.Direction, .outbound), ev1.peer_connected.direction);

    try std.testing.expectError(error.Timeout, swarm.nextEvent(20));

    _ = try cm.onConnectionClosed(1000, 1, .remote_close);
    try std.testing.expectError(error.Timeout, swarm.nextEvent(20));

    _ = try cm.onConnectionClosed(1000, 2, .remote_close);

    var ev2 = try swarm.nextEvent(100);
    defer ev2.deinit(a);
    try std.testing.expectEqual(@as(std.meta.Tag(swarm_mod.Event), .peer_disconnected), std.meta.activeTag(ev2));
    try std.testing.expect(ev2.peer_disconnected.peer.eql(&peer));
    try std.testing.expectEqual(@as(peer_events.Direction, .inbound), ev2.peer_disconnected.direction);
}

test "onConnectionClosed reports fully-disconnected only on the LAST leg (multi-leg gossipsub-state guard)" {
    // Regression: the Host gates gossipsub.onPeerDisconnected (which wipes
    // remote_interest / mesh membership) on this return. A peer with two legs
    // (inbound + outbound, common under sharding) losing ONE leg must report
    // false, or sparse subnet meshes bleed a member on every leg flap and the
    // heartbeat can never re-graft them -> coverage decays -> finality stalls.
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;
    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();
    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();

    const peer = try identity.PeerId.random();
    try cm.onConnectionEstablished(1, peer, .outbound, .{});
    try cm.onConnectionEstablished(2, peer, .inbound, .{});

    // One leg down, other still up -> NOT fully disconnected.
    try std.testing.expectEqual(false, try cm.onConnectionClosed(1000, 1, .remote_close));
    // Last leg down -> fully disconnected.
    try std.testing.expectEqual(true, try cm.onConnectionClosed(1000, 2, .remote_close));
    // Duplicate/unknown close -> false (no spurious peer teardown).
    try std.testing.expectEqual(false, try cm.onConnectionClosed(1000, 2, .remote_close));
}

test "tick submits dial after remote close backoff" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();

    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    try cm.registerKnownPeer(&ma, null);
    const peer = peerIdFromMultiaddr(&ma).?;

    try cm.onConnectionEstablished(1, peer, .outbound, .{});
    _ = try cm.onConnectionClosed(10_000, 1, .remote_close);

    // `registerKnownPeer` now eager-submits the first dial via the swarm,
    // which under the test stub completes as `peer_connection_failed`. The
    // event ordering against our manually-injected lifecycle events is
    // non-deterministic, so drain until we observe both peer_connected and
    // peer_disconnected.
    var saw_connected = false;
    var saw_disconnected = false;
    while (!(saw_connected and saw_disconnected)) {
        var ev = try swarm.nextEvent(200);
        defer ev.deinit(a);
        switch (std.meta.activeTag(ev)) {
            .peer_connected => saw_connected = true,
            .peer_disconnected => saw_disconnected = true,
            .peer_connection_failed => {},
            else => return error.UnexpectedEvent,
        }
    }

    // The synthetic dial-failure from the eager submit must not have
    // accumulated extra failure_count on top of the remote-close backoff.
    // (registerKnownPeer's submit completes asynchronously; we tolerate
    // either an extra failure_count of 1 or 2 depending on race ordering.)
    const st_before = cm.knownPeerStatus(peer).?;
    try std.testing.expect(st_before.failure_count >= 1);
    try std.testing.expect(!st_before.dial_inflight);
    // Force a deterministic state for the rest of the test: reset to mimic
    // the pre-eager-dial behaviour where only the remote-close drove the
    // backoff (15s deadline at failure_count==1).
    cm.known.getPtr(peer).?.failure_count = 1;
    cm.known.getPtr(peer).?.next_dial_deadline_ms = 15_000;

    try cm.tick(14_999);
    try std.testing.expect(!cm.knownPeerStatus(peer).?.dial_inflight);

    try cm.tick(15_000);
    try std.testing.expect(cm.knownPeerStatus(peer).?.dial_inflight);
}

test "known peer past former failure cap is still redialed (no permanent abandonment)" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();

    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    try cm.registerKnownPeer(&ma, null);
    const peer = peerIdFromMultiaddr(&ma).?;

    // Simulate a known peer that blew far past the old hard cap during a
    // fleet-wide restart storm, with its backoff window now elapsed. Pre-fix
    // the `failure_count >= max_reconnect_failures` gate skipped it forever.
    cm.known.getPtr(peer).?.failure_count = max_reconnect_failures + 7;
    cm.known.getPtr(peer).?.dial_inflight = false;
    cm.known.getPtr(peer).?.next_dial_deadline_ms = 1_000;

    try cm.tick(2_000);
    try std.testing.expect(cm.knownPeerStatus(peer).?.dial_inflight);

    // Backoff clamps to the slowest bucket rather than indexing past backoff_ms.
    const delay = reconnectDelayMs(max_reconnect_failures + 7, peer);
    const base = backoff_ms[backoff_ms.len - 1];
    const span = @divTrunc(base, 4);
    try std.testing.expect(delay >= base - span and delay <= base + span);
}

test "local close does not set reconnect backoff" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();

    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    try cm.registerKnownPeer(&ma, null);
    const peer = peerIdFromMultiaddr(&ma).?;

    try cm.onConnectionEstablished(1, peer, .outbound, .{});
    _ = try swarm.nextEvent(100);
    _ = try cm.onConnectionClosed(5_000, 1, .local_close);
    _ = try swarm.nextEvent(100);

    const st = cm.knownPeerStatus(peer).?;
    try std.testing.expectEqual(@as(u8, 0), st.failure_count);
    try std.testing.expectEqual(std.math.maxInt(i64), st.next_dial_deadline_ms);
}

test "onDialFailure with null peer emits swarm event only" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();

    try cm.onDialFailure(0, 0, null, .unknown, .timeout);

    var ev = try swarm.nextEvent(100);
    defer ev.deinit(a);
    try std.testing.expectEqual(.peer_connection_failed, std.meta.activeTag(ev));
    try std.testing.expect(ev.peer_connection_failed.peer == null);
    try std.testing.expectEqual(@as(peer_events.Direction, .unknown), ev.peer_connection_failed.direction);
}

test "connection manager notifies ReqResp on last disconnect" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();

    var rr = req_resp_runtime.ReqResp.init(a, &swarm, .{});
    defer rr.deinit();

    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();
    cm.setReqResp(&rr);

    const peer = try identity.PeerId.random();
    const stream_rid: u64 = 77;
    _ = try rr.registerInboundChannel(peer, .status, stream_rid, 0);

    try cm.onConnectionEstablished(1, peer, .outbound, .{});
    _ = try cm.onConnectionClosed(1000, 1, .remote_close);

    // onConnectionEstablished queues peer_connected; drain it first so the next
    // assertion lines up with peer_disconnected.
    var ev0 = try swarm.nextEvent(200);
    defer ev0.deinit(a);
    try std.testing.expectEqual(.peer_connected, std.meta.activeTag(ev0));

    var ev1 = try swarm.nextEvent(200);
    defer ev1.deinit(a);
    try std.testing.expectEqual(.peer_disconnected, std.meta.activeTag(ev1));

    var ev2 = try swarm.nextEvent(200);
    defer ev2.deinit(a);
    try std.testing.expectEqual(.rpc_error_response, std.meta.activeTag(ev2));
    try std.testing.expectEqual(error.Disconnected, ev2.rpc_error_response.kind);
    try std.testing.expectEqual(stream_rid, ev2.rpc_error_response.request_id);
    try std.testing.expectEqual(@as(u32, 0), rr.inbound.count());
}

// ---------------------------------------------------------------------------
// Connection trimming policy (#90)
// ---------------------------------------------------------------------------

fn drainEventOfTag(swarm_in: *swarm_mod.Swarm, comptime tag: std.meta.Tag(swarm_mod.Event), a: std.mem.Allocator) !swarm_mod.Event {
    while (true) {
        var ev = try swarm_in.nextEvent(1000);
        if (std.meta.activeTag(ev) == tag) return ev;
        ev.deinit(a);
    }
}

test "trim recommends close when per-peer cap is exceeded" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();
    cm.setLimits(.{ .max_per_peer = 2 });

    const peer = try identity.PeerId.random();
    try cm.onConnectionEstablished(1, peer, .inbound, .{});
    try cm.onConnectionEstablished(2, peer, .outbound, .{});
    try std.testing.expectEqual(@as(u64, 0), cm.trimRecommendationCount());

    try cm.onConnectionEstablished(3, peer, .inbound, .{});
    try std.testing.expectEqual(@as(u64, 1), cm.trimRecommendationCount());

    var ev_trim = try drainEventOfTag(&swarm, .connection_trim_recommended, a);
    defer ev_trim.deinit(a);
    try std.testing.expectEqual(@as(u64, 1), ev_trim.connection_trim_recommended.conn_id);
    try std.testing.expectEqual(swarm_mod.TrimReason.over_per_peer_cap, ev_trim.connection_trim_recommended.reason);
}

test "trim recommends oldest conns down to low_watermark when high_watermark crossed" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();
    cm.setLimits(.{ .high_watermark = 3, .low_watermark = 1 });

    var peers: [3]identity.PeerId = undefined;
    for (&peers) |*p| p.* = try identity.PeerId.random();
    try cm.onConnectionEstablished(10, peers[0], .inbound, .{});
    try cm.onConnectionEstablished(11, peers[1], .inbound, .{});
    try std.testing.expectEqual(@as(u64, 0), cm.trimRecommendationCount());

    // 3rd conn hits the high watermark; expect 2 trim recommendations (down to 1).
    try cm.onConnectionEstablished(12, peers[2], .inbound, .{});
    try std.testing.expectEqual(@as(u64, 2), cm.trimRecommendationCount());

    var saw_10 = false;
    var saw_11 = false;
    var collected: u32 = 0;
    while (collected < 2) : (collected += 1) {
        var ev = try drainEventOfTag(&swarm, .connection_trim_recommended, a);
        defer ev.deinit(a);
        try std.testing.expectEqual(swarm_mod.TrimReason.over_global_watermark, ev.connection_trim_recommended.reason);
        if (ev.connection_trim_recommended.conn_id == 10) saw_10 = true;
        if (ev.connection_trim_recommended.conn_id == 11) saw_11 = true;
    }
    try std.testing.expect(saw_10 and saw_11);
}

test "trim grace blocks re-recommend until expiry" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();
    cm.setLimits(.{ .max_per_peer = 1, .trim_grace_ms = 5 });

    const peer = try identity.PeerId.random();
    try cm.onConnectionEstablished(1, peer, .inbound, .{});
    try cm.onConnectionEstablished(2, peer, .outbound, .{});
    try std.testing.expectEqual(@as(u64, 1), cm.trimRecommendationCount());
    {
        var ev0 = try drainEventOfTag(&swarm, .connection_trim_recommended, a);
        defer ev0.deinit(a);
    }

    // Within grace: third conn trims conn 2, not conn 1 again.
    try cm.onConnectionEstablished(3, peer, .outbound, .{});
    try std.testing.expectEqual(@as(u64, 2), cm.trimRecommendationCount());
    {
        var ev = try drainEventOfTag(&swarm, .connection_trim_recommended, a);
        defer ev.deinit(a);
        try std.testing.expectEqual(@as(u64, 2), ev.connection_trim_recommended.conn_id);
    }

    // After grace expires, conn 1 is eligible again.
    var req = std.c.timespec{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
    var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
    _ = std.c.nanosleep(&req, &rem);
    try cm.tick(wall_time.milliTimestamp());
    try cm.onConnectionEstablished(4, peer, .inbound, .{});
    try std.testing.expectEqual(@as(u64, 3), cm.trimRecommendationCount());
    {
        var ev = try drainEventOfTag(&swarm, .connection_trim_recommended, a);
        defer ev.deinit(a);
        try std.testing.expectEqual(@as(u64, 1), ev.connection_trim_recommended.conn_id);
    }
}

test "protected peer is never trim-recommended" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();
    cm.setLimits(.{ .max_per_peer = 1 });

    const protected_peer = try identity.PeerId.random();
    const other = try identity.PeerId.random();
    try cm.protect(protected_peer);

    try cm.onConnectionEstablished(1, protected_peer, .inbound, .{});
    try cm.onConnectionEstablished(2, protected_peer, .outbound, .{});
    try std.testing.expectEqual(@as(u64, 0), cm.trimRecommendationCount());

    try cm.onConnectionEstablished(3, other, .inbound, .{});
    try cm.onConnectionEstablished(4, other, .outbound, .{});
    try std.testing.expectEqual(@as(u64, 1), cm.trimRecommendationCount());
}

test "reconnect backoff applies ±25% jitter" {
    const peer = try identity.PeerId.random();
    for (1..max_reconnect_failures) |fc| {
        const delay = reconnectDelayMs(@intCast(fc), peer);
        const base = backoff_ms[fc - 1];
        const span = @divTrunc(base, 4);
        try std.testing.expect(delay >= base - span and delay <= base + span);
    }
    try std.testing.expectEqual(reconnectDelayMs(1, peer), reconnectDelayMs(1, peer));
}

test "trim entry is cleaned on close" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();
    cm.setLimits(.{ .max_per_peer = 1 });

    const peer = try identity.PeerId.random();
    try cm.onConnectionEstablished(1, peer, .inbound, .{});
    try cm.onConnectionEstablished(2, peer, .inbound, .{});
    try std.testing.expectEqual(@as(usize, 1), cm.trim_recommended.count());

    _ = try cm.onConnectionClosed(0, 1, .remote_close);
    try std.testing.expectEqual(@as(usize, 0), cm.trim_recommended.count());
}

test "sim-open tie-break is symmetric — both ends keep the same leg" {
    // For any two distinct peers, exactly one end "keeps inbound": the larger id
    // keeps its inbound (= the smaller id's outbound), the smaller id keeps its
    // outbound. Both therefore preserve the single connection dialed by the
    // smaller id, matching lantern/go/rust-libp2p. If this symmetry ever breaks,
    // the two ends close DIFFERENT legs and the connection is lost entirely.
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const a = try identity.PeerId.random();
        const b = try identity.PeerId.random();
        try std.testing.expect(keepInboundOnTieBreak(a, b) != keepInboundOnTieBreak(b, a));
    }
}

test "dedup detection gates dial when we are the tie-break listener" {
    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();

    // Two random ids; assign roles so the tie-break makes US the designated
    // LISTENER (peer keeps its outbound = dials us), engaging the dial gate.
    var local = try identity.PeerId.random();
    var peer = try identity.PeerId.random();
    if (!keepInboundOnTieBreak(local, peer)) {
        const tmp = local;
        local = peer;
        peer = tmp;
    }
    try std.testing.expect(keepInboundOnTieBreak(local, peer));
    cm.setLocalPeer(local);

    // Bare multiaddr (no /p2p) + explicit peer override → `peer` is the known id.
    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1");
    defer ma.deinit();
    try cm.registerKnownPeer(&ma, peer);
    // Our outbound leg establishes, then the peer graceful-closes it at once —
    // the simultaneous-open dedup signature.
    try cm.onConnectionEstablished(1, peer, .outbound, .{});
    const t0 = wall_time.milliTimestamp();
    _ = try cm.onConnectionClosed(t0, 1, .remote_close);

    // Past the reconnect backoff, tick must GATE (not redial): it sets the long
    // safety deadline instead of submitting a dial, and leaves dial_inflight false.
    const t_tick = t0 + 20_000;
    try cm.tick(t_tick);
    const st = cm.knownPeerStatus(peer).?;
    try std.testing.expectEqual(t_tick + dedup_listener_retry_ms, st.next_dial_deadline_ms);
    try std.testing.expect(!st.dial_inflight);
}

test "non-dedup peer keeps normal multi-leg redial (zeam↔zeam unaffected)" {
    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();

    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    const peer = peerIdFromMultiaddr(&ma).?;
    cm.setLocalPeer(try identity.PeerId.random());
    try cm.registerKnownPeer(&ma, null);

    // A leg that lived a LONG time before a remote close is a genuine drop, NOT a
    // dedup — the peer must stay dialable on the normal reconnect backoff.
    try cm.onConnectionEstablished(1, peer, .outbound, .{});
    const t0 = wall_time.milliTimestamp();
    // Close reported far past the dedup window → not flagged as dedups.
    _ = try cm.onConnectionClosed(t0 + dedup_close_window_ms + 1_000, 1, .remote_close);
    const st = cm.knownPeerStatus(peer).?;
    // Normal backoff re-arm (well under the 60s dedup-listener safety deadline).
    try std.testing.expect(st.next_dial_deadline_ms < t0 + dedup_close_window_ms + 1_000 + dedup_listener_retry_ms);
}
