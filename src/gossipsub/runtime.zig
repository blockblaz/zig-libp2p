//! Gossipsub mesh runtime (incremental, #39): subscriptions, peer presence, per-topic mesh,
//! heartbeat GRAFT/PRUNE toward Zeam `mesh_n` / `mesh_n_low` / `mesh_n_high`, inbound control,
//! publish forwarding, duplicate cache, lazy gossip IHAVE toward non-mesh peers, IWANT fulfillment
//! from a bounded pull cache, and a targeted outbox with global plus per-peer caps (lazy IHAVE
//! dropped first on overflow). Optional [`setPeerBehaviourScore`] orders GRAFT targets, PRUNE
//! victims, and lazy IHAVE peer selection (with a shuffled prefix among top-ranked peers).
//!
//! Inbound `subscriptions` RPC entries record remote interest per topic. When at least one peer
//! has advertised interest for a topic, GRAFT candidates are restricted to those peers; if none
//! have, the implementation falls back to all connected peers (flood-style bootstrap).

const std = @import("std");
const builtin = @import("builtin");
const identity = @import("../identity.zig");
const connection_manager = @import("../connection_manager.zig");
const errors = @import("../errors.zig");
const control = @import("control.zig");
const duplicate_cache = @import("duplicate_cache.zig");
const metrics_mod = @import("../metrics.zig");
const gs_cfg = @import("config.zig");
const lim = @import("wire_limits.zig");
const message_id = @import("message_id.zig");
const msg_mod = @import("message.zig");
const rpc = @import("rpc.zig");

/// `arc4random_buf` is missing from `std.c` on Linux with older glibc (see `std.c.arc4random_buf`),
/// which breaks CI. Prefer the `getrandom` syscall on Linux; otherwise libc where linked.
fn gossipsubPrngSeed() u64 {
    if (builtin.is_test) return 0x1111_2222_3333_4444;
    var s: u64 = undefined;
    const bytes = std.mem.asBytes(&s);

    var filled = false;
    switch (builtin.os.tag) {
        .linux => {
            const n = std.os.linux.getrandom(bytes.ptr, bytes.len, 0);
            filled = (n == bytes.len);
        },
        else => {
            if (@TypeOf(std.c.arc4random_buf) != void) {
                std.c.arc4random_buf(bytes.ptr, bytes.len);
                filled = true;
            }
        },
    }

    if (!filled) {
        const addr: usize = @intFromPtr(bytes.ptr);
        s = std.hash.Wyhash.hash(0, std.mem.asBytes(&addr));
    }
    if (s == 0) s = 0xa5a5_a5a5_a5a5_a5a5;
    return s;
}

const SeenMsg = struct {
    topic: []u8,
    id: [20]u8,
    seen_ms: i64,
};

const PullEntry = struct {
    id: [20]u8,
    topic: []u8,
    data: []u8,
    stored_ms: i64,
};

/// Per-(peer, topic) PRUNE back-off entry (libp2p gossipsub v1.1).
///
/// While `expires_ms > clock_ms` the local node MUST NOT send GRAFT to `peer` on
/// `topic`. Inbound GRAFT received during the back-off window is refused with a
/// fresh PRUNE carrying the remaining back-off (spec: "graft flood mitigation").
const BackoffEntry = struct {
    peer: identity.PeerId,
    topic: []u8,
    expires_ms: i64,
};

/// Defense-in-depth (`from`, `seqno`) replay-suppression entry.
///
/// Eth2 / Lean gossipsub use the StrictNoSign policy (no signature, no seqno
/// expected on the wire), so this cache stays empty in normal operation. When a
/// peer *does* include `from` and `seqno` (e.g. a misbehaving or hostile node),
/// we still want to suppress trivial replays of the same `(from, seqno)` pair
/// even when the `data` differs, since one of the two is necessarily forged.
///
/// `from` and `seqno` are size-capped by [`wire_limits`]; we stash both inline
/// to avoid per-entry heap traffic on the inbound hot path.
const SeqnoEntry = struct {
    from_buf: [lim.max_gossip_message_from_bytes]u8 = undefined,
    from_len: u16 = 0,
    seqno_buf: [lim.max_gossip_message_seqno_bytes]u8 = undefined,
    seqno_len: u16 = 0,
    expires_ms: i64,

    fn from(self: *const SeqnoEntry) []const u8 {
        return self.from_buf[0..self.from_len];
    }
    fn seqno(self: *const SeqnoEntry) []const u8 {
        return self.seqno_buf[0..self.seqno_len];
    }
    fn matches(self: *const SeqnoEntry, f: []const u8, s: []const u8) bool {
        return std.mem.eql(u8, self.from(), f) and std.mem.eql(u8, self.seqno(), s);
    }
};

pub const GossipsubConfig = struct {
    local_peer_id: identity.PeerId,
    message_id_domain_snappy_ok: bool = true,
    mesh_n_low: u8 = gs_cfg.mesh_n_low,
    mesh_n: u8 = gs_cfg.mesh_n,
    mesh_n_high: u8 = gs_cfg.mesh_n_high,
    gossip_lazy: u8 = gs_cfg.gossip_lazy,
    history_length: u8 = gs_cfg.history_length,
    heartbeat_interval_ms: i64 = gs_cfg.heartbeat_interval_ms,
    duplicate_cache_ttl_ms: i64 = gs_cfg.duplicate_cache_ttl_ms,
    max_transmit_size_bytes: usize = gs_cfg.max_transmit_size_bytes,
    /// Recent `(topic, message_id)` pairs kept for IHAVE advertisement (FIFO cap).
    max_recent_messages: usize = 4096,
    /// Cached full payloads for answering IWANT (FIFO cap, TTL `duplicate_cache_ttl_ms`).
    max_pull_cache_entries: usize = 1024,
    /// Max queued outbound RPC blobs (`OutDelivery`) before subscribe/publish/heartbeat return
    /// `errors.GossipsubError.PublishQueueFull` (#39).
    max_outbox_entries: usize = 4096,
    /// Per-peer cap on directed outbox entries; overflow drops oldest `lazy_ihave` to that peer first (#39).
    max_queued_per_peer: usize = 256,
    /// Fallback PRUNE back-off applied when an inbound PRUNE omits `backoff_seconds`,
    /// when the local node prunes a peer in `pruneMeshDownToN`, and when an inbound
    /// GRAFT is refused (libp2p gossipsub v1.1).
    prune_backoff_default_ms: i64 = gs_cfg.prune_backoff_default_ms,
    /// Upper bound applied to peer-supplied `backoff_seconds` to bound griefing.
    prune_backoff_cap_ms: i64 = gs_cfg.prune_backoff_cap_ms,
    /// Back-off after `unsubscribe` before `subscribe` on the same topic (#83).
    unsubscribe_backoff_ms: i64 = gs_cfg.unsubscribe_backoff_ms,
    /// Hard upper bound on tracked `(peer, topic)` back-off entries; oldest evicted first.
    max_backoff_entries: usize = 4096,
    /// Defense-in-depth: when set, inbound publishes carrying both `from` and `seqno`
    /// are suppressed if a `(from, seqno)` pair has been seen within `seqno_dedup_ttl_ms`.
    /// Lean / eth2 use StrictNoSign at the gossipsub layer so this is a no-op for spec-compliant
    /// peers; the cache exists to throttle obvious replays from misbehaving peers (#75).
    seqno_dedup_enabled: bool = true,
    /// FIFO cap on `(from, seqno)` cache size.
    max_seqno_dedup_entries: usize = 4096,
    /// TTL applied to `(from, seqno)` cache entries when present.
    seqno_dedup_ttl_ms: i64 = gs_cfg.duplicate_cache_ttl_ms,
    /// Optional per-topic validation hook (#84). Applies to every accepted-by-dedup
    /// inbound publish. `null` keeps the previous behaviour (always-accept).
    topic_validator: ?TopicValidator = null,
    /// Opaque context passed verbatim to `topic_validator`.
    validator_ctx: ?*anyopaque = null,
    /// Behaviour score delta applied to the sender when the validator returns `reject` (#84).
    /// Default -100 matches the libp2p gossipsub v1.1 spec's `P4` weight for invalid messages.
    validator_reject_score_delta: i32 = -100,
    /// Behaviour score delta when the validator returns `ignore` (default 0).
    validator_ignore_score_delta: i32 = 0,
    /// Track inbound IDONTWANT signals and suppress outbound publishes / IHAVE entries
    /// for those `(peer, message_id)` pairs (libp2p gossipsub v1.2 #85).
    idontwant_runtime_enabled: bool = true,
    /// FIFO cap on `(peer, message_id)` IDONTWANT entries.
    max_idontwant_entries: usize = 16384,
    /// TTL applied to IDONTWANT cache entries.
    idontwant_ttl_ms: i64 = gs_cfg.duplicate_cache_ttl_ms,
    /// FIFO cap on the PX dial-suggestion queue (`peer_id` bytes pulled from inbound
    /// PRUNE `peers` lists, #85). Embedders pop via [`popDialSuggestion`] and feed
    /// `connection_manager.registerKnownPeer`.
    max_px_dial_queue: usize = 256,
    /// When set, [`Gossipsub`] updates `lean_gossip_mesh_peers` from [`meshPeers`] on membership changes and heartbeat (#43).
    metrics: ?*metrics_mod.Metrics = null,

    pub fn validate(c: GossipsubConfig) InitConfigError!void {
        if (c.mesh_n_low > c.mesh_n) return error.InvalidMeshKnobs;
        if (c.mesh_n > c.mesh_n_high) return error.InvalidMeshKnobs;
        if (c.max_outbox_entries == 0) return error.InvalidOutboxCap;
        if (c.max_queued_per_peer == 0) return error.InvalidGossipParams;
        if (c.history_length == 0) return error.InvalidGossipParams;
        if (c.max_recent_messages == 0) return error.InvalidGossipParams;
        if (c.max_pull_cache_entries == 0) return error.InvalidGossipParams;
        if (c.max_backoff_entries == 0) return error.InvalidGossipParams;
        if (c.prune_backoff_default_ms < 0) return error.InvalidGossipParams;
        if (c.prune_backoff_cap_ms < c.prune_backoff_default_ms) return error.InvalidGossipParams;
        if (c.unsubscribe_backoff_ms < 0) return error.InvalidGossipParams;
        if (c.seqno_dedup_enabled and c.max_seqno_dedup_entries == 0) return error.InvalidGossipParams;
        if (c.seqno_dedup_enabled and c.seqno_dedup_ttl_ms <= 0) return error.InvalidGossipParams;
        if (c.idontwant_runtime_enabled and c.max_idontwant_entries == 0) return error.InvalidGossipParams;
        if (c.idontwant_runtime_enabled and c.idontwant_ttl_ms <= 0) return error.InvalidGossipParams;
        if (c.max_px_dial_queue == 0) return error.InvalidGossipParams;
    }
};

pub const InitConfigError = error{ InvalidMeshKnobs, InvalidOutboxCap, InvalidGossipParams };

pub const OutDeliveryKind = enum {
    generic,
    lazy_ihave,
};

pub const OutDelivery = struct {
    wire: []u8,
    /// `null` means broadcast to all connected peers (subscribe / publish announcements).
    to: ?identity.PeerId,
    kind: OutDeliveryKind = .generic,
};

const TopicMesh = struct {
    peers: std.HashMap(identity.PeerId, void, connection_manager.PeerIdContext, std.hash_map.default_max_load_percentage),

    fn init(allocator: std.mem.Allocator) TopicMesh {
        return .{ .peers = .init(allocator) };
    }

    fn deinit(self: *TopicMesh) void {
        self.peers.deinit();
    }
};

/// Application-layer validation outcome for an inbound gossipsub publish (#84).
///
/// libp2p gossipsub v1.1 defines three outcomes:
/// * `accept`  — message is valid and should be forwarded normally.
/// * `reject`  — message is invalid; do not forward, apply a negative score
///   delta (configurable) to the sending peer.
/// * `ignore`  — message is unsolicited / off-topic / unverifiable but not
///   provably malicious; drop without scoring.
pub const ValidationResult = enum {
    accept,
    reject,
    ignore,
};

/// Embedder-supplied per-topic validator. Returning `reject` causes the
/// gossipsub runtime to drop the message *and* apply
/// `cfg.validator_reject_score_delta` to the sender's behaviour score.
/// `ignore` drops without scoring. `accept` continues the normal forward path.
///
/// The validator is called on the inbound publish hot path; keep it cheap and
/// allocation-free where possible.
pub const TopicValidator = *const fn (ctx: ?*anyopaque, topic: []const u8, data: []const u8) ValidationResult;

/// IDONTWANT cache key (#85): the peer that asked us to skip the message id.
const IDontWantEntry = struct {
    peer: identity.PeerId,
    id: [20]u8,
    expires_ms: i64,
};

pub const Gossipsub = struct {
    allocator: std.mem.Allocator,
    cfg: GossipsubConfig,
    dup: duplicate_cache.DuplicateCache,
    subs: std.StringHashMap(void),
    mesh: std.StringHashMap(TopicMesh),
    /// Peers that sent a SUBSCRIBE RPC for a topic (used to narrow GRAFT targets).
    remote_interest: std.StringHashMap(TopicMesh),
    connected: std.HashMap(identity.PeerId, void, connection_manager.PeerIdContext, std.hash_map.default_max_load_percentage),
    clock_ms: i64,
    outbox: std.ArrayList(OutDelivery),
    inbound_delivered: u64,
    /// Count of inbound control blobs that contained at least one IHAVE entry (observability, #39).
    control_i_have_rx: u64,
    /// Count of inbound control blobs that contained at least one IWANT entry.
    control_i_want_rx: u64,
    /// Publishes queued in response to IWANT when the id was still in the pull cache.
    control_i_want_fulfilled: u64,
    /// Outbound IHAVE RPCs emitted from [`heartbeat`] lazy gossip.
    lazy_i_have_tx: u64,
    /// Lazy IHAVE entries dropped due to per-peer or global outbox backpressure (#39).
    dropped_lazy_ihave_backpressure: u64,
    recent_seen: std.ArrayList(SeenMsg),
    pull_fifo: std.ArrayList(PullEntry),
    rng: std.Random.DefaultPrng,
    scratch_peers: std.ArrayList(identity.PeerId),
    /// Optional mesh / behaviour scores for candidate ordering (higher = preferred GRAFT target) (#39).
    peer_scores: std.HashMap(identity.PeerId, i32, connection_manager.PeerIdContext, std.hash_map.default_max_load_percentage),
    /// Active PRUNE back-off windows keyed by (peer, topic). Linear-scanned because the
    /// list stays bounded by `max_backoff_entries` and back-offs are short-lived.
    backoff: std.ArrayList(BackoffEntry),
    /// Inbound GRAFT messages refused because the sender was in active back-off.
    graft_refused_during_backoff: u64,
    /// Defense-in-depth `(from, seqno)` replay cache.
    seqno_dedup: std.ArrayList(SeqnoEntry),
    /// Inbound publishes dropped because their `(from, seqno)` pair was already seen.
    inbound_dropped_seqno_replay: u64,
    /// Inbound publishes dropped because the topic validator returned `reject` (#84).
    inbound_dropped_validator_reject: u64,
    /// Inbound publishes dropped because the topic validator returned `ignore` (#84).
    inbound_dropped_validator_ignore: u64,
    /// Per-peer IDONTWANT cache used to suppress redundant outbound publishes / IHAVE (#85).
    idontwant: std.ArrayList(IDontWantEntry),
    /// Outbound publishes suppressed because the destination had sent IDONTWANT (#85).
    suppressed_outbound_idontwant: u64,
    /// Always-mesh peers (libp2p gossipsub `direct peers`, #85). Never pruned, never backed-off.
    direct_peers: std.HashMap(identity.PeerId, void, connection_manager.PeerIdContext, std.hash_map.default_max_load_percentage),
    /// FIFO queue of peer-id bytes harvested from inbound PRUNE `peers` lists, surfaced via
    /// [`popDialSuggestion`] (#85).
    px_dial_queue: std.ArrayList([]u8),
    /// Per-topic deadline until we may `subscribe` again after `unsubscribe` (#83).
    topic_unsubscribed_until: std.StringHashMap(i64),

    pub fn init(allocator: std.mem.Allocator, config: GossipsubConfig) (InitConfigError || std.mem.Allocator.Error)!*Gossipsub {
        try config.validate();
        const p = try allocator.create(Gossipsub);
        errdefer allocator.destroy(p);
        const seed = gossipsubPrngSeed();
        p.* = .{
            .allocator = allocator,
            .cfg = config,
            .dup = duplicate_cache.DuplicateCache.init(allocator),
            .subs = std.StringHashMap(void).init(allocator),
            .mesh = std.StringHashMap(TopicMesh).init(allocator),
            .remote_interest = std.StringHashMap(TopicMesh).init(allocator),
            .connected = .init(allocator),
            .clock_ms = 0,
            .outbox = .empty,
            .inbound_delivered = 0,
            .control_i_have_rx = 0,
            .control_i_want_rx = 0,
            .control_i_want_fulfilled = 0,
            .lazy_i_have_tx = 0,
            .dropped_lazy_ihave_backpressure = 0,
            .recent_seen = .empty,
            .pull_fifo = .empty,
            .rng = std.Random.DefaultPrng.init(seed),
            .scratch_peers = .empty,
            .peer_scores = .init(allocator),
            .backoff = .empty,
            .graft_refused_during_backoff = 0,
            .seqno_dedup = .empty,
            .inbound_dropped_seqno_replay = 0,
            .inbound_dropped_validator_reject = 0,
            .inbound_dropped_validator_ignore = 0,
            .idontwant = .empty,
            .suppressed_outbound_idontwant = 0,
            .direct_peers = .init(allocator),
            .px_dial_queue = .empty,
            .topic_unsubscribed_until = std.StringHashMap(i64).init(allocator),
        };
        return p;
    }

    pub fn deinit(self: *Gossipsub) void {
        self.dup.deinit();
        for (self.recent_seen.items) |s| self.allocator.free(s.topic);
        self.recent_seen.deinit(self.allocator);
        for (self.pull_fifo.items) |e| {
            self.allocator.free(e.topic);
            self.allocator.free(e.data);
        }
        self.pull_fifo.deinit(self.allocator);
        self.subs.deinit();
        var mit = self.mesh.iterator();
        while (mit.next()) |e| {
            e.value_ptr.deinit();
        }
        self.mesh.deinit();
        var rit = self.remote_interest.iterator();
        while (rit.next()) |e| {
            e.value_ptr.deinit();
        }
        self.remote_interest.deinit();
        for (self.outbox.items) |d| self.allocator.free(d.wire);
        self.outbox.deinit(self.allocator);
        self.connected.deinit();
        self.peer_scores.deinit();
        self.scratch_peers.deinit(self.allocator);
        for (self.backoff.items) |b| self.allocator.free(b.topic);
        self.backoff.deinit(self.allocator);
        self.seqno_dedup.deinit(self.allocator);
        self.idontwant.deinit(self.allocator);
        self.direct_peers.deinit();
        for (self.px_dial_queue.items) |b| self.allocator.free(b);
        self.px_dial_queue.deinit(self.allocator);
        var tut = self.topic_unsubscribed_until.iterator();
        while (tut.next()) |e| self.allocator.free(e.key_ptr.*);
        self.topic_unsubscribed_until.deinit();
        const a = self.allocator;
        a.destroy(self);
    }

    pub fn setClockMs(self: *Gossipsub, t: i64) void {
        self.clock_ms = t;
    }

    fn historyWindowMs(self: *const Gossipsub) i64 {
        return @as(i64, self.cfg.history_length) * self.cfg.heartbeat_interval_ms;
    }

    fn syncMeshPeers(self: *Gossipsub) void {
        if (self.cfg.metrics) |m| {
            m.setMeshPeers(self.meshPeers());
        }
    }

    fn pruneRecentSeen(self: *Gossipsub) void {
        const win = self.historyWindowMs();
        var i: usize = 0;
        while (i < self.recent_seen.items.len) {
            const s = self.recent_seen.items[i];
            if (self.clock_ms - s.seen_ms > win) {
                self.allocator.free(s.topic);
                _ = self.recent_seen.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    fn prunePullCache(self: *Gossipsub) void {
        const cutoff = self.clock_ms - self.cfg.duplicate_cache_ttl_ms;
        var i: usize = 0;
        while (i < self.pull_fifo.items.len) {
            if (self.pull_fifo.items[i].stored_ms < cutoff) {
                const e = self.pull_fifo.orderedRemove(i);
                self.allocator.free(e.topic);
                self.allocator.free(e.data);
            } else {
                i += 1;
            }
        }
    }

    /// Drops expired back-off windows. Called from [`heartbeat`] and read paths.
    fn pruneBackoff(self: *Gossipsub) void {
        var i: usize = 0;
        while (i < self.backoff.items.len) {
            if (self.backoff.items[i].expires_ms <= self.clock_ms) {
                const e = self.backoff.orderedRemove(i);
                self.allocator.free(e.topic);
            } else {
                i += 1;
            }
        }
    }

    /// Returns the active back-off entry's index for `(peer, topic)` or `null`.
    /// Side effect: removes the entry on the fly if it has expired.
    fn findActiveBackoff(self: *Gossipsub, peer: identity.PeerId, topic: []const u8) ?usize {
        var i: usize = 0;
        while (i < self.backoff.items.len) {
            const b = self.backoff.items[i];
            if (b.expires_ms <= self.clock_ms) {
                const removed = self.backoff.orderedRemove(i);
                self.allocator.free(removed.topic);
                continue;
            }
            if (b.peer.eql(&peer) and std.mem.eql(u8, b.topic, topic)) return i;
            i += 1;
        }
        return null;
    }

    /// `true` iff the local node is currently in PRUNE back-off toward `(peer, topic)`,
    /// i.e. MUST NOT send GRAFT.
    pub fn isPeerBackedOff(self: *Gossipsub, peer: identity.PeerId, topic: []const u8) bool {
        return self.findActiveBackoff(peer, topic) != null;
    }

    /// Records (or extends) a back-off window for `(peer, topic)` to at least
    /// `clock_ms + backoff_ms` (capped at `prune_backoff_cap_ms` and floored to the
    /// existing expiry so successive PRUNEs only ever extend, never shorten).
    fn recordBackoff(self: *Gossipsub, peer: identity.PeerId, topic: []const u8, backoff_ms: i64) std.mem.Allocator.Error!void {
        const clamped = @max(@as(i64, 0), @min(backoff_ms, self.cfg.prune_backoff_cap_ms));
        const expires = self.clock_ms + clamped;

        if (self.findActiveBackoff(peer, topic)) |idx| {
            const cur = &self.backoff.items[idx];
            if (expires > cur.expires_ms) cur.expires_ms = expires;
            return;
        }

        // Cap pressure: drop the entry expiring soonest before appending.
        if (self.backoff.items.len >= self.cfg.max_backoff_entries) {
            var min_idx: usize = 0;
            var min_exp: i64 = self.backoff.items[0].expires_ms;
            for (self.backoff.items[1..], 1..) |b, j| {
                if (b.expires_ms < min_exp) {
                    min_exp = b.expires_ms;
                    min_idx = j;
                }
            }
            const removed = self.backoff.orderedRemove(min_idx);
            self.allocator.free(removed.topic);
        }

        const topic_owned = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(topic_owned);
        try self.backoff.append(self.allocator, .{
            .peer = peer,
            .topic = topic_owned,
            .expires_ms = expires,
        });
    }

    /// Remaining back-off in seconds for an inbound GRAFT refusal PRUNE (rounded up).
    fn remainingBackoffSecondsFor(self: *Gossipsub, peer: identity.PeerId, topic: []const u8) ?u64 {
        const idx = self.findActiveBackoff(peer, topic) orelse return null;
        const remain_ms = self.backoff.items[idx].expires_ms - self.clock_ms;
        if (remain_ms <= 0) return 0;
        return @intCast(@divTrunc(remain_ms + 999, 1000));
    }

    fn remainingTopicUnsubscribeSeconds(self: *Gossipsub, topic: []const u8) ?u64 {
        const exp = self.topic_unsubscribed_until.get(topic) orelse return null;
        const remain_ms = exp - self.clock_ms;
        if (remain_ms <= 0) return null;
        return @intCast(@divTrunc(remain_ms + 999, 1000));
    }

    fn pruneTopicUnsubscribeCooldown(self: *Gossipsub) void {
        var keys_to_remove: std.ArrayList([]const u8) = .empty;
        defer keys_to_remove.deinit(self.allocator);
        var it = self.topic_unsubscribed_until.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* <= self.clock_ms) {
                keys_to_remove.append(self.allocator, e.key_ptr.*) catch {};
            }
        }
        for (keys_to_remove.items) |k| {
            if (self.topic_unsubscribed_until.fetchRemove(k)) |kv| {
                self.allocator.free(kv.key);
            }
        }
    }

    /// LEAVE(topic): PRUNE every mesh peer and record reciprocal back-off (#83).
    fn leaveTopicMesh(
        self: *Gossipsub,
        topic: []const u8,
        backoff_ms: i64,
    ) (control.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        const mp = self.mesh.getPtr(topic) orelse return;
        const backoff_s: u64 = @intCast(@divTrunc(backoff_ms + 999, 1000));

        self.scratch_peers.clearRetainingCapacity();
        var pit = mp.peers.keyIterator();
        while (pit.next()) |kp| {
            try self.scratch_peers.append(self.allocator, kp.*);
        }
        for (self.scratch_peers.items) |peer| {
            _ = mp.peers.remove(peer);
            if (!self.direct_peers.contains(peer)) {
                try self.recordBackoff(peer, topic, backoff_ms);
            }
            const ctl = try control.encodePrune(self.allocator, topic, backoff_s);
            defer self.allocator.free(ctl);
            const rpcw = try rpc.encodeControlOnlyRpc(self.allocator, ctl);
            errdefer self.allocator.free(rpcw);
            try self.appendOut(rpcw, peer);
        }
    }

    fn clearBackoffForPeer(self: *Gossipsub, peer: identity.PeerId) void {
        var i: usize = 0;
        while (i < self.backoff.items.len) {
            if (self.backoff.items[i].peer.eql(&peer)) {
                const removed = self.backoff.orderedRemove(i);
                self.allocator.free(removed.topic);
            } else {
                i += 1;
            }
        }
    }

    /// Returns `true` if `(from, seqno)` was already cached inside the TTL window; otherwise
    /// records the entry. `from` and `seqno` are size-capped by [`wire_limits`]; oversize input
    /// is treated as "not a duplicate" and not cached (the per-field protobuf decoder rejects
    /// out-of-bound values upstream, so this only fires for the empty-input edge case).
    fn checkSeqnoDuplicate(self: *Gossipsub, from_b: []const u8, seqno_b: []const u8) bool {
        if (!self.cfg.seqno_dedup_enabled) return false;
        if (from_b.len == 0 or seqno_b.len == 0) return false;
        if (from_b.len > lim.max_gossip_message_from_bytes) return false;
        if (seqno_b.len > lim.max_gossip_message_seqno_bytes) return false;

        // Cheap LRU-ish: scan forward, evict expired in-flight.
        var i: usize = 0;
        while (i < self.seqno_dedup.items.len) {
            const e = &self.seqno_dedup.items[i];
            if (e.expires_ms <= self.clock_ms) {
                _ = self.seqno_dedup.orderedRemove(i);
                continue;
            }
            if (e.matches(from_b, seqno_b)) return true;
            i += 1;
        }

        if (self.seqno_dedup.items.len >= self.cfg.max_seqno_dedup_entries) {
            _ = self.seqno_dedup.orderedRemove(0);
        }
        var entry = SeqnoEntry{ .expires_ms = self.clock_ms + self.cfg.seqno_dedup_ttl_ms };
        entry.from_len = @intCast(from_b.len);
        entry.seqno_len = @intCast(seqno_b.len);
        @memcpy(entry.from_buf[0..from_b.len], from_b);
        @memcpy(entry.seqno_buf[0..seqno_b.len], seqno_b);
        self.seqno_dedup.append(self.allocator, entry) catch return false;
        return false;
    }

    /// `true` if `peer` previously sent IDONTWANT for `id` and the entry is still live (#85).
    /// Also sweeps expired entries along the way.
    fn peerWantsNotPublish(self: *Gossipsub, peer: identity.PeerId, id: [20]u8) bool {
        if (!self.cfg.idontwant_runtime_enabled) return false;
        var i: usize = 0;
        var hit = false;
        while (i < self.idontwant.items.len) {
            const e = self.idontwant.items[i];
            if (e.expires_ms <= self.clock_ms) {
                _ = self.idontwant.orderedRemove(i);
                continue;
            }
            if (!hit and e.peer.eql(&peer) and std.mem.eql(u8, &e.id, &id)) hit = true;
            i += 1;
        }
        return hit;
    }

    fn rememberIDontWant(self: *Gossipsub, peer: identity.PeerId, id: [20]u8) std.mem.Allocator.Error!void {
        if (!self.cfg.idontwant_runtime_enabled) return;
        // Already present? bump expiry only.
        for (self.idontwant.items) |*e| {
            if (e.peer.eql(&peer) and std.mem.eql(u8, &e.id, &id)) {
                e.expires_ms = self.clock_ms + self.cfg.idontwant_ttl_ms;
                return;
            }
        }
        if (self.idontwant.items.len >= self.cfg.max_idontwant_entries) {
            _ = self.idontwant.orderedRemove(0);
        }
        try self.idontwant.append(self.allocator, .{
            .peer = peer,
            .id = id,
            .expires_ms = self.clock_ms + self.cfg.idontwant_ttl_ms,
        });
    }

    /// Mark `peer` as a direct (always-mesh) peer. Direct peers are never pruned by the
    /// heartbeat and bypass PRUNE back-off (libp2p gossipsub direct-peer behaviour, #85).
    pub fn addDirectPeer(self: *Gossipsub, peer: identity.PeerId) std.mem.Allocator.Error!void {
        try self.direct_peers.put(peer, {});
    }

    pub fn removeDirectPeer(self: *Gossipsub, peer: identity.PeerId) void {
        _ = self.direct_peers.remove(peer);
    }

    pub fn isDirectPeer(self: *const Gossipsub, peer: identity.PeerId) bool {
        return self.direct_peers.contains(peer);
    }

    /// Pop the next PX dial suggestion (peer-id bytes) harvested from inbound PRUNE PX, or
    /// `null` if the queue is empty. Caller owns the returned slice (#85).
    pub fn popDialSuggestion(self: *Gossipsub) ?[]u8 {
        if (self.px_dial_queue.items.len == 0) return null;
        return self.px_dial_queue.orderedRemove(0);
    }

    fn queueDialSuggestion(self: *Gossipsub, peer_bytes: []const u8) void {
        if (peer_bytes.len == 0) return;
        if (self.px_dial_queue.items.len >= self.cfg.max_px_dial_queue) {
            const old = self.px_dial_queue.orderedRemove(0);
            self.allocator.free(old);
        }
        const copy = self.allocator.dupe(u8, peer_bytes) catch return;
        self.px_dial_queue.append(self.allocator, copy) catch {
            self.allocator.free(copy);
        };
    }

    fn applyScoreDelta(self: *Gossipsub, peer: identity.PeerId, delta: i32) void {
        if (delta == 0) return;
        const cur = self.peerBehaviourScore(peer);
        const next: i32 = cur +| delta;
        self.peer_scores.put(peer, next) catch return;
    }

    fn recordSeenForLazy(self: *Gossipsub, topic: []const u8, id: [20]u8) std.mem.Allocator.Error!void {
        self.pruneRecentSeen();
        const topic_owned = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(topic_owned);
        try self.recent_seen.append(self.allocator, .{ .topic = topic_owned, .id = id, .seen_ms = self.clock_ms });
        while (self.recent_seen.items.len > self.cfg.max_recent_messages) {
            const old = self.recent_seen.orderedRemove(0);
            self.allocator.free(old.topic);
        }
    }

    fn rememberPullPayload(self: *Gossipsub, topic: []const u8, id: [20]u8, data: []const u8) std.mem.Allocator.Error!void {
        const t = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(t);
        const d = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(d);

        var j: usize = 0;
        while (j < self.pull_fifo.items.len) {
            if (std.mem.eql(u8, &self.pull_fifo.items[j].id, &id)) {
                const old = self.pull_fifo.orderedRemove(j);
                self.allocator.free(old.topic);
                self.allocator.free(old.data);
            } else {
                j += 1;
            }
        }

        if (self.pull_fifo.items.len >= self.cfg.max_pull_cache_entries) {
            const old = self.pull_fifo.orderedRemove(0);
            self.allocator.free(old.topic);
            self.allocator.free(old.data);
        }
        try self.pull_fifo.append(self.allocator, .{ .id = id, .topic = t, .data = d, .stored_ms = self.clock_ms });
    }

    fn findPullPayload(self: *const Gossipsub, id: [20]u8) ?PullEntry {
        var i: usize = self.pull_fifo.items.len;
        while (i > 0) {
            i -= 1;
            if (std.mem.eql(u8, &self.pull_fifo.items[i].id, &id)) return self.pull_fifo.items[i];
        }
        return null;
    }

    fn emitLazyIHAVE(self: *Gossipsub) (control.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        if (self.cfg.gossip_lazy == 0) return;

        var uniq: std.ArrayList([20]u8) = .empty;
        defer uniq.deinit(self.allocator);
        var mid_slices: std.ArrayList([]const u8) = .empty;
        defer mid_slices.deinit(self.allocator);

        var sit = self.subs.iterator();
        while (sit.next()) |e| {
            const topic = e.key_ptr.*;
            uniq.clearRetainingCapacity();
            mid_slices.clearRetainingCapacity();

            for (self.recent_seen.items) |s| {
                if (!std.mem.eql(u8, s.topic, topic)) continue;
                var dup_id = false;
                for (uniq.items) |u| {
                    if (std.mem.eql(u8, &u, &s.id)) {
                        dup_id = true;
                        break;
                    }
                }
                if (dup_id) continue;
                try uniq.append(self.allocator, s.id);
                if (uniq.items.len >= lim.max_message_ids_per_entry) break;
            }
            if (uniq.items.len == 0) continue;

            for (uniq.items) |*mid| {
                try mid_slices.append(self.allocator, mid[0..]);
            }

            const cand = try self.candidatesOutsideMesh(topic);
            if (cand.len == 0) continue;

            const k: usize = @min(@as(usize, self.cfg.gossip_lazy), cand.len);
            const prefix_len = @max(k, @min(cand.len, 2 * k));
            const rng = self.rng.random();
            rng.shuffle(identity.PeerId, cand[0..prefix_len]);
            for (cand[0..k]) |target| {
                const ctl = try control.encodeIHave(self.allocator, topic, mid_slices.items);
                defer self.allocator.free(ctl);
                const rpcw = try rpc.encodeControlOnlyRpc(self.allocator, ctl);
                errdefer self.allocator.free(rpcw);
                try self.appendOutKind(rpcw, target, .lazy_ihave);
                self.lazy_i_have_tx += 1;
            }
        }
    }

    fn countDirectedTo(self: *Gossipsub, peer: identity.PeerId) usize {
        var n: usize = 0;
        for (self.outbox.items) |d| {
            if (d.to) |t| {
                if (t.eql(&peer)) n += 1;
            }
        }
        return n;
    }

    fn dropOldestDirectedTo(self: *Gossipsub, peer: identity.PeerId, lazy_only: bool) bool {
        for (self.outbox.items, 0..) |d, i| {
            const to = d.to orelse continue;
            if (!to.eql(&peer)) continue;
            if (lazy_only and d.kind != .lazy_ihave) continue;
            const removed = self.outbox.orderedRemove(i);
            self.allocator.free(removed.wire);
            if (removed.kind == .lazy_ihave) self.dropped_lazy_ihave_backpressure += 1;
            return true;
        }
        return false;
    }

    fn enforcePerPeerCap(self: *Gossipsub, peer: identity.PeerId) void {
        while (self.countDirectedTo(peer) >= self.cfg.max_queued_per_peer) {
            if (self.dropOldestDirectedTo(peer, true)) continue;
            if (self.dropOldestDirectedTo(peer, false)) continue;
            return;
        }
    }

    fn dropOldestLazyIHaveAny(self: *Gossipsub) bool {
        for (self.outbox.items, 0..) |d, i| {
            if (d.kind != .lazy_ihave) continue;
            const removed = self.outbox.orderedRemove(i);
            self.allocator.free(removed.wire);
            self.dropped_lazy_ihave_backpressure += 1;
            return true;
        }
        return false;
    }

    fn enforceGlobalOutboxCap(self: *Gossipsub) errors.GossipsubError!void {
        while (self.outbox.items.len >= self.cfg.max_outbox_entries) {
            if (self.dropOldestLazyIHaveAny()) continue;
            return error.PublishQueueFull;
        }
    }

    fn appendOutKind(self: *Gossipsub, wire: []u8, to: ?identity.PeerId, kind: OutDeliveryKind) (errors.GossipsubError || std.mem.Allocator.Error)!void {
        if (to) |p| {
            self.enforcePerPeerCap(p);
        }
        try self.enforceGlobalOutboxCap();
        try self.outbox.append(self.allocator, .{ .wire = wire, .to = to, .kind = kind });
    }

    fn appendOut(self: *Gossipsub, wire: []u8, to: ?identity.PeerId) (errors.GossipsubError || std.mem.Allocator.Error)!void {
        return self.appendOutKind(wire, to, .generic);
    }

    fn ensureTopicMesh(self: *Gossipsub, topic: []const u8) std.mem.Allocator.Error!void {
        const gop = try self.mesh.getOrPut(topic);
        if (!gop.found_existing) {
            gop.value_ptr.* = TopicMesh.init(self.allocator);
        }
    }

    fn ensureRemoteInterestTable(self: *Gossipsub, topic: []const u8) std.mem.Allocator.Error!void {
        const gop = try self.remote_interest.getOrPut(topic);
        if (!gop.found_existing) {
            gop.value_ptr.* = TopicMesh.init(self.allocator);
        }
    }

    fn noteRemoteSubscription(self: *Gossipsub, sender: identity.PeerId, topic: []const u8, want: bool) std.mem.Allocator.Error!void {
        // Remote SUBSCRIBE wire bytes are freed by `handleInboundRpc`'s deferred cleanup,
        // so we cannot store `topic` directly as a `remote_interest` map key — it would
        // dangle and any later StringHashMap lookup would UAF inside `std.mem.eql`.
        // Re-anchor on our own subscription's owned key (we only care about topics we
        // ourselves subscribe to anyway; this also bounds memory against a peer that
        // SUBSCRIBEs us to thousands of nonsense topics).
        const owned_topic = blk: {
            var it = self.subs.iterator();
            while (it.next()) |e| {
                if (std.mem.eql(u8, e.key_ptr.*, topic)) break :blk e.key_ptr.*;
            }
            return;
        };
        if (want) {
            try self.ensureRemoteInterestTable(owned_topic);
            const rp = self.remote_interest.getPtr(owned_topic).?;
            try rp.peers.put(sender, {});
        } else {
            if (self.remote_interest.getPtr(owned_topic)) |rp| {
                _ = rp.peers.remove(sender);
            }
        }
    }

    pub fn subscribe(self: *Gossipsub, topic: []const u8) (rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        if (self.subs.contains(topic)) return;
        if (self.remainingTopicUnsubscribeSeconds(topic)) |_| return error.TopicUnsubscribeBackoff;
        if (self.topic_unsubscribed_until.fetchRemove(topic)) |kv| {
            self.allocator.free(kv.key);
        }
        try self.subs.put(topic, {});
        errdefer _ = self.subs.fetchRemove(topic);
        try self.ensureTopicMesh(topic);
        const w = try rpc.encodeSubscribe(self.allocator, topic, true);
        errdefer self.allocator.free(w);
        try self.appendOut(w, null);
        self.syncMeshPeers();
    }

    pub fn unsubscribe(self: *Gossipsub, topic: []const u8) (control.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        if (!self.subs.contains(topic)) return;
        try self.leaveTopicMesh(topic, self.cfg.unsubscribe_backoff_ms);

        const expires_ms = self.clock_ms + self.cfg.unsubscribe_backoff_ms;
        if (self.topic_unsubscribed_until.fetchRemove(topic)) |kv| {
            self.allocator.free(kv.key);
        }
        const topic_owned = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(topic_owned);
        try self.topic_unsubscribed_until.put(topic_owned, expires_ms);

        _ = self.subs.fetchRemove(topic);
        if (self.mesh.fetchRemove(topic)) |kv| {
            var tm = kv.value;
            tm.deinit();
        }
        if (self.remote_interest.fetchRemove(topic)) |kv| {
            var tm = kv.value;
            tm.deinit();
        }
        const w = try rpc.encodeSubscribe(self.allocator, topic, false);
        errdefer self.allocator.free(w);
        try self.appendOut(w, null);
        self.syncMeshPeers();
    }

    pub fn publish(self: *Gossipsub, topic: []const u8, payload: []const u8) (msg_mod.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        const inner = try msg_mod.encode(self.allocator, .{ .topic = topic, .data = payload });
        defer self.allocator.free(inner);
        if (inner.len > self.cfg.max_transmit_size_bytes) return error.PayloadTooLarge;

        var id: [20]u8 = undefined;
        message_id.writeMessageId(topic, payload, self.cfg.message_id_domain_snappy_ok, &id);
        try self.recordSeenForLazy(topic, id);
        try self.rememberPullPayload(topic, id, payload);

        const wire = try rpc.encodePublish(self.allocator, inner);
        errdefer self.allocator.free(wire);
        try self.appendOut(wire, null);
    }

    pub fn onPeerConnected(self: *Gossipsub, peer: identity.PeerId) void {
        self.connected.put(peer, {}) catch return;
    }

    pub fn onPeerDisconnected(self: *Gossipsub, peer: identity.PeerId) void {
        _ = self.connected.remove(peer);
        _ = self.peer_scores.remove(peer);
        var mit = self.mesh.iterator();
        while (mit.next()) |e| {
            _ = e.value_ptr.peers.remove(peer);
        }
        var rit = self.remote_interest.iterator();
        while (rit.next()) |e| {
            _ = e.value_ptr.peers.remove(peer);
        }
        self.clearBackoffForPeer(peer);
        self.syncMeshPeers();
    }

    pub fn peerBehaviourScore(self: *const Gossipsub, peer: identity.PeerId) i32 {
        return self.peer_scores.get(peer) orelse 0;
    }

    /// Sets a behaviour score used for mesh GRAFT / PRUNE ordering and lazy IHAVE peer selection (#39).
    pub fn setPeerBehaviourScore(self: *Gossipsub, peer: identity.PeerId, score: i32) std.mem.Allocator.Error!void {
        try self.peer_scores.put(peer, score);
    }

    fn sortPeersByScoreDescThenBytes(self: *Gossipsub, peers: []identity.PeerId) void {
        const Ctx = struct { gs: *Gossipsub };
        const ctx = Ctx{ .gs = self };
        const S = struct {
            fn less(c: Ctx, a: identity.PeerId, b: identity.PeerId) bool {
                const sa = c.gs.peerBehaviourScore(a);
                const sb = c.gs.peerBehaviourScore(b);
                if (sa != sb) return sa > sb;
                var ba: [128]u8 = undefined;
                var bb: [128]u8 = undefined;
                const ab = a.toBytes(&ba) catch return false;
                const bb2 = b.toBytes(&bb) catch return true;
                return std.mem.order(u8, ab, bb2) == .lt;
            }
        };
        std.mem.sort(identity.PeerId, peers, ctx, S.less);
    }

    fn sortPeersByScoreAscThenBytes(self: *Gossipsub, peers: []identity.PeerId) void {
        const Ctx = struct { gs: *Gossipsub };
        const ctx = Ctx{ .gs = self };
        const S = struct {
            fn less(c: Ctx, a: identity.PeerId, b: identity.PeerId) bool {
                const sa = c.gs.peerBehaviourScore(a);
                const sb = c.gs.peerBehaviourScore(b);
                if (sa != sb) return sa < sb;
                var ba: [128]u8 = undefined;
                var bb: [128]u8 = undefined;
                const ab = a.toBytes(&ba) catch return false;
                const bb2 = b.toBytes(&bb) catch return true;
                return std.mem.order(u8, ab, bb2) == .lt;
            }
        };
        std.mem.sort(identity.PeerId, peers, ctx, S.less);
    }

    fn candidatesOutsideMesh(self: *Gossipsub, topic: []const u8) std.mem.Allocator.Error![]identity.PeerId {
        self.scratch_peers.clearRetainingCapacity();
        const mp = self.mesh.getPtr(topic) orelse return &[_]identity.PeerId{};
        const interest = self.remote_interest.getPtr(topic);
        const restrict = blk: {
            const ip = interest orelse break :blk false;
            break :blk ip.peers.count() > 0;
        };
        var cit = self.connected.keyIterator();
        while (cit.next()) |kp| {
            const p = kp.*;
            if (p.eql(&self.cfg.local_peer_id)) continue;
            if (mp.peers.contains(p)) continue;
            if (restrict and !self.direct_peers.contains(p)) {
                const ip = interest.?;
                if (!ip.peers.contains(p)) continue;
            }
            // libp2p gossipsub v1.1: skip peers currently in PRUNE back-off for this topic.
            // Direct peers bypass back-off entirely (always-mesh).
            if (!self.direct_peers.contains(p) and self.isPeerBackedOff(p, topic)) continue;
            try self.scratch_peers.append(self.allocator, p);
        }
        // Direct peers always sort to the front; otherwise score-desc, then bytes.
        self.sortPeersDirectThenScoreDescThenBytes(self.scratch_peers.items);
        return self.scratch_peers.items;
    }

    fn sortPeersDirectThenScoreDescThenBytes(self: *Gossipsub, peers: []identity.PeerId) void {
        const Ctx = struct { gs: *Gossipsub };
        const ctx = Ctx{ .gs = self };
        const S = struct {
            fn less(c: Ctx, a: identity.PeerId, b: identity.PeerId) bool {
                const da = c.gs.direct_peers.contains(a);
                const db = c.gs.direct_peers.contains(b);
                if (da != db) return da;
                const sa = c.gs.peerBehaviourScore(a);
                const sb = c.gs.peerBehaviourScore(b);
                if (sa != sb) return sa > sb;
                var ba: [128]u8 = undefined;
                var bb: [128]u8 = undefined;
                const ab = a.toBytes(&ba) catch return false;
                const bb2 = b.toBytes(&bb) catch return true;
                return std.mem.order(u8, ab, bb2) == .lt;
            }
        };
        std.mem.sort(identity.PeerId, peers, ctx, S.less);
    }

    fn handleInboundControl(self: *Gossipsub, sender: identity.PeerId, ctl: []const u8) (control.Error || rpc.Error || msg_mod.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        if (try control.decodeFirstGraftTopic(self.allocator, ctl)) |gt| {
            defer self.allocator.free(gt);
            const remain_s: ?u64 = blk: {
                if (self.remainingBackoffSecondsFor(sender, gt)) |s| break :blk s;
                if (!self.subs.contains(gt)) break :blk self.remainingTopicUnsubscribeSeconds(gt);
                break :blk null;
            };
            if (remain_s) |rs| {
                self.graft_refused_during_backoff += 1;
                const ctl_out = try control.encodePrune(self.allocator, gt, rs);
                defer self.allocator.free(ctl_out);
                const rpcw = try rpc.encodeControlOnlyRpc(self.allocator, ctl_out);
                errdefer self.allocator.free(rpcw);
                try self.appendOut(rpcw, sender);
            } else if (self.subs.contains(gt)) {
                try self.ensureTopicMesh(gt);
                const mp = self.mesh.getPtr(gt).?;
                try mp.peers.put(sender, {});
            }
        }
        // Decode PRUNE with PX peer-info first; falls back to the legacy view if no PRUNE
        // entry was present. Direct peers are not actually backed off (we always trust them),
        // but we still surface PX suggestions and update the mesh membership.
        if (try control.decodeFirstPruneWithPeers(self.allocator, ctl)) |pp_view| {
            var prune = pp_view;
            defer control.deinitPruneWithPeersOwned(self.allocator, &prune);
            if (self.mesh.getPtr(prune.topic)) |mp| {
                _ = mp.peers.remove(sender);
            }
            // Harvest PX peer-id suggestions (#85). signed_peer_record is preserved upstream
            // but not auto-verified here; embedders that want full verification can pull the
            // raw envelope via the lower-level `control.decodeFirstPruneWithPeers` API.
            for (prune.peers) |pi| {
                if (pi.peer_id) |pb| self.queueDialSuggestion(pb);
            }
            if (!self.direct_peers.contains(sender)) {
                const backoff_ms: i64 = if (prune.backoff_seconds) |s| blk: {
                    const ms_u: u128 = @as(u128, s) * 1000;
                    break :blk @intCast(@min(ms_u, @as(u128, @intCast(self.cfg.prune_backoff_cap_ms))));
                } else self.cfg.prune_backoff_default_ms;
                try self.recordBackoff(sender, prune.topic, backoff_ms);
            }
        }
        // IDONTWANT (libp2p gossipsub v1.2): record `(sender, message_id)` so future outbound
        // publishes / forwards to that peer can be suppressed (#85).
        if (try control.decodeFirstIDontWant(self.allocator, ctl)) |idw| {
            var owned = idw;
            defer control.deinitIWantOwned(self.allocator, &owned);
            for (owned.message_ids) |mid_raw| {
                if (mid_raw.len != 20) continue;
                var id: [20]u8 = undefined;
                @memcpy(id[0..], mid_raw[0..20]);
                try self.rememberIDontWant(sender, id);
            }
        }
        if (try control.decodeFirstIHave(self.allocator, ctl)) |ih| {
            var owned = ih;
            defer control.deinitIHaveOwned(self.allocator, &owned);
            self.control_i_have_rx += 1;
        }
        if (try control.decodeFirstIWant(self.allocator, ctl)) |iw| {
            var owned = iw;
            defer control.deinitIWantOwned(self.allocator, &owned);
            self.control_i_want_rx += 1;
            for (owned.message_ids) |mid_raw| {
                if (mid_raw.len != 20) continue;
                var id: [20]u8 = undefined;
                @memcpy(id[0..], mid_raw[0..20]);
                const hit = self.findPullPayload(id) orelse continue;
                const inner = try msg_mod.encode(self.allocator, .{ .topic = hit.topic, .data = hit.data });
                defer self.allocator.free(inner);
                const wire = try rpc.encodePublish(self.allocator, inner);
                errdefer self.allocator.free(wire);
                try self.appendOut(wire, sender);
                self.control_i_want_fulfilled += 1;
            }
        }
        self.syncMeshPeers();
    }

    fn forwardPublish(self: *Gossipsub, sender: identity.PeerId, topic: []const u8, data: []const u8) (msg_mod.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        var id: [20]u8 = undefined;
        message_id.writeMessageId(topic, data, self.cfg.message_id_domain_snappy_ok, &id);
        try self.forwardPublishWithId(sender, topic, data, id);
    }

    fn forwardPublishWithId(self: *Gossipsub, sender: identity.PeerId, topic: []const u8, data: []const u8, mid: [20]u8) (msg_mod.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        const mp = self.mesh.getPtr(topic) orelse return;
        var pit = mp.peers.keyIterator();
        while (pit.next()) |kp| {
            const dest = kp.*;
            if (dest.eql(&sender)) continue;
            if (self.peerWantsNotPublish(dest, mid)) {
                self.suppressed_outbound_idontwant += 1;
                continue;
            }
            const inner = try msg_mod.encode(self.allocator, .{ .topic = topic, .data = data });
            defer self.allocator.free(inner);
            const wire = try rpc.encodePublish(self.allocator, inner);
            errdefer self.allocator.free(wire);
            try self.appendOut(wire, dest);
        }
    }

    fn pruneMeshDownToN(self: *Gossipsub, topic: []const u8, target: usize) (control.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        const mp = self.mesh.getPtr(topic) orelse return;
        const c = mp.peers.count();
        if (c <= target) return;

        // Direct peers are always-mesh; pretend they were never counted toward `excess`.
        var direct_in_mesh: usize = 0;
        {
            var pit = mp.peers.keyIterator();
            while (pit.next()) |kp| {
                if (self.direct_peers.contains(kp.*)) direct_in_mesh += 1;
            }
        }
        const eligible = if (c > direct_in_mesh) c - direct_in_mesh else 0;
        const eligible_target = if (target > direct_in_mesh) target - direct_in_mesh else 0;
        if (eligible <= eligible_target) return;
        const excess = eligible - eligible_target;

        self.scratch_peers.clearRetainingCapacity();
        var pit = mp.peers.keyIterator();
        while (pit.next()) |kp| {
            if (self.direct_peers.contains(kp.*)) continue;
            try self.scratch_peers.append(self.allocator, kp.*);
        }
        self.sortPeersByScoreAscThenBytes(self.scratch_peers.items);

        // Advertise our own back-off so well-behaved peers don't immediately re-graft us;
        // also record a local back-off so our heartbeat won't immediately re-graft them.
        const backoff_s: u64 = @intCast(@divTrunc(self.cfg.prune_backoff_default_ms + 999, 1000));
        const n = @min(excess, self.scratch_peers.items.len);
        for (self.scratch_peers.items[0..n]) |victim| {
            _ = mp.peers.remove(victim);
            try self.recordBackoff(victim, topic, self.cfg.prune_backoff_default_ms);
            const ctl = try control.encodePrune(self.allocator, topic, backoff_s);
            defer self.allocator.free(ctl);
            const rpcw = try rpc.encodeControlOnlyRpc(self.allocator, ctl);
            errdefer self.allocator.free(rpcw);
            try self.appendOut(rpcw, victim);
        }
    }

    pub fn handleInboundRpc(self: *Gossipsub, sender: identity.PeerId, frame: []const u8) (rpc.Error || msg_mod.Error || control.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        const sub_views = try rpc.decodeSubscribes(self.allocator, frame);
        defer rpc.freeSubscribeViews(self.allocator, sub_views);
        for (sub_views) |sv| {
            try self.noteRemoteSubscription(sender, sv.topic, sv.subscribe);
        }

        if (try rpc.decodeControlPayload(self.allocator, frame)) |ctl| {
            defer self.allocator.free(ctl);
            try self.handleInboundControl(sender, ctl);
        }

        const blobs = try rpc.decodePublishes(self.allocator, frame);
        defer rpc.freePublishBlobs(self.allocator, blobs);
        for (blobs) |b| {
            var decoded = try msg_mod.decode(self.allocator, b);
            defer decoded.deinit(self.allocator);
            const topic = decoded.topic orelse continue;
            const data = decoded.data orelse continue;
            var id: [20]u8 = undefined;
            message_id.writeMessageId(topic, data, self.cfg.message_id_domain_snappy_ok, &id);
            if (try self.dup.checkDuplicate(topic, id, self.clock_ms)) continue;
            // Defense-in-depth: if the peer included both `from` and `seqno`, suppress
            // trivial `(from, seqno)` replays even when the payload differs. No-op for
            // Lean / eth2 StrictNoSign traffic (neither field is set on the wire).
            if (decoded.from) |f| {
                if (decoded.seqno) |sq| {
                    if (self.checkSeqnoDuplicate(f, sq)) {
                        self.inbound_dropped_seqno_replay += 1;
                        continue;
                    }
                }
            }
            // Application-layer validator (#84). Spec maps `reject` to behaviour-score P4
            // penalty; `ignore` drops without scoring.
            if (self.cfg.topic_validator) |vfn| {
                switch (vfn(self.cfg.validator_ctx, topic, data)) {
                    .accept => {},
                    .reject => {
                        self.inbound_dropped_validator_reject += 1;
                        self.applyScoreDelta(sender, self.cfg.validator_reject_score_delta);
                        continue;
                    },
                    .ignore => {
                        self.inbound_dropped_validator_ignore += 1;
                        self.applyScoreDelta(sender, self.cfg.validator_ignore_score_delta);
                        continue;
                    },
                }
            }
            self.inbound_delivered += 1;
            try self.recordSeenForLazy(topic, id);
            try self.rememberPullPayload(topic, id, data);
            try self.forwardPublishWithId(sender, topic, data, id);
        }
    }

    pub fn heartbeat(self: *Gossipsub) (control.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        self.dup.prune(self.clock_ms);
        self.prunePullCache();
        self.pruneRecentSeen();
        self.pruneBackoff();
        self.pruneTopicUnsubscribeCooldown();

        var sit = self.subs.iterator();
        while (sit.next()) |e| {
            const topic = e.key_ptr.*;
            const mp = self.mesh.getPtr(topic) orelse continue;

            var c = mp.peers.count();
            if (c < self.cfg.mesh_n_low) {
                const need: usize = self.cfg.mesh_n_low - c;
                const cand = try self.candidatesOutsideMesh(topic);
                var i: usize = 0;
                while (i < need and i < cand.len) : (i += 1) {
                    const target = cand[i];
                    const ctl = try control.encodeGraft(self.allocator, topic);
                    defer self.allocator.free(ctl);
                    const rpcw = try rpc.encodeControlOnlyRpc(self.allocator, ctl);
                    errdefer self.allocator.free(rpcw);
                    try self.appendOut(rpcw, target);
                    // Eagerly mark the target as in-mesh: we just told them so.
                    // Mirrors the inbound GRAFT handler that adds the sender on receive.
                    // If the target later PRUNEs us, the back-off / mesh-remove handler
                    // will clean up.
                    try mp.peers.put(target, {});
                }
            }

            c = mp.peers.count();
            if (c > self.cfg.mesh_n_high) {
                try self.pruneMeshDownToN(topic, self.cfg.mesh_n);
            }
        }

        try self.emitLazyIHAVE();
        self.syncMeshPeers();
    }

    /// Sum of per-topic mesh sizes (a peer in multiple topics is counted multiple times).
    pub fn meshPeers(self: *const Gossipsub) u64 {
        var it = self.mesh.iterator();
        var sum: u64 = 0;
        while (it.next()) |e| {
            sum += @intCast(e.value_ptr.peers.count());
        }
        return sum;
    }

    /// Mesh size for `topic`, or `null` if we have no mesh row for that topic string.
    pub fn meshPeerCountForTopic(self: *const Gossipsub, topic: []const u8) ?usize {
        const mp = self.mesh.getPtr(topic) orelse return null;
        return mp.peers.count();
    }

    pub fn inboundDeliveredCount(self: *const Gossipsub) u64 {
        return self.inbound_delivered;
    }

    /// Inbound GRAFTs refused because the sender was in active PRUNE back-off (#75).
    pub fn graftRefusedDuringBackoffCount(self: *const Gossipsub) u64 {
        return self.graft_refused_during_backoff;
    }

    /// Inbound publishes dropped because their `(from, seqno)` pair was already cached (#75).
    pub fn inboundDroppedSeqnoReplayCount(self: *const Gossipsub) u64 {
        return self.inbound_dropped_seqno_replay;
    }

    /// Active back-off window count (post-expiry sweep).
    pub fn activeBackoffCount(self: *Gossipsub) usize {
        self.pruneBackoff();
        return self.backoff.items.len;
    }

    /// Inbound publishes the topic validator marked `reject` (#84).
    pub fn validatorRejectCount(self: *const Gossipsub) u64 {
        return self.inbound_dropped_validator_reject;
    }
    /// Inbound publishes the topic validator marked `ignore` (#84).
    pub fn validatorIgnoreCount(self: *const Gossipsub) u64 {
        return self.inbound_dropped_validator_ignore;
    }
    /// Outbound publishes suppressed because the destination had sent IDONTWANT (#85).
    pub fn suppressedOutboundIDontWantCount(self: *const Gossipsub) u64 {
        return self.suppressed_outbound_idontwant;
    }
    /// Active IDONTWANT entries (post-lazy-sweep).
    pub fn idontwantCount(self: *const Gossipsub) usize {
        return self.idontwant.items.len;
    }
    /// PX dial-suggestion queue depth.
    pub fn dialSuggestionCount(self: *const Gossipsub) usize {
        return self.px_dial_queue.items.len;
    }

    pub fn popOutboxDelivery(self: *Gossipsub) ?OutDelivery {
        if (self.outbox.items.len == 0) return null;
        return self.outbox.orderedRemove(0);
    }
};

test "gossipsub subscribe, graft mesh, dedup, forward" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var reg = metrics_mod.Metrics{ .network_id = "testnet" };
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .metrics = &reg });
    defer g.deinit();

    try std.testing.expectEqual(@as(u64, 0), reg.meshPeers());

    try g.subscribe("blocks");
    const sub_d = g.popOutboxDelivery().?;
    defer a.free(sub_d.wire);
    try std.testing.expect(sub_d.to == null);
    var sv = (try rpc.decodeFirstSubscribe(a, sub_d.wire)).?;
    defer rpc.deinitSubscribeView(a, &sv);
    try std.testing.expect(sv.subscribe);
    try std.testing.expectEqualStrings("blocks", sv.topic);

    const p1 = try identity.PeerId.random();
    g.onPeerConnected(p1);
    try std.testing.expectEqual(@as(u64, 0), g.meshPeers());

    const ctl = try control.encodeGraft(a, "blocks");
    defer a.free(ctl);
    const graft_rpc = try rpc.encodeControlOnlyRpc(a, ctl);
    defer a.free(graft_rpc);
    try g.handleInboundRpc(p1, graft_rpc);
    try std.testing.expectEqual(@as(u64, 1), g.meshPeers());
    try std.testing.expectEqual(@as(u64, 1), reg.meshPeers());
    try std.testing.expectEqual(@as(?usize, 1), g.meshPeerCountForTopic("blocks"));

    const inner = try msg_mod.encode(a, .{ .topic = "blocks", .data = "hello" });
    defer a.free(inner);
    const rpc_wire = try rpc.encodePublish(a, inner);
    defer a.free(rpc_wire);

    g.setClockMs(0);
    try g.handleInboundRpc(p1, rpc_wire);
    try g.handleInboundRpc(p1, rpc_wire);
    try std.testing.expectEqual(@as(u64, 1), g.inboundDeliveredCount());

    try g.heartbeat();
}

test "mesh forward targets non-sender peer" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    const pa = try identity.PeerId.random();
    const pb = try identity.PeerId.random();

    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 1, .mesh_n = 1, .mesh_n_high = 12 });
    defer g.deinit();

    try g.subscribe("t");
    const sub_d = g.popOutboxDelivery().?;
    defer a.free(sub_d.wire);

    const graft_ctl = try control.encodeGraft(a, "t");
    defer a.free(graft_ctl);
    const graft_full = try rpc.encodeControlOnlyRpc(a, graft_ctl);
    defer a.free(graft_full);

    try g.handleInboundRpc(pa, graft_full);
    try g.handleInboundRpc(pb, graft_full);
    try std.testing.expectEqual(@as(u64, 2), g.meshPeers());

    const inner = try msg_mod.encode(a, .{ .topic = "t", .data = "x" });
    defer a.free(inner);
    const pubw = try rpc.encodePublish(a, inner);
    defer a.free(pubw);

    try g.handleInboundRpc(pa, pubw);

    var saw_pa = false;
    var saw_pb = false;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        try std.testing.expect(d.to != null);
        if (d.to.?.eql(&pa)) saw_pa = true;
        if (d.to.?.eql(&pb)) saw_pb = true;
    }
    try std.testing.expect(saw_pb);
    try std.testing.expect(!saw_pa);
}

test "Gossipsub init rejects invalid mesh knobs" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    try std.testing.expectError(
        error.InvalidMeshKnobs,
        Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 9, .mesh_n = 8, .mesh_n_high = 12 }),
    );
    try std.testing.expectError(
        error.InvalidMeshKnobs,
        Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 6, .mesh_n = 12, .mesh_n_high = 8 }),
    );
}

test "heartbeat emits GRAFT when mesh below mesh_n_low" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    const remote = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 2, .mesh_n = 2, .mesh_n_high = 12 });
    defer g.deinit();

    try g.subscribe("t");
    const sub_d = g.popOutboxDelivery().?;
    defer a.free(sub_d.wire);

    g.onPeerConnected(remote);
    try g.heartbeat();

    var saw_graft = false;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        if (d.to != null and d.to.?.eql(&remote)) {
            const ctl = (try rpc.decodeControlPayload(a, d.wire)).?;
            defer a.free(ctl);
            const graft_topic = (try control.decodeFirstGraftTopic(a, ctl)).?;
            defer a.free(graft_topic);
            try std.testing.expectEqualStrings("t", graft_topic);
            saw_graft = true;
        }
    }
    try std.testing.expect(saw_graft);
}

test "heartbeat prunes mesh above mesh_n_high down to mesh_n" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 1, .mesh_n = 2, .mesh_n_high = 3 });
    defer g.deinit();

    try g.subscribe("t");
    const sub_d = g.popOutboxDelivery().?;
    defer a.free(sub_d.wire);

    var peers: [4]identity.PeerId = undefined;
    for (&peers) |*p| p.* = try identity.PeerId.random();

    const graft_ctl = try control.encodeGraft(a, "t");
    defer a.free(graft_ctl);
    const graft_full = try rpc.encodeControlOnlyRpc(a, graft_ctl);
    defer a.free(graft_full);

    for (peers) |p| {
        g.onPeerConnected(p);
        try g.handleInboundRpc(p, graft_full);
    }
    try std.testing.expectEqual(@as(u64, 4), g.meshPeers());

    try g.heartbeat();

    var prune_count: u32 = 0;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        const ctl = (try rpc.decodeControlPayload(a, d.wire)) orelse continue;
        defer a.free(ctl);
        if (try control.decodeFirstPrune(a, ctl)) |pv| {
            var pvv = pv;
            defer control.deinitPruneView(a, &pvv);
            prune_count += 1;
        }
    }
    try std.testing.expectEqual(@as(u32, 2), prune_count);
    try std.testing.expectEqual(@as(?usize, 2), g.meshPeerCountForTopic("t"));
}

test "two nodes exchange graft then deliver publish forward" {
    const a = std.testing.allocator;
    const pa = try identity.PeerId.random();
    const pb = try identity.PeerId.random();

    var ga = try Gossipsub.init(a, .{ .local_peer_id = pa, .mesh_n_low = 1, .mesh_n = 1, .mesh_n_high = 12 });
    defer ga.deinit();
    var gb = try Gossipsub.init(a, .{ .local_peer_id = pb, .mesh_n_low = 1, .mesh_n = 1, .mesh_n_high = 12 });
    defer gb.deinit();

    try ga.subscribe("t");
    try gb.subscribe("t");
    const ga_sub = ga.popOutboxDelivery().?;
    defer a.free(ga_sub.wire);
    const gb_sub = gb.popOutboxDelivery().?;
    defer a.free(gb_sub.wire);

    ga.onPeerConnected(pb);
    gb.onPeerConnected(pa);

    // ga heartbeat → ga eagerly marks pb in its own mesh and queues a GRAFT to pb.
    try ga.heartbeat();
    const graft_a = ga.popOutboxDelivery().?;
    defer a.free(graft_a.wire);
    try std.testing.expect(graft_a.to != null and graft_a.to.?.eql(&pb));
    // gb processes the inbound GRAFT and adds pa to its mesh. Per libp2p gossipsub
    // there is no automatic GRAFT-back: the GRAFT itself signals mutual mesh intent.
    try gb.handleInboundRpc(pa, graft_a.wire);

    try std.testing.expectEqual(@as(?usize, 1), ga.meshPeerCountForTopic("t"));
    try std.testing.expectEqual(@as(?usize, 1), gb.meshPeerCountForTopic("t"));

    const inner = try msg_mod.encode(a, .{ .topic = "t", .data = "payload" });
    defer a.free(inner);
    const pubw = try rpc.encodePublish(a, inner);
    defer a.free(pubw);

    // pb sends a publish to ga. Forwarding excludes the sender, and pb is the
    // only mesh peer, so ga delivers the message locally but emits no forward.
    try ga.handleInboundRpc(pb, pubw);
    try std.testing.expectEqual(@as(u64, 1), ga.inboundDeliveredCount());
    try std.testing.expectEqual(@as(?OutDelivery, null), ga.popOutboxDelivery());
}

test "remote subscription narrows GRAFT candidates" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    const pa = try identity.PeerId.random();
    const pb = try identity.PeerId.random();

    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 1, .mesh_n = 1, .mesh_n_high = 12 });
    defer g.deinit();

    try g.subscribe("t");
    const sub_d = g.popOutboxDelivery().?;
    defer a.free(sub_d.wire);

    g.onPeerConnected(pa);
    g.onPeerConnected(pb);

    const pa_sub = try rpc.encodeSubscribe(a, "t", true);
    defer a.free(pa_sub);
    try g.handleInboundRpc(pa, pa_sub);

    try g.heartbeat();
    const d = g.popOutboxDelivery().?;
    defer a.free(d.wire);
    try std.testing.expect(d.to != null and d.to.?.eql(&pa));
}

test "Gossipsub init rejects zero max_outbox_entries" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    try std.testing.expectError(
        error.InvalidOutboxCap,
        Gossipsub.init(a, .{ .local_peer_id = me, .max_outbox_entries = 0 }),
    );
}

test "publish returns PublishQueueFull when outbox is full" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .max_outbox_entries = 1 });
    defer g.deinit();

    try g.publish("t", "one");
    try std.testing.expectError(error.PublishQueueFull, g.publish("t", "two"));
}

test "inbound IHAVE and IWANT increment control counters" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    const peer = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me });
    defer g.deinit();

    const ihave_ctl = try control.encodeIHave(a, "blocks", &[_][]const u8{"mid"});
    defer a.free(ihave_ctl);
    const ihave_rpc = try rpc.encodeControlOnlyRpc(a, ihave_ctl);
    defer a.free(ihave_rpc);

    const iwant_ctl = try control.encodeIWant(a, &[_][]const u8{"want-id"});
    defer a.free(iwant_ctl);
    const iwant_rpc = try rpc.encodeControlOnlyRpc(a, iwant_ctl);
    defer a.free(iwant_rpc);

    try g.handleInboundRpc(peer, ihave_rpc);
    try g.handleInboundRpc(peer, iwant_rpc);
    try std.testing.expectEqual(@as(u64, 1), g.control_i_have_rx);
    try std.testing.expectEqual(@as(u64, 1), g.control_i_want_rx);
}

test "lazy gossip heartbeat emits IHAVE to non-mesh peers" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 1, .mesh_n = 1, .mesh_n_high = 12, .gossip_lazy = 6 });
    defer g.deinit();

    try g.subscribe("t");
    const sub_d = g.popOutboxDelivery().?;
    defer a.free(sub_d.wire);

    const graft_ctl = try control.encodeGraft(a, "t");
    defer a.free(graft_ctl);
    const graft_full = try rpc.encodeControlOnlyRpc(a, graft_ctl);
    defer a.free(graft_full);

    var peers: [7]identity.PeerId = undefined;
    for (&peers) |*p| {
        p.* = try identity.PeerId.random();
        g.onPeerConnected(p.*);
    }
    try g.handleInboundRpc(peers[0], graft_full);

    try g.publish("t", "hello");
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
    }

    try g.heartbeat();
    try std.testing.expectEqual(@as(u64, 6), g.lazy_i_have_tx);

    var ihave_out: u32 = 0;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        const ctl = (try rpc.decodeControlPayload(a, d.wire)) orelse continue;
        defer a.free(ctl);
        if (try control.decodeFirstIHave(a, ctl)) |ih| {
            var owned = ih;
            defer control.deinitIHaveOwned(a, &owned);
            ihave_out += 1;
        }
    }
    try std.testing.expectEqual(@as(u32, 6), ihave_out);
}

test "IWANT with 20-byte id replays cached publish to requester" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    const requester = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me });
    defer g.deinit();

    try g.publish("t", "cached-body");
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
    }

    var id: [20]u8 = undefined;
    message_id.writeMessageId("t", "cached-body", g.cfg.message_id_domain_snappy_ok, &id);

    const iwant_ctl = try control.encodeIWant(a, &[_][]const u8{id[0..]});
    defer a.free(iwant_ctl);
    const iwant_rpc = try rpc.encodeControlOnlyRpc(a, iwant_ctl);
    defer a.free(iwant_rpc);

    try g.handleInboundRpc(requester, iwant_rpc);
    try std.testing.expectEqual(@as(u64, 1), g.control_i_want_fulfilled);

    const d = g.popOutboxDelivery().?;
    defer a.free(d.wire);
    try std.testing.expect(d.to != null and d.to.?.eql(&requester));
    const blobs = try rpc.decodePublishes(a, d.wire);
    defer rpc.freePublishBlobs(a, blobs);
    try std.testing.expectEqual(@as(usize, 1), blobs.len);
    var decoded = try msg_mod.decode(a, blobs[0]);
    defer decoded.deinit(a);
    try std.testing.expectEqualStrings("t", decoded.topic.?);
    try std.testing.expectEqualStrings("cached-body", decoded.data.?);
}

test "Gossipsub init rejects invalid lazy gossip cache params" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    try std.testing.expectError(
        error.InvalidGossipParams,
        Gossipsub.init(a, .{ .local_peer_id = me, .history_length = 0 }),
    );
    try std.testing.expectError(
        error.InvalidGossipParams,
        Gossipsub.init(a, .{ .local_peer_id = me, .max_recent_messages = 0 }),
    );
    try std.testing.expectError(
        error.InvalidGossipParams,
        Gossipsub.init(a, .{ .local_peer_id = me, .max_pull_cache_entries = 0 }),
    );
    try std.testing.expectError(
        error.InvalidGossipParams,
        Gossipsub.init(a, .{ .local_peer_id = me, .max_queued_per_peer = 0 }),
    );
}

test "lazy IHAVE per-peer cap drops older lazy first" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    const pm = try identity.PeerId.random();
    const pv = try identity.PeerId.random();

    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 1,
        .mesh_n_high = 12,
        .gossip_lazy = 1,
        .max_queued_per_peer = 1,
    });
    defer g.deinit();

    try g.subscribe("t1");
    try g.subscribe("t2");
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
    }

    const ctl1 = try control.encodeGraft(a, "t1");
    defer a.free(ctl1);
    const ctl2 = try control.encodeGraft(a, "t2");
    defer a.free(ctl2);
    const graft1 = try rpc.encodeControlOnlyRpc(a, ctl1);
    defer a.free(graft1);
    const graft2 = try rpc.encodeControlOnlyRpc(a, ctl2);
    defer a.free(graft2);

    g.onPeerConnected(pm);
    g.onPeerConnected(pv);
    try g.handleInboundRpc(pm, graft1);
    try g.handleInboundRpc(pm, graft2);

    try g.publish("t1", "a");
    try g.publish("t2", "b");
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
    }

    try g.heartbeat();
    try std.testing.expectEqual(@as(u64, 1), g.dropped_lazy_ihave_backpressure);
    try std.testing.expectEqual(@as(u64, 2), g.lazy_i_have_tx);

    const d = g.popOutboxDelivery().?;
    defer a.free(d.wire);
    try std.testing.expect(d.to != null and d.to.?.eql(&pv));
    try std.testing.expectEqual(OutDeliveryKind.lazy_ihave, d.kind);
}

test "global outbox cap evicts oldest lazy IHAVE" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    const pm = try identity.PeerId.random();
    const pa = try identity.PeerId.random();
    const pb = try identity.PeerId.random();

    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 1,
        .mesh_n_high = 12,
        .gossip_lazy = 2,
        .max_outbox_entries = 2,
    });
    defer g.deinit();

    try g.subscribe("t");
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
    }

    const gctl = try control.encodeGraft(a, "t");
    defer a.free(gctl);
    const graft = try rpc.encodeControlOnlyRpc(a, gctl);
    defer a.free(graft);

    g.onPeerConnected(pm);
    g.onPeerConnected(pa);
    g.onPeerConnected(pb);
    try g.handleInboundRpc(pm, graft);

    try g.publish("t", "x");
    // Intentionally leave the broadcast publish in the outbox so the heartbeat
    // hits `max_outbox_entries = 2` while emitting two lazy IHAVEs — one should
    // be dropped, accounted via `dropped_lazy_ihave_backpressure`.
    try g.heartbeat();
    try std.testing.expectEqual(@as(u64, 1), g.dropped_lazy_ihave_backpressure);
    try std.testing.expectEqual(@as(u64, 2), g.lazy_i_have_tx);

    var saw_pa = false;
    var saw_pb = false;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        if (d.kind != .lazy_ihave) continue; // drain the broadcast publish silently
        if (d.to) |t| {
            if (t.eql(&pa)) saw_pa = true;
            if (t.eql(&pb)) saw_pb = true;
        }
    }
    try std.testing.expect(saw_pa != saw_pb);
}

test "heartbeat GRAFT prefers higher behaviour score" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    const plow = try identity.PeerId.random();
    const phigh = try identity.PeerId.random();

    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 2, .mesh_n = 2, .mesh_n_high = 12 });
    defer g.deinit();

    try g.setPeerBehaviourScore(plow, 1);
    try g.setPeerBehaviourScore(phigh, 100);

    try g.subscribe("t");
    const sub_d = g.popOutboxDelivery().?;
    defer a.free(sub_d.wire);

    g.onPeerConnected(plow);
    g.onPeerConnected(phigh);
    try g.heartbeat();

    const d0 = g.popOutboxDelivery().?;
    defer a.free(d0.wire);
    const d1 = g.popOutboxDelivery().?;
    defer a.free(d1.wire);
    try std.testing.expect(d0.to != null and d0.to.?.eql(&phigh));
    try std.testing.expect(d1.to != null and d1.to.?.eql(&plow));
}

test "PRUNE prefers lowest behaviour score" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    const p10 = try identity.PeerId.random();
    const p20 = try identity.PeerId.random();
    const p30 = try identity.PeerId.random();
    const p40 = try identity.PeerId.random();

    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 1, .mesh_n = 2, .mesh_n_high = 3 });
    defer g.deinit();

    try g.setPeerBehaviourScore(p10, 10);
    try g.setPeerBehaviourScore(p20, 20);
    try g.setPeerBehaviourScore(p30, 30);
    try g.setPeerBehaviourScore(p40, 40);

    try g.subscribe("t");
    const sub_d = g.popOutboxDelivery().?;
    defer a.free(sub_d.wire);

    const graft_ctl = try control.encodeGraft(a, "t");
    defer a.free(graft_ctl);
    const graft_full = try rpc.encodeControlOnlyRpc(a, graft_ctl);
    defer a.free(graft_full);

    for ([_]identity.PeerId{ p10, p20, p30, p40 }) |p| {
        g.onPeerConnected(p);
        try g.handleInboundRpc(p, graft_full);
    }
    try std.testing.expectEqual(@as(u64, 4), g.meshPeers());

    try g.heartbeat();

    var pruned: [2]identity.PeerId = undefined;
    var n: usize = 0;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        const ctl = (try rpc.decodeControlPayload(a, d.wire)) orelse continue;
        defer a.free(ctl);
        if (try control.decodeFirstPrune(a, ctl)) |pv| {
            var pvv = pv;
            defer control.deinitPruneView(a, &pvv);
            if (d.to) |to| {
                pruned[n] = to;
                n += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expect(pruned[0].eql(&p10));
    try std.testing.expect(pruned[1].eql(&p20));
    try std.testing.expectEqual(@as(?usize, 2), g.meshPeerCountForTopic("t"));
}

test "publish rejects wire over max_transmit_size_bytes" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .max_transmit_size_bytes = 24 });
    defer g.deinit();

    const big = try a.alloc(u8, 80);
    defer a.free(big);
    @memset(big, 'q');
    try std.testing.expectError(error.PayloadTooLarge, g.publish("t", big));
}

// ---------------------------------------------------------------------------
// PRUNE back-off (#75 blocker 1)
// ---------------------------------------------------------------------------

test "inbound PRUNE records back-off; heartbeat refuses to re-graft inside window" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 1,
        .mesh_n_high = 2,
    });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    // Graft → PRUNE with 30s back-off from the remote.
    const graft = try control.encodeGraft(a, "t");
    defer a.free(graft);
    const graft_rpc = try rpc.encodeControlOnlyRpc(a, graft);
    defer a.free(graft_rpc);
    try g.handleInboundRpc(peer, graft_rpc);
    try std.testing.expectEqual(@as(?usize, 1), g.meshPeerCountForTopic("t"));

    const prune = try control.encodePrune(a, "t", 30);
    defer a.free(prune);
    const prune_rpc = try rpc.encodeControlOnlyRpc(a, prune);
    defer a.free(prune_rpc);
    try g.handleInboundRpc(peer, prune_rpc);
    try std.testing.expectEqual(@as(?usize, 0), g.meshPeerCountForTopic("t"));
    try std.testing.expect(g.isPeerBackedOff(peer, "t"));

    // Heartbeat while inside back-off window must not re-graft.
    g.setClockMs(15_000);
    try g.heartbeat();
    try std.testing.expectEqual(@as(?usize, 0), g.meshPeerCountForTopic("t"));
    var emitted_graft = false;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        const ctl = (try rpc.decodeControlPayload(a, d.wire)) orelse continue;
        defer a.free(ctl);
        if (try control.decodeFirstGraftTopic(a, ctl)) |topic| {
            a.free(topic);
            emitted_graft = true;
        }
    }
    try std.testing.expect(!emitted_graft);

    // After expiry the peer becomes graftable again.
    g.setClockMs(31_000);
    try g.heartbeat();
    try std.testing.expectEqual(@as(usize, 0), g.activeBackoffCount());

    var saw_graft = false;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        const ctl = (try rpc.decodeControlPayload(a, d.wire)) orelse continue;
        defer a.free(ctl);
        if (try control.decodeFirstGraftTopic(a, ctl)) |topic| {
            a.free(topic);
            saw_graft = true;
        }
    }
    try std.testing.expect(saw_graft);
}

test "PRUNE without backoff falls back to prune_backoff_default_ms" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 1,
        .mesh_n_high = 2,
        .prune_backoff_default_ms = 5_000,
    });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const prune = try control.encodePrune(a, "t", null);
    defer a.free(prune);
    const prune_rpc = try rpc.encodeControlOnlyRpc(a, prune);
    defer a.free(prune_rpc);
    try g.handleInboundRpc(peer, prune_rpc);

    try std.testing.expect(g.isPeerBackedOff(peer, "t"));
    g.setClockMs(4_999);
    try std.testing.expect(g.isPeerBackedOff(peer, "t"));
    g.setClockMs(5_000);
    try std.testing.expect(!g.isPeerBackedOff(peer, "t"));
}

test "inbound GRAFT during back-off is refused with a PRUNE carrying remaining backoff" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 1,
        .mesh_n_high = 2,
    });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const prune = try control.encodePrune(a, "t", 30);
    defer a.free(prune);
    const prune_rpc = try rpc.encodeControlOnlyRpc(a, prune);
    defer a.free(prune_rpc);
    try g.handleInboundRpc(peer, prune_rpc);

    // Sender tries to GRAFT us back while still in the back-off window.
    g.setClockMs(10_000);
    const graft = try control.encodeGraft(a, "t");
    defer a.free(graft);
    const graft_rpc = try rpc.encodeControlOnlyRpc(a, graft);
    defer a.free(graft_rpc);
    try g.handleInboundRpc(peer, graft_rpc);

    try std.testing.expectEqual(@as(u64, 1), g.graftRefusedDuringBackoffCount());
    try std.testing.expectEqual(@as(?usize, 0), g.meshPeerCountForTopic("t"));

    // The refusal PRUNE must be queued to that same peer with remaining_s ≥ 20.
    var saw_refusal_prune = false;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        try std.testing.expect(d.to != null and d.to.?.eql(&peer));
        const ctl = (try rpc.decodeControlPayload(a, d.wire)) orelse continue;
        defer a.free(ctl);
        if (try control.decodeFirstPrune(a, ctl)) |pv| {
            var pvv = pv;
            defer control.deinitPruneView(a, &pvv);
            try std.testing.expectEqualStrings("t", pvv.topic);
            try std.testing.expect(pvv.backoff_seconds.? >= 20);
            saw_refusal_prune = true;
        }
    }
    try std.testing.expect(saw_refusal_prune);
}

test "local mesh prune records reciprocal back-off so heartbeat doesn't re-graft victim" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 2,
        .mesh_n_high = 3,
    });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    var peers: [4]identity.PeerId = undefined;
    for (&peers) |*p| p.* = try identity.PeerId.random();
    const graft = try control.encodeGraft(a, "t");
    defer a.free(graft);
    const graft_rpc = try rpc.encodeControlOnlyRpc(a, graft);
    defer a.free(graft_rpc);
    for (peers) |p| {
        g.onPeerConnected(p);
        try g.handleInboundRpc(p, graft_rpc);
    }
    try std.testing.expectEqual(@as(u64, 4), g.meshPeers());

    try g.heartbeat();
    try std.testing.expectEqual(@as(?usize, 2), g.meshPeerCountForTopic("t"));
    try std.testing.expect(g.activeBackoffCount() >= 2);
    while (g.popOutboxDelivery()) |d| a.free(d.wire);

    // Immediate next heartbeat must not re-graft the just-pruned peers.
    try g.heartbeat();
    try std.testing.expectEqual(@as(?usize, 2), g.meshPeerCountForTopic("t"));
    var graft_count: u32 = 0;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        const ctl = (try rpc.decodeControlPayload(a, d.wire)) orelse continue;
        defer a.free(ctl);
        if (try control.decodeFirstGraftTopic(a, ctl)) |topic| {
            a.free(topic);
            graft_count += 1;
        }
    }
    try std.testing.expectEqual(@as(u32, 0), graft_count);
}

test "peer disconnect clears its back-off entries" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const prune = try control.encodePrune(a, "t", 30);
    defer a.free(prune);
    const prune_rpc = try rpc.encodeControlOnlyRpc(a, prune);
    defer a.free(prune_rpc);
    try g.handleInboundRpc(peer, prune_rpc);
    try std.testing.expect(g.isPeerBackedOff(peer, "t"));

    g.onPeerDisconnected(peer);
    try std.testing.expectEqual(@as(usize, 0), g.activeBackoffCount());
}

test "PRUNE backoff_seconds is clamped to prune_backoff_cap_ms" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .prune_backoff_default_ms = 1_000,
        .prune_backoff_cap_ms = 10_000,
    });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    // Hostile peer asks for 24h back-off.
    const prune = try control.encodePrune(a, "t", 24 * 60 * 60);
    defer a.free(prune);
    const prune_rpc = try rpc.encodeControlOnlyRpc(a, prune);
    defer a.free(prune_rpc);
    try g.handleInboundRpc(peer, prune_rpc);

    g.setClockMs(10_000);
    try std.testing.expect(!g.isPeerBackedOff(peer, "t"));
}

// ---------------------------------------------------------------------------
// (from, seqno) defense-in-depth dedup (#75 blocker 2)
// ---------------------------------------------------------------------------

test "duplicate (from, seqno) inbound publish is dropped even when data differs" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 1, .mesh_n = 1, .mesh_n_high = 2 });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const inner1 = try msg_mod.encode(a, .{
        .topic = "t",
        .data = "payload-1",
        .from = "spoofed-from",
        .seqno = &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 },
    });
    defer a.free(inner1);
    const rpc1 = try rpc.encodePublish(a, inner1);
    defer a.free(rpc1);

    const inner2 = try msg_mod.encode(a, .{
        .topic = "t",
        .data = "payload-2-different",
        .from = "spoofed-from",
        .seqno = &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 },
    });
    defer a.free(inner2);
    const rpc2 = try rpc.encodePublish(a, inner2);
    defer a.free(rpc2);

    try g.handleInboundRpc(peer, rpc1);
    try g.handleInboundRpc(peer, rpc2);
    try std.testing.expectEqual(@as(u64, 1), g.inboundDeliveredCount());
    try std.testing.expectEqual(@as(u64, 1), g.inboundDroppedSeqnoReplayCount());
}

test "different (from, seqno) pairs are not deduped" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 1, .mesh_n = 1, .mesh_n_high = 2 });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const inner1 = try msg_mod.encode(a, .{ .topic = "t", .data = "d1", .from = "A", .seqno = &[_]u8{1} });
    defer a.free(inner1);
    const r1 = try rpc.encodePublish(a, inner1);
    defer a.free(r1);
    const inner2 = try msg_mod.encode(a, .{ .topic = "t", .data = "d2", .from = "A", .seqno = &[_]u8{2} });
    defer a.free(inner2);
    const r2 = try rpc.encodePublish(a, inner2);
    defer a.free(r2);
    const inner3 = try msg_mod.encode(a, .{ .topic = "t", .data = "d3", .from = "B", .seqno = &[_]u8{1} });
    defer a.free(inner3);
    const r3 = try rpc.encodePublish(a, inner3);
    defer a.free(r3);

    try g.handleInboundRpc(peer, r1);
    try g.handleInboundRpc(peer, r2);
    try g.handleInboundRpc(peer, r3);
    try std.testing.expectEqual(@as(u64, 3), g.inboundDeliveredCount());
    try std.testing.expectEqual(@as(u64, 0), g.inboundDroppedSeqnoReplayCount());
}

test "StrictNoSign publishes (no from / no seqno) are unaffected" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 1, .mesh_n = 1, .mesh_n_high = 2 });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const inner = try msg_mod.encode(a, .{ .topic = "t", .data = "one-shot" });
    defer a.free(inner);
    const r = try rpc.encodePublish(a, inner);
    defer a.free(r);

    try g.handleInboundRpc(peer, r);
    try std.testing.expectEqual(@as(u64, 1), g.inboundDeliveredCount());
    try std.testing.expectEqual(@as(u64, 0), g.inboundDroppedSeqnoReplayCount());
}

test "seqno dedup can be disabled via config" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 1,
        .mesh_n_high = 2,
        .seqno_dedup_enabled = false,
    });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const inner1 = try msg_mod.encode(a, .{ .topic = "t", .data = "d1", .from = "A", .seqno = &[_]u8{1} });
    defer a.free(inner1);
    const r1 = try rpc.encodePublish(a, inner1);
    defer a.free(r1);
    const inner2 = try msg_mod.encode(a, .{ .topic = "t", .data = "d2-different", .from = "A", .seqno = &[_]u8{1} });
    defer a.free(inner2);
    const r2 = try rpc.encodePublish(a, inner2);
    defer a.free(r2);

    try g.handleInboundRpc(peer, r1);
    try g.handleInboundRpc(peer, r2);
    // Both have distinct message_ids (different data), and seqno dedup is off; both delivered.
    try std.testing.expectEqual(@as(u64, 2), g.inboundDeliveredCount());
    try std.testing.expectEqual(@as(u64, 0), g.inboundDroppedSeqnoReplayCount());
}

// ---------------------------------------------------------------------------
// Topic validator hook (#84)
// ---------------------------------------------------------------------------

const ValidatorRecorder = struct {
    rule: ValidationResult = .accept,
    last_topic_len: usize = 0,
    last_data_len: usize = 0,
    fn cb(ctx: ?*anyopaque, topic: []const u8, data: []const u8) ValidationResult {
        const self: *ValidatorRecorder = @ptrCast(@alignCast(ctx.?));
        self.last_topic_len = topic.len;
        self.last_data_len = data.len;
        return self.rule;
    }
};

test "validator accept passes message through" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var vr = ValidatorRecorder{ .rule = .accept };
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 1,
        .mesh_n_high = 2,
        .topic_validator = ValidatorRecorder.cb,
        .validator_ctx = @ptrCast(&vr),
    });
    defer g.deinit();

    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const inner = try msg_mod.encode(a, .{ .topic = "t", .data = "hello" });
    defer a.free(inner);
    const r = try rpc.encodePublish(a, inner);
    defer a.free(r);
    try g.handleInboundRpc(peer, r);
    try std.testing.expectEqual(@as(u64, 1), g.inboundDeliveredCount());
    try std.testing.expectEqual(@as(u64, 0), g.validatorRejectCount());
    try std.testing.expectEqual(@as(usize, 1), vr.last_topic_len);
    try std.testing.expectEqual(@as(usize, 5), vr.last_data_len);
}

test "validator reject drops message and applies reject score delta" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var vr = ValidatorRecorder{ .rule = .reject };
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 1,
        .mesh_n_high = 2,
        .topic_validator = ValidatorRecorder.cb,
        .validator_ctx = @ptrCast(&vr),
        .validator_reject_score_delta = -25,
    });
    defer g.deinit();

    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);
    try g.setPeerBehaviourScore(peer, 100);

    const inner = try msg_mod.encode(a, .{ .topic = "t", .data = "bogus" });
    defer a.free(inner);
    const r = try rpc.encodePublish(a, inner);
    defer a.free(r);
    try g.handleInboundRpc(peer, r);

    try std.testing.expectEqual(@as(u64, 0), g.inboundDeliveredCount());
    try std.testing.expectEqual(@as(u64, 1), g.validatorRejectCount());
    try std.testing.expectEqual(@as(i32, 75), g.peerBehaviourScore(peer));
}

test "validator ignore drops message without scoring" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var vr = ValidatorRecorder{ .rule = .ignore };
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 1,
        .mesh_n_high = 2,
        .topic_validator = ValidatorRecorder.cb,
        .validator_ctx = @ptrCast(&vr),
    });
    defer g.deinit();

    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);
    try g.setPeerBehaviourScore(peer, 50);

    const inner = try msg_mod.encode(a, .{ .topic = "t", .data = "off-topic" });
    defer a.free(inner);
    const r = try rpc.encodePublish(a, inner);
    defer a.free(r);
    try g.handleInboundRpc(peer, r);

    try std.testing.expectEqual(@as(u64, 0), g.inboundDeliveredCount());
    try std.testing.expectEqual(@as(u64, 1), g.validatorIgnoreCount());
    try std.testing.expectEqual(@as(i32, 50), g.peerBehaviourScore(peer));
}

// ---------------------------------------------------------------------------
// Direct peers (#85)
// ---------------------------------------------------------------------------

test "direct peer bypasses PRUNE back-off" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 1, .mesh_n = 1, .mesh_n_high = 2 });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);
    try g.addDirectPeer(peer);

    const prune = try control.encodePrune(a, "t", 60);
    defer a.free(prune);
    const prune_rpc = try rpc.encodeControlOnlyRpc(a, prune);
    defer a.free(prune_rpc);
    try g.handleInboundRpc(peer, prune_rpc);

    try std.testing.expect(!g.isPeerBackedOff(peer, "t"));
    try std.testing.expectEqual(@as(usize, 0), g.activeBackoffCount());
}

test "direct peer is never selected as mesh-prune victim" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 2,
        .mesh_n_high = 3,
    });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    var peers: [4]identity.PeerId = undefined;
    for (&peers) |*p| p.* = try identity.PeerId.random();
    try g.addDirectPeer(peers[0]);

    const graft = try control.encodeGraft(a, "t");
    defer a.free(graft);
    const graft_rpc = try rpc.encodeControlOnlyRpc(a, graft);
    defer a.free(graft_rpc);
    for (peers) |p| {
        g.onPeerConnected(p);
        try g.handleInboundRpc(p, graft_rpc);
    }
    try std.testing.expectEqual(@as(u64, 4), g.meshPeers());

    try g.heartbeat();
    // Mesh trimmed to mesh_n=2, but the direct peer must still be in the mesh.
    try std.testing.expectEqual(@as(?usize, 2), g.meshPeerCountForTopic("t"));

    var direct_pruned = false;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        if (d.to) |t| {
            if (t.eql(&peers[0])) {
                const ctl = (try rpc.decodeControlPayload(a, d.wire)) orelse continue;
                defer a.free(ctl);
                if ((try control.decodeFirstPrune(a, ctl)) != null) direct_pruned = true;
            }
        }
    }
    try std.testing.expect(!direct_pruned);
}

// ---------------------------------------------------------------------------
// IDONTWANT runtime suppression (#85)
// ---------------------------------------------------------------------------

test "IDONTWANT from mesh peer suppresses outbound publish to that peer" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .mesh_n_low = 1, .mesh_n = 1, .mesh_n_high = 3 });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const pa = try identity.PeerId.random();
    const pb = try identity.PeerId.random();
    g.onPeerConnected(pa);
    g.onPeerConnected(pb);

    const graft = try control.encodeGraft(a, "t");
    defer a.free(graft);
    const graft_rpc = try rpc.encodeControlOnlyRpc(a, graft);
    defer a.free(graft_rpc);
    try g.handleInboundRpc(pa, graft_rpc);
    try g.handleInboundRpc(pb, graft_rpc);
    while (g.popOutboxDelivery()) |d| a.free(d.wire);

    // Compute message_id for ("t", "hot") so we can pre-seed IDONTWANT from pb.
    var mid: [20]u8 = undefined;
    message_id.writeMessageId("t", "hot", true, &mid);
    const idw = try control.encodeIDontWant(a, &.{mid[0..]});
    defer a.free(idw);
    const idw_rpc = try rpc.encodeControlOnlyRpc(a, idw);
    defer a.free(idw_rpc);
    try g.handleInboundRpc(pb, idw_rpc);
    try std.testing.expectEqual(@as(usize, 1), g.idontwantCount());

    // Now inject the publish from pa. Forward must go to pb's IDONTWANT'd id → suppress.
    const inner = try msg_mod.encode(a, .{ .topic = "t", .data = "hot" });
    defer a.free(inner);
    const pubw = try rpc.encodePublish(a, inner);
    defer a.free(pubw);
    try g.handleInboundRpc(pa, pubw);

    var saw_pb_publish = false;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        const to = d.to orelse continue;
        if (to.eql(&pb)) {
            // Subscribe wires don't carry publishes; check for publish.
            const blobs = try rpc.decodePublishes(a, d.wire);
            defer rpc.freePublishBlobs(a, blobs);
            if (blobs.len > 0) saw_pb_publish = true;
        }
    }
    try std.testing.expect(!saw_pb_publish);
    try std.testing.expect(g.suppressedOutboundIDontWantCount() >= 1);
}

test "IDONTWANT cache expires after ttl" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .idontwant_ttl_ms = 2000,
    });
    defer g.deinit();

    g.setClockMs(0);
    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    var id: [20]u8 = [_]u8{0xab} ** 20;
    const idw = try control.encodeIDontWant(a, &.{id[0..]});
    defer a.free(idw);
    const idw_rpc = try rpc.encodeControlOnlyRpc(a, idw);
    defer a.free(idw_rpc);
    try g.handleInboundRpc(peer, idw_rpc);
    try std.testing.expectEqual(@as(usize, 1), g.idontwantCount());

    // Advance past TTL and trigger a sweep via lookup.
    g.setClockMs(3000);
    try std.testing.expect(!g.peerWantsNotPublish(peer, id));
    try std.testing.expectEqual(@as(usize, 0), g.idontwantCount());
}

// ---------------------------------------------------------------------------
// Unsubscribe back-off (#83)
// ---------------------------------------------------------------------------

test "unsubscribe LEAVE emits PRUNE with unsubscribe_backoff and blocks resubscribe" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .mesh_n_low = 1,
        .mesh_n = 2,
        .mesh_n_high = 4,
        .unsubscribe_backoff_ms = 10_000,
        .prune_backoff_default_ms = 60_000,
    });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    while (g.popOutboxDelivery()) |d| a.free(d.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const graft = try control.encodeGraft(a, "t");
    defer a.free(graft);
    const graft_rpc = try rpc.encodeControlOnlyRpc(a, graft);
    defer a.free(graft_rpc);
    try g.handleInboundRpc(peer, graft_rpc);
    try std.testing.expectEqual(@as(?usize, 1), g.meshPeerCountForTopic("t"));

    try g.unsubscribe("t");

    var saw_unsub = false;
    var saw_prune_unsub_backoff = false;
    while (g.popOutboxDelivery()) |d| {
        defer a.free(d.wire);
        const sub_views = try rpc.decodeSubscribes(a, d.wire);
        defer rpc.freeSubscribeViews(a, sub_views);
        for (sub_views) |sv| {
            if (!sv.subscribe and std.mem.eql(u8, sv.topic, "t")) saw_unsub = true;
        }
        const ctl = (try rpc.decodeControlPayload(a, d.wire)) orelse continue;
        defer a.free(ctl);
        if (try control.decodeFirstPrune(a, ctl)) |pv| {
            var pvv = pv;
            defer control.deinitPruneView(a, &pvv);
            if (d.to != null and d.to.?.eql(&peer) and std.mem.eql(u8, pvv.topic, "t")) {
                try std.testing.expectEqual(@as(?u64, 10), pvv.backoff_seconds);
                saw_prune_unsub_backoff = true;
            }
        }
    }
    try std.testing.expect(saw_unsub);
    try std.testing.expect(saw_prune_unsub_backoff);
    try std.testing.expectEqual(@as(?usize, null), g.meshPeerCountForTopic("t"));

    try std.testing.expectError(error.TopicUnsubscribeBackoff, g.subscribe("t"));

    g.setClockMs(10_000);
    try g.subscribe("t");
}

test "inbound GRAFT during topic unsubscribe cooldown is refused (#83)" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{
        .local_peer_id = me,
        .unsubscribe_backoff_ms = 10_000,
    });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    while (g.popOutboxDelivery()) |d| a.free(d.wire);
    try g.unsubscribe("t");
    while (g.popOutboxDelivery()) |d| a.free(d.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    g.setClockMs(2_000);
    const graft = try control.encodeGraft(a, "t");
    defer a.free(graft);
    const graft_rpc = try rpc.encodeControlOnlyRpc(a, graft);
    defer a.free(graft_rpc);
    try g.handleInboundRpc(peer, graft_rpc);

    try std.testing.expectEqual(@as(u64, 1), g.graftRefusedDuringBackoffCount());

    const d_opt = g.popOutboxDelivery();
    try std.testing.expect(d_opt != null);
    const d = d_opt.?;
    defer a.free(d.wire);
    try std.testing.expect(d.to != null and d.to.?.eql(&peer));
    const ctl = (try rpc.decodeControlPayload(a, d.wire)) orelse {
        try std.testing.expect(false);
        return;
    };
    defer a.free(ctl);
    const pv = (try control.decodeFirstPrune(a, ctl)) orelse {
        try std.testing.expect(false);
        return;
    };
    var pvv = pv;
    defer control.deinitPruneView(a, &pvv);
    try std.testing.expectEqualStrings("t", pvv.topic);
    try std.testing.expect(pvv.backoff_seconds.? >= 7 and pvv.backoff_seconds.? <= 9);
}

// ---------------------------------------------------------------------------
// PRUNE PX dial-suggestion queue (#85)
// ---------------------------------------------------------------------------

test "inbound PRUNE PX peer-ids surface in dial-suggestion queue" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const px = [_]control.PeerInfoOwned{
        .{ .peer_id = @constCast("px-peer-1") },
        .{ .peer_id = @constCast("px-peer-2") },
    };
    const prune = try control.encodePruneWithPeers(a, "t", 30, &px);
    defer a.free(prune);
    const prune_rpc = try rpc.encodeControlOnlyRpc(a, prune);
    defer a.free(prune_rpc);
    try g.handleInboundRpc(peer, prune_rpc);

    try std.testing.expectEqual(@as(usize, 2), g.dialSuggestionCount());
    const a1 = g.popDialSuggestion().?;
    defer a.free(a1);
    try std.testing.expectEqualStrings("px-peer-1", a1);
    const a2 = g.popDialSuggestion().?;
    defer a.free(a2);
    try std.testing.expectEqualStrings("px-peer-2", a2);
    try std.testing.expectEqual(@as(?[]u8, null), g.popDialSuggestion());
}

test "PX queue evicts oldest when full" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me, .max_px_dial_queue = 2 });
    defer g.deinit();

    g.setClockMs(0);
    try g.subscribe("t");
    a.free(g.popOutboxDelivery().?.wire);

    const peer = try identity.PeerId.random();
    g.onPeerConnected(peer);

    const px = [_]control.PeerInfoOwned{
        .{ .peer_id = @constCast("p1") },
        .{ .peer_id = @constCast("p2") },
        .{ .peer_id = @constCast("p3") },
    };
    const prune = try control.encodePruneWithPeers(a, "t", null, &px);
    defer a.free(prune);
    const prune_rpc = try rpc.encodeControlOnlyRpc(a, prune);
    defer a.free(prune_rpc);
    try g.handleInboundRpc(peer, prune_rpc);

    try std.testing.expectEqual(@as(usize, 2), g.dialSuggestionCount());
    const got1 = g.popDialSuggestion().?;
    defer a.free(got1);
    try std.testing.expectEqualStrings("p2", got1);
    const got2 = g.popDialSuggestion().?;
    defer a.free(got2);
    try std.testing.expectEqualStrings("p3", got2);
}
