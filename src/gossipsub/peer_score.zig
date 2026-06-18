//! libp2p gossipsub v1.1 peer scoring (#199).
//!
//! Spec: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md#peer-scoring

const std = @import("std");
const identity = @import("../identity.zig");
const connection_manager = @import("../connection_manager.zig");

pub const Direction = enum {
    inbound,
    outbound,
    unknown,
};

/// Per-topic scoring knobs (rust-libp2p defaults).
pub const TopicParams = struct {
    topic_weight: f64 = 1,
    time_in_mesh_weight: f64 = 0.0002778,
    time_in_mesh_cap: f64 = 3600,
    time_in_mesh_quantum_ms: i64 = 1000,
    first_message_deliveries_weight: f64 = 1,
    first_message_deliveries_cap: f64 = 2000,
    first_message_deliveries_decay: f64 = 0.9999,
    mesh_message_deliveries_weight: f64 = -1,
    mesh_message_deliveries_threshold: f64 = 6,
    mesh_message_deliveries_cap: f64 = 100,
    mesh_message_deliveries_decay: f64 = 0.99,
    mesh_message_deliveries_window_ms: i64 = 2000,
    mesh_failure_penalty_weight: f64 = -1,
    mesh_failure_penalty_decay: f64 = 0.99,
    invalid_message_deliveries_weight: f64 = -100,
    invalid_message_deliveries_decay: f64 = 0.9999,
    gossip_threshold: f64 = -500,
    publish_threshold: f64 = -1000,
    graylist_threshold: f64 = -2500,
    accept_px_threshold: f64 = -1000,
    opportunistic_graft_threshold: f64 = 1,
    opportunistic_graft_peers: u8 = 2,
    d_out: u8 = 2,
};

pub const Params = struct {
    topic: TopicParams = .{},
    decay_interval_ms: i64 = 10_000,
    decay_to_zero: f64 = 0.01,
    behaviour_penalty_weight: f64 = -10,
    behaviour_penalty_threshold: f64 = 0,
    behaviour_penalty_decay: f64 = 0.986,
};

const TopicPeerStats = struct {
    time_in_mesh_ms: i64 = 0,
    first_deliveries: f64 = 0,
    mesh_deliveries: f64 = 0,
    mesh_failures: f64 = 0,
    invalid_msgs: f64 = 0,
    behaviour_penalty: f64 = 0,
    last_mesh_delivery_ms: i64 = 0,
};

const PeerState = struct {
    direction: Direction = .unknown,
    topics: std.StringHashMap(TopicPeerStats),
};

pub const Tracker = struct {
    allocator: std.mem.Allocator,
    params: Params,
    peers: std.HashMap(identity.PeerId, PeerState, connection_manager.PeerIdContext, std.hash_map.default_max_load_percentage),
    last_decay_ms: i64 = 0,

    pub fn init(allocator: std.mem.Allocator, params: Params) Tracker {
        return .{
            .allocator = allocator,
            .params = params,
            .peers = .init(allocator),
        };
    }

    pub fn deinit(self: *Tracker) void {
        var it = self.peers.iterator();
        while (it.next()) |e| {
            var tit = e.value_ptr.topics.iterator();
            while (tit.next()) |te| self.allocator.free(te.key_ptr.*);
            e.value_ptr.topics.deinit();
        }
        self.peers.deinit();
    }

    pub fn setDirection(self: *Tracker, peer: identity.PeerId, conn_direction: Direction) void {
        const gop = self.peers.getOrPut(peer) catch return;
        if (!gop.found_existing) gop.value_ptr.* = .{ .topics = std.StringHashMap(TopicPeerStats).init(self.allocator) };
        gop.value_ptr.direction = conn_direction;
    }

    pub fn removePeer(self: *Tracker, peer: identity.PeerId) void {
        var st = self.peers.fetchRemove(peer) orelse return;
        var tit = st.value.topics.iterator();
        while (tit.next()) |te| self.allocator.free(te.key_ptr.*);
        st.value.topics.deinit();
    }

    fn statsFor(self: *Tracker, peer: identity.PeerId, topic: []const u8) !*TopicPeerStats {
        const gop = try self.peers.getOrPut(peer);
        if (!gop.found_existing) gop.value_ptr.* = .{ .topics = std.StringHashMap(TopicPeerStats).init(self.allocator) };
        if (gop.value_ptr.topics.getPtr(topic)) |existing| return existing;
        const topic_owned = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(topic_owned);
        const tg = try gop.value_ptr.topics.getOrPut(topic_owned);
        std.debug.assert(!tg.found_existing);
        tg.value_ptr.* = .{};
        return tg.value_ptr;
    }

    pub fn tickMeshMembership(self: *Tracker, topic: []const u8, mesh_peers: []const identity.PeerId, quantum_ms: i64) void {
        for (mesh_peers) |peer| {
            const st = self.statsFor(peer, topic) catch continue;
            st.time_in_mesh_ms += quantum_ms;
        }
    }

    pub fn recordFirstDelivery(self: *Tracker, peer: identity.PeerId, topic: []const u8) void {
        const st = self.statsFor(peer, topic) catch return;
        st.first_deliveries += 1;
    }

    pub fn recordMeshDelivery(self: *Tracker, peer: identity.PeerId, topic: []const u8, now_ms: i64) void {
        const st = self.statsFor(peer, topic) catch return;
        st.mesh_deliveries += 1;
        st.last_mesh_delivery_ms = now_ms;
    }

    pub fn recordMeshFailure(self: *Tracker, peer: identity.PeerId, topic: []const u8) void {
        const st = self.statsFor(peer, topic) catch return;
        st.mesh_failures += 1;
    }

    pub fn recordInvalidMessage(self: *Tracker, peer: identity.PeerId, topic: []const u8) void {
        const st = self.statsFor(peer, topic) catch return;
        st.invalid_msgs += 1;
    }

    pub fn applyBehaviourDelta(self: *Tracker, peer: identity.PeerId, topic: []const u8, delta: f64) void {
        if (delta == 0) return;
        const st = self.statsFor(peer, topic) catch return;
        st.behaviour_penalty += delta;
    }

    pub fn decay(self: *Tracker, now_ms: i64) void {
        if (self.last_decay_ms != 0 and now_ms - self.last_decay_ms < self.params.decay_interval_ms) return;
        self.last_decay_ms = now_ms;
        const tp = self.params.topic;
        var it = self.peers.iterator();
        while (it.next()) |e| {
            var tit = e.value_ptr.topics.iterator();
            while (tit.next()) |te| {
                var s = te.value_ptr;
                s.first_deliveries *= tp.first_message_deliveries_decay;
                s.mesh_deliveries *= tp.mesh_message_deliveries_decay;
                s.mesh_failures *= tp.mesh_failure_penalty_decay;
                s.invalid_msgs *= tp.invalid_message_deliveries_decay;
                s.behaviour_penalty *= self.params.behaviour_penalty_decay;
                if (s.first_deliveries < self.params.decay_to_zero) s.first_deliveries = 0;
                if (s.mesh_deliveries < self.params.decay_to_zero) s.mesh_deliveries = 0;
                if (s.mesh_failures < self.params.decay_to_zero) s.mesh_failures = 0;
                if (s.invalid_msgs < self.params.decay_to_zero) s.invalid_msgs = 0;
                if (s.behaviour_penalty < self.params.decay_to_zero) s.behaviour_penalty = 0;
            }
        }
    }

    fn topicScore(self: *const Tracker, stats: *const TopicPeerStats, now_ms: i64) f64 {
        const tp = self.params.topic;
        var score: f64 = 0;
        const time_in_mesh = @min(
            @as(f64, @floatFromInt(stats.time_in_mesh_ms)) / @as(f64, @floatFromInt(tp.time_in_mesh_quantum_ms)),
            tp.time_in_mesh_cap,
        );
        score += time_in_mesh * tp.time_in_mesh_weight;
        score += @min(stats.first_deliveries, tp.first_message_deliveries_cap) * tp.first_message_deliveries_weight;
        const mesh_deliveries = if (now_ms - stats.last_mesh_delivery_ms > tp.mesh_message_deliveries_window_ms)
            0
        else
            stats.mesh_deliveries;
        if (mesh_deliveries > tp.mesh_message_deliveries_threshold) {
            score += @min(mesh_deliveries - tp.mesh_message_deliveries_threshold, tp.mesh_message_deliveries_cap) *
                tp.mesh_message_deliveries_weight;
        }
        score += stats.mesh_failures * tp.mesh_failure_penalty_weight;
        score += stats.invalid_msgs * tp.invalid_message_deliveries_weight;
        if (stats.behaviour_penalty > self.params.behaviour_penalty_threshold) {
            score += (stats.behaviour_penalty - self.params.behaviour_penalty_threshold) * self.params.behaviour_penalty_weight;
        }
        return score * tp.topic_weight;
    }

    pub fn scoreForTopic(self: *const Tracker, peer: identity.PeerId, topic: []const u8, now_ms: i64) i32 {
        const peer_st = self.peers.get(peer) orelse return 0;
        const stats = peer_st.topics.get(topic) orelse return 0;
        return @intFromFloat(self.topicScore(&stats, now_ms));
    }

    pub fn minTopicScore(self: *const Tracker, peer: identity.PeerId, now_ms: i64) i32 {
        const peer_st = self.peers.get(peer) orelse return 0;
        var min: f64 = std.math.floatMax(f64);
        var any = false;
        var it = peer_st.topics.iterator();
        while (it.next()) |e| {
            any = true;
            const s = self.topicScore(e.value_ptr, now_ms);
            if (s < min) min = s;
        }
        if (!any) return 0;
        return @intFromFloat(min);
    }

    pub fn allowsGossip(self: *const Tracker, peer: identity.PeerId, topic: []const u8, now_ms: i64) bool {
        return @as(f64, @floatFromInt(self.scoreForTopic(peer, topic, now_ms))) >= self.params.topic.gossip_threshold;
    }

    pub fn allowsPublishForward(self: *const Tracker, peer: identity.PeerId, topic: []const u8, now_ms: i64) bool {
        return @as(f64, @floatFromInt(self.scoreForTopic(peer, topic, now_ms))) >= self.params.topic.publish_threshold;
    }

    pub fn allowsRpc(self: *const Tracker, peer: identity.PeerId, now_ms: i64) bool {
        return @as(f64, @floatFromInt(self.minTopicScore(peer, now_ms))) >= self.params.topic.graylist_threshold;
    }

    pub fn allowsPx(self: *const Tracker, peer: identity.PeerId, topic: []const u8, now_ms: i64) bool {
        return @as(f64, @floatFromInt(self.scoreForTopic(peer, topic, now_ms))) >= self.params.topic.accept_px_threshold;
    }

    pub fn opportunisticGraftCandidates(
        self: *const Tracker,
        allocator: std.mem.Allocator,
        topic: []const u8,
        connected: []const identity.PeerId,
        mesh: []const identity.PeerId,
        now_ms: i64,
    ) ![]identity.PeerId {
        var out: std.ArrayList(identity.PeerId) = .empty;
        errdefer out.deinit(allocator);
        const threshold = self.params.topic.opportunistic_graft_threshold;
        for (connected) |peer| {
            if (containsPeer(mesh, peer)) continue;
            if (@as(f64, @floatFromInt(self.scoreForTopic(peer, topic, now_ms))) < threshold) continue;
            try out.append(allocator, peer);
        }
        const SortCtx = struct {
            tr: *const Tracker,
            topic: []const u8,
            now_ms: i64,
        };
        const sort_ctx = SortCtx{ .tr = self, .topic = topic, .now_ms = now_ms };
        std.mem.sort(identity.PeerId, out.items, sort_ctx, struct {
            fn less(ctx: SortCtx, a: identity.PeerId, b: identity.PeerId) bool {
                return ctx.tr.scoreForTopic(a, ctx.topic, ctx.now_ms) > ctx.tr.scoreForTopic(b, ctx.topic, ctx.now_ms);
            }
        }.less);
        const n = @min(out.items.len, self.params.topic.opportunistic_graft_peers);
        out.shrinkRetainingCapacity(n);
        return try out.toOwnedSlice(allocator);
    }

    pub fn outboundMeshDeficit(self: *const Tracker, _: []const u8, mesh_peers: []const identity.PeerId) u8 {
        var outbound: u8 = 0;
        for (mesh_peers) |peer| {
            const st = self.peers.get(peer) orelse continue;
            if (st.direction == .outbound) outbound += 1;
        }
        if (outbound >= self.params.topic.d_out) return 0;
        return self.params.topic.d_out - outbound;
    }

    pub fn peerDirection(self: *const Tracker, peer: identity.PeerId) Direction {
        return self.peers.get(peer).?.direction;
    }
};

fn containsPeer(peers: []const identity.PeerId, needle: identity.PeerId) bool {
    for (peers) |p| if (p.eql(&needle)) return true;
    return false;
}

test "invalid message drives score below gossip threshold" {
    const a = std.testing.allocator;
    var tr = Tracker.init(a, .{});
    defer tr.deinit();
    const peer = try identity.PeerId.random();
    for (0..6) |_| tr.recordInvalidMessage(peer, "blocks");
    try std.testing.expect(!tr.allowsGossip(peer, "blocks", 0));
}

test "decay restores gossip eligibility" {
    const a = std.testing.allocator;
    var tr = Tracker.init(a, .{
        .topic = .{
            .gossip_threshold = -50,
            .invalid_message_deliveries_decay = 0.5,
        },
    });
    defer tr.deinit();
    const peer = try identity.PeerId.random();
    tr.recordInvalidMessage(peer, "blocks");
    try std.testing.expect(!tr.allowsGossip(peer, "blocks", 0));
    tr.decay(10_000);
    try std.testing.expect(tr.allowsGossip(peer, "blocks", 10_000));
}

test "first delivery increases topic score" {
    const a = std.testing.allocator;
    var tr = Tracker.init(a, .{});
    defer tr.deinit();
    const peer = try identity.PeerId.random();
    const before = tr.scoreForTopic(peer, "blocks", 0);
    tr.recordFirstDelivery(peer, "blocks");
    const after = tr.scoreForTopic(peer, "blocks", 0);
    try std.testing.expect(after > before);
}
