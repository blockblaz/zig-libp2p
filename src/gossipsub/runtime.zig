//! Gossipsub mesh runtime (incremental, #39): subscriptions, peer presence, per-topic mesh,
//! heartbeat GRAFT/PRUNE toward Zeam `mesh_n` / `mesh_n_low` / `mesh_n_high`, inbound control,
//! publish forwarding, duplicate cache, and a targeted outbox.
//!
//! Inbound `subscriptions` RPC entries record remote interest per topic. When at least one peer
//! has advertised interest for a topic, GRAFT candidates are restricted to those peers; if none
//! have, the implementation falls back to all connected peers (flood-style bootstrap).

const std = @import("std");
const identity = @import("../identity.zig");
const connection_manager = @import("../connection_manager.zig");
const errors = @import("../errors.zig");
const control = @import("control.zig");
const duplicate_cache = @import("duplicate_cache.zig");
const gs_cfg = @import("config.zig");
const message_id = @import("message_id.zig");
const msg_mod = @import("message.zig");
const rpc = @import("rpc.zig");

pub const GossipsubConfig = struct {
    local_peer_id: identity.PeerId,
    message_id_domain_snappy_ok: bool = true,
    mesh_n_low: u8 = gs_cfg.mesh_n_low,
    mesh_n: u8 = gs_cfg.mesh_n,
    mesh_n_high: u8 = gs_cfg.mesh_n_high,
    /// Max queued outbound RPC blobs (`OutDelivery`) before subscribe/publish/heartbeat return
    /// `errors.GossipsubError.PublishQueueFull` (#39).
    max_outbox_entries: usize = 4096,

    pub fn validate(c: GossipsubConfig) InitConfigError!void {
        if (c.mesh_n_low > c.mesh_n) return error.InvalidMeshKnobs;
        if (c.mesh_n > c.mesh_n_high) return error.InvalidMeshKnobs;
        if (c.max_outbox_entries == 0) return error.InvalidOutboxCap;
    }
};

pub const InitConfigError = error{ InvalidMeshKnobs, InvalidOutboxCap };

pub const OutDelivery = struct {
    wire: []u8,
    /// `null` means broadcast to all connected peers (subscribe / publish announcements).
    to: ?identity.PeerId,
};

const TopicMesh = struct {
    peers: std.HashMap(identity.PeerId, void, connection_manager.PeerIdContext, std.hash_map.default_max_load_percentage),

    fn init(allocator: std.mem.Allocator) TopicMesh {
        return .{ .peers = .init(allocator) };
    }

    fn deinit(self: *TopicMesh, allocator: std.mem.Allocator) void {
        self.peers.deinit(allocator);
    }
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
    scratch_peers: std.ArrayList(identity.PeerId),

    pub fn init(allocator: std.mem.Allocator, config: GossipsubConfig) (InitConfigError || std.mem.Allocator.Error)!*Gossipsub {
        try config.validate();
        const p = try allocator.create(Gossipsub);
        errdefer allocator.destroy(p);
        p.* = .{
            .allocator = allocator,
            .cfg = config,
            .dup = duplicate_cache.DuplicateCache.init(allocator),
            .subs = std.StringHashMap(void).init(allocator),
            .mesh = std.StringHashMap(TopicMesh).init(allocator),
            .remote_interest = std.StringHashMap(TopicMesh).init(allocator),
            .connected = .init(allocator),
            .clock_ms = 0,
            .outbox = .init(allocator),
            .inbound_delivered = 0,
            .control_i_have_rx = 0,
            .control_i_want_rx = 0,
            .scratch_peers = .init(allocator),
        };
        return p;
    }

    pub fn deinit(self: *Gossipsub) void {
        self.dup.deinit();
        self.subs.deinit(self.allocator);
        var mit = self.mesh.iterator();
        while (mit.next()) |e| {
            e.value_ptr.deinit(self.allocator);
        }
        self.mesh.deinit(self.allocator);
        var rit = self.remote_interest.iterator();
        while (rit.next()) |e| {
            e.value_ptr.deinit(self.allocator);
        }
        self.remote_interest.deinit(self.allocator);
        for (self.outbox.items) |d| self.allocator.free(d.wire);
        self.outbox.deinit(self.allocator);
        self.connected.deinit(self.allocator);
        self.scratch_peers.deinit(self.allocator);
        const a = self.allocator;
        a.destroy(self);
    }

    pub fn setClockMs(self: *Gossipsub, t: i64) void {
        self.clock_ms = t;
    }

    fn appendOut(self: *Gossipsub, wire: []u8, to: ?identity.PeerId) (errors.GossipsubError || std.mem.Allocator.Error)!void {
        if (self.outbox.items.len >= self.cfg.max_outbox_entries) return error.PublishQueueFull;
        try self.outbox.append(.{ .wire = wire, .to = to });
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
        if (want) {
            try self.ensureRemoteInterestTable(topic);
            const rp = self.remote_interest.getPtr(topic).?;
            try rp.peers.put(sender, {});
        } else {
            if (self.remote_interest.getPtr(topic)) |rp| {
                _ = rp.peers.remove(sender);
            }
        }
    }

    pub fn subscribe(self: *Gossipsub, topic: []const u8) (rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        if (self.subs.contains(topic)) return;
        try self.subs.put(topic, {});
        errdefer _ = self.subs.fetchRemove(topic);
        try self.ensureTopicMesh(topic);
        const w = try rpc.encodeSubscribe(self.allocator, topic, true);
        errdefer self.allocator.free(w);
        try self.appendOut(w, null);
    }

    pub fn unsubscribe(self: *Gossipsub, topic: []const u8) (rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        if (self.subs.fetchRemove(topic)) |_| {
            if (self.mesh.fetchRemove(topic)) |kv| {
                var tm = kv.value;
                tm.deinit(self.allocator);
            }
            if (self.remote_interest.fetchRemove(topic)) |kv| {
                var tm = kv.value;
                tm.deinit(self.allocator);
            }
            const w = try rpc.encodeSubscribe(self.allocator, topic, false);
            errdefer self.allocator.free(w);
            try self.appendOut(w, null);
        }
    }

    pub fn publish(self: *Gossipsub, topic: []const u8, payload: []const u8) (msg_mod.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        const inner = try msg_mod.encode(self.allocator, .{ .topic = topic, .data = payload });
        defer self.allocator.free(inner);
        const wire = try rpc.encodePublish(self.allocator, inner);
        errdefer self.allocator.free(wire);
        try self.appendOut(wire, null);
    }

    pub fn onPeerConnected(self: *Gossipsub, peer: identity.PeerId) void {
        self.connected.put(peer, {}) catch return;
    }

    pub fn onPeerDisconnected(self: *Gossipsub, peer: identity.PeerId) void {
        _ = self.connected.remove(peer);
        var mit = self.mesh.iterator();
        while (mit.next()) |e| {
            _ = e.value_ptr.peers.remove(peer);
        }
        var rit = self.remote_interest.iterator();
        while (rit.next()) |e| {
            _ = e.value_ptr.peers.remove(peer);
        }
    }

    fn sortPeersByBytes(peers: []identity.PeerId) void {
        const S = struct {
            fn less(_: void, a: identity.PeerId, b: identity.PeerId) bool {
                var ba: [128]u8 = undefined;
                var bb: [128]u8 = undefined;
                const sa = a.toBytes(&ba) catch return false;
                const sb = b.toBytes(&bb) catch return true;
                return std.mem.order(u8, sa, sb) == .lt;
            }
        };
        std.mem.sort(identity.PeerId, peers, {}, S.less);
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
            if (restrict) {
                const ip = interest.?;
                if (!ip.peers.contains(p)) continue;
            }
            try self.scratch_peers.append(p);
        }
        sortPeersByBytes(self.scratch_peers.items);
        return self.scratch_peers.items;
    }

    fn handleInboundControl(self: *Gossipsub, sender: identity.PeerId, ctl: []const u8) (control.Error || std.mem.Allocator.Error)!void {
        if (try control.decodeFirstGraftTopic(self.allocator, ctl)) |gt| {
            defer self.allocator.free(gt);
            if (self.subs.contains(gt)) {
                try self.ensureTopicMesh(gt);
                const mp = self.mesh.getPtr(gt).?;
                try mp.peers.put(sender, {});
            }
        }
        if (try control.decodeFirstPrune(self.allocator, ctl)) |pv| {
            var prune = pv;
            defer control.deinitPruneView(self.allocator, &prune);
            if (self.mesh.getPtr(prune.topic)) |mp| {
                _ = mp.peers.remove(sender);
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
        }
    }

    fn forwardPublish(self: *Gossipsub, sender: identity.PeerId, topic: []const u8, data: []const u8) (msg_mod.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        const mp = self.mesh.getPtr(topic) orelse return;
        var pit = mp.peers.keyIterator();
        while (pit.next()) |kp| {
            const dest = kp.*;
            if (dest.eql(&sender)) continue;
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
        const excess = c - target;

        self.scratch_peers.clearRetainingCapacity();
        var pit = mp.peers.keyIterator();
        while (pit.next()) |kp| try self.scratch_peers.append(kp.*);
        sortPeersByBytes(self.scratch_peers.items);

        const n = @min(excess, self.scratch_peers.items.len);
        for (self.scratch_peers.items[0..n]) |victim| {
            _ = mp.peers.remove(victim);
            const ctl = try control.encodePrune(self.allocator, topic, null);
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
            self.inbound_delivered += 1;
            try self.forwardPublish(sender, topic, data);
        }
    }

    pub fn heartbeat(self: *Gossipsub) (control.Error || rpc.Error || errors.GossipsubError || std.mem.Allocator.Error)!void {
        self.dup.prune(self.clock_ms);

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
                }
            }

            c = mp.peers.count();
            if (c > self.cfg.mesh_n_high) {
                try self.pruneMeshDownToN(topic, self.cfg.mesh_n);
            }
        }
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

    pub fn popOutboxDelivery(self: *Gossipsub) ?OutDelivery {
        if (self.outbox.items.len == 0) return null;
        return self.outbox.orderedRemove(0);
    }
};

test "gossipsub subscribe, graft mesh, dedup, forward" {
    const a = std.testing.allocator;
    const me = try identity.PeerId.random();
    var g = try Gossipsub.init(a, .{ .local_peer_id = me });
    defer g.deinit();

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

    try ga.heartbeat();
    const graft_a = ga.popOutboxDelivery().?;
    defer a.free(graft_a.wire);
    try std.testing.expect(graft_a.to != null and graft_a.to.?.eql(&pb));
    try gb.handleInboundRpc(pa, graft_a.wire);

    try gb.heartbeat();
    const graft_b = gb.popOutboxDelivery().?;
    defer a.free(graft_b.wire);
    try std.testing.expect(graft_b.to != null and graft_b.to.?.eql(&pa));
    try ga.handleInboundRpc(pb, graft_b.wire);

    try std.testing.expectEqual(@as(?usize, 1), ga.meshPeerCountForTopic("t"));
    try std.testing.expectEqual(@as(?usize, 1), gb.meshPeerCountForTopic("t"));

    const inner = try msg_mod.encode(a, .{ .topic = "t", .data = "payload" });
    defer a.free(inner);
    const pubw = try rpc.encodePublish(a, inner);
    defer a.free(pubw);

    try ga.handleInboundRpc(pb, pubw);
    const fwd = ga.popOutboxDelivery().?;
    defer a.free(fwd.wire);
    try std.testing.expect(fwd.to != null and fwd.to.?.eql(&pb));
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
