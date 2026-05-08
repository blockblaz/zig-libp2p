//! Gossipsub mesh runtime (incremental, #39): subscriptions, peer presence, per-topic mesh,
//! heartbeat GRAFT/PRUNE toward Zeam `mesh_n` / `mesh_n_low` / `mesh_n_high`, inbound control,
//! publish forwarding, duplicate cache, and a targeted outbox.

const std = @import("std");
const identity = @import("../identity.zig");
const connection_manager = @import("../connection_manager.zig");
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
};

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
    connected: std.HashMap(identity.PeerId, void, connection_manager.PeerIdContext, std.hash_map.default_max_load_percentage),
    clock_ms: i64,
    outbox: std.ArrayList(OutDelivery),
    inbound_delivered: u64,
    scratch_peers: std.ArrayList(identity.PeerId),

    pub fn init(allocator: std.mem.Allocator, config: GossipsubConfig) std.mem.Allocator.Error!*Gossipsub {
        const p = try allocator.create(Gossipsub);
        errdefer allocator.destroy(p);
        p.* = .{
            .allocator = allocator,
            .cfg = config,
            .dup = duplicate_cache.DuplicateCache.init(allocator),
            .subs = std.StringHashMap(void).init(allocator),
            .mesh = std.StringHashMap(TopicMesh).init(allocator),
            .connected = .init(allocator),
            .clock_ms = 0,
            .outbox = .init(allocator),
            .inbound_delivered = 0,
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

    fn appendOut(self: *Gossipsub, wire: []u8, to: ?identity.PeerId) std.mem.Allocator.Error!void {
        try self.outbox.append(.{ .wire = wire, .to = to });
    }

    fn ensureTopicMesh(self: *Gossipsub, topic: []const u8) std.mem.Allocator.Error!void {
        const gop = try self.mesh.getOrPut(topic);
        if (!gop.found_existing) {
            gop.value_ptr.* = TopicMesh.init(self.allocator);
        }
    }

    pub fn subscribe(self: *Gossipsub, topic: []const u8) (rpc.Error || std.mem.Allocator.Error)!void {
        if (self.subs.contains(topic)) return;
        try self.subs.put(topic, {});
        errdefer _ = self.subs.fetchRemove(topic);
        try self.ensureTopicMesh(topic);
        const w = try rpc.encodeSubscribe(self.allocator, topic, true);
        errdefer self.allocator.free(w);
        try self.appendOut(w, null);
    }

    pub fn unsubscribe(self: *Gossipsub, topic: []const u8) (rpc.Error || std.mem.Allocator.Error)!void {
        if (self.subs.fetchRemove(topic)) |_| {
            if (self.mesh.fetchRemove(topic)) |kv| {
                var tm = kv.value;
                tm.deinit(self.allocator);
            }
            const w = try rpc.encodeSubscribe(self.allocator, topic, false);
            errdefer self.allocator.free(w);
            try self.appendOut(w, null);
        }
    }

    pub fn publish(self: *Gossipsub, topic: []const u8, payload: []const u8) (msg_mod.Error || rpc.Error || std.mem.Allocator.Error)!void {
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
        var cit = self.connected.keyIterator();
        while (cit.next()) |kp| {
            const p = kp.*;
            if (p.eql(&self.cfg.local_peer_id)) continue;
            if (mp.peers.contains(p)) continue;
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
    }

    fn forwardPublish(self: *Gossipsub, sender: identity.PeerId, topic: []const u8, data: []const u8) (msg_mod.Error || rpc.Error || std.mem.Allocator.Error)!void {
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

    fn pruneMeshDownToN(self: *Gossipsub, topic: []const u8, target: usize) (control.Error || rpc.Error || std.mem.Allocator.Error)!void {
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

    pub fn handleInboundRpc(self: *Gossipsub, sender: identity.PeerId, frame: []const u8) (rpc.Error || msg_mod.Error || control.Error || std.mem.Allocator.Error)!void {
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

    pub fn heartbeat(self: *Gossipsub) (control.Error || rpc.Error || std.mem.Allocator.Error)!void {
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
