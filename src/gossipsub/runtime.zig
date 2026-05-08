//! Gossipsub mesh runtime (incremental, #39): subscriptions, peer presence, inbound publish
//! handling with wire message IDs + duplicate cache, and an outbox of RPC blobs for the
//! transport to send. Per-topic mesh scoring, GRAFT/PRUNE, and IHave/IWant are not implemented yet.

const std = @import("std");
const identity = @import("../identity.zig");
const connection_manager = @import("../connection_manager.zig");
const duplicate_cache = @import("duplicate_cache.zig");
const message_id = @import("message_id.zig");
const msg_mod = @import("message.zig");
const rpc = @import("rpc.zig");

pub const GossipsubConfig = struct {
    /// Domain byte for [`message_id.writeMessageId`] (true = post-snappy Zeam path).
    message_id_domain_snappy_ok: bool = true,
};

pub const Gossipsub = struct {
    allocator: std.mem.Allocator,
    cfg: GossipsubConfig,
    dup: duplicate_cache.DuplicateCache,
    subs: std.StringHashMap(void),
    connected: std.HashMap(identity.PeerId, void, connection_manager.PeerIdContext, std.hash_map.default_max_load_percentage),
    clock_ms: i64,
    outbox: std.ArrayList([]u8),
    inbound_delivered: u64,

    pub fn init(allocator: std.mem.Allocator, config: GossipsubConfig) std.mem.Allocator.Error!*Gossipsub {
        const p = try allocator.create(Gossipsub);
        errdefer allocator.destroy(p);
        p.* = .{
            .allocator = allocator,
            .cfg = config,
            .dup = duplicate_cache.DuplicateCache.init(allocator),
            .subs = std.StringHashMap(void).init(allocator),
            .connected = .init(allocator),
            .clock_ms = 0,
            .outbox = .init(allocator),
            .inbound_delivered = 0,
        };
        return p;
    }

    pub fn deinit(self: *Gossipsub) void {
        self.dup.deinit();
        self.subs.deinit(self.allocator);
        for (self.outbox.items) |b| self.allocator.free(b);
        self.outbox.deinit(self.allocator);
        self.connected.deinit(self.allocator);
        const a = self.allocator;
        a.destroy(self);
    }

    /// Monotonic clock for duplicate-cache TTL and pruning; set from the embedder each tick.
    pub fn setClockMs(self: *Gossipsub, t: i64) void {
        self.clock_ms = t;
    }

    pub fn subscribe(self: *Gossipsub, topic: []const u8) (rpc.Error || std.mem.Allocator.Error)!void {
        if (self.subs.contains(topic)) return;
        try self.subs.put(topic, {});
        errdefer _ = self.subs.fetchRemove(topic);
        const w = try rpc.encodeSubscribe(self.allocator, topic, true);
        errdefer self.allocator.free(w);
        try self.outbox.append(w);
    }

    pub fn unsubscribe(self: *Gossipsub, topic: []const u8) (rpc.Error || std.mem.Allocator.Error)!void {
        if (self.subs.fetchRemove(topic)) |_| {
            const w = try rpc.encodeSubscribe(self.allocator, topic, false);
            errdefer self.allocator.free(w);
            try self.outbox.append(w);
        }
    }

    pub fn publish(self: *Gossipsub, topic: []const u8, payload: []const u8) (msg_mod.Error || rpc.Error || std.mem.Allocator.Error)!void {
        const inner = try msg_mod.encode(self.allocator, .{ .topic = topic, .data = payload });
        defer self.allocator.free(inner);
        const wire = try rpc.encodePublish(self.allocator, inner);
        errdefer self.allocator.free(wire);
        try self.outbox.append(wire);
    }

    pub fn onPeerConnected(self: *Gossipsub, peer: identity.PeerId) void {
        self.connected.put(peer, {}) catch return;
    }

    pub fn onPeerDisconnected(self: *Gossipsub, peer: identity.PeerId) void {
        _ = self.connected.remove(peer);
    }

    pub fn handleInboundRpc(self: *Gossipsub, sender: identity.PeerId, frame: []const u8) (rpc.Error || msg_mod.Error || std.mem.Allocator.Error)!void {
        _ = sender;
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
        }
    }

    pub fn heartbeat(self: *Gossipsub) !void {
        self.dup.prune(self.clock_ms);
    }

    /// Stub metric: number of connected peers (per-topic mesh sizing is not implemented yet).
    pub fn meshPeers(self: *const Gossipsub) u64 {
        return @intCast(self.connected.count());
    }

    pub fn inboundDeliveredCount(self: *const Gossipsub) u64 {
        return self.inbound_delivered;
    }

    /// Pops the next outbound RPC blob (subscribe / publish wire). Caller frees the slice.
    pub fn popOutboxRpc(self: *Gossipsub) ?[]u8 {
        if (self.outbox.items.len == 0) return null;
        return self.outbox.orderedRemove(0);
    }
};

test "gossipsub subscribe outbox and inbound publish dedup" {
    const a = std.testing.allocator;
    var g = try Gossipsub.init(a, .{});
    defer g.deinit();

    try g.subscribe("blocks");
    const sub_wire = g.popOutboxRpc().?;
    defer a.free(sub_wire);
    var sv = (try rpc.decodeFirstSubscribe(a, sub_wire)).?;
    defer rpc.deinitSubscribeView(a, &sv);
    try std.testing.expect(sv.subscribe);
    try std.testing.expectEqualStrings("blocks", sv.topic);

    const p1 = try identity.PeerId.random();
    g.onPeerConnected(p1);
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
