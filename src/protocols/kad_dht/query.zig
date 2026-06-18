//! Iterative Kademlia lookups (findNode, findProviders) (#93).

const std = @import("std");
const keyspace = @import("keyspace.zig");
const routing_table = @import("routing_table.zig");
const wire = @import("wire.zig");
const mode = @import("mode.zig");

pub const Error = wire.Error || std.mem.Allocator.Error;

pub const Config = struct {
    k: usize = 20,
    alpha: usize = 3,
    routing: routing_table.Config = .{},
};

pub const QueryPeerFn = *const fn (
    ctx: ?*anyopaque,
    peer_id: []const u8,
    request: wire.MessageView,
    response_out: *wire.MessageOwned,
) Error!void;

const Candidate = struct {
    id: []u8,
    addrs: [][]u8,
    distance: keyspace.Key,
    queried: bool = false,
};

pub const QueryEngine = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    local_id: []u8,
    routing: routing_table.RoutingTable,
    query_peer: QueryPeerFn,
    query_ctx: ?*anyopaque = null,

    pub fn init(
        allocator: std.mem.Allocator,
        local_id: []const u8,
        cfg: Config,
        query_peer: QueryPeerFn,
    ) std.mem.Allocator.Error!QueryEngine {
        const id_copy = try allocator.dupe(u8, local_id);
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .local_id = id_copy,
            .routing = routing_table.RoutingTable.init(allocator, local_id, cfg.routing),
            .query_peer = query_peer,
        };
    }

    pub fn deinit(self: *QueryEngine) void {
        self.routing.deinit();
        self.allocator.free(self.local_id);
    }

    pub fn routingTable(self: *QueryEngine) *routing_table.RoutingTable {
        return &self.routing;
    }

    pub fn localId(self: *const QueryEngine) []const u8 {
        return self.local_id;
    }

    fn freeCandidate(self: *QueryEngine, c: *Candidate) void {
        self.allocator.free(c.id);
        for (c.addrs) |a| self.allocator.free(a);
        self.allocator.free(c.addrs);
        c.* = .{ .id = &.{}, .addrs = &.{}, .distance = undefined, .queried = false };
    }

    fn upsertCandidate(self: *QueryEngine, list: *std.ArrayList(Candidate), id: []const u8, addrs: []const []const u8, target: keyspace.Key) !void {
        for (list.items) |c| {
            if (std.mem.eql(u8, c.id, id)) return;
        }
        const pk = keyspace.hashKey(id);
        const id_copy = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(id_copy);
        var addr_copy = try self.allocator.alloc([]u8, addrs.len);
        errdefer self.allocator.free(addr_copy);
        for (addrs, 0..) |a, i| addr_copy[i] = try self.allocator.dupe(u8, a);
        try list.append(self.allocator, .{
            .id = id_copy,
            .addrs = addr_copy,
            .distance = keyspace.xorDistance(pk, target),
        });
        std.mem.sort(Candidate, list.items, {}, struct {
            fn less(_: void, a: Candidate, b: Candidate) bool {
                return keyspace.compareKeys(a.distance, b.distance) == .lt;
            }
        }.less);
    }

    fn ingestPeers(self: *QueryEngine, list: *std.ArrayList(Candidate), peers: []const wire.PeerOwned, target: keyspace.Key, now_ms: i64) !void {
        for (peers) |p| {
            const id = p.id orelse continue;
            var addr_views: std.ArrayList([]const u8) = .empty;
            defer addr_views.deinit(self.allocator);
            for (p.addrs) |a| try addr_views.append(self.allocator, a);
            _ = try self.routing.update(id, addr_views.items, .server, now_ms);
            try self.upsertCandidate(list, id, addr_views.items, target);
        }
    }

    fn runLookup(
        self: *QueryEngine,
        target_key_raw: []const u8,
        msg_type: wire.MessageType,
        now_ms: i64,
        providers_out: ?*std.ArrayList(wire.PeerOwned),
    ) ![]Candidate {
        const target = keyspace.hashKey(target_key_raw);
        var candidates = std.ArrayList(Candidate).empty;
        errdefer {
            for (candidates.items) |*c| self.freeCandidate(c);
            candidates.deinit(self.allocator);
        }

        const seed = try self.routing.nearestPeers(target, self.cfg.k);
        defer self.routing.freeNearestPeers(seed);
        for (seed) |s| {
            try self.upsertCandidate(&candidates, s.id, s.addrs, target);
        }

        var queried_count: usize = 0;
        while (true) {
            var inflight: usize = 0;
            var done = true;
            for (candidates.items, 0..) |*c, i| {
                if (i >= self.cfg.k) break;
                if (c.queried) {
                    queried_count += 1;
                    continue;
                }
                if (inflight >= self.cfg.alpha) break;
                done = false;
                c.queried = true;
                inflight += 1;

                var response: wire.MessageOwned = .{ .msg_type = msg_type };
                self.query_peer(self.query_ctx, c.id, .{
                    .msg_type = msg_type,
                    .key = target_key_raw,
                }, &response) catch {
                    continue;
                };
                defer response.deinit(self.allocator);

                try self.ingestPeers(&candidates, response.closer_peers, target, now_ms);
                if (providers_out) |po| {
                    for (response.provider_peers) |p| {
                        var copy = wire.PeerOwned{
                            .id = if (p.id) |x| try self.allocator.dupe(u8, x) else null,
                            .addrs = &[_][]u8{},
                            .connection = p.connection,
                        };
                        copy.addrs = try self.allocator.alloc([]u8, p.addrs.len);
                        for (p.addrs, 0..) |a, j| copy.addrs[j] = try self.allocator.dupe(u8, a);
                        try po.append(self.allocator, copy);
                    }
                }
            }
            if (done or queried_count >= self.cfg.k or candidates.items.len <= self.cfg.k) break;
        }

        return try candidates.toOwnedSlice(self.allocator);
    }

    pub fn findNode(self: *QueryEngine, peer_id: []const u8, now_ms: i64) ![]routing_table.NearestQuery {
        const candidates = try self.runLookup(peer_id, .find_node, now_ms, null);
        defer {
            for (candidates) |*c| self.freeCandidate(c);
            self.allocator.free(candidates);
        }
        const target = keyspace.hashKey(peer_id);
        return self.routing.nearestPeers(target, self.cfg.k);
    }

    pub const ProviderResult = struct {
        id: []u8,
        addrs: [][]u8,
    };

    pub fn findProviders(self: *QueryEngine, key: []const u8, now_ms: i64) ![]ProviderResult {
        var providers = std.ArrayList(wire.PeerOwned).empty;
        defer {
            for (providers.items) |*p| p.deinit(self.allocator);
            providers.deinit(self.allocator);
        }
        const candidates = try self.runLookup(key, .get_providers, now_ms, &providers);
        defer {
            for (candidates) |*c| self.freeCandidate(c);
            self.allocator.free(candidates);
        }

        var out = std.ArrayList(ProviderResult).empty;
        errdefer {
            for (out.items) |*r| {
                self.allocator.free(r.id);
                for (r.addrs) |a| self.allocator.free(a);
                self.allocator.free(r.addrs);
            }
            out.deinit(self.allocator);
        }
        for (providers.items) |p| {
            const id = p.id orelse continue;
            const id_copy = try self.allocator.dupe(u8, id);
            errdefer self.allocator.free(id_copy);
            var addrs = try self.allocator.alloc([]u8, p.addrs.len);
            errdefer self.allocator.free(addrs);
            for (p.addrs, 0..) |a, i| addrs[i] = try self.allocator.dupe(u8, a);
            try out.append(self.allocator, .{ .id = id_copy, .addrs = addrs });
        }
        return try out.toOwnedSlice(self.allocator);
    }

    pub fn freeProviders(self: *QueryEngine, providers: []ProviderResult) void {
        for (providers) |*p| {
            self.allocator.free(p.id);
            for (p.addrs) |a| self.allocator.free(a);
            self.allocator.free(p.addrs);
        }
        self.allocator.free(providers);
    }
};

test "in-memory findNode across three nodes" {
    const a = std.testing.allocator;

    const Node = struct {
        id: []const u8,
        rt: routing_table.RoutingTable,
    };

    var nodes: [3]Node = undefined;
    const ids = [_][]const u8{ "node-a", "node-b", "node-c" };
    for (&nodes, ids) |*n, id| {
        n.id = id;
        n.rt = routing_table.RoutingTable.init(a, id, .{ .k = 3 });
    }
    defer for (&nodes) |*n| n.rt.deinit();

    const addr = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};
    for (&nodes, 0..) |*n, i| {
        for (&nodes, 0..) |*other, j| {
            if (i == j) continue;
            _ = try n.rt.update(other.id, &addr, .server, 0);
        }
    }

    const Ctx = struct {
        nodes: *[3]Node,
        fn query(ctx: ?*anyopaque, peer_id: []const u8, request: wire.MessageView, response_out: *wire.MessageOwned) Error!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            for (self.nodes) |*n| {
                if (!std.mem.eql(u8, n.id, peer_id)) continue;
                const key = request.key orelse return;
                const target = keyspace.hashKey(key);
                const nearest = try n.rt.nearestPeers(target, 3);
                defer n.rt.freeNearestPeers(nearest);
                var peers: std.ArrayList(wire.PeerView) = .empty;
                defer peers.deinit(a);
                for (nearest) |q| {
                    try peers.append(a, .{ .id = q.id, .addrs = q.addrs, .connection = .connected });
                }
                const wire_msg = try wire.encode(a, .{
                    .msg_type = .find_node,
                    .key = key,
                    .closer_peers = peers.items,
                });
                defer a.free(wire_msg);
                const decoded = try wire.decodeOwned(a, wire_msg, .standard);
                response_out.* = decoded;
                return;
            }
            return error.InvalidMessageType;
        }
    };

    var ctx: Ctx = .{ .nodes = &nodes };
    var engine = try QueryEngine.init(a, "node-a", .{ .k = 3, .alpha = 2, .routing = .{ .k = 3 } }, Ctx.query);
    defer engine.deinit();
    engine.query_ctx = &ctx;

    _ = try engine.routing.update("node-b", &addr, .server, 0);
    _ = try engine.routing.update("node-c", &addr, .server, 0);

    const result = try engine.findNode("node-c", 0);
    defer engine.routing.freeNearestPeers(result);
    try std.testing.expect(result.len > 0);
}
