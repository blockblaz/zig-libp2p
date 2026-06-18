//! kad-dht client: bootstrap and high-level lookups (#93).

const std = @import("std");
const query = @import("query.zig");
const routing_table = @import("routing_table.zig");
const record_store = @import("record_store.zig");
const mode = @import("mode.zig");
const wire = @import("wire.zig");
const keyspace = @import("keyspace.zig");

pub const Error = query.Error || std.mem.Allocator.Error;

pub const Config = struct {
    query: query.Config = .{},
    records: record_store.Config = .{},
    mode: mode.Mode = .client,
};

pub const BootstrapPeer = struct {
    id: []const u8,
    addrs: []const []const u8,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    engine: query.QueryEngine,
    records: record_store.RecordStore,

    pub fn init(
        allocator: std.mem.Allocator,
        local_id: []const u8,
        cfg: Config,
        query_peer: query.QueryPeerFn,
    ) Error!Client {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .engine = try query.QueryEngine.init(allocator, local_id, cfg.query, query_peer),
            .records = record_store.RecordStore.init(allocator, cfg.records),
        };
    }

    pub fn deinit(self: *Client) void {
        self.engine.deinit();
        self.records.deinit();
    }

    pub fn routingTable(self: *Client) *routing_table.RoutingTable {
        return self.engine.routingTable();
    }

    pub fn setMode(self: *Client, dht_mode: mode.Mode) void {
        self.cfg.mode = dht_mode;
    }

    pub fn dhtMode(self: *const Client) mode.Mode {
        return self.cfg.mode;
    }

    pub fn setQueryContext(self: *Client, ctx: ?*anyopaque) void {
        self.engine.query_ctx = ctx;
    }

    /// Remove a disconnected peer from the local routing table (#203).
    pub fn onPeerDisconnected(self: *Client, peer_id: []const u8) void {
        self.routingTable().remove(peer_id);
    }

    /// Seed routing table from configured bootstrap peers, then run `findNode(local_id)`.
    pub fn bootstrap(self: *Client, peers: []const BootstrapPeer, now_ms: i64) Error!void {
        for (peers) |bp| {
            _ = try self.routingTable().update(bp.id, bp.addrs, .server, now_ms);
        }
        const nearest = try self.engine.findNode(self.engine.localId(), now_ms);
        defer self.engine.routing.freeNearestPeers(nearest);
    }

    pub fn findNode(self: *Client, peer_id: []const u8, now_ms: i64) Error![]routing_table.NearestQuery {
        return self.engine.findNode(peer_id, now_ms);
    }

    pub fn findProviders(self: *Client, key: []const u8, now_ms: i64) Error![]query.QueryEngine.ProviderResult {
        return self.engine.findProviders(key, now_ms);
    }

    pub fn freeNearest(self: *Client, peers: []routing_table.NearestQuery) void {
        self.routingTable().freeNearestPeers(peers);
    }

    pub fn freeProviders(self: *Client, providers: []query.QueryEngine.ProviderResult) void {
        self.engine.freeProviders(providers);
    }

    /// Local provider advertisement; embedder should fan out via `ADD_PROVIDER` RPC.
    pub fn addLocalProvider(self: *Client, key: []const u8, local_id: []const u8, addrs: []const []const u8, now_ms: i64) Error!void {
        try self.records.addProvider(key, local_id, addrs, now_ms);
    }

    pub fn providersNeedingRepublish(self: *Client, now_ms: i64) Error![][]const u8 {
        var keys = std.ArrayList([]const u8).empty;
        try self.records.providersDueRepublish(&keys, now_ms);
        return try keys.toOwnedSlice(self.allocator);
    }

    pub fn freeRepublishKeys(self: *Client, keys: [][]const u8) void {
        self.allocator.free(keys);
    }

    /// Fan out `ADD_PROVIDER` for `key` to the k closest peers and refresh the
    /// local provider record (#203).
    pub fn announceProvider(
        self: *Client,
        key: []const u8,
        addrs: []const []const u8,
        now_ms: i64,
    ) Error!void {
        try self.addLocalProvider(key, self.engine.localId(), addrs, now_ms);
        const target = keyspace.hashKey(key);
        const nearest = try self.routingTable().nearestPeers(target, self.cfg.query.k);
        defer self.routingTable().freeNearestPeers(nearest);

        const local_peer = wire.PeerView{
            .id = self.engine.localId(),
            .addrs = addrs,
            .connection = .connected,
        };
        for (nearest) |p| {
            var response: wire.MessageOwned = .{ .msg_type = .add_provider };
            self.engine.query_peer(self.engine.query_ctx, p.id, .{
                .msg_type = .add_provider,
                .key = key,
                .provider_peers = &.{local_peer},
            }, &response) catch continue;
            response.deinit(self.allocator);
        }
    }

    /// Republish every local provider whose TTL window requires refresh (#203).
    pub fn republishProviders(self: *Client, addrs: []const []const u8, now_ms: i64) Error!void {
        const keys = try self.providersNeedingRepublish(now_ms);
        defer self.freeRepublishKeys(keys);
        for (keys) |key| {
            try self.announceProvider(key, addrs, now_ms);
        }
    }

    pub const protocol_line = wire.protocol_line;
    pub const protocol_id = wire.protocol_id;
};

test "bootstrap inserts peers then findNode" {
    const a = std.testing.allocator;
    const Ctx = struct {
        fn noop(_: ?*anyopaque, _: []const u8, _: wire.MessageView, response_out: *wire.MessageOwned) Error!void {
            response_out.* = .{ .msg_type = .find_node };
            return;
        }
    };
    var client = try Client.init(a, "self-id", .{}, Ctx.noop);
    defer client.deinit();
    const addr = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};
    const boot = [_]BootstrapPeer{.{ .id = "boot-1", .addrs = &addr }};
    try client.bootstrap(&boot, 0);
    try std.testing.expect(client.routingTable().len() >= 1);
}

test "announceProvider fans out add_provider to nearest peers" {
    const a = std.testing.allocator;
    const addr = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};
    const Ctx = struct {
        calls: usize = 0,
        fn query(ctx: ?*anyopaque, _: []const u8, request: wire.MessageView, response_out: *wire.MessageOwned) Error!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (request.msg_type == .add_provider) self.calls += 1;
            response_out.* = .{ .msg_type = .add_provider };
        }
    };
    var ctx: Ctx = .{};
    var server = try Client.init(a, "server-node", .{ .mode = .server }, Ctx.query);
    defer server.deinit();
    server.setQueryContext(&ctx);
    _ = try server.routingTable().update("client-node", &addr, .server, 0);
    try server.announceProvider("content-key", &addr, 0);
    try std.testing.expect(ctx.calls >= 1);
}

test "client findProviders collects remote provider records" {
    const a = std.testing.allocator;
    const addr = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};
    const Ctx = struct {
        fn query(_: ?*anyopaque, _: []const u8, request: wire.MessageView, response_out: *wire.MessageOwned) Error!void {
            if (request.msg_type != .get_providers) {
                response_out.* = .{ .msg_type = .find_node };
                return;
            }
            const key = request.key orelse return;
            const wire_bytes = try wire.encode(a, .{
                .msg_type = .get_providers,
                .key = key,
                .provider_peers = &.{
                    .{ .id = "server-node", .addrs = &addr, .connection = .connected },
                },
            });
            defer a.free(wire_bytes);
            response_out.* = try wire.decodeOwned(a, wire_bytes, .standard);
        }
    };
    var client = try Client.init(a, "client-node", .{ .mode = .client }, Ctx.query);
    defer client.deinit();
    _ = try client.routingTable().update("server-node", &addr, .server, 0);
    const providers = try client.findProviders("content-key", 0);
    defer client.freeProviders(providers);
    try std.testing.expect(providers.len >= 1);
    try std.testing.expectEqualStrings("server-node", providers[0].id);
}

test "onPeerDisconnected evicts routing-table entry" {
    const a = std.testing.allocator;
    const Ctx = struct {
        fn noop(_: ?*anyopaque, _: []const u8, _: wire.MessageView, response_out: *wire.MessageOwned) Error!void {
            response_out.* = .{ .msg_type = .find_node };
        }
    };
    var client = try Client.init(a, "self-id", .{}, Ctx.noop);
    defer client.deinit();
    const addr = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};
    _ = try client.routingTable().update("peer-a", &addr, .server, 0);
    try std.testing.expect(client.routingTable().contains("peer-a"));
    client.onPeerDisconnected("peer-a");
    try std.testing.expect(!client.routingTable().contains("peer-a"));
}

test "republishProviders refreshes stale local advertisements" {
    const a = std.testing.allocator;
    const addr = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};
    const Ctx = struct {
        announce_calls: usize = 0,
        fn query(ctx: ?*anyopaque, _: []const u8, request: wire.MessageView, response_out: *wire.MessageOwned) Error!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (request.msg_type == .add_provider) self.announce_calls += 1;
            response_out.* = .{ .msg_type = .add_provider };
        }
    };
    var ctx: Ctx = .{};
    var client = try Client.init(a, "provider-node", .{
        .records = .{ .provider_ttl_ms = 10_000, .provider_republish_ms = 100 },
    }, Ctx.query);
    defer client.deinit();
    client.setQueryContext(&ctx);
    _ = try client.routingTable().update("peer-b", &addr, .server, 0);
    try client.addLocalProvider("cid-key", "provider-node", &addr, 0);

    try client.republishProviders(&addr, 0);
    try std.testing.expectEqual(@as(usize, 0), ctx.announce_calls);

    try client.republishProviders(&addr, 150);
    try std.testing.expect(ctx.announce_calls >= 1);

    const keys = try client.providersNeedingRepublish(150);
    defer client.freeRepublishKeys(keys);
    try std.testing.expectEqual(@as(usize, 0), keys.len);
}

test "setMode tracks autonat promotion" {
    const a = std.testing.allocator;
    const Ctx = struct {
        fn noop(_: ?*anyopaque, _: []const u8, _: wire.MessageView, response_out: *wire.MessageOwned) Error!void {
            response_out.* = .{ .msg_type = .find_node };
        }
    };
    var client = try Client.init(a, "self-id", .{ .mode = .client }, Ctx.noop);
    defer client.deinit();
    try std.testing.expect(client.dhtMode() == .client);
    client.setMode(mode.fromNatStatus(.public));
    try std.testing.expect(client.dhtMode() == .server);
}
