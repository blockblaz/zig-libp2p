//! kad-dht client: bootstrap and high-level lookups (#93).

const std = @import("std");
const query = @import("query.zig");
const routing_table = @import("routing_table.zig");
const record_store = @import("record_store.zig");
const mode = @import("mode.zig");
const wire = @import("wire.zig");

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
