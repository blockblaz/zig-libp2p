//! Kademlia routing table: CPL-indexed k-buckets with LRU (#93).

const std = @import("std");
const keyspace = @import("keyspace.zig");
const mode = @import("mode.zig");

pub const Config = struct {
    k: usize = 20,
};

pub const Entry = struct {
    id: []u8,
    addrs: [][]u8,
    mode: mode.Mode = .server,
    last_seen_ms: i64 = 0,

    pub fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        for (self.addrs) |a| allocator.free(a);
        allocator.free(self.addrs);
        self.* = undefined;
        self.id = &.{};
        self.addrs = &.{};
    }
};

const Bucket = struct {
    entries: std.ArrayList(Entry),

    fn init() Bucket {
        return .{ .entries = std.ArrayList(Entry).empty };
    }

    fn deinit(self: *Bucket, allocator: std.mem.Allocator) void {
        for (self.entries.items) |*e| e.deinit(allocator);
        self.entries.deinit(allocator);
    }

    fn upsert(self: *Bucket, allocator: std.mem.Allocator, cfg: Config, entry: Entry) !bool {
        for (self.entries.items, 0..) |*e, i| {
            if (std.mem.eql(u8, e.id, entry.id)) {
                e.deinit(allocator);
                _ = self.entries.orderedRemove(i);
                break;
            }
        }
        try self.entries.append(allocator, entry);
        while (self.entries.items.len > cfg.k) {
            var oldest = self.entries.orderedRemove(0);
            oldest.deinit(allocator);
        }
        return true;
    }
};

pub const NearestQuery = struct {
    id: []const u8,
    addrs: []const []const u8,
    distance: keyspace.Key,
};

pub const RoutingTable = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    local_key: keyspace.Key,
    buckets: [256]Bucket,

    pub fn init(allocator: std.mem.Allocator, local_id: []const u8, cfg: Config) RoutingTable {
        var rt: RoutingTable = .{
            .allocator = allocator,
            .cfg = cfg,
            .local_key = keyspace.hashKey(local_id),
            .buckets = undefined,
        };
        for (&rt.buckets) |*b| b.* = Bucket.init();
        return rt;
    }

    pub fn deinit(self: *RoutingTable) void {
        for (&self.buckets) |*b| b.deinit(self.allocator);
    }

    fn bucketIndex(self: *const RoutingTable, peer_key: keyspace.Key) ?usize {
        const cpl = keyspace.commonPrefixLength(self.local_key, peer_key);
        if (cpl >= keyspace.key_bits) return null;
        return cpl;
    }

    /// Returns false when peer is self, client-mode, or bucket rejects.
    pub fn update(
        self: *RoutingTable,
        peer_id: []const u8,
        addrs: []const []const u8,
        peer_mode: mode.Mode,
        now_ms: i64,
    ) std.mem.Allocator.Error!bool {
        if (peer_mode == .client) return false;
        const peer_key = keyspace.hashKey(peer_id);
        const idx = self.bucketIndex(peer_key) orelse return false;

        const id_copy = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(id_copy);

        var addr_list = try self.allocator.alloc([]u8, addrs.len);
        errdefer self.allocator.free(addr_list);
        for (addrs, 0..) |a, i| {
            addr_list[i] = try self.allocator.dupe(u8, a);
        }

        return self.buckets[idx].upsert(self.allocator, self.cfg, .{
            .id = id_copy,
            .addrs = addr_list,
            .mode = peer_mode,
            .last_seen_ms = now_ms,
        });
    }

    pub fn len(self: *const RoutingTable) usize {
        var n: usize = 0;
        for (&self.buckets) |*b| n += b.entries.items.len;
        return n;
    }

    /// Closest `count` peers to `target_key` from the routing table.
    pub fn nearestPeers(
        self: *const RoutingTable,
        target_key: keyspace.Key,
        count: usize,
    ) std.mem.Allocator.Error![]NearestQuery {
        var all = std.ArrayList(NearestQuery).empty;
        defer all.deinit(self.allocator);

        for (&self.buckets) |*b| {
            for (b.entries.items) |e| {
                const pk = keyspace.hashKey(e.id);
                try all.append(self.allocator, .{
                    .id = e.id,
                    .addrs = e.addrs,
                    .distance = keyspace.xorDistance(pk, target_key),
                });
            }
        }

        std.mem.sort(NearestQuery, all.items, {}, struct {
            fn less(_: void, a: NearestQuery, b: NearestQuery) bool {
                return keyspace.compareKeys(a.distance, b.distance) == .lt;
            }
        }.less);

        const n = @min(count, all.items.len);
        var out = try self.allocator.alloc(NearestQuery, n);
        for (0..n) |i| out[i] = all.items[i];
        return out;
    }

    pub fn freeNearestPeers(self: *const RoutingTable, peers: []NearestQuery) void {
        self.allocator.free(peers);
    }
};

test "routing table stores server-mode peers in cpl buckets" {
    const a = std.testing.allocator;
    var rt = RoutingTable.init(a, "self-node-id", .{ .k = 2 });
    defer rt.deinit();

    const addr = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};
    try std.testing.expect(try rt.update("peer-a", &addr, .server, 1));
    try std.testing.expect(try rt.update("peer-b", &addr, .server, 2));
    try std.testing.expect(try rt.update("peer-c", &addr, .server, 3));
    try std.testing.expect(rt.len() >= 2);

    const target = keyspace.hashKey("lookup");
    const nearest = try rt.nearestPeers(target, 2);
    defer rt.freeNearestPeers(nearest);
    try std.testing.expect(nearest.len > 0);
}

test "routing table deduplicates peer on refresh" {
    const a = std.testing.allocator;
    var rt = RoutingTable.init(a, "self-node-id", .{ .k = 2 });
    defer rt.deinit();
    const addr = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};
    try std.testing.expect(try rt.update("peer-a", &addr, .server, 1));
    try std.testing.expect(try rt.update("peer-a", &addr, .server, 2));
    try std.testing.expectEqual(@as(usize, 1), rt.len());
}

test "client mode peers are not stored" {
    const a = std.testing.allocator;
    var rt = RoutingTable.init(a, "self", .{});
    defer rt.deinit();
    const addr = [_][]const u8{"/ip4/1.1.1.1/udp/1/quic-v1"};
    try std.testing.expect(!try rt.update("client-peer", &addr, .client, 0));
    try std.testing.expectEqual(@as(usize, 0), rt.len());
}
