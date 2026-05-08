//! Time-bounded `(topic, message_id)` duplicate suppression (#39).

const std = @import("std");
const cfg = @import("config.zig");
const message_id = @import("message_id.zig");

pub const DuplicateCache = struct {
    allocator: std.mem.Allocator,
    map: std.HashMap(CacheKey, i64, CacheContext, std.hash_map.default_max_load_percentage),

    const CacheKey = struct {
        topic: []u8,
        id: [20]u8,
    };

    const CacheContext = struct {
        pub fn hash(_: CacheContext, k: CacheKey) u64 {
            return std.hash.Wyhash.hash(0, k.topic) ^ std.hash.Wyhash.hash(0, &k.id);
        }
        pub fn eql(_: CacheContext, a: CacheKey, b: CacheKey, _: usize) bool {
            return std.mem.eql(u8, a.topic, b.topic) and std.mem.eql(u8, &a.id, &b.id);
        }
    };

    pub fn init(allocator: std.mem.Allocator) DuplicateCache {
        return .{ .allocator = allocator, .map = .init(allocator) };
    }

    pub fn deinit(self: *DuplicateCache) void {
        while (self.map.count() != 0) {
            const k0 = self.map.keys()[0];
            if (self.map.fetchRemove(k0)) |kv| {
                self.allocator.free(kv.key.topic);
            }
        }
        self.map.deinit(self.allocator);
    }

    /// Drops entries whose expiry is at or before `now_ms`.
    pub fn prune(self: *DuplicateCache, now_ms: i64) void {
        var rm = std.ArrayList(CacheKey).init(self.allocator);
        defer rm.deinit(self.allocator);

        var it = self.map.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* <= now_ms) {
                rm.append(e.key_ptr.*) catch return;
            }
        }
        for (rm.items) |k| {
            if (self.map.fetchRemove(k)) |kv| {
                self.allocator.free(kv.key.topic);
            }
        }
    }

    /// Returns `true` if `(topic, id)` is a duplicate (already seen inside the TTL window).
    pub fn checkDuplicate(self: *DuplicateCache, topic: []const u8, id: [20]u8, now_ms: i64) std.mem.Allocator.Error!bool {
        self.prune(now_ms);

        const topic_owned = try self.allocator.dupe(u8, topic);
        const key = CacheKey{ .topic = topic_owned, .id = id };
        const gop = self.map.getOrPut(key) catch |err| {
            self.allocator.free(topic_owned);
            return err;
        };
        if (gop.found_existing) {
            self.allocator.free(topic_owned);
            return true;
        }
        gop.value_ptr.* = now_ms + cfg.duplicate_cache_ttl_ms;
        return false;
    }

    pub fn count(self: *const DuplicateCache) usize {
        return self.map.count();
    }
};

test "duplicate cache drops after ttl" {
    const a = std.testing.allocator;
    var c = DuplicateCache.init(a);
    defer c.deinit();

    var id: [20]u8 = [_]u8{0} ** 20;
    id[0] = 1;

    try std.testing.expectEqual(false, try c.checkDuplicate("topic-a", id, 0));
    try std.testing.expectEqual(@as(usize, 1), c.count());
    try std.testing.expectEqual(true, try c.checkDuplicate("topic-a", id, 0));

    c.prune(cfg.duplicate_cache_ttl_ms + 1);
    try std.testing.expectEqual(@as(usize, 0), c.count());

    try std.testing.expectEqual(false, try c.checkDuplicate("topic-a", id, cfg.duplicate_cache_ttl_ms + 2));
}

test "duplicate cache uses message ids from writeMessageId" {
    const a = std.testing.allocator;
    var c = DuplicateCache.init(a);
    defer c.deinit();

    var id: [20]u8 = undefined;
    message_id.writeMessageId("/lean/x/foo", "payload", true, &id);
    try std.testing.expectEqual(false, try c.checkDuplicate("/lean/x/foo", id, 0));
    try std.testing.expectEqual(true, try c.checkDuplicate("/lean/x/foo", id, 0));
}
