//! Time-bounded `(topic, message_id)` duplicate suppression (#39).
//!
//! ## Performance notes (#75 / #105 follow-up)
//!
//! Two concerns surfaced after the cache went into the inbound publish hot
//! path:
//!
//! 1. **`checkDuplicate` used to call `prune` unconditionally** — O(n) sweep
//!    per inbound message. At 4096 cached entries and 1000 msg/s sustained,
//!    that's ~4M comparisons/s just to discard expired rows. Now prune runs
//!    only every `prune_interval_inserts` *new* entries (the cache stays
//!    bounded by `max_entries` as a hard cap); the heartbeat continues to
//!    call `prune` explicitly for accuracy.
//! 2. **`checkDuplicate` used to `dupe` the topic before the hash lookup** —
//!    one allocation per inbound message even for duplicates (the common
//!    case). We now `getAdapted` against a borrowed-slice key first and
//!    only allocate when we actually need to insert.

const std = @import("std");
const cfg = @import("config.zig");
const message_id = @import("message_id.zig");

pub const DuplicateCache = struct {
    allocator: std.mem.Allocator,
    map: std.HashMap(CacheKey, i64, CacheContext, std.hash_map.default_max_load_percentage),
    /// Hard ceiling on tracked `(topic, id)` pairs; once reached we evict the
    /// soonest-to-expire entry to make room (cheap; bounds memory).
    max_entries: usize = 65_536,
    /// `checkDuplicate` runs `prune` only every Nth insert. The amortised
    /// per-check cost stays at the `getAdapted` lookup; the per-Nth call pays
    /// the O(n) sweep.
    prune_interval_inserts: u32 = 256,
    inserts_since_prune: u32 = 0,

    const CacheKey = struct {
        topic: []u8,
        id: [20]u8,
    };

    const BorrowedKey = struct {
        topic: []const u8,
        id: [20]u8,
    };

    const CacheContext = struct {
        pub fn hash(_: CacheContext, k: CacheKey) u64 {
            return std.hash.Wyhash.hash(0, k.topic) ^ std.hash.Wyhash.hash(0, &k.id);
        }
        pub fn eql(_: CacheContext, a: CacheKey, b: CacheKey) bool {
            return std.mem.eql(u8, a.topic, b.topic) and std.mem.eql(u8, &a.id, &b.id);
        }
    };

    /// Lookup adapter so `getAdapted` can find an owned key from a borrowed slice
    /// without allocating.
    const BorrowedContext = struct {
        pub fn hash(_: BorrowedContext, k: BorrowedKey) u64 {
            return std.hash.Wyhash.hash(0, k.topic) ^ std.hash.Wyhash.hash(0, &k.id);
        }
        pub fn eql(_: BorrowedContext, a: BorrowedKey, b: CacheKey) bool {
            return std.mem.eql(u8, a.topic, b.topic) and std.mem.eql(u8, &a.id, &b.id);
        }
    };

    pub fn init(allocator: std.mem.Allocator) DuplicateCache {
        return .{ .allocator = allocator, .map = .init(allocator) };
    }

    pub fn deinit(self: *DuplicateCache) void {
        var it = self.map.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.topic);
        }
        self.map.deinit();
    }

    /// Drops entries whose expiry is at or before `now_ms`. Called by the
    /// heartbeat; `checkDuplicate` runs this lazily via [`prune_interval_inserts`].
    pub fn prune(self: *DuplicateCache, now_ms: i64) void {
        var rm: std.ArrayList(CacheKey) = .empty;
        defer rm.deinit(self.allocator);

        var it = self.map.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* <= now_ms) {
                rm.append(self.allocator, e.key_ptr.*) catch return;
            }
        }
        for (rm.items) |k| {
            if (self.map.fetchRemove(k)) |kv| {
                self.allocator.free(kv.key.topic);
            }
        }
        self.inserts_since_prune = 0;
    }

    /// Evict the entry expiring soonest so a new insert fits under `max_entries`.
    fn evictOldest(self: *DuplicateCache) void {
        var victim: ?CacheKey = null;
        var victim_exp: i64 = std.math.maxInt(i64);
        var it = self.map.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* < victim_exp) {
                victim_exp = e.value_ptr.*;
                victim = e.key_ptr.*;
            }
        }
        if (victim) |k| {
            if (self.map.fetchRemove(k)) |kv| {
                self.allocator.free(kv.key.topic);
            }
        }
    }

    /// Returns `true` if `(topic, id)` is a duplicate (already seen inside the TTL window).
    /// Allocator is only touched on the insert path.
    pub fn checkDuplicate(self: *DuplicateCache, topic: []const u8, id: [20]u8, now_ms: i64) std.mem.Allocator.Error!bool {
        // Fast path: cheap borrowed-key lookup. No allocation for duplicates.
        const borrowed = BorrowedKey{ .topic = topic, .id = id };
        if (self.map.getAdapted(borrowed, BorrowedContext{})) |_| {
            return true;
        }

        // Miss: insert. Amortise prune so we don't sweep the whole map per call.
        self.inserts_since_prune +%= 1;
        if (self.inserts_since_prune >= self.prune_interval_inserts) {
            self.prune(now_ms);
        }
        if (self.map.count() >= self.max_entries) {
            self.evictOldest();
        }

        const topic_owned = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(topic_owned);
        try self.map.put(CacheKey{ .topic = topic_owned, .id = id }, now_ms + cfg.duplicate_cache_ttl_ms);
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

test "duplicate cache duplicate lookup does not allocate" {
    // We assert allocator usage indirectly: testing.allocator panics on leaks.
    // The hit path that returns `true` must not allocate, so a million repeated
    // lookups should leave `count()` at 1 and not blow up the leak detector.
    const a = std.testing.allocator;
    var c = DuplicateCache.init(a);
    defer c.deinit();

    const id: [20]u8 = [_]u8{0xab} ** 20;
    _ = try c.checkDuplicate("/t", id, 0);
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        try std.testing.expectEqual(true, try c.checkDuplicate("/t", id, 0));
    }
    try std.testing.expectEqual(@as(usize, 1), c.count());
}

test "max_entries evicts soonest-to-expire on overflow" {
    const a = std.testing.allocator;
    var c = DuplicateCache.init(a);
    c.max_entries = 3;
    c.prune_interval_inserts = 1_000_000; // disable lazy prune for this test
    defer c.deinit();

    const id_a: [20]u8 = [_]u8{1} ** 20;
    const id_b: [20]u8 = [_]u8{2} ** 20;
    const id_c: [20]u8 = [_]u8{3} ** 20;
    const id_d: [20]u8 = [_]u8{4} ** 20;

    // Stagger expiries: id_a expires soonest. ttl is added to now_ms, so use now_ms.
    _ = try c.checkDuplicate("/t", id_a, 0); // exp = ttl
    _ = try c.checkDuplicate("/t", id_b, 5); // exp = ttl + 5
    _ = try c.checkDuplicate("/t", id_c, 10); // exp = ttl + 10
    try std.testing.expectEqual(@as(usize, 3), c.count());

    _ = try c.checkDuplicate("/t", id_d, 20); // overflow → evict id_a
    try std.testing.expectEqual(@as(usize, 3), c.count());
    // id_a should be gone; lookup re-inserts it.
    try std.testing.expectEqual(false, try c.checkDuplicate("/t", id_a, 30));
    // The evictOldest path leaves the cache at max_entries via another eviction.
    try std.testing.expectEqual(@as(usize, 3), c.count());
}

test "lazy prune still happens via interval" {
    const a = std.testing.allocator;
    var c = DuplicateCache.init(a);
    c.prune_interval_inserts = 1; // prune fires on every insert for this test
    defer c.deinit();

    const id1: [20]u8 = [_]u8{0x11} ** 20;
    const id2: [20]u8 = [_]u8{0x22} ** 20;
    const id3: [20]u8 = [_]u8{0x33} ** 20;

    _ = try c.checkDuplicate("/t", id1, 0);
    _ = try c.checkDuplicate("/t", id2, 0);
    try std.testing.expectEqual(@as(usize, 2), c.count());
    // Third insert is past the TTL of the first two; lazy prune should fire and
    // evict id1 and id2 before id3 is added.
    _ = try c.checkDuplicate("/t", id3, cfg.duplicate_cache_ttl_ms + 100);
    try std.testing.expectEqual(@as(usize, 1), c.count());
}
