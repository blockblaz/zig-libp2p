//! Local DHT record and provider storage with TTL (#93).

const std = @import("std");
const wire = @import("wire.zig");
const record_validator = @import("record_validator.zig");

pub const Config = struct {
    /// Provider record expiration (issue #93: 24 h).
    provider_ttl_ms: i64 = 24 * 60 * 60 * 1000,
    /// Republish interval hint for embedders (issue #93: 12 h).
    provider_republish_ms: i64 = 12 * 60 * 60 * 1000,
    value_ttl_ms: i64 = 24 * 60 * 60 * 1000,
    /// Optional prefix validators consulted before `PUT_VALUE` storage (#198).
    validators: ?*const record_validator.Registry = null,
    validation_stats: ?*record_validator.Stats = null,
};

pub const PutResult = enum {
    stored,
    rejected,
    ignored,
};

const ValueEntry = struct {
    value: []u8,
    expires_ms: i64,
};

const ProviderEntry = struct {
    id: []u8,
    addrs: [][]u8,
    expires_ms: i64,

    fn deinit(self: *ProviderEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        for (self.addrs) |a| allocator.free(a);
        allocator.free(self.addrs);
        self.* = undefined;
        self.id = &.{};
        self.addrs = &.{};
        self.expires_ms = 0;
    }
};

pub const RecordStore = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    values: std.StringHashMap(ValueEntry),
    providers: std.StringHashMap(std.ArrayList(ProviderEntry)),

    pub fn init(allocator: std.mem.Allocator, cfg: Config) RecordStore {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .values = std.StringHashMap(ValueEntry).init(allocator),
            .providers = std.StringHashMap(std.ArrayList(ProviderEntry)).init(allocator),
        };
    }

    pub fn deinit(self: *RecordStore) void {
        var vit = self.values.iterator();
        while (vit.next()) |e| self.allocator.free(e.value_ptr.value);
        self.values.deinit();

        var pit = self.providers.iterator();
        while (pit.next()) |e| {
            for (e.value_ptr.items) |*p| p.deinit(self.allocator);
            e.value_ptr.deinit(self.allocator);
        }
        self.providers.deinit();
    }

    pub fn purgeExpired(self: *RecordStore, now_ms: i64) void {
        var vit = self.values.iterator();
        while (vit.next()) |e| {
            if (e.value_ptr.expires_ms <= now_ms) {
                self.allocator.free(e.value_ptr.value);
                _ = self.values.remove(e.key_ptr.*);
            }
        }

        var pit = self.providers.iterator();
        while (pit.next()) |e| {
            var i: usize = 0;
            while (i < e.value_ptr.items.len) {
                if (e.value_ptr.items[i].expires_ms <= now_ms) {
                    var removed = e.value_ptr.orderedRemove(i);
                    removed.deinit(self.allocator);
                } else {
                    i += 1;
                }
            }
            if (e.value_ptr.items.len == 0) {
                e.value_ptr.deinit(self.allocator);
                _ = self.providers.remove(e.key_ptr.*);
            }
        }
    }

    pub fn putValue(self: *RecordStore, key: []const u8, value: []const u8, now_ms: i64) std.mem.Allocator.Error!PutResult {
        const existing = self.getValue(key, now_ms);
        if (self.cfg.validators) |reg| {
            const verdict = reg.validate(key, value, existing, now_ms);
            if (self.cfg.validation_stats) |s| switch (verdict) {
                .reject => {
                    s.rejected += 1;
                    return .rejected;
                },
                .ignore => {
                    s.ignored += 1;
                    return .ignored;
                },
                .accept => {},
            } else switch (verdict) {
                .reject => return .rejected,
                .ignore => return .ignored,
                .accept => {},
            }
        }

        const gop = try self.values.getOrPut(key);
        if (gop.found_existing) self.allocator.free(gop.value_ptr.value);
        gop.value_ptr.* = .{
            .value = try self.allocator.dupe(u8, value),
            .expires_ms = now_ms + self.cfg.value_ttl_ms,
        };
        if (self.cfg.validation_stats) |s| s.accepted += 1;
        return .stored;
    }

    pub fn getValue(self: *RecordStore, key: []const u8, now_ms: i64) ?[]const u8 {
        const e = self.values.get(key) orelse return null;
        if (e.expires_ms <= now_ms) return null;
        return e.value;
    }

    pub fn addProvider(
        self: *RecordStore,
        key: []const u8,
        provider_id: []const u8,
        addrs: []const []const u8,
        now_ms: i64,
    ) std.mem.Allocator.Error!void {
        const gop = try self.providers.getOrPut(key);
        if (!gop.found_existing) gop.value_ptr.* = std.ArrayList(ProviderEntry).empty;

        for (gop.value_ptr.items, 0..) |*existing, i| {
            if (std.mem.eql(u8, existing.id, provider_id)) {
                existing.deinit(self.allocator);
                _ = gop.value_ptr.orderedRemove(i);
                break;
            }
        }

        var addr_copy = try self.allocator.alloc([]u8, addrs.len);
        errdefer self.allocator.free(addr_copy);
        for (addrs, 0..) |a, idx| addr_copy[idx] = try self.allocator.dupe(u8, a);

        try gop.value_ptr.append(self.allocator, .{
            .id = try self.allocator.dupe(u8, provider_id),
            .addrs = addr_copy,
            .expires_ms = now_ms + self.cfg.provider_ttl_ms,
        });
    }

    pub fn getProviders(self: *RecordStore, key: []const u8, now_ms: i64) []const ProviderEntry {
        const list = self.providers.get(key) orelse return &[_]ProviderEntry{};
        _ = now_ms;
        return list.items;
    }

    pub fn providersDueRepublish(self: *RecordStore, keys_out: *std.ArrayList([]const u8), now_ms: i64) std.mem.Allocator.Error!void {
        var it = self.providers.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.items.len == 0) continue;
            const oldest = e.value_ptr.items[0].expires_ms - self.cfg.provider_ttl_ms;
            if (now_ms - oldest >= self.cfg.provider_republish_ms) {
                try keys_out.append(self.allocator, e.key_ptr.*);
            }
        }
    }

    pub fn recordView(self: *RecordStore, key: []const u8, value: []const u8) wire.RecordView {
        _ = self;
        return .{ .key = key, .value = value, .time_received = null };
    }
};

test "provider ttl and republish tracking" {
    const a = std.testing.allocator;
    var store = RecordStore.init(a, .{ .provider_ttl_ms = 1000, .provider_republish_ms = 500 });
    defer store.deinit();

    const addr = [_][]const u8{"/ip4/1.2.3.4/udp/1/quic-v1"};
    try store.addProvider("cid-key", "provider-a", &addr, 0);
    try std.testing.expectEqual(@as(usize, 1), store.getProviders("cid-key", 0).len);

    store.purgeExpired(1001);
    try std.testing.expectEqual(@as(usize, 0), store.getProviders("cid-key", 1001).len);
}
