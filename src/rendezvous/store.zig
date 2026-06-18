//! Rendezvous registration store with cookie-based discover paging (#209).

const std = @import("std");
const wire = @import("wire.zig");
const identity = @import("../identity.zig");
const wall_time = @import("../wall_time.zig");

pub const Error = wire.Error || std.mem.Allocator.Error || error{Unavailable};

pub const Config = struct {
    min_ttl_s: u64 = wire.min_ttl_s,
    max_ttl_s: u64 = wire.max_ttl_s,
    max_registrations_per_peer: usize = 32,
    max_registrations_total: usize = 10_000,
    max_cookies: usize = 10_000,
};

pub const DiscoverResult = struct {
    registrations: []Registration,
    cookie: wire.Cookie,
};

pub const Registration = struct {
    namespace: []u8,
    signed_peer_record: []u8,
    ttl_s: u64,
    peer: identity.PeerId,

    pub fn deinit(self: *Registration, allocator: std.mem.Allocator) void {
        allocator.free(self.namespace);
        allocator.free(self.signed_peer_record);
        self.* = undefined;
    }
};

const Entry = struct {
    peer: identity.PeerId,
    namespace: []u8,
    signed_peer_record: []u8,
    ttl_s: u64,
    expires_at_ms: i64,
};

const CookieState = struct {
    cookie: wire.Cookie,
    returned_ids: std.ArrayList(u64),

    fn deinit(self: *CookieState, allocator: std.mem.Allocator) void {
        self.cookie.deinit(allocator);
        self.returned_ids.deinit(allocator);
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    entries: std.HashMap(u64, Entry, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    peer_ns_to_id: std.StringHashMap(u64),
    cookies: std.ArrayList(CookieState) = .empty,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Store {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .entries = .init(allocator),
            .peer_ns_to_id = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *Store) void {
        var it = self.entries.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.value_ptr.namespace);
            self.allocator.free(e.value_ptr.signed_peer_record);
        }
        self.entries.deinit();
        var kit = self.peer_ns_to_id.keyIterator();
        while (kit.next()) |k| self.allocator.free(k.*);
        self.peer_ns_to_id.deinit();
        for (self.cookies.items) |*c| c.deinit(self.allocator);
        self.cookies.deinit(self.allocator);
    }

    fn peerNsKey(self: *Store, peer: identity.PeerId, namespace: []const u8) ![]u8 {
        var buf: [256]u8 = undefined;
        const peer_bytes = peer.toBytes(&buf) catch return error.InvalidNamespace;
        const key = try self.allocator.alloc(u8, peer_bytes.len + 1 + namespace.len);
        @memcpy(key[0..peer_bytes.len], peer_bytes);
        key[peer_bytes.len] = 0;
        @memcpy(key[peer_bytes.len + 1 ..], namespace);
        return key;
    }

    fn countForPeer(self: *Store, peer: identity.PeerId) usize {
        var n: usize = 0;
        var it = self.entries.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.peer.eql(&peer)) n += 1;
        }
        return n;
    }

    fn purgeExpired(self: *Store, now_ms: i64) void {
        var to_remove = std.ArrayList(u64).empty;
        defer to_remove.deinit(self.allocator);
        var it = self.entries.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.expires_at_ms <= now_ms) to_remove.append(self.allocator, e.key_ptr.*) catch {};
        }
        for (to_remove.items) |id| self.removeById(id);
    }

    fn removeById(self: *Store, id: u64) void {
        const entry = self.entries.fetchRemove(id) orelse return;
        self.allocator.free(entry.value.namespace);
        self.allocator.free(entry.value.signed_peer_record);
        var kit = self.peer_ns_to_id.keyIterator();
        while (kit.next()) |k| {
            if (self.peer_ns_to_id.get(k.*) == id) {
                const owned = k.*;
                _ = self.peer_ns_to_id.remove(owned);
                self.allocator.free(owned);
                break;
            }
        }
        for (self.cookies.items) |*c| {
            var i: usize = 0;
            while (i < c.returned_ids.items.len) {
                if (c.returned_ids.items[i] == id) _ = c.returned_ids.swapRemove(i) else i += 1;
            }
        }
    }

    fn findCookie(self: *Store, cookie: wire.Cookie) ?*CookieState {
        for (self.cookies.items) |*c| {
            const a = c.cookie;
            if (a.id != cookie.id) continue;
            if (a.namespace == null and cookie.namespace == null) return c;
            if (a.namespace) |an| {
                if (cookie.namespace) |bn| {
                    if (std.mem.eql(u8, an, bn)) return c;
                }
            }
        }
        return null;
    }

    fn trimCookies(self: *Store) void {
        while (self.cookies.items.len > self.cfg.max_cookies) {
            var old = self.cookies.orderedRemove(0);
            old.deinit(self.allocator);
        }
    }

    pub fn add(
        self: *Store,
        peer: identity.PeerId,
        namespace: []const u8,
        signed_peer_record: []const u8,
        ttl_s: u64,
        now_ms: i64,
    ) Error!Registration {
        try wire.validateNamespace(namespace);
        if (ttl_s < self.cfg.min_ttl_s or ttl_s > self.cfg.max_ttl_s) return error.InvalidMessageType;

        self.purgeExpired(now_ms);

        if (self.countForPeer(peer) >= self.cfg.max_registrations_per_peer or
            self.entries.count() >= self.cfg.max_registrations_total)
        {
            return error.Unavailable;
        }

        const index_key = try self.peerNsKey(peer, namespace);
        defer self.allocator.free(index_key);
        if (self.peer_ns_to_id.get(index_key)) |old_id| self.removeById(old_id);

        var prng = std.Random.DefaultPrng.init(@intCast(@max(1, wall_time.unixTimestamp())));
        const id = prng.random().int(u64);

        const ns_owned = try self.allocator.dupe(u8, namespace);
        errdefer self.allocator.free(ns_owned);
        const spr_owned = try self.allocator.dupe(u8, signed_peer_record);
        errdefer self.allocator.free(spr_owned);
        const key_owned = try self.allocator.dupe(u8, index_key);
        errdefer self.allocator.free(key_owned);

        try self.entries.put(id, .{
            .peer = peer,
            .namespace = ns_owned,
            .signed_peer_record = spr_owned,
            .ttl_s = ttl_s,
            .expires_at_ms = now_ms + @as(i64, @intCast(ttl_s * 1000)),
        });
        try self.peer_ns_to_id.put(key_owned, id);

        return .{
            .namespace = try self.allocator.dupe(u8, namespace),
            .signed_peer_record = try self.allocator.dupe(u8, signed_peer_record),
            .ttl_s = ttl_s,
            .peer = peer,
        };
    }

    pub fn remove(self: *Store, peer: identity.PeerId, namespace: []const u8) void {
        const index_key = self.peerNsKey(peer, namespace) catch return;
        defer self.allocator.free(index_key);
        if (self.peer_ns_to_id.get(index_key)) |id| self.removeById(id);
    }

    pub fn discover(
        self: *Store,
        discover_ns: ?[]const u8,
        cookie_wire: ?[]const u8,
        limit: ?u64,
        now_ms: i64,
    ) Error!DiscoverResult {
        self.purgeExpired(now_ms);

        var cookie_in: ?wire.Cookie = null;
        defer if (cookie_in) |*c| c.deinit(self.allocator);

        if (cookie_wire) |cw| {
            cookie_in = try wire.Cookie.decodeWire(self.allocator, cw);
            if (discover_ns == null and cookie_in.?.namespace != null) return error.InvalidCookie;
            if (discover_ns) |dns| {
                if (cookie_in.?.namespace) |cns| {
                    if (!std.mem.eql(u8, cns, dns)) return error.InvalidCookie;
                }
            }
        }

        var seen = std.AutoHashMap(u64, void).init(self.allocator);
        defer seen.deinit();

        if (cookie_in) |c| {
            if (self.findCookie(c)) |state| {
                for (state.returned_ids.items) |id| _ = seen.put(id, {}) catch {};
            }
        }

        const max_n = @min(limit orelse 1000, 1000);
        var out_regs = std.ArrayList(Registration).empty;
        errdefer {
            for (out_regs.items) |*r| r.deinit(self.allocator);
            out_regs.deinit(self.allocator);
        }
        var returned_ids = std.ArrayList(u64).empty;
        errdefer returned_ids.deinit(self.allocator);

        var it = self.entries.iterator();
        while (it.next()) |e| {
            if (seen.contains(e.key_ptr.*)) continue;
            const entry = e.value_ptr.*;
            if (discover_ns) |dns| {
                if (!std.mem.eql(u8, entry.namespace, dns)) continue;
            }
            if (returned_ids.items.len >= max_n) break;
            try out_regs.append(self.allocator, .{
                .namespace = try self.allocator.dupe(u8, entry.namespace),
                .signed_peer_record = try self.allocator.dupe(u8, entry.signed_peer_record),
                .ttl_s = entry.ttl_s,
                .peer = entry.peer,
            });
            try returned_ids.append(self.allocator, e.key_ptr.*);
        }

        var all_ids = std.ArrayList(u64).empty;
        errdefer all_ids.deinit(self.allocator);
        if (cookie_in) |c| {
            if (self.findCookie(c)) |state| try all_ids.appendSlice(self.allocator, state.returned_ids.items);
        }
        try all_ids.appendSlice(self.allocator, returned_ids.items);

        const new_cookie = if (discover_ns) |dns|
            try wire.Cookie.forNamespace(self.allocator, dns)
        else
            try wire.Cookie.forAllNamespaces(self.allocator);

        var state = CookieState{ .cookie = new_cookie, .returned_ids = .empty };
        try state.returned_ids.appendSlice(self.allocator, all_ids.items);
        try self.cookies.append(self.allocator, state);
        self.trimCookies();

        const return_cookie = wire.Cookie{
            .id = new_cookie.id,
            .namespace = if (new_cookie.namespace) |n| try self.allocator.dupe(u8, n) else null,
        };

        return .{
            .registrations = try out_regs.toOwnedSlice(self.allocator),
            .cookie = return_cookie,
        };
    }

    pub fn freeDiscoverResult(self: *Store, result: DiscoverResult) void {
        for (result.registrations) |*r| r.deinit(self.allocator);
        self.allocator.free(result.registrations);
        var c = result.cookie;
        c.deinit(self.allocator);
    }
};

test "cookie discover returns only delta" {
    const a = std.testing.allocator;
    var store = Store.init(a, .{});
    defer store.deinit();

    const peer_a = try identity.PeerId.random();
    const peer_b = try identity.PeerId.random();
    _ = try store.add(peer_a, "foo", "spr-a", wire.default_ttl_s, 0);
    _ = try store.add(peer_b, "foo", "spr-b", wire.default_ttl_s, 0);

    var first = try store.discover(null, null, null, 0);
    defer store.freeDiscoverResult(first);
    try std.testing.expectEqual(@as(usize, 2), first.registrations.len);

    const cookie_wire = try first.cookie.encodeWire(a);
    defer a.free(cookie_wire);

    const second = try store.discover(null, cookie_wire, null, 0);
    defer store.freeDiscoverResult(second);
    try std.testing.expectEqual(@as(usize, 0), second.registrations.len);
}
