//! Circuit Relay v2 reservation store (#91).

const std = @import("std");
const identity = @import("../../primitives/identity.zig");
const wall_time = @import("../../primitives/wall_time.zig");

pub const Error = error{
    ReservationRefused,
    NoReservation,
    ResourceLimitExceeded,
    TooManyReservations,
} || std.mem.Allocator.Error;

pub const Config = struct {
    /// Default reservation TTL (seconds).
    reservation_ttl_sec: u64 = 3600,
    max_reservations_per_peer: u32 = 1,
    max_total_reservations: u32 = 256,
    max_simultaneous_bridges: u32 = 64,
};

pub const ReservationEntry = struct {
    peer: identity.PeerId,
    expire_unix: u64,
    addrs: [][]u8,
    voucher: ?[]u8,

    pub fn deinit(self: *ReservationEntry, allocator: std.mem.Allocator) void {
        for (self.addrs) |a| allocator.free(a);
        if (self.addrs.len > 0) allocator.free(self.addrs);
        if (self.voucher) |v| allocator.free(v);
        self.* = undefined;
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    entries: std.ArrayList(ReservationEntry),
    active_bridges: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Store {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .entries = std.ArrayList(ReservationEntry).empty,
        };
    }

    pub fn deinit(self: *Store) void {
        for (self.entries.items) |*e| e.deinit(self.allocator);
        self.entries.deinit(self.allocator);
    }

    pub fn reservationCount(self: *const Store) usize {
        return self.entries.items.len;
    }

    pub fn findReservation(self: *const Store, peer: identity.PeerId) ?*const ReservationEntry {
        const now = @as(u64, @intCast(wall_time.unixTimestamp()));
        for (self.entries.items) |*e| {
            if (e.peer.eql(&peer) and e.expire_unix > now) return e;
        }
        return null;
    }

    pub fn pruneExpired(self: *Store) void {
        const now = @as(u64, @intCast(wall_time.unixTimestamp()));
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].expire_unix <= now) {
                var e = self.entries.orderedRemove(i);
                e.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    pub fn createReservation(
        self: *Store,
        peer: identity.PeerId,
        relay_addrs: []const []const u8,
        voucher: ?[]const u8,
    ) Error!ReservationEntry {
        self.pruneExpired();
        if (self.entries.items.len >= self.cfg.max_total_reservations) return error.ReservationRefused;

        var peer_count: u32 = 0;
        for (self.entries.items) |e| {
            if (e.peer.eql(&peer)) peer_count += 1;
        }
        if (peer_count >= self.cfg.max_reservations_per_peer) return error.TooManyReservations;

        const expire = @as(u64, @intCast(wall_time.unixTimestamp())) + self.cfg.reservation_ttl_sec;
        var addrs_copy = std.ArrayList([]u8).empty;
        errdefer {
            for (addrs_copy.items) |a| self.allocator.free(a);
            addrs_copy.deinit(self.allocator);
        }
        for (relay_addrs) |a| try addrs_copy.append(self.allocator, try self.allocator.dupe(u8, a));
        const voucher_copy = if (voucher) |v| try self.allocator.dupe(u8, v) else null;

        const entry = ReservationEntry{
            .peer = peer,
            .expire_unix = expire,
            .addrs = try addrs_copy.toOwnedSlice(self.allocator),
            .voucher = voucher_copy,
        };
        try self.entries.append(self.allocator, entry);
        return self.entries.items[self.entries.items.len - 1];
    }

    pub fn beginBridge(self: *Store) Error!void {
        if (self.active_bridges >= self.cfg.max_simultaneous_bridges) return error.ResourceLimitExceeded;
        self.active_bridges += 1;
    }

    pub fn endBridge(self: *Store) void {
        if (self.active_bridges > 0) self.active_bridges -= 1;
    }
};

test "reservation create and find" {
    const a = std.testing.allocator;
    var store = Store.init(a, .{ .reservation_ttl_sec = 3600 });
    defer store.deinit();
    const peer = try identity.PeerId.random();
    const addrs = [_][]const u8{"/ip4/1.2.3.4/udp/4001/quic-v1"};
    _ = try store.createReservation(peer, &addrs, "voucher");
    try std.testing.expect(store.findReservation(peer) != null);
}
