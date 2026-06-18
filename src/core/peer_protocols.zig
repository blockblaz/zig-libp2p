//! Remote peer protocol sets learned from Identify (#206).

const std = @import("std");
const identity = @import("../primitives/identity.zig");
const autonat_wire = @import("../protocols/autonat/wire.zig");

const PeerIdContext = struct {
    pub fn hash(_: PeerIdContext, key: identity.PeerId) u64 {
        var buf: [128]u8 = undefined;
        const b = key.toBytes(&buf) catch return 0;
        return std.hash.Wyhash.hash(0, b);
    }
    pub fn eql(_: PeerIdContext, a: identity.PeerId, b: identity.PeerId) bool {
        return a.eql(&b);
    }
};

const Entry = struct {
    protocols: std.ArrayList([]u8) = .empty,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    map: std.HashMap(identity.PeerId, Entry, PeerIdContext, std.hash_map.default_max_load_percentage),

    pub fn init(allocator: std.mem.Allocator) Store {
        return .{
            .allocator = allocator,
            .map = std.HashMap(identity.PeerId, Entry, PeerIdContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }

    pub fn deinit(self: *Store) void {
        var it = self.map.valueIterator();
        while (it.next()) |e| {
            for (e.protocols.items) |p| self.allocator.free(p);
            e.protocols.deinit(self.allocator);
        }
        self.map.deinit();
    }

    pub fn removePeer(self: *Store, peer: identity.PeerId) void {
        if (self.map.fetchRemove(peer)) |kv| {
            var entry = kv.value;
            for (entry.protocols.items) |p| self.allocator.free(p);
            entry.protocols.deinit(self.allocator);
        }
    }

    pub fn setProtocols(self: *Store, peer: identity.PeerId, protocols: []const []const u8) std.mem.Allocator.Error!void {
        const gop = try self.map.getOrPut(peer);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        for (gop.value_ptr.protocols.items) |p| self.allocator.free(p);
        gop.value_ptr.protocols.clearRetainingCapacity();
        for (protocols) |proto| {
            const owned = try self.allocator.dupe(u8, proto);
            try gop.value_ptr.protocols.append(self.allocator, owned);
        }
    }

    pub fn supports(self: *const Store, peer: identity.PeerId, protocol_id: []const u8) bool {
        const e = self.map.get(peer) orelse return false;
        for (e.protocols.items) |p| {
            if (std.mem.eql(u8, p, protocol_id)) return true;
        }
        return false;
    }

    pub fn supportsAutonatV1(self: *const Store, peer: identity.PeerId) bool {
        return self.supports(peer, autonat_wire.v1_multistream_protocol_id);
    }

    pub fn collectAutonatServers(
        self: *const Store,
        connected: []const identity.PeerId,
        out: *std.ArrayList(identity.PeerId),
    ) std.mem.Allocator.Error!void {
        for (connected) |peer| {
            if (self.supportsAutonatV1(peer)) {
                try out.append(self.allocator, peer);
            }
        }
    }
};

test "peer protocol store" {
    const a = std.testing.allocator;
    var store = Store.init(a);
    defer store.deinit();

    const peer = try identity.PeerId.random();
    try store.setProtocols(peer, &.{ autonat_wire.v1_multistream_protocol_id, "/other" });
    try std.testing.expect(store.supportsAutonatV1(peer));
    try std.testing.expect(!store.supportsAutonatV1(try identity.PeerId.random()));
}
