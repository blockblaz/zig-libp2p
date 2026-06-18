//! Local Identify advertisement state and dirty tracking (#202).
//!
//! QUIC [`transport.quic_runtime.QuicRuntime`] registers
//! [`host.Host.setIdentifyPushDispatch`] and opens `/ipfs/id/push/1.0.0`
//! streams directly; other embedders drain [`swarm.Event.identify_push_peer`].
//! This module owns the wire payload inputs (listen addrs, protocol set,
//! signed peer record).

const std = @import("std");
const identify_mod = @import("../protocols/identify/identify.zig");

pub const Advertisement = struct {
    allocator: std.mem.Allocator,
    listen_addrs: std.ArrayList([]u8) = .empty,
    protocols: std.ArrayList([]u8) = .empty,
    public_key: ?[]u8 = null,
    signed_peer_record: ?[]u8 = null,
    signed_peer_record_seq: u64 = 0,
    dirty: bool = false,

    pub fn init(allocator: std.mem.Allocator) Advertisement {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Advertisement) void {
        for (self.listen_addrs.items) |a| self.allocator.free(a);
        self.listen_addrs.deinit(self.allocator);
        for (self.protocols.items) |p| self.allocator.free(p);
        self.protocols.deinit(self.allocator);
        if (self.public_key) |pk| self.allocator.free(pk);
        if (self.signed_peer_record) |spr| self.allocator.free(spr);
        self.* = undefined;
    }

    pub fn isDirty(self: *const Advertisement) bool {
        return self.dirty;
    }

    pub fn markDirty(self: *Advertisement) void {
        self.dirty = true;
    }

    /// Returns whether the advertisement was dirty and clears the flag.
    pub fn takeDirty(self: *Advertisement) bool {
        const was = self.dirty;
        self.dirty = false;
        return was;
    }

    pub fn setListenAddrs(self: *Advertisement, addrs: []const []const u8) std.mem.Allocator.Error!void {
        for (self.listen_addrs.items) |a| self.allocator.free(a);
        self.listen_addrs.clearRetainingCapacity();
        for (addrs) |a| {
            const owned = try self.allocator.dupe(u8, a);
            try self.listen_addrs.append(self.allocator, owned);
        }
        self.dirty = true;
    }

    pub fn addListenAddr(self: *Advertisement, addr: []const u8) std.mem.Allocator.Error!void {
        const owned = try self.allocator.dupe(u8, addr);
        try self.listen_addrs.append(self.allocator, owned);
        self.dirty = true;
    }

    pub fn removeListenAddr(self: *Advertisement, addr: []const u8) void {
        var i: usize = 0;
        while (i < self.listen_addrs.items.len) {
            if (std.mem.eql(u8, self.listen_addrs.items[i], addr)) {
                self.allocator.free(self.listen_addrs.orderedRemove(i));
                self.dirty = true;
            } else {
                i += 1;
            }
        }
    }

    pub fn addProtocol(self: *Advertisement, proto: []const u8) std.mem.Allocator.Error!void {
        for (self.protocols.items) |p| {
            if (std.mem.eql(u8, p, proto)) return;
        }
        const owned = try self.allocator.dupe(u8, proto);
        try self.protocols.append(self.allocator, owned);
        self.dirty = true;
    }

    pub fn removeProtocol(self: *Advertisement, proto: []const u8) void {
        var i: usize = 0;
        while (i < self.protocols.items.len) {
            if (std.mem.eql(u8, self.protocols.items[i], proto)) {
                self.allocator.free(self.protocols.orderedRemove(i));
                self.dirty = true;
            } else {
                i += 1;
            }
        }
    }

    pub fn setPublicKey(self: *Advertisement, key: ?[]const u8) std.mem.Allocator.Error!void {
        if (self.public_key) |pk| self.allocator.free(pk);
        self.public_key = if (key) |k| try self.allocator.dupe(u8, k) else null;
        self.dirty = true;
    }

    pub fn setSignedPeerRecord(self: *Advertisement, spr: ?[]const u8, seq: u64) std.mem.Allocator.Error!void {
        if (seq != self.signed_peer_record_seq or !sprEql(self.signed_peer_record, spr)) {
            if (self.signed_peer_record) |old| self.allocator.free(old);
            self.signed_peer_record = if (spr) |s| try self.allocator.dupe(u8, s) else null;
            self.signed_peer_record_seq = seq;
            self.dirty = true;
        }
    }

    fn sprEql(a: ?[]const u8, b: ?[]const u8) bool {
        const aa = a orelse return b == null;
        const bb = b orelse return false;
        return std.mem.eql(u8, aa, bb);
    }

    pub fn replyParamsInto(
        self: *const Advertisement,
        addr_scratch: *std.ArrayList([]const u8),
        proto_scratch: *std.ArrayList([]const u8),
    ) identify_mod.ReplyParams {
        addr_scratch.clearRetainingCapacity();
        for (self.listen_addrs.items) |a| addr_scratch.append(self.allocator, a) catch {};
        proto_scratch.clearRetainingCapacity();
        for (self.protocols.items) |p| proto_scratch.append(self.allocator, p) catch {};
        return .{
            .listen_addrs = addr_scratch.items,
            .protocols = proto_scratch.items,
            .public_key = self.public_key,
            .signed_peer_record = self.signed_peer_record,
        };
    }
};

test "setListenAddrs and addProtocol mark dirty" {
    const a = std.testing.allocator;
    var ad = Advertisement.init(a);
    defer ad.deinit();
    try std.testing.expect(!ad.isDirty());
    try ad.setListenAddrs(&.{"addr1"});
    try std.testing.expect(ad.isDirty());
    _ = ad.takeDirty();
    try ad.addProtocol("/meshsub/1.1.0");
    try std.testing.expect(ad.takeDirty());
}

test "setSignedPeerRecord dirty only on seq or bytes change" {
    const a = std.testing.allocator;
    var ad = Advertisement.init(a);
    defer ad.deinit();
    try ad.setSignedPeerRecord("spr-v1", 1);
    try std.testing.expect(ad.takeDirty());
    try ad.setSignedPeerRecord("spr-v1", 1);
    try std.testing.expect(!ad.takeDirty());
    try ad.setSignedPeerRecord("spr-v2", 2);
    try std.testing.expect(ad.takeDirty());
}
