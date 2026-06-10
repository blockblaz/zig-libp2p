//! Circuit Relay v2 client (#91).

const std = @import("std");
const Io = std.Io;
const identity = @import("../identity.zig");
const wall_time = @import("../wall_time.zig");
const wire = @import("wire.zig");

pub const Error = wire.Error || error{
    IoReadFailed,
    IoWriteFailed,
    ReservationFailed,
    ConnectFailed,
    InvalidPeerId,
} || std.mem.Allocator.Error;

pub const Config = struct {
    limits: wire.Limits = .standard,
    /// Refresh reservation when fewer than this many seconds remain.
    refresh_before_sec: u64 = 300,
};

pub const ReservationState = struct {
    expire_unix: u64 = 0,
    addrs: [][]u8 = &[_][]u8{},
    voucher: ?[]u8 = null,
    relay_peer: identity.PeerId,

    pub fn deinit(self: *ReservationState, allocator: std.mem.Allocator) void {
        for (self.addrs) |a| allocator.free(a);
        if (self.addrs.len > 0) allocator.free(self.addrs);
        if (self.voucher) |v| allocator.free(v);
        self.* = undefined;
    }

    pub fn needsRefresh(self: *const ReservationState, now_unix: u64, refresh_before: u64) bool {
        if (self.expire_unix == 0) return true;
        return self.expire_unix <= now_unix + refresh_before;
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    reservation: ?ReservationState = null,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Client {
        return .{ .allocator = allocator, .cfg = cfg };
    }

    pub fn deinit(self: *Client) void {
        if (self.reservation) |*r| r.deinit(self.allocator);
    }

    pub fn peerIdToWire(self: *Client, peer: identity.PeerId) Error![]u8 {
        var buf: [128]u8 = undefined;
        const bytes = peer.toBytes(&buf) catch return error.InvalidPeerId;
        return try self.allocator.dupe(u8, bytes);
    }

    pub fn buildReserveRequest(self: *Client) Error![]u8 {
        return try wire.encodeHop(self.allocator, .{ .msg_type = .reserve });
    }

    pub fn buildConnectRequest(self: *Client, target: identity.PeerId) Error![]u8 {
        const id_wire = try self.peerIdToWire(target);
        defer self.allocator.free(id_wire);
        return try wire.encodeHop(self.allocator, .{
            .msg_type = .connect,
            .peer = .{ .id = id_wire },
        });
    }

    pub fn parseReserveResponse(self: *Client, frame: []const u8, relay: identity.PeerId) Error!void {
        var msg = try wire.decodeHopOwned(self.allocator, frame, self.cfg.limits);
        defer msg.deinit(self.allocator);
        if (msg.msg_type != .status or msg.status != .ok or msg.reservation == null) return error.ReservationFailed;
        if (self.reservation) |*old| old.deinit(self.allocator);
        const res = msg.reservation.?;
        var addrs = std.ArrayList([]u8).empty;
        errdefer {
            for (addrs.items) |a| self.allocator.free(a);
            addrs.deinit(self.allocator);
        }
        for (res.addrs) |a| try addrs.append(self.allocator, try self.allocator.dupe(u8, a));
        const voucher_copy = if (res.voucher) |v| try self.allocator.dupe(u8, v) else null;
        self.reservation = .{
            .expire_unix = res.expire_unix,
            .addrs = try addrs.toOwnedSlice(self.allocator),
            .voucher = voucher_copy,
            .relay_peer = relay,
        };
    }

    pub fn reserveOnStream(
        self: *Client,
        r: *Io.Reader,
        w: *Io.Writer,
        relay: identity.PeerId,
    ) Error!void {
        const req = try self.buildReserveRequest();
        defer self.allocator.free(req);
        wire.writeLengthPrefixed(w, req) catch return error.IoWriteFailed;
        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);
        try self.parseReserveResponse(frame, relay);
    }

    pub fn connectOnStream(
        self: *Client,
        r: *Io.Reader,
        w: *Io.Writer,
        target: identity.PeerId,
    ) Error!void {
        const req = try self.buildConnectRequest(target);
        defer self.allocator.free(req);
        wire.writeLengthPrefixed(w, req) catch return error.IoWriteFailed;
        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);
        var msg = try wire.decodeHopOwned(self.allocator, frame, self.cfg.limits);
        defer msg.deinit(self.allocator);
        if (msg.msg_type != .status or msg.status != .ok) return error.ConnectFailed;
    }

    pub fn pollRefresh(self: *Client, now_unix: u64) bool {
        const res = self.reservation orelse return true;
        return res.needsRefresh(now_unix, self.cfg.refresh_before_sec);
    }

    pub fn nowUnix() u64 {
        return @intCast(wall_time.unixTimestamp());
    }
};

test "client reserve request round trip" {
    const a = std.testing.allocator;
    var client = Client.init(a, .{});
    defer client.deinit();
    const req = try client.buildReserveRequest();
    defer a.free(req);
    try std.testing.expect(req.len > 0);
}
