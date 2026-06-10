//! Circuit Relay v2 server (hop + stop handlers) (#91).

const std = @import("std");
const Io = std.Io;
const identity = @import("../identity.zig");
const wire = @import("wire.zig");
const reservation = @import("reservation.zig");

pub const Error = wire.Error || reservation.Error || error{
    IoReadFailed,
    IoWriteFailed,
    PermissionDenied,
    ConnectionFailed,
    InvalidPeerId,
    UnexpectedMessage,
} || std.mem.Allocator.Error;

pub const OpenStopResult = enum {
    ok,
    connection_failed,
    no_reservation,
};

/// Relay-side callback: open a stop-protocol stream to `target` for `initiator` wire id bytes.
pub const OpenStopFn = *const fn (
    ctx: ?*anyopaque,
    target: identity.PeerId,
    initiator_id_wire: []const u8,
    limit: ?wire.LimitView,
) OpenStopResult;

pub const Config = struct {
    limits: wire.Limits = .standard,
    store: reservation.Config = .{},
    relay_addrs: []const []const u8 = &.{},
    /// When true, reject hop traffic received over relayed connections.
    reject_relayed_hop: bool = true,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    store: reservation.Store,
    local_peer: identity.PeerId,
    open_stop: OpenStopFn,
    open_stop_ctx: ?*anyopaque = null,

    pub fn init(
        allocator: std.mem.Allocator,
        cfg: Config,
        local_peer: identity.PeerId,
        open_stop: OpenStopFn,
    ) Server {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .store = reservation.Store.init(allocator, cfg.store),
            .local_peer = local_peer,
            .open_stop = open_stop,
        };
    }

    pub fn deinit(self: *Server) void {
        self.store.deinit();
    }

    pub fn peerIdToWire(self: *Server, peer: identity.PeerId) Error![]u8 {
        var buf: [128]u8 = undefined;
        const bytes = peer.toBytes(&buf) catch return error.InvalidPeerId;
        return try self.allocator.dupe(u8, bytes);
    }

    pub fn peerIdFromWire(self: *Server, wire_bytes: []const u8) Error!identity.PeerId {
        _ = self;
        return identity.PeerId.fromBytes(wire_bytes) catch error.InvalidPeerId;
    }

    pub fn writeHopStatus(
        self: *Server,
        w: *Io.Writer,
        status: wire.Status,
        res: ?wire.ReservationView,
        limit: ?wire.LimitView,
    ) Error!void {
        const payload = try wire.encodeHop(self.allocator, .{
            .msg_type = .status,
            .status = status,
            .reservation = res,
            .limit = limit,
        });
        defer self.allocator.free(payload);
        wire.writeLengthPrefixed(w, payload) catch return error.IoWriteFailed;
    }

    pub fn writeStopStatus(self: *Server, w: *Io.Writer, status: wire.Status) Error!void {
        const payload = try wire.encodeStop(self.allocator, .{
            .msg_type = .status,
            .status = status,
        });
        defer self.allocator.free(payload);
        wire.writeLengthPrefixed(w, payload) catch return error.IoWriteFailed;
    }

    fn mintVoucher(self: *Server, peer: identity.PeerId, expire: u64) Error![]u8 {
        const peer_wire = try self.peerIdToWire(peer);
        defer self.allocator.free(peer_wire);
        const relay_wire = try self.peerIdToWire(self.local_peer);
        defer self.allocator.free(relay_wire);
        // Advisory voucher payload (signed envelope deferred — bytes-only for now).
        return try std.fmt.allocPrint(self.allocator, "rsvp:{d}:{s}:{s}", .{
            expire,
            relay_wire,
            peer_wire,
        });
    }

    /// Handle one inbound hop stream message (reserve or connect).
    pub fn handleHopStream(
        self: *Server,
        r: *Io.Reader,
        w: *Io.Writer,
        hop_peer: identity.PeerId,
        is_relayed: bool,
    ) Error!void {
        if (is_relayed and self.cfg.reject_relayed_hop) {
            try self.writeHopStatus(w, .permission_denied, null, null);
            return;
        }

        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);

        var msg = try wire.decodeHopOwned(self.allocator, frame, self.cfg.limits);
        defer msg.deinit(self.allocator);

        switch (msg.msg_type) {
            .reserve => {
                _ = self.store.createReservation(hop_peer, self.cfg.relay_addrs, null) catch |e| switch (e) {
                    reservation.Error.ReservationRefused, reservation.Error.TooManyReservations => {
                        try self.writeHopStatus(w, .reservation_refused, null, null);
                        return;
                    },
                    else => |x| return x,
                };
                const res_entry = self.store.findReservation(hop_peer) orelse {
                    try self.writeHopStatus(w, .reservation_refused, null, null);
                    return;
                };
                const voucher = try self.mintVoucher(hop_peer, res_entry.expire_unix);
                defer self.allocator.free(voucher);

                var addr_views = std.ArrayList([]const u8).empty;
                defer addr_views.deinit(self.allocator);
                for (res_entry.addrs) |a| try addr_views.append(self.allocator, a);

                try self.writeHopStatus(w, .ok, .{
                    .expire_unix = res_entry.expire_unix,
                    .addrs = addr_views.items,
                    .voucher = voucher,
                }, .{ .duration_sec = 120, .data_bytes = 1 << 20 });
            },
            .connect => {
                const target_wire = msg.peer.?.id orelse {
                    try self.writeHopStatus(w, .malformed_message, null, null);
                    return;
                };
                const target = try self.peerIdFromWire(target_wire);
                if (self.store.findReservation(target) == null) {
                    try self.writeHopStatus(w, .no_reservation, null, null);
                    return;
                }
                self.store.beginBridge() catch {
                    try self.writeHopStatus(w, .resource_limit_exceeded, null, null);
                    return;
                };
                const initiator_wire = try self.peerIdToWire(hop_peer);
                defer self.allocator.free(initiator_wire);
                const lim_view: ?wire.LimitView = if (msg.limit) |l| .{
                    .duration_sec = l.duration_sec,
                    .data_bytes = l.data_bytes,
                } else null;
                const open_res = self.open_stop(self.open_stop_ctx, target, initiator_wire, lim_view);
                switch (open_res) {
                    .ok => try self.writeHopStatus(w, .ok, null, lim_view),
                    .no_reservation => {
                        self.store.endBridge();
                        try self.writeHopStatus(w, .no_reservation, null, null);
                    },
                    .connection_failed => {
                        self.store.endBridge();
                        try self.writeHopStatus(w, .connection_failed, null, null);
                    },
                }
            },
            else => try self.writeHopStatus(w, .unexpected_message, null, null),
        }
    }

    /// Target-side stop handler: accept relayed connection from initiator `peer`.
    pub fn handleStopStream(
        self: *Server,
        r: *Io.Reader,
        w: *Io.Writer,
        local_peer: identity.PeerId,
    ) Error!void {
        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);

        var msg = try wire.decodeStopOwned(self.allocator, frame, self.cfg.limits);
        defer msg.deinit(self.allocator);

        if (msg.msg_type != .connect) {
            try self.writeStopStatus(w, .unexpected_message);
            return;
        }
        if (self.store.findReservation(local_peer) == null) {
            try self.writeStopStatus(w, .connection_failed);
            return;
        }
        try self.writeStopStatus(w, .ok);
    }

    pub fn endBridge(self: *Server) void {
        self.store.endBridge();
    }
};

test "hop reserve accepts and returns reservation" {
    const a = std.testing.allocator;
    const OpenStub = struct {
        fn open(ctx: ?*anyopaque, target: identity.PeerId, initiator: []const u8, limit: ?wire.LimitView) OpenStopResult {
            _ = ctx;
            _ = target;
            _ = initiator;
            _ = limit;
            return .ok;
        }
    };
    const relay = try identity.PeerId.random();
    const client_peer = try identity.PeerId.random();
    var srv = Server.init(a, .{
        .relay_addrs = &.{"/ip4/203.0.113.1/udp/4001/quic-v1"},
    }, relay, OpenStub.open);
    defer srv.deinit();

    const req = try wire.encodeHop(a, .{ .msg_type = .reserve });
    defer a.free(req);

    var in_buf: [4096]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var w_in = Io.Writer.fixed(&in_buf);
    try wire.writeLengthPrefixed(&w_in, req);
    var r = Io.Reader.fixed(in_buf[0..w_in.end]);
    var w_out = Io.Writer.fixed(&out_buf);
    try srv.handleHopStream(&r, &w_out, client_peer, false);

    var resp_r = Io.Reader.fixed(out_buf[0..w_out.end]);
    const resp_frame = try wire.readLengthPrefixedAlloc(&resp_r, a, wire.Limits.standard.max_frame_bytes);
    defer a.free(resp_frame);
    var resp = try wire.decodeHopOwned(a, resp_frame, .standard);
    defer resp.deinit(a);
    try std.testing.expectEqual(wire.Status.ok, resp.status.?);
    try std.testing.expect(resp.reservation != null);
}
