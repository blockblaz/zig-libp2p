//! DCUtR hole-punch coordinator (#91).

const std = @import("std");
const Io = std.Io;
const wall_time = @import("../wall_time.zig");
const wire = @import("wire.zig");

pub const Error = wire.Error || error{
    IoReadFailed,
    IoWriteFailed,
    ProtocolError,
    Timeout,
} || std.mem.Allocator.Error;

pub const Role = enum { initiator, responder };

/// Direct-dial request emitted by the coordinator. The `addrs` slice is
/// freshly allocated and owned by the caller — call `deinit` when done so
/// the underlying address strings are not leaked.
pub const DirectDialRequest = struct {
    addrs: [][]u8,
    fire_at_ms: i64,

    pub fn deinit(self: *DirectDialRequest, allocator: std.mem.Allocator) void {
        for (self.addrs) |a| allocator.free(a);
        if (self.addrs.len > 0) allocator.free(self.addrs);
        self.* = undefined;
    }
};

fn dupeAddrs(allocator: std.mem.Allocator, src: []const []const u8) ![][]u8 {
    var list = std.ArrayList([]u8).empty;
    errdefer {
        for (list.items) |a| allocator.free(a);
        list.deinit(allocator);
    }
    for (src) |a| try list.append(allocator, try allocator.dupe(u8, a));
    return try list.toOwnedSlice(allocator);
}

pub const Config = struct {
    limits: wire.Limits = .standard,
    max_attempts: u32 = 3,
};

/// Internal, owned-by-coordinator state describing when a dial should fire.
/// Distinct from `DirectDialRequest` (which is the *output* handed to the
/// caller with its own owned `addrs` copy) so coordinator state mutations
/// can never invalidate a request already returned to the caller.
const PendingDial = struct { fire_at_ms: i64 };

pub const Coordinator = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    role: Role,
    connect_sent_ms: ?i64 = null,
    remote_addrs: [][]u8 = &[_][]u8{},
    attempt: u32 = 0,
    pending_dial: ?PendingDial = null,

    pub fn init(allocator: std.mem.Allocator, cfg: Config, role: Role) Coordinator {
        return .{ .allocator = allocator, .cfg = cfg, .role = role };
    }

    pub fn deinit(self: *Coordinator) void {
        for (self.remote_addrs) |a| self.allocator.free(a);
        if (self.remote_addrs.len > 0) self.allocator.free(self.remote_addrs);
    }

    pub fn buildConnect(self: *Coordinator, obs_addrs: []const []const u8) Error![]u8 {
        return try wire.encode(self.allocator, .{ .msg_type = .connect, .obs_addrs = obs_addrs });
    }

    pub fn buildSync(self: *Coordinator) Error![]u8 {
        return try wire.encode(self.allocator, .{ .msg_type = .sync });
    }

    fn storeRemoteAddrs(self: *Coordinator, addrs: []const []const u8) Error!void {
        for (self.remote_addrs) |a| self.allocator.free(a);
        if (self.remote_addrs.len > 0) self.allocator.free(self.remote_addrs);
        var list = std.ArrayList([]u8).empty;
        errdefer list.deinit(self.allocator);
        for (addrs) |a| try list.append(self.allocator, try self.allocator.dupe(u8, a));
        self.remote_addrs = try list.toOwnedSlice(self.allocator);
    }

    /// Responder: received CONNECT from initiator — reply with our addrs and schedule dial.
    pub fn onRemoteConnect(self: *Coordinator, frame: []const u8, local_obs_addrs: []const []const u8) Error![]u8 {
        var msg = try wire.decodeOwned(self.allocator, frame, self.cfg.limits);
        defer msg.deinit(self.allocator);
        if (msg.msg_type != .connect) return error.ProtocolError;
        try self.storeRemoteAddrs(msg.obs_addrs);
        self.connect_sent_ms = @intCast(wall_time.milliTimestamp());
        return try self.buildConnect(local_obs_addrs);
    }

    /// Initiator: received CONNECT reply — send SYNC and schedule half-RTT dial.
    pub fn onRemoteConnectReply(self: *Coordinator, frame: []const u8) Error![]u8 {
        var msg = try wire.decodeOwned(self.allocator, frame, self.cfg.limits);
        defer msg.deinit(self.allocator);
        if (msg.msg_type != .connect) return error.ProtocolError;
        try self.storeRemoteAddrs(msg.obs_addrs);
        const now = wall_time.milliTimestamp();
        const rtt = if (self.connect_sent_ms) |t| now - t else 0;
        const fire_at = now + @divTrunc(rtt, 2);
        self.pending_dial = .{ .fire_at_ms = fire_at };
        return try self.buildSync();
    }

    /// Responder: received SYNC — dial immediately. The returned request owns
    /// its `addrs` copy; caller must `request.deinit(allocator)` when done.
    pub fn onRemoteSync(self: *Coordinator) Error!DirectDialRequest {
        if (self.connect_sent_ms == null) return error.ProtocolError;
        const now_ms = @as(i64, @intCast(wall_time.milliTimestamp()));
        self.pending_dial = .{ .fire_at_ms = now_ms };
        return .{
            .addrs = try dupeAddrs(self.allocator, self.remote_addrs),
            .fire_at_ms = now_ms,
        };
    }

    /// Returns an owned DirectDialRequest when the scheduled time is reached.
    /// Caller must `request.deinit(allocator)` to free the duped `addrs`.
    pub fn pollDial(self: *Coordinator, now_ms: i64) ?DirectDialRequest {
        const p = self.pending_dial orelse return null;
        if (now_ms < p.fire_at_ms) return null;
        self.pending_dial = null;
        const owned_addrs = dupeAddrs(self.allocator, self.remote_addrs) catch return null;
        return .{ .addrs = owned_addrs, .fire_at_ms = p.fire_at_ms };
    }

    pub fn runInitiatorExchange(
        self: *Coordinator,
        r: *Io.Reader,
        w: *Io.Writer,
        local_obs_addrs: []const []const u8,
    ) Error!DirectDialRequest {
        self.connect_sent_ms = @intCast(wall_time.milliTimestamp());
        const connect = try self.buildConnect(local_obs_addrs);
        defer self.allocator.free(connect);
        wire.writeLengthPrefixed(w, connect) catch return error.IoWriteFailed;
        const reply_frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(reply_frame);
        const sync = try self.onRemoteConnectReply(reply_frame);
        defer self.allocator.free(sync);
        wire.writeLengthPrefixed(w, sync) catch return error.IoWriteFailed;
        const p = self.pending_dial orelse return error.ProtocolError;
        return .{
            .addrs = try dupeAddrs(self.allocator, self.remote_addrs),
            .fire_at_ms = p.fire_at_ms,
        };
    }

    pub fn runResponderExchange(
        self: *Coordinator,
        r: *Io.Reader,
        w: *Io.Writer,
        local_obs_addrs: []const []const u8,
    ) Error!DirectDialRequest {
        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);
        const connect_reply = try self.onRemoteConnect(frame, local_obs_addrs);
        defer self.allocator.free(connect_reply);
        wire.writeLengthPrefixed(w, connect_reply) catch return error.IoWriteFailed;
        const sync_frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(sync_frame);
        var sync_msg = try wire.decodeOwned(self.allocator, sync_frame, self.cfg.limits);
        defer sync_msg.deinit(self.allocator);
        if (sync_msg.msg_type != .sync) return error.ProtocolError;
        return try self.onRemoteSync();
    }
};

test "connect reply schedules dial" {
    const a = std.testing.allocator;
    const obs_b = [_][]const u8{"/ip4/5.6.7.8/udp/4002/quic-v1"};
    var initiator = Coordinator.init(a, .{}, .initiator);
    defer initiator.deinit();
    initiator.connect_sent_ms = 0;
    const reply = try wire.encode(a, .{ .msg_type = .connect, .obs_addrs = &obs_b });
    defer a.free(reply);
    const sync = try initiator.onRemoteConnectReply(reply);
    defer a.free(sync);
    try std.testing.expect(initiator.pending_dial != null);
    try std.testing.expectEqual(@as(usize, 1), initiator.remote_addrs.len);
}
