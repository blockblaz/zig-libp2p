//! Req/resp runtime helpers: outbound `request_id` tracking, request timeouts, inbound response
//! channel idle timeouts, and [`swarm.SwarmCommand`] wiring (#40).
//!
//! Embedders must call [`ReqResp.tick`] periodically with a monotonic millisecond clock. After
//! [`ReqResp.sendRequest`], drain or handle swarm events as usual; when a matching response stream
//! ends (success or peer error), call [`ReqResp.completeOutbound`] so the pending slot is cleared.
//! When serving inbound RPC, call [`ReqResp.onInboundRpcRequest`] so idle timeouts apply, then use
//! [`sendResponseChunk`], [`finishResponseStream`], or [`sendErrorResponse`].

const std = @import("std");
const builtin = @import("builtin");

const errors = @import("../errors.zig");
const identity = @import("../identity.zig");
const protocol = @import("../protocol.zig");
const swarm_mod = @import("../swarm.zig");

pub const ReqRespConfig = struct {
    /// Milliseconds after [`sendRequest`] without [`completeOutbound`] before emitting
    /// [`swarm.Event.rpc_error_response`] with [`errors.ReqRespError.StreamTimedOut`] (#40).
    request_timeout_ms: i64 = 15_000,
    /// Milliseconds of idle time on an inbound response channel (no chunk sent) before emitting
    /// [`swarm.Event.rpc_error_response`] with [`errors.ReqRespError.StreamTimedOut`] (#40).
    response_idle_timeout_ms: i64 = 5 * 60 * 1000,
};

pub const ChannelKey = struct {
    peer: identity.PeerId,
    request_id: u64,

    pub const Context = struct {
        pub fn hash(_: Context, k: ChannelKey) u64 {
            var buf: [128]u8 = undefined;
            const b = k.peer.toBytes(&buf) catch return k.request_id;
            const h = std.hash.Wyhash.hash(0, b);
            return h ^ std.hash.Wyhash.hash(0, std.mem.asBytes(&k.request_id));
        }
        pub fn eql(_: Context, a: ChannelKey, b: ChannelKey, _: usize) bool {
            return a.request_id == b.request_id and a.peer.eql(&b.peer);
        }
    };
};

const PendingOutbound = struct {
    peer: identity.PeerId,
    deadline_ms: i64,
};

const InboundChannel = struct {
    last_activity_ms: i64,
};

pub const ReqResp = struct {
    allocator: std.mem.Allocator,
    swarm: *swarm_mod.Swarm,
    cfg: ReqRespConfig,
    next_request_id: u64 = 1,
    pending_out: std.AutoHashMap(u64, PendingOutbound),
    inbound: std.HashMap(ChannelKey, InboundChannel, ChannelKey.Context, std.hash_map.default_max_load_percentage),

    pub fn init(allocator: std.mem.Allocator, s: *swarm_mod.Swarm, cfg: ReqRespConfig) ReqResp {
        return .{
            .allocator = allocator,
            .swarm = s,
            .cfg = cfg,
            .pending_out = .init(allocator),
            .inbound = .init(allocator),
        };
    }

    pub fn deinit(self: *ReqResp) void {
        self.pending_out.deinit(self.allocator);
        self.inbound.deinit(self.allocator);
    }

    /// Allocates a monotonic `request_id`, records a deadline, and submits [`SwarmCommand.send_request`].
    pub fn sendRequest(
        self: *ReqResp,
        peer: identity.PeerId,
        proto: protocol.LeanSupportedProtocol,
        payload: []const u8,
        now_ms: i64,
    ) swarm_mod.SubmitError!u64 {
        const id = self.next_request_id;
        self.next_request_id += 1;
        const deadline_ms = now_ms + self.cfg.request_timeout_ms;
        try self.pending_out.put(id, .{ .peer = peer, .deadline_ms = deadline_ms });
        errdefer _ = self.pending_out.remove(id);
        try self.swarm.submit(.{ .send_request = .{
            .peer = peer,
            .protocol = proto,
            .request_id = id,
            .payload = payload,
        } });
        return id;
    }

    /// Drops the outbound deadline without emitting an event (does not cancel transport I/O).
    pub fn cancelRequest(self: *ReqResp, request_id: u64) void {
        _ = self.pending_out.remove(request_id);
    }

    /// Clears the outbound pending slot after a terminal response (`rpc_response_end` or
    /// `rpc_error_response`) for this `request_id`.
    pub fn completeOutbound(self: *ReqResp, request_id: u64) void {
        _ = self.pending_out.remove(request_id);
    }

    /// Register an inbound RPC so [`tick`] can enforce [`ReqRespConfig.response_idle_timeout_ms`].
    pub fn onInboundRpcRequest(self: *ReqResp, r: swarm_mod.RpcRequest, now_ms: i64) std.mem.Allocator.Error!void {
        const key = ChannelKey{ .peer = r.peer, .request_id = r.request_id };
        try self.inbound.put(key, .{ .last_activity_ms = now_ms });
    }

    pub fn sendResponseChunk(
        self: *ReqResp,
        peer: identity.PeerId,
        request_id: u64,
        payload: []const u8,
        now_ms: i64,
    ) swarm_mod.SubmitError!void {
        const key = ChannelKey{ .peer = peer, .request_id = request_id };
        if (self.inbound.getPtr(key)) |ch| {
            ch.last_activity_ms = now_ms;
        }
        try self.swarm.submit(.{ .send_response_chunk = .{
            .peer = peer,
            .request_id = request_id,
            .chunk = payload,
        } });
    }

    pub fn finishResponseStream(self: *ReqResp, peer: identity.PeerId, request_id: u64) swarm_mod.SubmitError!void {
        _ = self.inbound.remove(.{ .peer = peer, .request_id = request_id });
        try self.swarm.submit(.{ .send_end_of_stream = .{
            .peer = peer,
            .request_id = request_id,
        } });
    }

    /// UTF-8 diagnostic is stored via [`errors.setLastErrorMessage`] for this thread (`RawError` + #45).
    pub fn sendErrorResponse(
        self: *ReqResp,
        peer: identity.PeerId,
        request_id: u64,
        message: []const u8,
    ) swarm_mod.SubmitError!void {
        _ = self.inbound.remove(.{ .peer = peer, .request_id = request_id });
        errors.setLastErrorMessage(message);
        try self.swarm.submit(.{ .send_error_response = .{
            .peer = peer,
            .request_id = request_id,
            .kind = error.RawError,
        } });
    }

    /// Expire outbound requests and idle inbound channels; emits [`swarm.Event.rpc_error_response`]
    /// through [`swarm.Swarm.queueEvent`].
    pub fn tick(self: *ReqResp, now_ms: i64) std.mem.Allocator.Error!void {
        var expired_out = std.ArrayList(u64).init(self.allocator);
        defer expired_out.deinit(self.allocator);
        {
            var it = self.pending_out.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.deadline_ms <= now_ms) {
                    try expired_out.append(e.key_ptr.*);
                }
            }
        }
        for (expired_out.items) |rid| {
            const p = self.pending_out.fetchRemove(rid) orelse continue;
            try self.swarm.queueEvent(.{ .rpc_error_response = .{
                .peer = p.value.peer,
                .request_id = rid,
                .kind = error.StreamTimedOut,
            } });
        }

        var idle_in = std.ArrayList(ChannelKey).init(self.allocator);
        defer idle_in.deinit(self.allocator);
        const idle_ms = self.cfg.response_idle_timeout_ms;
        {
            var it = self.inbound.iterator();
            while (it.next()) |e| {
                const elapsed = now_ms - e.value_ptr.last_activity_ms;
                if (elapsed >= idle_ms) {
                    try idle_in.append(e.key_ptr.*);
                }
            }
        }
        for (idle_in.items) |k| {
            _ = self.inbound.remove(k);
            try self.swarm.queueEvent(.{ .rpc_error_response = .{
                .peer = k.peer,
                .request_id = k.request_id,
                .kind = error.StreamTimedOut,
            } });
        }
    }
};

test "req_resp outbound timeout emits rpc_error_response" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var rr = ReqResp.init(a, &swarm, .{ .request_timeout_ms = 50, .response_idle_timeout_ms = 10_000 });
    defer rr.deinit();

    const peer = try identity.PeerId.random();
    const rid = try rr.sendRequest(peer, .status, "ping", 1_000);

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_request, std.meta.activeTag(ev));
        try std.testing.expectEqual(rid, ev.rpc_request.request_id);
    }

    try rr.tick(1_100);

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_error_response, std.meta.activeTag(ev));
        try std.testing.expectEqual(error.StreamTimedOut, ev.rpc_error_response.kind);
        try std.testing.expect(ev.rpc_error_response.peer.eql(&peer));
        try std.testing.expectEqual(rid, ev.rpc_error_response.request_id);
    }

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
}

test "req_resp completeOutbound suppresses timeout" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var rr = ReqResp.init(a, &swarm, .{ .request_timeout_ms = 50, .response_idle_timeout_ms = 10_000 });
    defer rr.deinit();

    const peer = try identity.PeerId.random();
    const rid = try rr.sendRequest(peer, .status, "x", 0);

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_request, std.meta.activeTag(ev));
    }

    rr.completeOutbound(rid);
    try rr.tick(10_000);
    try std.testing.expectError(error.Timeout, swarm.nextEvent(0));

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
}

test "req_resp inbound idle timeout" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var rr = ReqResp.init(a, &swarm, .{ .request_timeout_ms = 10_000, .response_idle_timeout_ms = 40 });
    defer rr.deinit();

    const peer = try identity.PeerId.random();
    try rr.onInboundRpcRequest(.{
        .peer = peer,
        .protocol = .status,
        .request_id = 99,
        .payload = "",
    }, 500);

    try rr.tick(530);

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_error_response, std.meta.activeTag(ev));
        try std.testing.expectEqual(@as(u64, 99), ev.rpc_error_response.request_id);
        try std.testing.expectEqual(error.StreamTimedOut, ev.rpc_error_response.kind);
    }

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
}

test "req_resp sendResponseChunk extends inbound idle window" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var rr = ReqResp.init(a, &swarm, .{ .request_timeout_ms = 10_000, .response_idle_timeout_ms = 50 });
    defer rr.deinit();

    const peer = try identity.PeerId.random();
    try rr.onInboundRpcRequest(.{
        .peer = peer,
        .protocol = .status,
        .request_id = 7,
        .payload = "",
    }, 0);

    try rr.tick(45);
    try std.testing.expectError(error.Timeout, swarm.nextEvent(0));

    try rr.sendResponseChunk(peer, 7, "a", 50);
    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_response_chunk, std.meta.activeTag(ev));
    }

    try rr.tick(80);
    try std.testing.expectError(error.Timeout, swarm.nextEvent(0));

    try rr.tick(95);
    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_error_response, std.meta.activeTag(ev));
    }

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
}
