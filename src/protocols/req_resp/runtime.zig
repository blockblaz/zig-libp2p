//! Req/resp runtime helpers (#40): outbound `request_id` tracking, per-inbound `channel_id`,
//! request/idle timeouts, and [`swarm.SwarmCommand`] wiring.
//!
//! Call [`ReqResp.tick`] with a monotonic millisecond clock. After [`sendRequest`], call
//! [`completeOutbound`] when the response stream ends. For inbound RPC, call
//! [`registerInboundChannel`] before queuing [`swarm.Event.rpc_request`] with the returned
//! `channel_id`, then respond with [`sendResponseChunk`], [`finishResponseStream`], or
//! [`sendErrorResponse`] using that `channel_id`.
//!
//! When the transport drops the last session to a peer, call [`onPeerDisconnected`] so pending
//! outbound work and open inbound response channels emit [`errors.ReqRespError.Disconnected`] (#40).

const std = @import("std");
const builtin = @import("builtin");

const errors = @import("../../primitives/errors.zig");
const identity = @import("../../primitives/identity.zig");
const protocol = @import("../../primitives/protocol.zig");
const swarm_mod = @import("../../core/swarm.zig");

pub const ReqRespConfig = struct {
    /// Milliseconds after [`sendRequest`] without [`completeOutbound`] before emitting
    /// [`swarm.Event.rpc_error_response`] with [`errors.ReqRespError.StreamTimedOut`] (#40).
    request_timeout_ms: i64 = 15_000,
    /// Milliseconds of idle time on an inbound response channel (no chunk sent) before emitting
    /// [`swarm.Event.rpc_error_response`] with [`errors.ReqRespError.StreamTimedOut`] (#40).
    response_idle_timeout_ms: i64 = 5 * 60 * 1000,
};

const PendingOutbound = struct {
    peer: identity.PeerId,
    deadline_ms: i64,
};

const InboundChannel = struct {
    peer: identity.PeerId,
    protocol: protocol.LeanSupportedProtocol,
    stream_request_id: u64,
    last_activity_ms: i64,
};

pub const Error = error{
    UnknownInboundChannel,
};

/// Minimal atomic spin lock (Zig 0.16 std has no Thread.Mutex). Mirrors
/// `transport/quic/conn_table.SpinLock`; defined locally to avoid a
/// protocols→transport layering dependency.
const SpinLock = struct {
    locked: std.atomic.Value(bool) = .init(false),
    fn lock(self: *SpinLock) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }
    fn unlock(self: *SpinLock) void {
        self.locked.store(false, .release);
    }
};

pub const ReqResp = struct {
    allocator: std.mem.Allocator,
    swarm: *swarm_mod.Swarm,
    cfg: ReqRespConfig,
    next_request_id: u64 = 1,
    next_channel_id: u64 = 1,
    pending_out: std.AutoHashMap(u64, PendingOutbound),
    inbound: std.AutoHashMap(u64, InboundChannel),
    /// Guards `next_request_id`, `next_channel_id`, `pending_out`, and `inbound`.
    /// With QUIC connection sharding (`drive_shards > 1`) `registerInboundChannel`
    /// is called concurrently from N drive threads (each shard's
    /// `advanceInboundStreams`), `tick` runs on the shard-0 drive thread, and the
    /// response side (`sendRequest`/`sendResponseChunk`/`finishResponseStream`/
    /// `sendErrorResponse`/`completeOutbound`) runs on the embedder/swarm thread —
    /// so the two HashMaps and the monotonic counters are touched by multiple
    /// threads and must be serialized. At `drive_shards == 1` there is a single
    /// drive thread, so contention is only ever between it and the embedder thread
    /// (uncontended fast path).
    state_lock: SpinLock = .{},

    pub fn init(allocator: std.mem.Allocator, s: *swarm_mod.Swarm, cfg: ReqRespConfig) ReqResp {
        return .{
            .allocator = allocator,
            .swarm = s,
            .cfg = cfg,
            .pending_out = .init(allocator),
            .inbound = .init(allocator),
        };
    }

    pub fn create(allocator: std.mem.Allocator, s: *swarm_mod.Swarm, cfg: ReqRespConfig) std.mem.Allocator.Error!*ReqResp {
        const p = try allocator.create(ReqResp);
        errdefer allocator.destroy(p);
        p.* = ReqResp.init(allocator, s, cfg);
        return p;
    }

    pub fn destroy(self: *ReqResp) void {
        const a = self.allocator;
        self.deinit();
        a.destroy(self);
    }

    pub fn deinit(self: *ReqResp) void {
        self.pending_out.deinit();
        self.inbound.deinit();
    }

    /// Clears outbound and inbound state without emitting events (does not stop the swarm).
    pub fn shutdown(self: *ReqResp) void {
        self.pending_out.clearRetainingCapacity();
        self.inbound.clearRetainingCapacity();
    }

    /// Allocates a monotonic `request_id`, records a deadline, and submits [`SwarmCommand.send_request`].
    pub fn sendRequest(
        self: *ReqResp,
        peer: identity.PeerId,
        proto: protocol.LeanSupportedProtocol,
        payload: []const u8,
        now_ms: i64,
    ) swarm_mod.SubmitError!u64 {
        const deadline_ms = now_ms + self.cfg.request_timeout_ms;
        const id = blk: {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            const new_id = self.next_request_id;
            self.next_request_id += 1;
            try self.pending_out.put(new_id, .{ .peer = peer, .deadline_ms = deadline_ms });
            break :blk new_id;
        };
        errdefer {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            _ = self.pending_out.remove(id);
        }
        try self.swarm.submit(.{ .send_request = .{
            .peer = peer,
            .protocol = proto,
            .request_id = id,
            .channel_id = 0,
            .payload = payload,
        } });
        return id;
    }

    pub fn cancelRequest(self: *ReqResp, request_id: u64) void {
        self.state_lock.lock();
        defer self.state_lock.unlock();
        _ = self.pending_out.remove(request_id);
    }

    /// Clears the outbound pending slot after a terminal response (`rpc_response_end` or
    /// `rpc_error_response`) for this `request_id`.
    pub fn completeOutbound(self: *ReqResp, request_id: u64) void {
        self.state_lock.lock();
        defer self.state_lock.unlock();
        _ = self.pending_out.remove(request_id);
    }

    /// Returns `channel_id` for [`swarm.RpcRequest.channel_id`]. `request_id` is the stream
    /// correlation for response commands (`send_response_chunk`, `rpc_response_chunk`, …).
    pub fn registerInboundChannel(
        self: *ReqResp,
        peer: identity.PeerId,
        proto: protocol.LeanSupportedProtocol,
        request_id: u64,
        now_ms: i64,
    ) std.mem.Allocator.Error!u64 {
        self.state_lock.lock();
        defer self.state_lock.unlock();
        const ch = self.next_channel_id;
        self.next_channel_id += 1;
        try self.inbound.put(ch, .{
            .peer = peer,
            .protocol = proto,
            .stream_request_id = request_id,
            .last_activity_ms = now_ms,
        });
        return ch;
    }

    pub fn sendResponseChunk(
        self: *ReqResp,
        channel_id: u64,
        payload: []const u8,
        now_ms: i64,
    ) (Error || swarm_mod.SubmitError)!void {
        const snap = blk: {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            const ent = self.inbound.getPtr(channel_id) orelse return error.UnknownInboundChannel;
            ent.last_activity_ms = now_ms;
            break :blk .{ .peer = ent.peer, .request_id = ent.stream_request_id };
        };
        try self.swarm.submit(.{ .send_response_chunk = .{
            .peer = snap.peer,
            .request_id = snap.request_id,
            .chunk = payload,
        } });
    }

    pub fn finishResponseStream(self: *ReqResp, channel_id: u64) (Error || swarm_mod.SubmitError)!void {
        const ent = blk: {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            break :blk self.inbound.fetchRemove(channel_id) orelse return error.UnknownInboundChannel;
        };
        try self.swarm.submit(.{ .send_end_of_stream = .{
            .peer = ent.value.peer,
            .request_id = ent.value.stream_request_id,
        } });
    }

    /// UTF-8 diagnostic is stored via [`errors.setLastErrorMessage`] for this thread (`RawError` + #45).
    pub fn sendErrorResponse(self: *ReqResp, channel_id: u64, message: []const u8) (Error || swarm_mod.SubmitError)!void {
        const ent = blk: {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            break :blk self.inbound.fetchRemove(channel_id) orelse return error.UnknownInboundChannel;
        };
        errors.setLastErrorMessage(message);
        try self.swarm.submit(.{ .send_error_response = .{
            .peer = ent.value.peer,
            .request_id = ent.value.stream_request_id,
            .kind = error.RawError,
        } });
    }

    /// Expire outbound requests and idle inbound channels; emits [`swarm.Event.rpc_error_response`]
    /// through [`swarm.Swarm.queueEvent`].
    pub fn tick(self: *ReqResp, now_ms: i64) std.mem.Allocator.Error!void {
        var expired_out: std.ArrayList(u64) = .empty;
        defer expired_out.deinit(self.allocator);
        {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            var it = self.pending_out.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.deadline_ms <= now_ms) {
                    try expired_out.append(self.allocator, e.key_ptr.*);
                }
            }
        }
        for (expired_out.items) |rid| {
            const p = blk: {
                self.state_lock.lock();
                defer self.state_lock.unlock();
                break :blk self.pending_out.fetchRemove(rid) orelse continue;
            };
            try self.swarm.queueEvent(.{ .rpc_error_response = .{
                .peer = p.value.peer,
                .request_id = rid,
                .kind = error.StreamTimedOut,
            } });
        }

        var idle_ch: std.ArrayList(u64) = .empty;
        defer idle_ch.deinit(self.allocator);
        const idle_ms = self.cfg.response_idle_timeout_ms;
        {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            var it = self.inbound.iterator();
            while (it.next()) |e| {
                const elapsed = now_ms - e.value_ptr.last_activity_ms;
                if (elapsed >= idle_ms) {
                    try idle_ch.append(self.allocator, e.key_ptr.*);
                }
            }
        }
        for (idle_ch.items) |cid| {
            const ent = blk: {
                self.state_lock.lock();
                defer self.state_lock.unlock();
                break :blk self.inbound.fetchRemove(cid) orelse continue;
            };
            try self.swarm.queueEvent(.{ .rpc_error_response = .{
                .peer = ent.value.peer,
                .request_id = ent.value.stream_request_id,
                .kind = error.StreamTimedOut,
            } });
        }
    }

    /// Call when the peer has no remaining connection (transport callback). Cancels pending outbound
    /// requests and open inbound response channels, emitting [`errors.ReqRespError.Disconnected`].
    pub fn onPeerDisconnected(self: *ReqResp, peer: identity.PeerId) std.mem.Allocator.Error!void {
        var drop_out: std.ArrayList(u64) = .empty;
        defer drop_out.deinit(self.allocator);
        {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            var it = self.pending_out.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.peer.eql(&peer)) {
                    try drop_out.append(self.allocator, e.key_ptr.*);
                }
            }
        }
        for (drop_out.items) |rid| {
            {
                self.state_lock.lock();
                defer self.state_lock.unlock();
                _ = self.pending_out.remove(rid);
            }
            try self.swarm.queueEvent(.{ .rpc_error_response = .{
                .peer = peer,
                .request_id = rid,
                .kind = error.Disconnected,
            } });
        }

        const InboundDrop = struct {
            channel_id: u64,
            stream_request_id: u64,
        };
        var drop_in: std.ArrayList(InboundDrop) = .empty;
        defer drop_in.deinit(self.allocator);
        {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            var it = self.inbound.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.peer.eql(&peer)) {
                    try drop_in.append(self.allocator, .{
                        .channel_id = e.key_ptr.*,
                        .stream_request_id = e.value_ptr.stream_request_id,
                    });
                }
            }
        }
        for (drop_in.items) |d| {
            {
                self.state_lock.lock();
                defer self.state_lock.unlock();
                _ = self.inbound.remove(d.channel_id);
            }
            try self.swarm.queueEvent(.{ .rpc_error_response = .{
                .peer = peer,
                .request_id = d.stream_request_id,
                .kind = error.Disconnected,
            } });
        }
    }
};

fn queueInboundRpcRequest(
    a: std.mem.Allocator,
    swarm_ptr: *swarm_mod.Swarm,
    peer: identity.PeerId,
    proto: protocol.LeanSupportedProtocol,
    request_id: u64,
    channel_id: u64,
    payload: []const u8,
) std.mem.Allocator.Error!void {
    const owned = try a.dupe(u8, payload);
    errdefer a.free(owned);
    try swarm_ptr.queueEvent(.{ .rpc_request = .{
        .peer = peer,
        .protocol = proto,
        .request_id = request_id,
        .channel_id = channel_id,
        .payload = owned,
    } });
}

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
        try std.testing.expectEqual(@as(u64, 0), ev.rpc_request.channel_id);
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
    const cid = try rr.registerInboundChannel(peer, .status, 99, 500);
    try queueInboundRpcRequest(a, &swarm, peer, .status, 99, cid, "");

    // last_activity = 500, idle_timeout = 40 → elapsed must be ≥ 40, i.e. now_ms ≥ 540.
    try rr.tick(541);

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_request, std.meta.activeTag(ev));
    }
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
    const cid = try rr.registerInboundChannel(peer, .status, 7, 0);
    try queueInboundRpcRequest(a, &swarm, peer, .status, 7, cid, "");

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_request, std.meta.activeTag(ev));
    }

    try rr.tick(45);
    try std.testing.expectError(error.Timeout, swarm.nextEvent(0));

    try rr.sendResponseChunk(cid, "a", 50);
    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_response_chunk, std.meta.activeTag(ev));
    }

    try rr.tick(80);
    try std.testing.expectError(error.Timeout, swarm.nextEvent(0));

    // After sendResponseChunk(.., 50) last_activity = 50; idle_timeout = 50.
    // Need now_ms - 50 ≥ 50, i.e. now_ms ≥ 100.
    try rr.tick(101);
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

test "req_resp unknown inbound channel returns error" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var rr = ReqResp.init(a, &swarm, .{});
    defer rr.deinit();

    try std.testing.expectError(error.UnknownInboundChannel, rr.sendResponseChunk(999, "x", 0));

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
}

test "req_resp create destroy and shutdown clears maps" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    const rr = try ReqResp.create(a, &swarm, .{ .request_timeout_ms = 60_000, .response_idle_timeout_ms = 60_000 });
    defer rr.destroy();

    const peer = try identity.PeerId.random();
    _ = try rr.sendRequest(peer, .status, "q", 0);
    _ = try rr.registerInboundChannel(peer, .status, 1, 0);

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_request, std.meta.activeTag(ev));
    }

    rr.shutdown();
    try std.testing.expectEqual(@as(u32, 0), rr.pending_out.count());
    try std.testing.expectEqual(@as(u32, 0), rr.inbound.count());

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
}

test "req_resp onPeerDisconnected emits Disconnected for pending outbound" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var rr = ReqResp.init(a, &swarm, .{ .request_timeout_ms = 60_000, .response_idle_timeout_ms = 60_000 });
    defer rr.deinit();

    const peer = try identity.PeerId.random();
    const rid = try rr.sendRequest(peer, .status, "x", 0);

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_request, std.meta.activeTag(ev));
    }

    try rr.onPeerDisconnected(peer);

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_error_response, std.meta.activeTag(ev));
        try std.testing.expectEqual(error.Disconnected, ev.rpc_error_response.kind);
        try std.testing.expectEqual(rid, ev.rpc_error_response.request_id);
        try std.testing.expect(ev.rpc_error_response.peer.eql(&peer));
    }

    try std.testing.expectEqual(@as(u32, 0), rr.pending_out.count());

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
}

test "req_resp onPeerDisconnected clears inbound channels" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var rr = ReqResp.init(a, &swarm, .{});
    defer rr.deinit();

    const peer = try identity.PeerId.random();
    const stream_rid: u64 = 404;
    const cid = try rr.registerInboundChannel(peer, .blocks_by_range, stream_rid, 0);
    try queueInboundRpcRequest(a, &swarm, peer, .blocks_by_range, stream_rid, cid, "");

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_request, std.meta.activeTag(ev));
    }

    try rr.onPeerDisconnected(peer);

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_error_response, std.meta.activeTag(ev));
        try std.testing.expectEqual(error.Disconnected, ev.rpc_error_response.kind);
        try std.testing.expectEqual(stream_rid, ev.rpc_error_response.request_id);
    }

    try std.testing.expectEqual(@as(u32, 0), rr.inbound.count());
    try std.testing.expectError(error.UnknownInboundChannel, rr.sendResponseChunk(cid, "nope", 0));

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
}

test "req_resp single response chunk then end of stream" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var rr = ReqResp.init(a, &swarm, .{});
    defer rr.deinit();

    const peer = try identity.PeerId.random();
    const stream_rid: u64 = 1;
    const cid = try rr.registerInboundChannel(peer, .status, stream_rid, 0);
    try queueInboundRpcRequest(a, &swarm, peer, .status, stream_rid, cid, "req");

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_request, std.meta.activeTag(ev));
    }

    try rr.sendResponseChunk(cid, "status-bytes", 0);
    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_response_chunk, std.meta.activeTag(ev));
        try std.testing.expectEqualStrings("status-bytes", ev.rpc_response_chunk.chunk);
    }

    try rr.finishResponseStream(cid);
    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_response_end, std.meta.activeTag(ev));
        try std.testing.expect(ev.rpc_response_end.peer.eql(&peer));
        try std.testing.expectEqual(stream_rid, ev.rpc_response_end.request_id);
    }

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
}

test "req_resp multiple response chunks then end of stream" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    var rr = ReqResp.init(a, &swarm, .{});
    defer rr.deinit();

    const peer = try identity.PeerId.random();
    const stream_rid: u64 = 2;
    const cid = try rr.registerInboundChannel(peer, .blocks_by_range, stream_rid, 0);
    try queueInboundRpcRequest(a, &swarm, peer, .blocks_by_range, stream_rid, cid, "range-req");

    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_request, std.meta.activeTag(ev));
    }

    for ([_][]const u8{ "blk_a", "blk_b", "blk_c" }) |part| {
        try rr.sendResponseChunk(cid, part, 0);
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_response_chunk, std.meta.activeTag(ev));
        try std.testing.expectEqualStrings(part, ev.rpc_response_chunk.chunk);
    }

    try rr.finishResponseStream(cid);
    {
        var ev = try swarm.nextEvent(5000);
        defer ev.deinit(a);
        try std.testing.expectEqual(.rpc_response_end, std.meta.activeTag(ev));
        try std.testing.expectEqual(stream_rid, ev.rpc_response_end.request_id);
    }

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
}
