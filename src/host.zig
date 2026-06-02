//! Canonical libp2p node wiring: bundles [`Swarm`], [`Gossipsub`], [`ReqResp`],
//! and [`ConnectionManager`] into one initializable object (`Host`) with a
//! consistent lifecycle and type-safe convenience helpers.
//!
//! Without `Host`, every embedder writes the same ~250 lines of plumbing to
//! init four subsystems, plumb the shared swarm reference through three of
//! them, register the optional req/resp ↔ connection-manager hook, and drain
//! shutdown events in the right order. This module is that plumbing, in one
//! place, so the next thing embedders write is *their* logic — bootnodes,
//! topic strings, RPC handlers — instead of bring-up boilerplate.
//!
//! Transport (TCP / QUIC listener + dialer + multistream-select + security
//! upgrade) is **still owned by the embedder** because it's where most
//! deployment choices live (cert pinning, ALPN selection, NAT discovery,
//! per-network listen addresses). `Host` exposes the hooks the transport
//! layer calls into — `onConnectionEstablished`, `onConnectionClosed`,
//! `onDialFailure`, `handleGossipRpc` — see `examples/host_quic_node.zig`
//! for the canonical wiring.

const std = @import("std");
const swarm_mod = @import("swarm.zig");
const gossipsub_runtime = @import("gossipsub/runtime.zig");
const req_resp_runtime = @import("req_resp/runtime.zig");
const connection_manager_mod = @import("connection_manager.zig");
const metrics_mod = @import("metrics.zig");
const identity = @import("identity.zig");
const peer_events = @import("peer_events.zig");
const protocol_mod = @import("protocol.zig");
const multiaddr_mod = @import("multiaddr");
const gs_rpc = @import("gossipsub/rpc.zig");
const gs_msg = @import("gossipsub/message.zig");
const gs_control = @import("gossipsub/control.zig");
const errors_mod = @import("errors.zig");

/// Union of every typed error the gossipsub runtime can surface, in one alias
/// so Host method signatures stay legible.
pub const GossipsubError = gs_rpc.Error || gs_msg.Error || gs_control.Error ||
    errors_mod.GossipsubError || std.mem.Allocator.Error;

pub const SwarmBootConfig = struct {
    event_capacity: usize = swarm_mod.default_event_capacity,
    command_ring_capacity: usize = 0,
    /// Optional real-transport interception hook (#TBD). See
    /// [`swarm_mod.CommandDispatchHook`].
    command_dispatch: ?swarm_mod.CommandDispatchHook = null,
};

pub const HostConfig = struct {
    allocator: std.mem.Allocator,
    /// Required: the node's libp2p PeerId. Used by gossipsub for mesh
    /// membership decisions and by swarm metrics labels.
    local_peer: identity.PeerId,
    /// Optional shared metrics registry. When set, both `Swarm` and
    /// `Gossipsub` write into it; embedders typically expose this via a
    /// `/metrics` HTTP endpoint.
    metrics: ?*metrics_mod.Metrics = null,
    /// Swarm queue sizing. Defaults match `swarm.default_event_capacity`.
    swarm: SwarmBootConfig = .{},
    /// Gossipsub knobs. `local_peer_id` is auto-populated from `local_peer`
    /// if left at the default sentinel.
    gossipsub: gossipsub_runtime.GossipsubConfig,
    /// Req/resp knobs (timeouts, idle window).
    req_resp: req_resp_runtime.ReqRespConfig = .{},
    /// Connection-manager trim policy. Defaults to "unlimited" (`null` knobs).
    connection_limits: connection_manager_mod.ConnectionLimits = .{},
};

pub const InitError = error{
    SwarmInitFailed,
    GossipsubInitFailed,
    ConnectionManagerInitFailed,
} || std.mem.Allocator.Error;

/// Canonical libp2p node bundle. Owns its component subsystems; on
/// [`destroy`] tears them down in the order required to drain pending
/// outbound RPCs and gossip queues before the swarm ring vanishes.
pub const Host = struct {
    allocator: std.mem.Allocator,
    /// Swarm command + event queue. Owned (heap).
    swarm: *swarm_mod.Swarm,
    /// Gossipsub mesh runtime. Owned (heap, via `Gossipsub.init`).
    gossipsub: *gossipsub_runtime.Gossipsub,
    /// Req/resp runtime. Owned (heap, via `ReqResp.create`).
    req_resp: *req_resp_runtime.ReqResp,
    /// Known-peer dial scheduling + trim policy. Owned (heap; `ConnectionManager`
    /// is small but we keep it on the heap so callers can hand `&host.connection_manager`
    /// to the transport layer without worrying about Host moves).
    connection_manager: *connection_manager_mod.ConnectionManager,

    pub fn create(cfg: HostConfig) InitError!*Host {
        const allocator = cfg.allocator;

        const self = try allocator.create(Host);
        errdefer allocator.destroy(self);

        const swarm = try allocator.create(swarm_mod.Swarm);
        errdefer allocator.destroy(swarm);
        swarm.* = swarm_mod.Swarm.initWithConfig(allocator, .{
            .event_capacity = cfg.swarm.event_capacity,
            .local_peer = cfg.local_peer,
            .command_ring_capacity = cfg.swarm.command_ring_capacity,
            .metrics = cfg.metrics,
            .command_dispatch = cfg.swarm.command_dispatch,
        }) catch return error.SwarmInitFailed;
        errdefer swarm.deinit();

        // Auto-bind `gossipsub.local_peer_id` if the embedder left it as the
        // sentinel `.local_peer_id = .{}` (matching identity.PeerId's zero
        // value would be ambiguous, so we always overwrite — embedders that
        // *really* want a different PeerId on gossipsub vs. swarm should
        // construct the components manually rather than via Host).
        var gs_cfg = cfg.gossipsub;
        gs_cfg.local_peer_id = cfg.local_peer;
        if (gs_cfg.metrics == null) gs_cfg.metrics = cfg.metrics;
        const gs = gossipsub_runtime.Gossipsub.init(allocator, gs_cfg) catch return error.GossipsubInitFailed;
        errdefer gs.deinit();

        const rr = try req_resp_runtime.ReqResp.create(allocator, swarm, cfg.req_resp);
        errdefer rr.destroy();

        const cm = try allocator.create(connection_manager_mod.ConnectionManager);
        errdefer allocator.destroy(cm);
        cm.* = connection_manager_mod.ConnectionManager.init(allocator, swarm);
        cm.setLimits(cfg.connection_limits);
        cm.setReqResp(rr);

        self.* = .{
            .allocator = allocator,
            .swarm = swarm,
            .gossipsub = gs,
            .req_resp = rr,
            .connection_manager = cm,
        };
        return self;
    }

    pub fn destroy(self: *Host) void {
        // Order matters: shut down command flow first so no new submits land
        // mid-deinit, then drain in dependency order (req/resp → conn_mgr →
        // gossipsub → swarm). The swarm's own deinit drains its ring.
        self.swarm.shutdown();
        self.req_resp.destroy();
        self.connection_manager.deinit();
        self.allocator.destroy(self.connection_manager);
        self.gossipsub.deinit();
        self.swarm.deinit();
        self.allocator.destroy(self.swarm);
        self.allocator.destroy(self);
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    /// Spawns the swarm background worker. Idempotent.
    pub fn startBackground(self: *Host) std.Thread.SpawnError!void {
        try self.swarm.startBackground();
    }

    /// Blocks until the worker has entered its loop (or `tick` has been called
    /// in single-threaded mode). See [`Swarm.waitUntilReady`].
    pub fn waitUntilReady(self: *Host, timeout_ms: u32) bool {
        return self.swarm.waitUntilReady(timeout_ms);
    }

    pub fn isReady(self: *Host) bool {
        return self.swarm.isReady();
    }

    /// Signals shutdown without waiting. Pair with `nextEvent` until
    /// `Event.swarm_closed` arrives, then `destroy`.
    pub fn shutdown(self: *Host) void {
        self.swarm.shutdown();
    }

    /// Single-threaded driver step: drains up to `budget` commands and runs
    /// periodic ticks (gossipsub heartbeat, req/resp timeouts, conn-mgr dial
    /// scheduling). Background-mode embedders don't call this; the worker
    /// handles command dispatch and the embedder calls
    /// [`runPeriodicTicks`] from its own clock instead.
    pub fn tick(self: *Host, command_budget: u32, now_ms: i64) (GossipsubError || req_resp_runtime.Error || std.mem.Allocator.Error || swarm_mod.SubmitError)!void {
        _ = self.swarm.tick(command_budget);
        try self.runPeriodicTicks(now_ms);
    }

    /// Runs the periodic per-subsystem ticks: gossipsub heartbeat, req/resp
    /// timeout sweep, connection-manager dial scheduling. Call once per
    /// heartbeat interval (default 700ms) from your reactor.
    pub fn runPeriodicTicks(self: *Host, now_ms: i64) (GossipsubError || req_resp_runtime.Error || std.mem.Allocator.Error || swarm_mod.SubmitError)!void {
        self.gossipsub.setClockMs(now_ms);
        try self.gossipsub.heartbeat();
        try self.req_resp.tick(now_ms);
        try self.connection_manager.tick(now_ms);
    }

    // ── Pub/sub ────────────────────────────────────────────────────────────

    pub fn subscribe(self: *Host, topic: []const u8) (GossipsubError || swarm_mod.SubmitError)!void {
        try self.swarm.submit(.{ .subscribe = .{ .topic = topic } });
        _ = try self.gossipsub.subscribe(topic);
    }

    pub fn publish(self: *Host, topic: []const u8, data: []const u8) (GossipsubError || swarm_mod.SubmitError)!void {
        try self.swarm.submit(.{ .publish = .{ .topic = topic, .payload = data } });
        try self.gossipsub.publish(topic, data);
    }

    pub fn addDirectPeer(self: *Host, peer: identity.PeerId) std.mem.Allocator.Error!void {
        try self.gossipsub.addDirectPeer(peer);
    }

    pub fn removeDirectPeer(self: *Host, peer: identity.PeerId) void {
        self.gossipsub.removeDirectPeer(peer);
    }

    /// Receive an inbound gossipsub RPC frame from the transport layer. Call
    /// from the embedder's stream-dispatch path after multistream-select
    /// negotiates `/meshsub/1.1.0` and the snappy-framed frame is reassembled.
    pub fn handleGossipRpc(self: *Host, sender: identity.PeerId, frame: []const u8) GossipsubError!void {
        try self.gossipsub.handleInboundRpc(sender, frame);
    }

    // ── Req/resp ───────────────────────────────────────────────────────────

    pub fn sendRequest(
        self: *Host,
        peer: identity.PeerId,
        proto: protocol_mod.LeanSupportedProtocol,
        payload: []const u8,
        timeout_ms: u32,
    ) (req_resp_runtime.Error || swarm_mod.SubmitError || std.mem.Allocator.Error)!u64 {
        return self.req_resp.sendRequest(peer, proto, payload, timeout_ms);
    }

    pub fn registerInboundReqRespChannel(
        self: *Host,
        peer: identity.PeerId,
        proto: protocol_mod.LeanSupportedProtocol,
        request_id: u64,
        now_ms: i64,
    ) std.mem.Allocator.Error!u64 {
        return self.req_resp.registerInboundChannel(peer, proto, request_id, now_ms);
    }

    pub fn sendResponseChunk(self: *Host, channel_id: u64, payload: []const u8, now_ms: i64) (req_resp_runtime.Error || swarm_mod.SubmitError)!void {
        return self.req_resp.sendResponseChunk(channel_id, payload, now_ms);
    }

    pub fn finishResponseStream(self: *Host, channel_id: u64) (req_resp_runtime.Error || swarm_mod.SubmitError)!void {
        return self.req_resp.finishResponseStream(channel_id);
    }

    pub fn sendErrorResponse(self: *Host, channel_id: u64, message: []const u8) (req_resp_runtime.Error || swarm_mod.SubmitError)!void {
        return self.req_resp.sendErrorResponse(channel_id, message);
    }

    // ── Known peers / dialing ─────────────────────────────────────────────

    pub fn registerKnownPeer(
        self: *Host,
        ma: *const multiaddr_mod.Multiaddr,
        peer_override: ?identity.PeerId,
    ) connection_manager_mod.ConnectionManager.RegisterError!void {
        try self.connection_manager.registerKnownPeer(ma, peer_override);
    }

    pub fn knownPeerStatus(self: *const Host, peer: identity.PeerId) ?connection_manager_mod.KnownPeerDialStatus {
        return self.connection_manager.knownPeerStatus(peer);
    }

    // ── Drain ──────────────────────────────────────────────────────────────

    pub fn nextEvent(self: *Host, timeout_ms: u32) swarm_mod.NextEventError!swarm_mod.Event {
        return self.swarm.nextEvent(timeout_ms);
    }

    // ── Transport hooks ───────────────────────────────────────────────────

    pub fn onConnectionEstablished(
        self: *Host,
        conn_id: connection_manager_mod.ConnectionId,
        peer: identity.PeerId,
        direction: peer_events.Direction,
    ) (std.mem.Allocator.Error || swarm_mod.SubmitError)!void {
        try self.connection_manager.onConnectionEstablished(conn_id, peer, direction);
        self.gossipsub.onPeerConnected(peer);
    }

    pub fn onConnectionClosed(
        self: *Host,
        now_ms: i64,
        conn_id: connection_manager_mod.ConnectionId,
        peer: identity.PeerId,
        reason: peer_events.DisconnectReason,
    ) (std.mem.Allocator.Error || swarm_mod.SubmitError)!void {
        try self.connection_manager.onConnectionClosed(now_ms, conn_id, reason);
        self.gossipsub.onPeerDisconnected(peer);
    }

    pub fn onDialFailure(
        self: *Host,
        now_ms: i64,
        conn_id: connection_manager_mod.ConnectionId,
        peer: ?identity.PeerId,
        direction: peer_events.Direction,
        result: peer_events.ConnectionFailureResult,
    ) (std.mem.Allocator.Error || swarm_mod.SubmitError)!void {
        try self.connection_manager.onDialFailure(now_ms, conn_id, peer, direction, result);
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Host.create / destroy round trip" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();

    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    try testing.expect(host.gossipsub.cfg.local_peer_id.eql(&me));
}

test "Host.startBackground + waitUntilReady chains to swarm" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    try testing.expect(!host.isReady());
    try host.startBackground();
    try testing.expect(host.waitUntilReady(5_000));
    try testing.expect(host.isReady());
}

test "Host.subscribe forwards to gossipsub" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    try host.subscribe("blocks");
    try testing.expect(host.gossipsub.subs.contains("blocks"));

    // The subscribe broadcast was also pushed into the swarm queue; drain it
    // so deinit doesn't complain about leaked OwnedCommand.
    host.swarm.tick(8);
}

test "Host req/resp wrapper methods compile + route to runtime" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    // Regression for the v0.1.0 type-annotation bug: `Host.sendResponseChunk`
    // / `finishResponseStream` / `sendErrorResponse` named `ReqResp.Error`
    // where the type actually lives at module scope as `req_resp_runtime.Error`.
    // Lazy compilation hid this in v0.1.0 because no test referenced the
    // wrappers; this test does, so the signatures stay correct going forward.
    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    // No inbound channel registered → both methods return `UnknownInboundChannel`.
    // Routing through the wrappers exercises the type annotations.
    try testing.expectError(error.UnknownInboundChannel, host.sendResponseChunk(999, "x", 0));
    try testing.expectError(error.UnknownInboundChannel, host.finishResponseStream(999));
    try testing.expectError(error.UnknownInboundChannel, host.sendErrorResponse(999, "boom"));

    // tick / runPeriodicTicks reference the same union; calling them is the
    // straightforward way to anchor the annotation against future refactors.
    try host.runPeriodicTicks(0);
    try host.tick(8, 0);
}

test "Host transport hooks update both connection_manager and gossipsub" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    const peer = try identity.PeerId.random();
    try host.onConnectionEstablished(1, peer, .outbound);
    try testing.expect(host.gossipsub.connected.contains(peer));

    // Drain the peer_connected event queued by ConnectionManager.
    try host.startBackground();
    _ = host.waitUntilReady(5_000);
    var ev = try host.nextEvent(1_000);
    defer ev.deinit(a);
    try testing.expectEqual(@as(std.meta.Tag(swarm_mod.Event), .peer_connected), std.meta.activeTag(ev));

    try host.onConnectionClosed(1_000, 1, peer, .remote_close);
    try testing.expect(!host.gossipsub.connected.contains(peer));
}
