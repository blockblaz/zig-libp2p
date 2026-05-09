//! Known-peer dial scheduling, reconnect backoff, and peer lifecycle events (#38).
//!
//! Embedders call [`ConnectionManager.tick`] with a monotonic clock and forward transport
//! callbacks into [`onConnectionEstablished`], [`onConnectionClosed`], and [`onDialFailure`].
//! Dial commands use multiaddrs with `/p2p` stripped so the transport dials by address only.
//!
//! Optional: set [`ConnectionManager.setReqResp`] so [`onConnectionClosed`] invokes
//! [`req_resp.runtime.ReqResp.onPeerDisconnected`] when the last session to a peer ends.

const std = @import("std");
const multiaddr = @import("multiaddr");
const identity = @import("identity.zig");
const peer_events = @import("peer_events.zig");
const req_resp_runtime = @import("req_resp/runtime.zig");
const swarm_mod = @import("swarm.zig");

pub const ConnectionId = u64;

/// At most this many consecutive failures (failed dials or non-local closes) before giving up.
pub const max_reconnect_failures: u8 = 5;

const backoff_ms: [max_reconnect_failures]i64 = .{
    5000, 10000, 20000, 40000, 80000,
};

pub const PeerIdContext = struct {
    pub fn hash(_: PeerIdContext, key: identity.PeerId) u64 {
        var buf: [128]u8 = undefined;
        const b = key.toBytes(&buf) catch return 0;
        return std.hash.Wyhash.hash(0, b);
    }
    pub fn eql(_: PeerIdContext, a: identity.PeerId, b: identity.PeerId) bool {
        return a.eql(&b);
    }
};

const KnownState = struct {
    dial_str: []const u8,
    next_dial_deadline_ms: i64,
    /// Counts failures since the last fully established session; capped by scheduling logic.
    failure_count: u8,
    dial_inflight: bool,
};

const ConnEntry = struct {
    peer: identity.PeerId,
    direction: peer_events.Direction,
};

pub const ConnectionManager = struct {
    allocator: std.mem.Allocator,
    swarm: *swarm_mod.Swarm,
    /// When set, [`onConnectionClosed`] calls [`req_resp.runtime.ReqResp.onPeerDisconnected`] if the
    /// peer drops to zero active connections.
    req_resp: ?*req_resp_runtime.ReqResp = null,

    known: std.HashMap(identity.PeerId, KnownState, PeerIdContext, std.hash_map.default_max_load_percentage),
    conns: std.AutoHashMap(ConnectionId, ConnEntry),
    peer_active: std.HashMap(identity.PeerId, u32, PeerIdContext, std.hash_map.default_max_load_percentage),

    pub fn init(allocator: std.mem.Allocator, s: *swarm_mod.Swarm) ConnectionManager {
        return .{
            .allocator = allocator,
            .swarm = s,
            .known = .init(allocator),
            .conns = .init(allocator),
            .peer_active = .init(allocator),
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        var it = self.known.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.value_ptr.dial_str);
        }
        self.known.deinit();
        self.conns.deinit();
        self.peer_active.deinit();
    }

    pub fn setReqResp(self: *ConnectionManager, rr: ?*req_resp_runtime.ReqResp) void {
        self.req_resp = rr;
    }

    fn peerActiveCount(self: *ConnectionManager, peer: identity.PeerId) u32 {
        return self.peer_active.get(peer) orelse 0;
    }

    pub const RegisterError = error{
        PeerIdMismatch,
        KnownPeerRequiresPeerId,
    } || multiaddr.multiaddr.Error || std.mem.Allocator.Error;

    /// Registers interest in a peer. The dial string is the multiaddr without any `/p2p` segment.
    /// Either the multiaddr must end with `/p2p/<id>` or `peer_override` must be set.
    pub fn registerKnownPeer(
        self: *ConnectionManager,
        ma: *const multiaddr.Multiaddr,
        peer_override: ?identity.PeerId,
    ) RegisterError!void {
        const from_addr = peerIdFromMultiaddr(ma);
        if (peer_override) |o| {
            if (from_addr) |f| {
                if (!o.eql(&f)) return error.PeerIdMismatch;
            }
        }
        const effective = peer_override orelse from_addr orelse return error.KnownPeerRequiresPeerId;

        const dial_str = try multiaddrDialString(self.allocator, ma);
        errdefer self.allocator.free(dial_str);

        const gop = try self.known.getOrPut(effective);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.dial_str);
        }
        gop.value_ptr.* = .{
            .dial_str = dial_str,
            .next_dial_deadline_ms = 0,
            .failure_count = 0,
            .dial_inflight = false,
        };
        if (self.peerActiveCount(effective) > 0) {
            gop.value_ptr.next_dial_deadline_ms = std.math.maxInt(i64);
        }
    }

    /// Submits [`swarm_mod.SwarmCommand.dial`] for due peers. `now_ms` must be comparable
    /// deadlines from [`onDialFailure`] / [`onConnectionClosed`].
    pub fn tick(self: *ConnectionManager, now_ms: i64) swarm_mod.SubmitError!void {
        var it = self.known.iterator();
        while (it.next()) |e| {
            const peer = e.key_ptr.*;
            const st = e.value_ptr;
            if (self.peerActiveCount(peer) > 0) continue;
            if (st.dial_inflight) continue;
            if (st.failure_count >= max_reconnect_failures) continue;
            if (st.next_dial_deadline_ms > now_ms) continue;

            try self.swarm.submit(.{ .dial = .{ .addr = st.dial_str } });
            st.dial_inflight = true;
            st.next_dial_deadline_ms = std.math.maxInt(i64);
        }
    }

    pub fn onDialFailure(
        self: *ConnectionManager,
        now_ms: i64,
        conn_id: ConnectionId,
        peer: ?identity.PeerId,
        direction: peer_events.Direction,
        result: peer_events.ConnectionFailureResult,
    ) !void {
        _ = conn_id;
        try self.swarm.queueEvent(.{ .peer_connection_failed = .{
            .peer = peer,
            .direction = direction,
            .result = result,
        } });

        if (peer) |p| {
            if (self.known.getPtr(p)) |st| {
                st.dial_inflight = false;
                st.failure_count += 1;
                if (st.failure_count < max_reconnect_failures) {
                    const idx = st.failure_count - 1;
                    st.next_dial_deadline_ms = now_ms + backoff_ms[idx];
                }
            }
        }
    }

    pub fn onConnectionEstablished(
        self: *ConnectionManager,
        conn_id: ConnectionId,
        peer: identity.PeerId,
        direction: peer_events.Direction,
    ) !void {
        if (self.known.getPtr(peer)) |st| {
            st.dial_inflight = false;
            st.failure_count = 0;
            st.next_dial_deadline_ms = std.math.maxInt(i64);
        }

        try self.conns.put(conn_id, .{ .peer = peer, .direction = direction });

        const gop = try self.peer_active.getOrPut(peer);
        const prev = if (gop.found_existing) gop.value_ptr.* else 0;
        gop.value_ptr.* = prev + 1;
        if (prev == 0) {
            try self.swarm.queueEvent(.{ .peer_connected = .{
                .peer = peer,
                .direction = direction,
            } });
        }
    }

    pub fn onConnectionClosed(
        self: *ConnectionManager,
        now_ms: i64,
        conn_id: ConnectionId,
        reason: peer_events.DisconnectReason,
    ) !void {
        const ent = self.conns.fetchRemove(conn_id) orelse return;
        const peer = ent.value.peer;
        const direction = ent.value.direction;

        const pr = self.peer_active.getPtr(peer) orelse return;
        pr.* -= 1;
        const count = pr.*;
        if (count == 0) {
            _ = self.peer_active.remove(peer);
            try self.swarm.queueEvent(.{ .peer_disconnected = .{
                .peer = peer,
                .direction = direction,
                .reason = reason,
            } });

            if (self.req_resp) |rr| {
                try rr.onPeerDisconnected(peer);
            }

            if (reason != .local_close) {
                if (self.known.getPtr(peer)) |st| {
                    st.dial_inflight = false;
                    st.failure_count += 1;
                    if (st.failure_count < max_reconnect_failures) {
                        const idx = st.failure_count - 1;
                        st.next_dial_deadline_ms = now_ms + backoff_ms[idx];
                    }
                }
            }
        }
    }
};

fn peerIdFromMultiaddr(ma: *const multiaddr.Multiaddr) ?identity.PeerId {
    var iter = ma.iterator();
    var last: ?identity.PeerId = null;
    while (iter.next() catch return null) |proto| {
        switch (proto) {
            .P2P => |id| last = id,
            else => {},
        }
    }
    return last;
}

fn multiaddrDialString(allocator: std.mem.Allocator, ma: *const multiaddr.Multiaddr) (multiaddr.multiaddr.Error || std.mem.Allocator.Error)![]u8 {
    var out = multiaddr.Multiaddr.init(allocator);
    defer out.deinit();
    var iter = ma.iterator();
    while (try iter.next()) |proto| {
        if (proto == .P2P) continue;
        try out.push(proto);
    }
    return try out.toString(allocator);
}

test "strip p2p from dial string" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    const s = try multiaddrDialString(a, &ma);
    defer a.free(s);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/udp/4001/quic-v1", s);
}

test "connection manager emits single peer_connected for two conns" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();

    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();

    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    try cm.registerKnownPeer(&ma, null);

    const peer = peerIdFromMultiaddr(&ma).?;

    try cm.onConnectionEstablished(1, peer, .outbound);
    try cm.onConnectionEstablished(2, peer, .inbound);

    var ev1 = try swarm.nextEvent(100);
    defer ev1.deinit(a);
    try std.testing.expectEqual(@as(std.meta.Tag(swarm_mod.Event), .peer_connected), std.meta.activeTag(ev1));
    try std.testing.expect(ev1.peer_connected.peer.eql(&peer));
    try std.testing.expectEqual(@as(peer_events.Direction, .outbound), ev1.peer_connected.direction);

    try std.testing.expectError(error.Timeout, swarm.nextEvent(20));

    try cm.onConnectionClosed(1000, 1, .remote_close);
    try std.testing.expectError(error.Timeout, swarm.nextEvent(20));

    try cm.onConnectionClosed(1000, 2, .remote_close);

    var ev2 = try swarm.nextEvent(100);
    defer ev2.deinit(a);
    try std.testing.expectEqual(@as(std.meta.Tag(swarm_mod.Event), .peer_disconnected), std.meta.activeTag(ev2));
    try std.testing.expect(ev2.peer_disconnected.peer.eql(&peer));
    try std.testing.expectEqual(@as(peer_events.Direction, .inbound), ev2.peer_disconnected.direction);
}

test "connection manager notifies ReqResp on last disconnect" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try swarm_mod.Swarm.init(a, swarm_mod.default_event_capacity);
    defer swarm.deinit();

    var rr = req_resp_runtime.ReqResp.init(a, &swarm, .{});
    defer rr.deinit();

    var cm = ConnectionManager.init(a, &swarm);
    defer cm.deinit();
    cm.setReqResp(&rr);

    const peer = try identity.PeerId.random();
    const stream_rid: u64 = 77;
    _ = try rr.registerInboundChannel(peer, .status, stream_rid, 0);

    try cm.onConnectionEstablished(1, peer, .outbound);
    try cm.onConnectionClosed(1000, 1, .remote_close);

    var ev1 = try swarm.nextEvent(200);
    defer ev1.deinit(a);
    try std.testing.expectEqual(.peer_disconnected, std.meta.activeTag(ev1));

    var ev2 = try swarm.nextEvent(200);
    defer ev2.deinit(a);
    try std.testing.expectEqual(.rpc_error_response, std.meta.activeTag(ev2));
    try std.testing.expectEqual(error.Disconnected, ev2.rpc_error_response.kind);
    try std.testing.expectEqual(stream_rid, ev2.rpc_error_response.request_id);
    try std.testing.expectEqual(@as(u32, 0), rr.inbound.count());
}
