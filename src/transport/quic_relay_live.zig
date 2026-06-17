//! Live Circuit Relay v2 integration for [`quic_runtime`](quic_runtime.zig) (#91).

const std = @import("std");
const Io = std.Io;
const log = std.log.scoped(.quic_relay);

const identity = @import("../identity.zig");
const relay = @import("../relay/root.zig");
const circuit_transport = @import("circuit_transport.zig");
const quic_raw_stream_io = @import("quic_raw_stream_io.zig");
const stream_multistream = @import("stream_multistream.zig");
const multistream_neg = @import("multistream_negotiate.zig");
const wall_time = @import("../wall_time.zig");

const zquic = @import("zquic");
const ZIo = zquic.transport.io;

pub const Error = relay.server.Error || relay.client.Error || circuit_transport.Error || stream_multistream.StreamHandshakeError || multistream_neg.NegotiateError || std.mem.Allocator.Error;

pub const Config = struct {
    /// When true, accept inbound hop/stop streams and bridge relayed connections.
    enable_server: bool = true,
    /// When true, track local reservations for circuit dialing.
    enable_client: bool = true,
    /// Advertised relay listen addrs (without `/p2p`). Built from bound port when empty.
    relay_addrs: []const []const u8 = &.{},

    /// Pre-encoded libp2p PublicKey protobuf of this relay's host key.
    /// Forwarded to `relay.server.Server.Config.public_key_pb`; see there.
    public_key_pb: ?[]const u8 = null,
    sign_fn: ?relay.server.SignFn = null,
    sign_ctx: ?*anyopaque = null,

    /// Per-source-IP / token-bucket rate limit on RESERVE.
    /// Forwarded to `relay.server.Server.Config.reserve_accept_fn`.
    reserve_accept_fn: ?relay.server.ReserveAcceptFn = null,
    reserve_accept_ctx: ?*anyopaque = null,
};

/// One leg of a relay bridge (inbound server stream or outbound client stream).
pub const StreamLeg = union(enum) {
    inbound: quic_raw_stream_io.RawAppBidiServer,
    outbound: quic_raw_stream_io.RawAppBidiClient,

    fn reader(self: *StreamLeg) Io.Reader {
        return switch (self.*) {
            .inbound => |*s| s.reader(),
            .outbound => |*c| c.reader(),
        };
    }

    fn writer(self: *StreamLeg) Io.Writer {
        return switch (self.*) {
            .inbound => |*s| s.writer(),
            .outbound => |*c| c.writer(),
        };
    }
};

pub const Bridge = struct {
    hop: StreamLeg,
    stop: StreamLeg,
    buf: [8192]u8 = undefined,
    done: bool = false,

    /// Reservation byte budget for this bridge (`null` = unbounded). The
    /// relay tears the bridge down once `bytes_used >= limit_data_bytes` so a
    /// reserved-but-unbounded peer can't burn through the relay forever.
    limit_data_bytes: ?u64 = null,
    /// Wall-clock unix-second deadline (`null` = unbounded). Once reached,
    /// the bridge is torn down regardless of whether bytes are flowing.
    limit_expire_unix: ?u64 = null,
    bytes_used: u64 = 0,
};

/// Outbound stop stream open for a pending hop CONNECT.
const StopOpen = struct {
    target: identity.PeerId,
    initiator_wire: []u8,
    limit: ?relay.wire.LimitView,
    hop: StreamLeg,
    hop_peer: identity.PeerId,
    raw: quic_raw_stream_io.RawAppBidiClient,
    handshake_sent: bool = false,
    handshake_done: bool = false,
    connect_sent: bool = false,
    connect_ok: bool = false,
    failed: bool = false,
    bridge: ?*Bridge = null,
};

/// Virtual outbound connection over a relayed hop stream (initiator / circuit dialer).
pub const RelayVirtualConn = struct {
    target: identity.PeerId,
    relay: identity.PeerId,
    stream_id: u64,
    raw: quic_raw_stream_io.RawAppBidiClient,
    conn_id: u64,
    notified: bool = false,
};

/// Pending circuit multiaddr dial (dial relay, then HOP CONNECT).
pub const CircuitDial = struct {
    plan: circuit_transport.CircuitDialPlan,
    expected_target: identity.PeerId,
    phase: enum {
        dial_relay,
        hop_handshake,
        hop_connect,
        done,
        failed,
    } = .dial_relay,
    relay_outbound: ?*anyopaque = null,
    hop_raw: ?quic_raw_stream_io.RawAppBidiClient = null,
    hop_handshake_sent: bool = false,
    hop_handshake_done: bool = false,
};

pub const RuntimeHooks = struct {
    ctx: ?*anyopaque = null,
    /// Dial a plain (non-circuit) multiaddr; returns false on failure.
    dial_plain: *const fn (ctx: ?*anyopaque, addr: []const u8, expected: ?identity.PeerId) bool,
    /// Outbound QUIC client for `peer`, if connected.
    outbound_client: *const fn (ctx: ?*anyopaque, peer: identity.PeerId) ?*ZIo.Client,
    /// Allocate next local bidi stream id on outbound conn to `peer`.
    next_bidi_stream: *const fn (ctx: ?*anyopaque, peer: identity.PeerId) ?u64,
    /// Notify host that a relayed connection to `target` is up.
    on_relayed_connected: *const fn (ctx: ?*anyopaque, target: identity.PeerId, conn_id: u64) void,
    /// Notify host of dial failure for circuit target.
    on_relayed_dial_failed: *const fn (ctx: ?*anyopaque, target: ?identity.PeerId) void,
    /// Next connection id allocator.
    next_conn_id: *const fn (ctx: ?*anyopaque) u64,
    /// Reservation acquired / refreshed / lost (#204).
    on_relay_reservation: ?*const fn (
        ctx: ?*anyopaque,
        relay: identity.PeerId,
        kind: ReservationEventKind,
        expire_unix: ?u64,
    ) void = null,
};

pub const ReservationEventKind = enum {
    acquired,
    refreshed,
    lost,
};

pub const LiveRelay = struct {
    allocator: std.mem.Allocator,
    local_peer: identity.PeerId,
    cfg: Config,
    hooks: RuntimeHooks,
    server: relay.server.Server,
    client: relay.client.Client,
    relay_addrs_owned: [][]u8 = &[_][]u8{},
    bridges: std.ArrayList(*Bridge) = .empty,
    stop_opens: std.ArrayList(*StopOpen) = .empty,
    circuit_dials: std.ArrayList(*CircuitDial) = .empty,
    relay_virtual: std.AutoHashMap(identity.PeerId, *RelayVirtualConn),
    /// Unix seconds; skip refresh attempts until this time after a failure (#204).
    reserve_refresh_backoff_until: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        local_peer: identity.PeerId,
        cfg: Config,
        hooks: RuntimeHooks,
    ) LiveRelay {
        var relay_addrs = cfg.relay_addrs;
        var addrs_owned: [][]u8 = &[_][]u8{};
        if (relay_addrs.len == 0) {
            addrs_owned = &[_][]u8{};
            relay_addrs = addrs_owned;
        }
        return .{
            .allocator = allocator,
            .local_peer = local_peer,
            .cfg = cfg,
            .hooks = hooks,
            .server = relay.server.Server.init(allocator, .{
                .relay_addrs = relay_addrs,
                .public_key_pb = cfg.public_key_pb,
                .sign_fn = cfg.sign_fn,
                .sign_ctx = cfg.sign_ctx,
                .reserve_accept_fn = cfg.reserve_accept_fn,
                .reserve_accept_ctx = cfg.reserve_accept_ctx,
            }, local_peer),
            .client = relay.client.Client.init(allocator, .{}),
            .relay_addrs_owned = addrs_owned,
            .relay_virtual = std.AutoHashMap(identity.PeerId, *RelayVirtualConn).init(allocator),
        };
    }

    pub fn setRelayAddrs(self: *LiveRelay, addrs: []const []const u8) Error!void {
        for (self.relay_addrs_owned) |a| self.allocator.free(a);
        if (self.relay_addrs_owned.len > 0) self.allocator.free(self.relay_addrs_owned);
        var list = std.ArrayList([]u8).empty;
        errdefer {
            for (list.items) |a| self.allocator.free(a);
            list.deinit(self.allocator);
        }
        for (addrs) |a| try list.append(self.allocator, try self.allocator.dupe(u8, a));
        self.relay_addrs_owned = try list.toOwnedSlice(self.allocator);
        self.server.cfg.relay_addrs = self.relay_addrs_owned;
    }

    pub fn deinit(self: *LiveRelay) void {
        for (self.bridges.items) |b| {
            self.allocator.destroy(b);
        }
        self.bridges.deinit(self.allocator);
        for (self.stop_opens.items) |so| {
            self.allocator.free(so.initiator_wire);
            self.allocator.destroy(so);
        }
        self.stop_opens.deinit(self.allocator);
        for (self.circuit_dials.items) |cd| {
            cd.plan.deinit(self.allocator);
            self.allocator.destroy(cd);
        }
        self.circuit_dials.deinit(self.allocator);
        var vit = self.relay_virtual.valueIterator();
        while (vit.next()) |v| {
            self.allocator.destroy(v.*);
        }
        self.relay_virtual.deinit();
        for (self.relay_addrs_owned) |a| self.allocator.free(a);
        if (self.relay_addrs_owned.len > 0) self.allocator.free(self.relay_addrs_owned);
        self.server.deinit();
        self.client.deinit();
    }

    /// Circuit reservation addrs for Identify / peer records.
    pub fn extraListenAddrs(self: *const LiveRelay) []const []const u8 {
        if (self.client.reservation) |*r| return r.addrs;
        return &.{};
    }

    pub fn isCircuitDialAddr(addr: []const u8) bool {
        return std.mem.indexOf(u8, addr, "/p2p-circuit") != null;
    }

    pub fn enqueueCircuitDial(self: *LiveRelay, circuit_addr: []const u8, expected: ?identity.PeerId) Error!void {
        var plan = try circuit_transport.planCircuitDial(self.allocator, circuit_addr);
        errdefer plan.deinit(self.allocator);
        const target = expected orelse plan.target_id;
        const cd = try self.allocator.create(CircuitDial);
        cd.* = .{
            .plan = plan,
            .expected_target = target,
        };
        try self.circuit_dials.append(self.allocator, cd);
    }

    /// Process one length-prefixed hop frame on an inbound hop stream.
    pub fn handleHopFrame(
        self: *LiveRelay,
        hop: StreamLeg,
        hop_peer: identity.PeerId,
        frame: []const u8,
        is_relayed: bool,
    ) Error![]const u8 {
        var msg = try relay.wire.decodeHopOwned(self.allocator, frame, .standard);
        defer msg.deinit(self.allocator);

        switch (msg.msg_type) {
            .connect => {
                try self.beginHopConnect(hop, hop_peer, frame, is_relayed);
                return &.{};
            },
            else => {
                var in_r = Io.Reader.fixed(frame);
                var out_buf: [4096]u8 = undefined;
                var w = Io.Writer.fixed(&out_buf);
                try self.server.handleHopStream(&in_r, &w, hop_peer, is_relayed);
                return out_buf[0..w.end];
            },
        }
    }

    fn beginHopConnect(
        self: *LiveRelay,
        hop: StreamLeg,
        hop_peer: identity.PeerId,
        frame: []const u8,
        is_relayed: bool,
    ) Error!void {
        if (is_relayed and self.server.cfg.reject_relayed_hop) return error.PermissionDenied;

        var msg = try relay.wire.decodeHopOwned(self.allocator, frame, .standard);
        defer msg.deinit(self.allocator);
        if (msg.msg_type != .connect) return error.UnexpectedMessage;

        const target_wire = msg.peer.?.id orelse return error.UnexpectedMessage;
        const target = try self.server.peerIdFromWire(target_wire);
        if (self.server.store.findReservation(target) == null) {
            var w_buf: [512]u8 = undefined;
            var w = Io.Writer.fixed(&w_buf);
            try self.server.writeHopStatus(&w, .no_reservation, null, null);
            return;
        }
        self.server.store.beginBridge() catch {
            var w_buf: [512]u8 = undefined;
            var w = Io.Writer.fixed(&w_buf);
            try self.server.writeHopStatus(&w, .resource_limit_exceeded, null, null);
            return;
        };

        const initiator_wire = try self.server.peerIdToWire(hop_peer);
        const lim_view: ?relay.wire.LimitView = if (msg.limit) |l| .{
            .duration_sec = l.duration_sec,
            .data_bytes = l.data_bytes,
        } else null;

        const client = self.hooks.outbound_client(self.hooks.ctx, target) orelse {
            self.server.store.endBridge();
            return error.ConnectionFailed;
        };
        const sid = self.hooks.next_bidi_stream(self.hooks.ctx, target) orelse {
            self.server.store.endBridge();
            return error.ConnectionFailed;
        };

        const so = try self.allocator.create(StopOpen);
        so.* = .{
            .target = target,
            .initiator_wire = initiator_wire,
            .limit = lim_view,
            .hop = hop,
            .hop_peer = hop_peer,
            .raw = .{ .client = client, .stream_id = sid },
        };
        try self.stop_opens.append(self.allocator, so);
    }

    /// Process inbound stop CONNECT frame; writes STATUS and leaves stream for bridging.
    pub fn handleStopFrame(
        self: *LiveRelay,
        stop: StreamLeg,
        local_peer: identity.PeerId,
        frame: []const u8,
    ) Error!void {
        var r = Io.Reader.fixed(frame);
        var out_buf: [4096]u8 = undefined;
        var w = Io.Writer.fixed(&out_buf);
        try self.server.handleStopStream(&r, &w, local_peer);
        if (w.end > 0) {
            var resp_r = Io.Reader.fixed(out_buf[0..w.end]);
            const resp_frame = try relay.wire.readLengthPrefixedAlloc(&resp_r, self.allocator, relay.wire.Limits.standard.max_frame_bytes);
            defer self.allocator.free(resp_frame);
            var resp = try relay.wire.decodeStopOwned(self.allocator, resp_frame, .standard);
            defer resp.deinit(self.allocator);
            if (resp.msg_type == .status and resp.status == .ok) {
                _ = stop;
            }
        }
    }

    pub fn advance(self: *LiveRelay) void {
        self.advanceStopOpens();
        self.advanceBridges();
        self.advanceCircuitDials();
        self.advanceReservationRefresh();
    }

    fn advanceReservationRefresh(self: *LiveRelay) void {
        if (!self.cfg.enable_client) return;
        const now: u64 = @intCast(wall_time.unixTimestamp());
        if (self.reserve_refresh_backoff_until > now) return;
        const res = self.client.reservation orelse return;
        if (!self.client.pollRefresh(now)) return;
        if (self.hooks.outbound_client(self.hooks.ctx, res.relay_peer) == null) return;

        self.reserveOnRelay(res.relay_peer) catch |err| {
            log.warn("relay: reservation refresh failed relay={any} err={s}", .{ res.relay_peer, @errorName(err) });
            self.reserve_refresh_backoff_until = now + 30;
            self.notifyRelayReservation(res.relay_peer, .lost, null);
            return;
        };
    }

    fn notifyRelayReservation(
        self: *LiveRelay,
        relay_peer: identity.PeerId,
        kind: ReservationEventKind,
        expire_unix: ?u64,
    ) void {
        if (self.hooks.on_relay_reservation) |cb| {
            cb(self.hooks.ctx, relay_peer, kind, expire_unix);
        }
    }

    fn advanceStopOpens(self: *LiveRelay) void {
        var i: usize = 0;
        while (i < self.stop_opens.items.len) {
            const so = self.stop_opens.items[i];
            if (so.failed) {
                self.server.store.endBridge();
                self.allocator.free(so.initiator_wire);
                self.allocator.destroy(so);
                _ = self.stop_opens.swapRemove(i);
                continue;
            }
            if (!so.handshake_sent) {
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(self.allocator);
                stream_multistream.appendFirstStreamInitiatorHandshake(&out, self.allocator, relay.wire.stop_protocol_id) catch {
                    so.failed = true;
                    continue;
                };
                var w = so.raw.writer();
                Io.Writer.writeAll(&w, out.items) catch {
                    so.failed = true;
                    continue;
                };
                Io.Writer.flush(&w) catch {};
                so.handshake_sent = true;
            }
            if (!so.handshake_done) {
                const need = stream_multistream.responderSuccessReplyWireLen(relay.wire.stop_protocol_id) catch {
                    so.failed = true;
                    continue;
                };
                if (so.raw.unreadRecvLen() < need) {
                    i += 1;
                    continue;
                }
                var r = so.raw.reader();
                var w = so.raw.writer();
                stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, relay.wire.stop_protocol_id, self.allocator, null) catch {
                    so.failed = true;
                    continue;
                };
                so.handshake_done = true;
            }
            if (!so.connect_sent) {
                const req = relay.wire.encodeStop(self.allocator, .{
                    .msg_type = .connect,
                    .peer = .{ .id = so.initiator_wire },
                    .limit = if (so.limit) |l| .{
                        .duration_sec = l.duration_sec,
                        .data_bytes = l.data_bytes,
                    } else null,
                }) catch {
                    so.failed = true;
                    continue;
                };
                defer self.allocator.free(req);
                var w = so.raw.writer();
                relay.wire.writeLengthPrefixed(&w, req) catch {
                    so.failed = true;
                    continue;
                };
                Io.Writer.flush(&w) catch {};
                so.connect_sent = true;
            }
            if (!so.connect_ok) {
                if (so.raw.unreadRecvLen() < 4) {
                    i += 1;
                    continue;
                }
                var r = so.raw.reader();
                const resp_frame = relay.wire.readLengthPrefixedAlloc(&r, self.allocator, relay.wire.Limits.standard.max_frame_bytes) catch {
                    i += 1;
                    continue;
                };
                defer self.allocator.free(resp_frame);
                var resp = relay.wire.decodeStopOwned(self.allocator, resp_frame, .standard) catch {
                    so.failed = true;
                    continue;
                };
                defer resp.deinit(self.allocator);
                if (resp.msg_type != .status or resp.status != .ok) {
                    so.failed = true;
                    continue;
                }
                so.connect_ok = true;

                // Reply OK on hop side and start bridge.
                var hop_w_buf: [512]u8 = undefined;
                var hop_w = Io.Writer.fixed(&hop_w_buf);
                self.server.writeHopStatus(&hop_w, .ok, null, so.limit) catch {
                    so.failed = true;
                    continue;
                };
                var hop_w_stream = so.hop.writer();
                Io.Writer.writeAll(&hop_w_stream, hop_w_buf[0..hop_w.end]) catch {
                    so.failed = true;
                    continue;
                };
                Io.Writer.flush(&hop_w_stream) catch {};

                const bridge = self.allocator.create(Bridge) catch {
                    so.failed = true;
                    continue;
                };
                // Carry the reservation `limit` over to the bridge so
                // advanceBridges can tear it down at the budget. Without
                // this, the relay would accept the limit on the wire but
                // never actually enforce it — letting one peer drain the
                // relay forever.
                const expire_unix: ?u64 = if (so.limit) |l| blk: {
                    if (l.duration_sec) |secs| {
                        const now = @as(u64, @intCast(wall_time.unixTimestamp()));
                        break :blk now + @as(u64, secs);
                    }
                    break :blk null;
                } else null;
                bridge.* = .{
                    .hop = so.hop,
                    .stop = .{ .outbound = so.raw },
                    .limit_data_bytes = if (so.limit) |l| l.data_bytes else null,
                    .limit_expire_unix = expire_unix,
                };
                self.bridges.append(self.allocator, bridge) catch {
                    self.allocator.destroy(bridge);
                    so.failed = true;
                    continue;
                };
                self.allocator.free(so.initiator_wire);
                self.allocator.destroy(so);
                _ = self.stop_opens.swapRemove(i);
                continue;
            }
            i += 1;
        }
    }

    fn advanceBridges(self: *LiveRelay) void {
        var i: usize = 0;
        while (i < self.bridges.items.len) {
            const b = self.bridges.items[i];
            if (b.done) {
                self.server.endBridge();
                self.allocator.destroy(b);
                _ = self.bridges.swapRemove(i);
                continue;
            }
            // Duration cap: tear down once the wall-clock deadline arrives.
            if (b.limit_expire_unix) |deadline| {
                if (@as(u64, @intCast(wall_time.unixTimestamp())) >= deadline) {
                    b.done = true;
                    continue;
                }
            }
            // Per-bridge byte budget: stop pumping once we've used what was
            // reserved; the bridge is torn down on the next tick.
            const remaining: ?u64 = if (b.limit_data_bytes) |total| blk: {
                if (b.bytes_used >= total) break :blk 0;
                break :blk total - b.bytes_used;
            } else null;
            if (remaining) |r| if (r == 0) {
                b.done = true;
                continue;
            };

            var hop_r = b.hop.reader();
            var hop_w = b.hop.writer();
            var stop_r = b.stop.reader();
            var stop_w = b.stop.writer();
            const pumped = circuit_transport.bridgeStreamsUntilClosed(
                &hop_r,
                &hop_w,
                &stop_r,
                &stop_w,
                &b.buf,
                8,
                remaining,
            ) catch {
                b.done = true;
                continue;
            };
            b.bytes_used +|= pumped;
            i += 1;
        }
    }

    fn advanceCircuitDials(self: *LiveRelay) void {
        var i: usize = 0;
        while (i < self.circuit_dials.items.len) {
            const cd = self.circuit_dials.items[i];
            switch (cd.phase) {
                .dial_relay => {
                    if (!self.hooks.dial_plain(self.hooks.ctx, cd.plan.relay_dial_addr, cd.plan.relay_id)) {
                        cd.phase = .failed;
                        self.hooks.on_relayed_dial_failed(self.hooks.ctx, cd.expected_target);
                        continue;
                    }
                    cd.phase = .hop_handshake;
                },
                .hop_handshake => {
                    const client = self.hooks.outbound_client(self.hooks.ctx, cd.plan.relay_id) orelse {
                        i += 1;
                        continue;
                    };
                    if (cd.hop_raw == null) {
                        const sid = self.hooks.next_bidi_stream(self.hooks.ctx, cd.plan.relay_id) orelse {
                            i += 1;
                            continue;
                        };
                        cd.hop_raw = .{ .client = client, .stream_id = sid };
                    }
                    var hop = cd.hop_raw.?;
                    if (!cd.hop_handshake_sent) {
                        var out: std.ArrayList(u8) = .empty;
                        defer out.deinit(self.allocator);
                        stream_multistream.appendFirstStreamInitiatorHandshake(&out, self.allocator, relay.wire.hop_protocol_id) catch {
                            cd.phase = .failed;
                            continue;
                        };
                        var w = hop.writer();
                        Io.Writer.writeAll(&w, out.items) catch {
                            cd.phase = .failed;
                            continue;
                        };
                        Io.Writer.flush(&w) catch {};
                        cd.hop_handshake_sent = true;
                    }
                    if (!cd.hop_handshake_done) {
                        const need = stream_multistream.responderSuccessReplyWireLen(relay.wire.hop_protocol_id) catch {
                            cd.phase = .failed;
                            continue;
                        };
                        if (hop.unreadRecvLen() < need) {
                            i += 1;
                            continue;
                        }
                        var r = hop.reader();
                        var w = hop.writer();
                        stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, relay.wire.hop_protocol_id, self.allocator, null) catch {
                            cd.phase = .failed;
                            continue;
                        };
                        cd.hop_handshake_done = true;
                        cd.phase = .hop_connect;
                    }
                },
                .hop_connect => {
                    var hop = cd.hop_raw orelse {
                        cd.phase = .failed;
                        continue;
                    };
                    var hr = hop.reader();
                    var hw = hop.writer();
                    self.client.connectOnStream(&hr, &hw, cd.expected_target) catch {
                        cd.phase = .failed;
                        self.hooks.on_relayed_dial_failed(self.hooks.ctx, cd.expected_target);
                        continue;
                    };
                    const conn_id = self.hooks.next_conn_id(self.hooks.ctx);
                    const vc = self.allocator.create(RelayVirtualConn) catch {
                        cd.phase = .failed;
                        continue;
                    };
                    vc.* = .{
                        .target = cd.expected_target,
                        .relay = cd.plan.relay_id,
                        .stream_id = hop.stream_id,
                        .raw = hop,
                        .conn_id = conn_id,
                    };
                    // `put` would silently overwrite and leak a prior
                    // `RelayVirtualConn` for the same target. Use `getOrPut`
                    // and destroy the prior entry explicitly when replacing
                    // (e.g., a duplicate circuit dial racing the first).
                    const gop = self.relay_virtual.getOrPut(cd.expected_target) catch {
                        self.allocator.destroy(vc);
                        cd.phase = .failed;
                        continue;
                    };
                    if (gop.found_existing) {
                        self.allocator.destroy(gop.value_ptr.*);
                    }
                    gop.value_ptr.* = vc;
                    self.hooks.on_relayed_connected(self.hooks.ctx, cd.expected_target, conn_id);
                    cd.phase = .done;
                    cd.plan.deinit(self.allocator);
                    self.allocator.destroy(cd);
                    _ = self.circuit_dials.swapRemove(i);
                    continue;
                },
                .done, .failed => {
                    cd.plan.deinit(self.allocator);
                    self.allocator.destroy(cd);
                    _ = self.circuit_dials.swapRemove(i);
                    continue;
                },
            }
            i += 1;
        }
    }

    /// Reserve a slot on `relay` (opens hop stream on existing conn to relay).
    pub fn reserveOnRelay(self: *LiveRelay, relay_peer: identity.PeerId) Error!void {
        const had_reservation = self.client.reservation != null;
        const client = self.hooks.outbound_client(self.hooks.ctx, relay_peer) orelse return error.ConnectFailed;
        const sid = self.hooks.next_bidi_stream(self.hooks.ctx, relay_peer) orelse return error.ConnectFailed;
        var raw: quic_raw_stream_io.RawAppBidiClient = .{ .client = client, .stream_id = sid };

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);
        try stream_multistream.appendFirstStreamInitiatorHandshake(&out, self.allocator, relay.wire.hop_protocol_id);
        var w = raw.writer();
        try Io.Writer.writeAll(&w, out.items);
        try Io.Writer.flush(&w);

        const need = try stream_multistream.responderSuccessReplyWireLen(relay.wire.hop_protocol_id);
        while (raw.unreadRecvLen() < need) {}
        var r = raw.reader();
        try stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, relay.wire.hop_protocol_id, self.allocator, null);

        try self.client.reserveOnStream(&r, &w, relay_peer);
        const expire = self.client.reservation.?.expire_unix;
        self.reserve_refresh_backoff_until = 0;
        self.notifyRelayReservation(
            relay_peer,
            if (had_reservation) .refreshed else .acquired,
            expire,
        );
    }
};

test "isCircuitDialAddr detects p2p-circuit" {
    try std.testing.expect(LiveRelay.isCircuitDialAddr("/ip4/1.1.1.1/udp/1/quic-v1/p2p/Qm/p2p-circuit/p2p/Qm2"));
    try std.testing.expect(!LiveRelay.isCircuitDialAddr("/ip4/1.1.1.1/udp/1/quic-v1"));
}
