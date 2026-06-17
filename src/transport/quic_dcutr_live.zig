//! Live DCUtR hole-punch scheduling for [`quic_runtime`](quic_runtime.zig) (#91).

const std = @import("std");
const Io = std.Io;
const log = std.log.scoped(.quic_dcutr);

const identity = @import("../identity.zig");
const dcutr = @import("../dcutr/root.zig");
const dcutr_retry = @import("../dcutr/retry.zig");
const dcutr_punch = @import("dcutr_punch.zig");
const quic = @import("quic.zig");
const quic_endpoint = @import("quic_endpoint.zig");
const quic_raw_stream_io = @import("quic_raw_stream_io.zig");
const stream_multistream = @import("stream_multistream.zig");
const multiaddr = @import("multiaddr");
const wall_time = @import("../wall_time.zig");

const zquic = @import("zquic");
const ZIo = zquic.transport.io;

pub const Error = dcutr.coordinator.Error || dcutr_punch.Error || std.mem.Allocator.Error;

pub const Config = struct {
    enable: bool = true,
    local_obs_addrs: []const []const u8 = &.{},
    max_attempts: u32 = dcutr_retry.max_attempts,
};

pub const FailReason = enum {
    exchange_failed,
    punch_failed,
    max_attempts_exceeded,
};

pub const TlsPemRef = struct {
    cert: []const u8,
    key: []const u8,
};

pub const RuntimeHooks = struct {
    ctx: ?*anyopaque = null,
    now_ms: *const fn () i64,
    listener_port_v4: *const fn (ctx: ?*anyopaque) ?u16,
    tls_pem_paths: *const fn (ctx: ?*anyopaque) TlsPemRef,
    tls_pem_bytes: *const fn (ctx: ?*anyopaque) TlsPemRef,
    use_pem_bytes: *const fn (ctx: ?*anyopaque) bool,
    on_direct_connected: *const fn (
        ctx: ?*anyopaque,
        peer: identity.PeerId,
        relayed_conn_id: u64,
        direct_conn_id: u64,
    ) void,
    close_relayed: *const fn (ctx: ?*anyopaque, peer: identity.PeerId) void,
    on_dcutr_failed: ?*const fn (
        ctx: ?*anyopaque,
        peer: identity.PeerId,
        relayed_conn_id: u64,
        reason: FailReason,
    ) void = null,
    next_conn_id: *const fn (ctx: ?*anyopaque) u64,
};

const PunchDial = struct {
    peer: identity.PeerId,
    relayed_conn_id: u64,
    addrs: [][]u8,
    fire_at_ms: i64,
    started: bool = false,
    outbound: ?quic_endpoint.QuicOutbound = null,
};

const StreamLeg = union(enum) {
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

    fn unreadRecvLen(self: *const StreamLeg) usize {
        return switch (self.*) {
            .inbound => |*s| s.unreadRecvLen(),
            .outbound => |*c| c.unreadRecvLen(),
        };
    }
};

const StreamExchange = struct {
    peer: identity.PeerId,
    relayed_conn_id: u64,
    raw: StreamLeg,
    outbound_client: ?*ZIo.Client = null,
    coordinator: dcutr.coordinator.Coordinator,
    role: dcutr.coordinator.Role,
    attempt: u32 = 0,
    handshake_sent: bool = false,
    handshake_done: bool = false,
    phase: enum { handshake, connect, sync, done, failed } = .handshake,
};

const PendingUpgrade = struct {
    peer: identity.PeerId,
    relayed_conn_id: u64,
    role: dcutr.coordinator.Role,
    client: *ZIo.Client,
    attempt: u32,
    next_attempt_ms: i64,
};

pub const LiveDcutr = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    hooks: RuntimeHooks,
    pending_punches: std.ArrayList(*PunchDial) = .empty,
    exchanges: std.ArrayList(*StreamExchange) = .empty,
    pending_upgrades: std.ArrayList(PendingUpgrade) = .empty,

    pub fn init(allocator: std.mem.Allocator, cfg: Config, hooks: RuntimeHooks) LiveDcutr {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .hooks = hooks,
        };
    }

    pub fn deinit(self: *LiveDcutr) void {
        for (self.pending_punches.items) |p| {
            for (p.addrs) |a| self.allocator.free(a);
            self.allocator.free(p.addrs);
            if (p.outbound) |*o| o.deinit();
            self.allocator.destroy(p);
        }
        self.pending_punches.deinit(self.allocator);
        for (self.exchanges.items) |ex| {
            ex.coordinator.deinit();
            self.allocator.destroy(ex);
        }
        self.exchanges.deinit(self.allocator);
        self.pending_upgrades.deinit(self.allocator);
    }

    /// Queue a DCUtR upgrade on a relayed connection (#205).
    pub fn scheduleRelayedUpgrade(
        self: *LiveDcutr,
        peer: identity.PeerId,
        relayed_conn_id: u64,
        role: dcutr.coordinator.Role,
        raw: quic_raw_stream_io.RawAppBidiClient,
    ) Error!void {
        const ex = try self.allocator.create(StreamExchange);
        ex.* = .{
            .peer = peer,
            .relayed_conn_id = relayed_conn_id,
            .raw = .{ .outbound = raw },
            .outbound_client = raw.client,
            .coordinator = dcutr.coordinator.Coordinator.init(self.allocator, .{}, role),
            .role = role,
        };
        try self.exchanges.append(self.allocator, ex);
    }

    pub fn scheduleRelayedUpgradeLater(
        self: *LiveDcutr,
        peer: identity.PeerId,
        relayed_conn_id: u64,
        role: dcutr.coordinator.Role,
        client: *ZIo.Client,
        attempt: u32,
        next_attempt_ms: i64,
    ) Error!void {
        try self.pending_upgrades.append(self.allocator, .{
            .peer = peer,
            .relayed_conn_id = relayed_conn_id,
            .role = role,
            .client = client,
            .attempt = attempt,
            .next_attempt_ms = next_attempt_ms,
        });
    }

    pub fn startInitiator(
        self: *LiveDcutr,
        peer: identity.PeerId,
        relayed_conn_id: u64,
        raw: quic_raw_stream_io.RawAppBidiClient,
    ) Error!void {
        try self.scheduleRelayedUpgrade(peer, relayed_conn_id, .initiator, raw);
    }

    pub fn startResponderInbound(
        self: *LiveDcutr,
        peer: identity.PeerId,
        relayed_conn_id: u64,
        raw: quic_raw_stream_io.RawAppBidiServer,
    ) Error!void {
        const ex = try self.allocator.create(StreamExchange);
        ex.* = .{
            .peer = peer,
            .relayed_conn_id = relayed_conn_id,
            .raw = .{ .inbound = raw },
            .coordinator = dcutr.coordinator.Coordinator.init(self.allocator, .{}, .responder),
            .role = .responder,
        };
        try self.exchanges.append(self.allocator, ex);
    }

    pub fn advance(self: *LiveDcutr) void {
        if (!self.cfg.enable) return;
        self.advancePendingUpgrades();
        self.advanceExchanges();
        self.advancePunches();
    }

    fn advancePendingUpgrades(self: *LiveDcutr) void {
        const now = self.hooks.now_ms();
        var i: usize = 0;
        while (i < self.pending_upgrades.items.len) {
            const pu = self.pending_upgrades.items[i];
            if (now < pu.next_attempt_ms) {
                i += 1;
                continue;
            }
            const sid = ZIo.rawAllocateNextLocalBidiStream(&pu.client.conn) catch {
                self.failUpgrade(pu.peer, pu.relayed_conn_id, pu.attempt + 1, pu.client, pu.role);
                _ = self.pending_upgrades.swapRemove(i);
                continue;
            };
            self.scheduleRelayedUpgrade(pu.peer, pu.relayed_conn_id, pu.role, .{
                .client = pu.client,
                .stream_id = sid,
            }) catch {
                self.failUpgrade(pu.peer, pu.relayed_conn_id, pu.attempt + 1, pu.client, pu.role);
            };
            _ = self.pending_upgrades.swapRemove(i);
        }
    }

    fn failUpgrade(
        self: *LiveDcutr,
        peer: identity.PeerId,
        relayed_conn_id: u64,
        completed_attempt: u32,
        client: *ZIo.Client,
        role: dcutr.coordinator.Role,
    ) void {
        if (completed_attempt >= self.cfg.max_attempts) {
            if (self.hooks.on_dcutr_failed) |cb| {
                cb(self.hooks.ctx, peer, relayed_conn_id, .max_attempts_exceeded);
            }
            return;
        }
        const seed: u64 = @bitCast(@as(i64, wall_time.milliTimestamp()));
        const delay = dcutr_retry.delayMs(completed_attempt -| 1, seed);
        self.scheduleRelayedUpgradeLater(
            peer,
            relayed_conn_id,
            role,
            client,
            completed_attempt,
            self.hooks.now_ms() + delay,
        ) catch {
            if (self.hooks.on_dcutr_failed) |cb| {
                cb(self.hooks.ctx, peer, relayed_conn_id, .max_attempts_exceeded);
            }
        };
    }

    fn handleFailedExchange(self: *LiveDcutr, ex: *StreamExchange) void {
        if (ex.phase != .failed) return;
        const completed_attempt = ex.attempt + 1;
        const client = ex.outbound_client;
        const peer = ex.peer;
        const relayed_conn_id = ex.relayed_conn_id;
        const role = ex.role;
        ex.coordinator.deinit();
        self.allocator.destroy(ex);
        if (client) |c| {
            self.failUpgrade(peer, relayed_conn_id, completed_attempt, c, role);
        } else if (self.hooks.on_dcutr_failed) |cb| {
            cb(self.hooks.ctx, peer, relayed_conn_id, .exchange_failed);
        }
    }

    fn advanceExchanges(self: *LiveDcutr) void {
        var i: usize = 0;
        while (i < self.exchanges.items.len) {
            const ex = self.exchanges.items[i];
            if (ex.phase == .done) {
                ex.coordinator.deinit();
                self.allocator.destroy(ex);
                _ = self.exchanges.swapRemove(i);
                continue;
            }
            if (ex.phase == .failed) {
                self.handleFailedExchange(ex);
                _ = self.exchanges.swapRemove(i);
                continue;
            }
            if (!ex.handshake_sent) {
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(self.allocator);
                stream_multistream.appendFirstStreamInitiatorHandshake(&out, self.allocator, dcutr.wire.protocol_id) catch {
                    ex.phase = .failed;
                    continue;
                };
                var w = ex.raw.writer();
                Io.Writer.writeAll(&w, out.items) catch {
                    ex.phase = .failed;
                    continue;
                };
                Io.Writer.flush(&w) catch {};
                ex.handshake_sent = true;
            }
            if (!ex.handshake_done) {
                const need = stream_multistream.responderSuccessReplyWireLen(dcutr.wire.protocol_id) catch {
                    ex.phase = .failed;
                    continue;
                };
                if (ex.raw.unreadRecvLen() < need) {
                    i += 1;
                    continue;
                }
                var r = ex.raw.reader();
                var w = ex.raw.writer();
                stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, dcutr.wire.protocol_id, self.allocator, null) catch {
                    ex.phase = .failed;
                    continue;
                };
                ex.handshake_done = true;
            }
            switch (ex.role) {
                .initiator => self.advanceInitiatorExchange(ex),
                .responder => self.advanceResponderExchange(ex),
            }
            i += 1;
        }
    }

    fn advanceInitiatorExchange(self: *LiveDcutr, ex: *StreamExchange) void {
        switch (ex.phase) {
            .handshake => {
                ex.coordinator.connect_sent_ms = self.hooks.now_ms();
                const connect = ex.coordinator.buildConnect(self.cfg.local_obs_addrs) catch {
                    ex.phase = .failed;
                    return;
                };
                defer self.allocator.free(connect);
                var w = ex.raw.writer();
                dcutr.wire.writeLengthPrefixed(&w, connect) catch {
                    ex.phase = .failed;
                    return;
                };
                Io.Writer.flush(&w) catch {};
                ex.phase = .connect;
            },
            .connect => {
                if (ex.raw.unreadRecvLen() < 4) return;
                var r = ex.raw.reader();
                const frame = dcutr.wire.readLengthPrefixedAlloc(&r, self.allocator, dcutr.wire.Limits.standard.max_frame_bytes) catch return;
                defer self.allocator.free(frame);
                const sync = ex.coordinator.onRemoteConnectReply(frame) catch {
                    ex.phase = .failed;
                    return;
                };
                defer self.allocator.free(sync);
                var w = ex.raw.writer();
                dcutr.wire.writeLengthPrefixed(&w, sync) catch {
                    ex.phase = .failed;
                    return;
                };
                Io.Writer.flush(&w) catch {};
                // pollDial returns an owned DirectDialRequest (its own copy
                // of addrs); we hand the addrs to schedulePunch (which dupes
                // them) and then deinit the request to free our copy.
                if (ex.coordinator.pollDial(wall_time.milliTimestamp())) |req_in| {
                    var req = req_in;
                    defer req.deinit(self.allocator);
                    self.schedulePunch(ex.peer, ex.relayed_conn_id, req.addrs, req.fire_at_ms);
                }
                ex.phase = .done;
            },
            else => {},
        }
    }

    fn advanceResponderExchange(self: *LiveDcutr, ex: *StreamExchange) void {
        switch (ex.phase) {
            .handshake => {
                if (ex.raw.unreadRecvLen() < 4) return;
                var r = ex.raw.reader();
                const frame = dcutr.wire.readLengthPrefixedAlloc(&r, self.allocator, dcutr.wire.Limits.standard.max_frame_bytes) catch return;
                defer self.allocator.free(frame);
                const reply = ex.coordinator.onRemoteConnect(frame, self.cfg.local_obs_addrs) catch {
                    ex.phase = .failed;
                    return;
                };
                defer self.allocator.free(reply);
                var w = ex.raw.writer();
                dcutr.wire.writeLengthPrefixed(&w, reply) catch {
                    ex.phase = .failed;
                    return;
                };
                Io.Writer.flush(&w) catch {};
                ex.phase = .sync;
            },
            .sync => {
                if (ex.raw.unreadRecvLen() < 4) return;
                var r = ex.raw.reader();
                const frame = dcutr.wire.readLengthPrefixedAlloc(&r, self.allocator, dcutr.wire.Limits.standard.max_frame_bytes) catch return;
                defer self.allocator.free(frame);
                var msg = dcutr.wire.decodeOwned(self.allocator, frame, .standard) catch {
                    ex.phase = .failed;
                    return;
                };
                defer msg.deinit(self.allocator);
                if (msg.msg_type != .sync) {
                    ex.phase = .failed;
                    return;
                }
                var req = ex.coordinator.onRemoteSync() catch {
                    ex.phase = .failed;
                    return;
                };
                defer req.deinit(self.allocator);
                self.schedulePunch(ex.peer, ex.relayed_conn_id, req.addrs, req.fire_at_ms);
                ex.phase = .done;
            },
            else => {},
        }
    }

    fn schedulePunch(
        self: *LiveDcutr,
        peer: identity.PeerId,
        relayed_conn_id: u64,
        addrs: []const []const u8,
        fire_at_ms: i64,
    ) void {
        const p = self.allocator.create(PunchDial) catch return;
        var list = std.ArrayList([]u8).empty;
        for (addrs) |a| {
            list.append(self.allocator, self.allocator.dupe(u8, a) catch return) catch return;
        }
        p.* = .{
            .peer = peer,
            .relayed_conn_id = relayed_conn_id,
            .addrs = list.toOwnedSlice(self.allocator) catch return,
            .fire_at_ms = fire_at_ms,
        };
        self.pending_punches.append(self.allocator, p) catch {
            for (p.addrs) |a| self.allocator.free(a);
            self.allocator.free(p.addrs);
            self.allocator.destroy(p);
        };
    }

    fn advancePunches(self: *LiveDcutr) void {
        const now = self.hooks.now_ms();
        var i: usize = 0;
        while (i < self.pending_punches.items.len) {
            const p = self.pending_punches.items[i];
            if (now < p.fire_at_ms) {
                i += 1;
                continue;
            }
            if (!p.started) {
                p.started = true;
                self.firePunchDial(p);
                if (p.outbound == null) {
                    if (self.hooks.on_dcutr_failed) |cb| {
                        cb(self.hooks.ctx, p.peer, p.relayed_conn_id, .punch_failed);
                    }
                    for (p.addrs) |a| self.allocator.free(a);
                    self.allocator.free(p.addrs);
                    self.allocator.destroy(p);
                    _ = self.pending_punches.swapRemove(i);
                    continue;
                }
            }
            if (p.outbound) |*ob| {
                var recv: [4096]u8 = undefined;
                ob.drive(&recv, 0) catch {};
                if (ob.client.conn.phase == .connected) {
                    const direct_conn_id = self.hooks.next_conn_id(self.hooks.ctx);
                    self.hooks.on_direct_connected(
                        self.hooks.ctx,
                        p.peer,
                        p.relayed_conn_id,
                        direct_conn_id,
                    );
                    self.hooks.close_relayed(self.hooks.ctx, p.peer);
                    ob.deinit();
                    p.outbound = null;
                    for (p.addrs) |a| self.allocator.free(a);
                    self.allocator.free(p.addrs);
                    self.allocator.destroy(p);
                    _ = self.pending_punches.swapRemove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    fn firePunchDial(self: *LiveDcutr, p: *PunchDial) void {
        const listen_port = self.hooks.listener_port_v4(self.hooks.ctx) orelse return;
        for (p.addrs) |addr_str| {
            var ma = multiaddr.Multiaddr.fromString(self.allocator, addr_str) catch continue;
            defer ma.deinit();

            // Pick the address family from the remote multiaddr so we bind a
            // socket that can actually reach it. `/ip6/...` requires an AF_INET6
            // socket; anything else (including the common `/ip4/`) uses AF_INET.
            const family: dcutr_punch.Family = if (std.mem.indexOf(u8, addr_str, "/ip6/") != null)
                .ipv6
            else
                .ipv4;

            // REUSEPORT-bind the shared socket. We tolerate
            // ReusePortUnsupported (best-effort punch on platforms without
            // REUSEPORT) but otherwise propagate to the next candidate addr.
            _ = dcutr_punch.bindUdpSocketReusePort(family, listen_port) catch continue;

            var dial_opts: quic.Libp2pZquicClientDialOptions = .{};
            if (self.hooks.use_pem_bytes(self.hooks.ctx)) {
                const pb = self.hooks.tls_pem_bytes(self.hooks.ctx);
                dial_opts.client_cert_pem = pb.cert;
                dial_opts.client_key_pem = pb.key;
            } else {
                const pp = self.hooks.tls_pem_paths(self.hooks.ctx);
                dial_opts.client_cert_path = pp.cert;
                dial_opts.client_key_path = pp.key;
            }
            const outbound = quic_endpoint.QuicOutbound.dial(self.allocator, ma, dial_opts) catch continue;
            p.outbound = outbound;
            return;
        }
    }
};

const quic_posix_udp = @import("quic_posix_udp.zig");

test "LiveDcutr init smoke" {
    const a = std.testing.allocator;
    const tlsStub = struct {
        fn pem(ctx: ?*anyopaque) TlsPemRef {
            _ = ctx;
            return .{ .cert = "", .key = "" };
        }
    };
    var d = LiveDcutr.init(a, .{ .enable = false }, .{
        .now_ms = struct {
            fn f() i64 {
                return 0;
            }
        }.f,
        .listener_port_v4 = struct {
            fn f(ctx: ?*anyopaque) ?u16 {
                _ = ctx;
                return null;
            }
        }.f,
        .tls_pem_paths = tlsStub.pem,
        .tls_pem_bytes = tlsStub.pem,
        .use_pem_bytes = struct {
            fn f(ctx: ?*anyopaque) bool {
                _ = ctx;
                return false;
            }
        }.f,
        .on_direct_connected = struct {
            fn f(ctx: ?*anyopaque, peer: identity.PeerId, relayed_conn_id: u64, direct_conn_id: u64) void {
                _ = ctx;
                _ = peer;
                _ = relayed_conn_id;
                _ = direct_conn_id;
            }
        }.f,
        .close_relayed = struct {
            fn f(ctx: ?*anyopaque, peer: identity.PeerId) void {
                _ = ctx;
                _ = peer;
            }
        }.f,
        .next_conn_id = struct {
            fn f(ctx: ?*anyopaque) u64 {
                _ = ctx;
                return 1;
            }
        }.f,
    });
    defer d.deinit();
}
