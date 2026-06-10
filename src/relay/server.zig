//! Circuit Relay v2 server (hop + stop handlers) (#91).
//!
//! Spec: https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md
//!
//! This module handles the *protocol* side: reservation bookkeeping and
//! writing protobuf responses. The actual stream-bridging — opening a STOP
//! stream to the target and pumping bytes between hop and stop — lives in
//! `src/transport/quic_relay_live.zig` (`LiveRelay.beginHopConnect`).
//!
//! `handleHopStream` therefore intentionally rejects HOP CONNECT messages
//! with `unexpected_message`: production callers route CONNECT through
//! `LiveRelay.handleHopFrame` *before* it ever reaches `handleHopStream`.
//! Keeping a separate CONNECT branch here invited a stub callback that
//! would silently lie ("ok" with no bridge); the cleaner fix is to make
//! this surface RESERVE-only.

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

/// Sign callback the host wires to its own private-key implementation.
///
/// Given the domain-separated `signing_input` bytes, the host produces a
/// signature in `out_sig` and returns the signature length. Returning null
/// means signing failed (no signature returned, voucher will be omitted from
/// the reservation response — clients that require a voucher will refuse the
/// reservation, which is the safe outcome).
pub const SignFn = *const fn (
    ctx: ?*anyopaque,
    signing_input: []const u8,
    out_sig: []u8,
) ?usize;

/// Rate-limit callback. Return false to refuse a RESERVE attempt for this
/// peer (typically because a per-source-IP / token-bucket limiter is full).
/// Without this hook the relay still enforces `max_reservations_per_peer` and
/// `max_total_reservations`, but those are sybil-vulnerable since they key
/// on PeerId — wire a real per-IP limiter via this hook for hardened relays.
pub const ReserveAcceptFn = *const fn (ctx: ?*anyopaque, peer: identity.PeerId) bool;

pub const Config = struct {
    limits: wire.Limits = .standard,
    store: reservation.Config = .{},
    relay_addrs: []const []const u8 = &.{},
    /// When true, reject hop traffic received over relayed connections.
    reject_relayed_hop: bool = true,

    /// Pre-encoded libp2p PublicKey protobuf for this relay's host key.
    /// When null (or `sign_fn` is null), vouchers are omitted from RESERVE
    /// responses — spec-conformant peers that require a signed voucher will
    /// then refuse the reservation, which is the safe-by-default behavior.
    public_key_pb: ?[]const u8 = null,
    sign_fn: ?SignFn = null,
    sign_ctx: ?*anyopaque = null,
    /// Maximum signature length the host produces (Ed25519 = 64, RSA varies).
    /// Bound to prevent oversize stack/heap allocations.
    max_signature_bytes: usize = 256,

    reserve_accept_fn: ?ReserveAcceptFn = null,
    reserve_accept_ctx: ?*anyopaque = null,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    store: reservation.Store,
    local_peer: identity.PeerId,

    pub fn init(
        allocator: std.mem.Allocator,
        cfg: Config,
        local_peer: identity.PeerId,
    ) Server {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .store = reservation.Store.init(allocator, cfg.store),
            .local_peer = local_peer,
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

    /// Mint a SignedEnvelope-wrapped ReservationVoucher per circuit-v2 spec.
    ///
    /// Returns null (caller should omit the voucher field) when this relay is
    /// running without a sign callback / public key, or when signing failed.
    /// `expire_unix_s` is the wall-clock unix seconds; the voucher records it
    /// as nanoseconds per the on-wire spec.
    fn mintVoucher(self: *Server, peer: identity.PeerId, expire_unix_s: u64) Error!?[]u8 {
        const sign_fn = self.cfg.sign_fn orelse return null;
        const pk = self.cfg.public_key_pb orelse return null;

        const peer_wire = try self.peerIdToWire(peer);
        defer self.allocator.free(peer_wire);
        const relay_wire = try self.peerIdToWire(self.local_peer);
        defer self.allocator.free(relay_wire);

        const expiration_ns = expire_unix_s *| std.time.ns_per_s;
        const payload = try wire.buildReservationVoucherPayload(
            self.allocator,
            relay_wire,
            peer_wire,
            expiration_ns,
        );
        defer self.allocator.free(payload);

        const signing_input = try wire.buildSignedEnvelopeSigningInput(
            self.allocator,
            wire.voucher_domain,
            wire.voucher_payload_type,
            payload,
        );
        defer self.allocator.free(signing_input);

        const sig_buf = try self.allocator.alloc(u8, self.cfg.max_signature_bytes);
        defer self.allocator.free(sig_buf);
        const sig_len = sign_fn(self.cfg.sign_ctx, signing_input, sig_buf) orelse return null;
        if (sig_len == 0 or sig_len > sig_buf.len) return null;

        return try wire.buildSignedEnvelope(
            self.allocator,
            pk,
            wire.voucher_payload_type,
            payload,
            sig_buf[0..sig_len],
        );
    }

    /// Handle one inbound hop stream message. CONNECT is intentionally
    /// rejected here — see module docstring; route via `LiveRelay.handleHopFrame`.
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
            .reserve => try self.handleReserve(w, hop_peer),
            .connect => try self.writeHopStatus(w, .unexpected_message, null, null),
            else => try self.writeHopStatus(w, .unexpected_message, null, null),
        }
    }

    fn handleReserve(self: *Server, w: *Io.Writer, hop_peer: identity.PeerId) Error!void {
        // Host-supplied rate limit (typically per source IP) gets first say
        // so sybil-cheap PeerIds can't drive a relay into max_total_reservations.
        if (self.cfg.reserve_accept_fn) |accept| {
            if (!accept(self.cfg.reserve_accept_ctx, hop_peer)) {
                try self.writeHopStatus(w, .reservation_refused, null, null);
                return;
            }
        }

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

        const voucher_opt = try self.mintVoucher(hop_peer, res_entry.expire_unix);
        defer if (voucher_opt) |v| self.allocator.free(v);

        var addr_views = std.ArrayList([]const u8).empty;
        defer addr_views.deinit(self.allocator);
        for (res_entry.addrs) |a| try addr_views.append(self.allocator, a);

        try self.writeHopStatus(w, .ok, .{
            .expire_unix = res_entry.expire_unix,
            .addrs = addr_views.items,
            .voucher = voucher_opt,
        }, .{ .duration_sec = 120, .data_bytes = 1 << 20 });
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

test "hop reserve accepts and returns reservation (voucher omitted without signer)" {
    const a = std.testing.allocator;
    const relay = try identity.PeerId.random();
    const client_peer = try identity.PeerId.random();
    var srv = Server.init(a, .{
        .relay_addrs = &.{"/ip4/203.0.113.1/udp/4001/quic-v1"},
    }, relay);
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
    try std.testing.expect(resp.reservation.?.voucher == null);
}

test "hop reserve with signer mints signed-envelope voucher" {
    const a = std.testing.allocator;
    const SignStub = struct {
        fn sign(ctx: ?*anyopaque, signing_input: []const u8, out_sig: []u8) ?usize {
            _ = ctx;
            // Stub "signature" = first 32 bytes of the signing input echoed.
            const n = @min(signing_input.len, @min(out_sig.len, @as(usize, 32)));
            @memcpy(out_sig[0..n], signing_input[0..n]);
            return n;
        }
    };
    const relay = try identity.PeerId.random();
    const client_peer = try identity.PeerId.random();
    var srv = Server.init(a, .{
        .relay_addrs = &.{"/ip4/203.0.113.1/udp/4001/quic-v1"},
        .public_key_pb = "fake-public-key-bytes",
        .sign_fn = SignStub.sign,
    }, relay);
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
    try std.testing.expect(resp.reservation != null);
    const voucher = resp.reservation.?.voucher orelse return error.NoVoucher;
    try std.testing.expect(voucher.len > 0);
}

test "hop connect on handleHopStream returns unexpected_message" {
    const a = std.testing.allocator;
    const relay = try identity.PeerId.random();
    const client_peer = try identity.PeerId.random();
    var srv = Server.init(a, .{}, relay);
    defer srv.deinit();

    const req = try wire.encodeHop(a, .{
        .msg_type = .connect,
        .peer = .{ .id = "target-id" },
    });
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
    try std.testing.expectEqual(wire.Status.unexpected_message, resp.status.?);
}

test "reserve_accept_fn returning false refuses reservation" {
    const a = std.testing.allocator;
    const Reject = struct {
        fn no(ctx: ?*anyopaque, peer: identity.PeerId) bool {
            _ = ctx;
            _ = peer;
            return false;
        }
    };
    const relay = try identity.PeerId.random();
    const client_peer = try identity.PeerId.random();
    var srv = Server.init(a, .{
        .reserve_accept_fn = Reject.no,
    }, relay);
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
    try std.testing.expectEqual(wire.Status.reservation_refused, resp.status.?);
    try std.testing.expectEqual(@as(usize, 0), srv.store.reservationCount());
}
