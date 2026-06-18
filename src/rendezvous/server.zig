//! Rendezvous server: REGISTER / UNREGISTER / DISCOVER (#209).

const std = @import("std");
const Io = std.Io;
const wire = @import("wire.zig");
const store_mod = @import("store.zig");
const identity = @import("../identity.zig");
const identify_mod = @import("../identify.zig");

pub const Error = wire.Error || store_mod.Error || identify_mod.Error || error{
    IoReadFailed,
    IoWriteFailed,
    NotAuthorized,
} || std.mem.Allocator.Error;

pub const Config = struct {
    limits: wire.Limits = .standard,
    store: store_mod.Config = .{},
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    store: store_mod.Store,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Server {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .store = store_mod.Store.init(allocator, cfg.store),
        };
    }

    pub fn deinit(self: *Server) void {
        self.store.deinit();
    }

    pub fn registrationStore(self: *Server) *store_mod.Store {
        return &self.store;
    }

    fn writeMessage(self: *Server, w: *Io.Writer, msg: wire.MessageView) Error!void {
        const payload = try wire.encode(self.allocator, msg);
        defer self.allocator.free(payload);
        wire.writeLengthPrefixed(w, payload) catch return error.IoWriteFailed;
    }

    fn verifyRegistration(
        self: *Server,
        transport_peer: identity.PeerId,
        spr_wire: []const u8,
    ) Error!identify_mod.PeerRecordOwned {
        return identify_mod.verifySignedPeerRecord(self.allocator, spr_wire, transport_peer);
    }

    pub fn handleStream(
        self: *Server,
        r: *Io.Reader,
        w: *Io.Writer,
        transport_peer: identity.PeerId,
        now_ms: i64,
    ) Error!void {
        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);

        var msg = try wire.decodeOwned(self.allocator, frame, self.cfg.limits);
        defer msg.deinit(self.allocator);

        switch (msg) {
            .register => |reg| {
                const ns = reg.ns orelse {
                    try self.writeMessage(w, .{
                        .register_response = .{ .status = .e_invalid_namespace },
                    });
                    return;
                };
                const spr = reg.signed_peer_record orelse {
                    try self.writeMessage(w, .{
                        .register_response = .{ .status = .e_invalid_signed_peer_record },
                    });
                    return;
                };

                var peer_rec = self.verifyRegistration(transport_peer, spr) catch {
                    try self.writeMessage(w, .{
                        .register_response = .{ .status = .e_invalid_signed_peer_record },
                    });
                    return;
                };
                defer peer_rec.deinit(self.allocator);

                const ttl = reg.ttl orelse wire.default_ttl_s;
                var added = self.store.add(transport_peer, ns, spr, ttl, now_ms) catch |e| switch (e) {
                    error.InvalidNamespace => {
                        try self.writeMessage(w, .{ .register_response = .{ .status = .e_invalid_namespace } });
                        return;
                    },
                    error.InvalidMessageType => {
                        try self.writeMessage(w, .{ .register_response = .{ .status = .e_invalid_ttl } });
                        return;
                    },
                    error.Unavailable => {
                        try self.writeMessage(w, .{ .register_response = .{ .status = .e_unavailable } });
                        return;
                    },
                    else => |x| return x,
                };
                defer added.deinit(self.allocator);

                try self.writeMessage(w, .{
                    .register_response = .{ .status = .ok, .ttl = added.ttl_s },
                });
            },
            .unregister => |unreg| {
                if (unreg.ns) |ns| self.store.remove(transport_peer, ns);
            },
            .discover => |disc| {
                const result = self.store.discover(disc.ns, disc.cookie, disc.limit, now_ms) catch {
                    try self.writeMessage(w, .{
                        .discover_response = .{
                            .status = .e_invalid_cookie,
                            .registrations = &.{},
                        },
                    });
                    return;
                };
                defer self.store.freeDiscoverResult(result);

                var reg_views = std.ArrayList(wire.RegisterView).empty;
                defer reg_views.deinit(self.allocator);
                for (result.registrations) |entry| {
                    try reg_views.append(self.allocator, .{
                        .ns = entry.namespace,
                        .signed_peer_record = entry.signed_peer_record,
                        .ttl = entry.ttl_s,
                    });
                }

                const cookie_wire = try result.cookie.encodeWire(self.allocator);
                defer self.allocator.free(cookie_wire);

                try self.writeMessage(w, .{
                    .discover_response = .{
                        .registrations = reg_views.items,
                        .cookie = cookie_wire,
                        .status = .ok,
                    },
                });
            },
            else => return error.InvalidMessageType,
        }
    }
};

test "register and discover roundtrip" {
    const a = std.testing.allocator;

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    var pk = identity.PublicKey{ .type = .ED25519, .data = &kp.public_key.bytes };
    const peer = try identity.PeerId.fromPublicKey(a, &pk);

    var peer_id_buf: [128]u8 = undefined;
    const peer_id_bytes = try peer.toBytes(&peer_id_buf);
    const rec_wire = try identify_mod.encodePeerRecordTestWire(a, peer_id_bytes, 1);
    defer a.free(rec_wire);
    const spr = try identify_mod.encodeSignedPeerRecordTestWire(a, kp, rec_wire, .{});
    defer a.free(spr);

    var server = Server.init(a, .{});
    defer server.deinit();

    const reg_bytes = try wire.encode(a, .{
        .register = .{ .ns = "my-app", .signed_peer_record = spr, .ttl = wire.default_ttl_s },
    });
    defer a.free(reg_bytes);

    var in_buf: [8192]u8 = undefined;
    var out_buf: [8192]u8 = undefined;
    var w_in = Io.Writer.fixed(&in_buf);
    try wire.writeLengthPrefixed(&w_in, reg_bytes);
    var r = Io.Reader.fixed(in_buf[0..w_in.end]);
    var w_out = Io.Writer.fixed(&out_buf);
    try server.handleStream(&r, &w_out, peer, 0);

    var r_out = Io.Reader.fixed(out_buf[0..w_out.end]);
    const reg_resp_frame = try wire.readLengthPrefixedAlloc(&r_out, a, wire.Limits.standard.max_frame_bytes);
    defer a.free(reg_resp_frame);
    var reg_resp = try wire.decodeOwned(a, reg_resp_frame, .standard);
    defer reg_resp.deinit(a);
    try std.testing.expectEqual(wire.ResponseStatus.ok, reg_resp.register_response.status);

    const disc_bytes = try wire.encode(a, .{ .discover = .{ .ns = "my-app" } });
    defer a.free(disc_bytes);
    @memset(&in_buf, 0);
    @memset(&out_buf, 0);
    w_in = Io.Writer.fixed(&in_buf);
    try wire.writeLengthPrefixed(&w_in, disc_bytes);
    r = Io.Reader.fixed(in_buf[0..w_in.end]);
    w_out = Io.Writer.fixed(&out_buf);
    try server.handleStream(&r, &w_out, peer, 0);

    r_out = Io.Reader.fixed(out_buf[0..w_out.end]);
    const disc_frame = try wire.readLengthPrefixedAlloc(&r_out, a, wire.Limits.standard.max_frame_bytes);
    defer a.free(disc_frame);
    var disc_resp = try wire.decodeOwned(a, disc_frame, .standard);
    defer disc_resp.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), disc_resp.discover_response.registrations.len);
}
