//! Rendezvous client: register, unregister, discover (#209).

const std = @import("std");
const Io = std.Io;
const wire = @import("wire.zig");
const identity = @import("../identity.zig");
const identify_mod = @import("../identify.zig");
const pid = @import("peer_id");

pub const Error = wire.Error || identify_mod.Error || error{
    IoReadFailed,
    IoWriteFailed,
    RequestRejected,
} || std.mem.Allocator.Error;

pub const Config = struct {
    limits: wire.Limits = .standard,
};

pub const DiscoveredPeer = struct {
    peer: identity.PeerId,
    namespace: []u8,
    addrs: [][]u8,
    signed_peer_record: []u8,
    ttl_s: u64,

    pub fn deinit(self: *DiscoveredPeer, allocator: std.mem.Allocator) void {
        allocator.free(self.namespace);
        for (self.addrs) |a| allocator.free(a);
        allocator.free(self.addrs);
        allocator.free(self.signed_peer_record);
        self.* = undefined;
    }
};

pub const DiscoverResult = struct {
    peers: []DiscoveredPeer,
    cookie: ?[]u8,

    pub fn deinit(self: *DiscoverResult, allocator: std.mem.Allocator) void {
        for (self.peers) |*p| p.deinit(allocator);
        allocator.free(self.peers);
        if (self.cookie) |c| allocator.free(c);
        self.* = .{ .peers = &.{}, .cookie = null };
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    cfg: Config,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Client {
        return .{ .allocator = allocator, .cfg = cfg };
    }

    fn writeMessage(self: *Client, w: *Io.Writer, msg: wire.MessageView) Error!void {
        const payload = try wire.encode(self.allocator, msg);
        defer self.allocator.free(payload);
        wire.writeLengthPrefixed(w, payload) catch return error.IoWriteFailed;
    }

    fn parseSignedPeerRecord(
        self: *Client,
        spr: []const u8,
    ) Error!struct { peer: identity.PeerId, rec: identify_mod.PeerRecordOwned } {
        var env = try identify_mod.decodeSignedEnvelope(self.allocator, spr);
        defer env.deinit(self.allocator);
        const reader = pid.PublicKeyReader.init(env.public_key) catch return error.BadSignature;
        const key_dup = try self.allocator.dupe(u8, reader.getData());
        defer self.allocator.free(key_dup);
        var pk = pid.PublicKey{ .type = reader.getType(), .data = key_dup };
        const peer = pid.PeerId.fromPublicKey(self.allocator, &pk) catch return error.BadSignature;
        const rec = try identify_mod.verifySignedPeerRecord(self.allocator, spr, peer);
        return .{ .peer = peer, .rec = rec };
    }

    fn readMessage(self: *Client, r: *Io.Reader) Error!wire.MessageOwned {
        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);
        return try wire.decodeOwned(self.allocator, frame, self.cfg.limits);
    }

    pub fn writeRegister(
        self: *Client,
        w: *Io.Writer,
        namespace: []const u8,
        signed_peer_record: []const u8,
        ttl_s: ?u64,
    ) Error!void {
        try self.writeMessage(w, .{
            .register = .{
                .ns = namespace,
                .signed_peer_record = signed_peer_record,
                .ttl = ttl_s,
            },
        });
    }

    pub fn readRegisterResponse(self: *Client, r: *Io.Reader) Error!u64 {
        var resp = try self.readMessage(r);
        defer resp.deinit(self.allocator);
        const rr = resp.register_response;
        if (rr.status != .ok) return error.RequestRejected;
        return rr.ttl orelse wire.default_ttl_s;
    }

    pub fn register(
        self: *Client,
        w: *Io.Writer,
        r: *Io.Reader,
        namespace: []const u8,
        signed_peer_record: []const u8,
        ttl_s: ?u64,
    ) Error!u64 {
        try self.writeRegister(w, namespace, signed_peer_record, ttl_s);
        return try self.readRegisterResponse(r);
    }

    pub fn writeUnregister(self: *Client, w: *Io.Writer, namespace: []const u8) Error!void {
        try self.writeMessage(w, .{ .unregister = .{ .ns = namespace } });
    }

    pub fn unregister(self: *Client, w: *Io.Writer, namespace: []const u8) Error!void {
        try self.writeUnregister(w, namespace);
    }

    pub fn writeDiscover(
        self: *Client,
        w: *Io.Writer,
        namespace: ?[]const u8,
        cookie: ?[]const u8,
        limit: ?u64,
    ) Error!void {
        try self.writeMessage(w, .{
            .discover = .{ .ns = namespace, .cookie = cookie, .limit = limit },
        });
    }

    pub fn readDiscoverResponse(self: *Client, r: *Io.Reader) Error!DiscoverResult {
        var resp = try self.readMessage(r);
        defer resp.deinit(self.allocator);
        const dr = resp.discover_response;
        if (dr.status) |st| {
            if (st != .ok) return error.RequestRejected;
        }

        var peers = std.ArrayList(DiscoveredPeer).empty;
        errdefer {
            for (peers.items) |*p| p.deinit(self.allocator);
            peers.deinit(self.allocator);
        }

        for (dr.registrations) |reg| {
            const spr = reg.signed_peer_record orelse continue;
            var parsed = self.parseSignedPeerRecord(spr) catch continue;
            defer parsed.rec.deinit(self.allocator);

            var addrs = std.ArrayList([]u8).empty;
            errdefer {
                for (addrs.items) |a| self.allocator.free(a);
                addrs.deinit(self.allocator);
            }
            for (parsed.rec.addresses) |addr| try addrs.append(self.allocator, try self.allocator.dupe(u8, addr));

            const ns = reg.ns orelse continue;
            try peers.append(self.allocator, .{
                .peer = parsed.peer,
                .namespace = try self.allocator.dupe(u8, ns),
                .addrs = try addrs.toOwnedSlice(self.allocator),
                .signed_peer_record = try self.allocator.dupe(u8, spr),
                .ttl_s = reg.ttl orelse wire.default_ttl_s,
            });
        }

        return .{
            .peers = try peers.toOwnedSlice(self.allocator),
            .cookie = if (dr.cookie) |c| try self.allocator.dupe(u8, c) else null,
        };
    }

    pub fn discover(
        self: *Client,
        w: *Io.Writer,
        r: *Io.Reader,
        namespace: ?[]const u8,
        cookie: ?[]const u8,
        limit: ?u64,
    ) Error!DiscoverResult {
        try self.writeDiscover(w, namespace, cookie, limit);
        return try self.readDiscoverResponse(r);
    }
};

test "client register and discover against server" {
    const a = std.testing.allocator;

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x77);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    var pk = identity.PublicKey{ .type = .ED25519, .data = &kp.public_key.bytes };
    const peer = try identity.PeerId.fromPublicKey(a, &pk);

    var peer_id_buf: [128]u8 = undefined;
    const peer_id_bytes = try peer.toBytes(&peer_id_buf);
    const rec_wire = try identify_mod.encodePeerRecordTestWire(a, peer_id_bytes, 1);
    defer a.free(rec_wire);
    const spr = try identify_mod.encodeSignedPeerRecordTestWire(a, kp, rec_wire, .{});
    defer a.free(spr);

    var server = @import("server.zig").Server.init(a, .{});
    defer server.deinit();
    var client = Client.init(a, .{});

    var req_buf: [8192]u8 = undefined;
    var resp_buf: [8192]u8 = undefined;

    var req_w = Io.Writer.fixed(&req_buf);
    try client.writeRegister(&req_w, "lean-net", spr, null);

    var srv_r = Io.Reader.fixed(req_buf[0..req_w.end]);
    var srv_w = Io.Writer.fixed(&resp_buf);
    try server.handleStream(&srv_r, &srv_w, peer, 0);

    var cli_r = Io.Reader.fixed(resp_buf[0..srv_w.end]);
    _ = try client.readRegisterResponse(&cli_r);

    @memset(&req_buf, 0);
    @memset(&resp_buf, 0);
    req_w = Io.Writer.fixed(&req_buf);
    try client.writeDiscover(&req_w, "lean-net", null, null);

    srv_r = Io.Reader.fixed(req_buf[0..req_w.end]);
    srv_w = Io.Writer.fixed(&resp_buf);
    try server.handleStream(&srv_r, &srv_w, peer, 0);

    cli_r = Io.Reader.fixed(resp_buf[0..srv_w.end]);
    var result = try client.readDiscoverResponse(&cli_r);
    defer result.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), result.peers.len);
}
