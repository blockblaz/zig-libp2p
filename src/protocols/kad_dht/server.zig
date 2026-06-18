//! kad-dht inbound RPC handler (#93).

const std = @import("std");
const Io = std.Io;
const wire = @import("wire.zig");
const keyspace = @import("keyspace.zig");
const routing_table = @import("routing_table.zig");
const record_store = @import("record_store.zig");
const mode = @import("mode.zig");

pub const Error = wire.Error || std.mem.Allocator.Error || error{
    IoReadFailed,
    IoWriteFailed,
    ClientModeRefused,
};

pub const Config = struct {
    limits: wire.Limits = .standard,
    routing: routing_table.Config = .{},
    records: record_store.Config = .{},
    mode: mode.Mode = .server,
    /// Called when a `PUT_VALUE` record fails validation (#198).
    on_validation_reject: ?*const fn (ctx: ?*anyopaque, key: []const u8, value: []const u8) void = null,
    validation_reject_ctx: ?*anyopaque = null,
};

fn encodeFromOwned(allocator: std.mem.Allocator, msg: *const wire.MessageOwned) Error![]u8 {
    var closer = std.ArrayList(wire.PeerView).empty;
    defer closer.deinit(allocator);
    for (msg.closer_peers) |p| {
        try closer.append(allocator, .{
            .id = p.id,
            .addrs = p.addrs,
            .connection = p.connection,
        });
    }
    var providers = std.ArrayList(wire.PeerView).empty;
    defer providers.deinit(allocator);
    for (msg.provider_peers) |p| {
        try providers.append(allocator, .{
            .id = p.id,
            .addrs = p.addrs,
            .connection = p.connection,
        });
    }
    return try wire.encode(allocator, .{
        .msg_type = msg.msg_type,
        .key = msg.key,
        .record = if (msg.record) |r| wire.RecordView{
            .key = r.key,
            .value = r.value,
            .time_received = r.time_received,
        } else null,
        .closer_peers = closer.items,
        .provider_peers = providers.items,
    });
}

pub const Server = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    local_id: []u8,
    routing: routing_table.RoutingTable,
    records: record_store.RecordStore,

    pub fn init(allocator: std.mem.Allocator, local_id: []const u8, cfg: Config) std.mem.Allocator.Error!Server {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .local_id = try allocator.dupe(u8, local_id),
            .routing = routing_table.RoutingTable.init(allocator, local_id, cfg.routing),
            .records = record_store.RecordStore.init(allocator, cfg.records),
        };
    }

    pub fn deinit(self: *Server) void {
        self.routing.deinit();
        self.records.deinit();
        self.allocator.free(self.local_id);
    }

    pub fn routingTable(self: *Server) *routing_table.RoutingTable {
        return &self.routing;
    }

    pub fn recordStore(self: *Server) *record_store.RecordStore {
        return &self.records;
    }

    fn peersToWire(self: *Server, nearest: []routing_table.NearestQuery) std.mem.Allocator.Error![]wire.PeerView {
        var out = std.ArrayList(wire.PeerView).empty;
        defer out.deinit(self.allocator);
        for (nearest) |n| {
            try out.append(self.allocator, .{
                .id = n.id,
                .addrs = n.addrs,
                .connection = .connected,
            });
        }
        return try out.toOwnedSlice(self.allocator);
    }

    fn encodeDecodeOwned(self: *Server, view: wire.MessageView) Error!wire.MessageOwned {
        const bytes = try wire.encode(self.allocator, view);
        defer self.allocator.free(bytes);
        return try wire.decodeOwned(self.allocator, bytes, self.cfg.limits);
    }

    fn handleMessage(self: *Server, req: wire.MessageOwned, now_ms: i64) Error!wire.MessageOwned {
        self.records.purgeExpired(now_ms);
        switch (req.msg_type) {
            .find_node => {
                const key = req.key orelse return error.MissingRequiredField;
                const target = keyspace.hashKey(key);
                const nearest = try self.routing.nearestPeers(target, self.cfg.routing.k);
                defer self.routing.freeNearestPeers(nearest);
                const peers = try self.peersToWire(nearest);
                defer self.allocator.free(peers);
                const wire_bytes = try wire.encode(self.allocator, .{
                    .msg_type = .find_node,
                    .key = key,
                    .closer_peers = peers,
                });
                defer self.allocator.free(wire_bytes);
                return try wire.decodeOwned(self.allocator, wire_bytes, self.cfg.limits);
            },
            .get_providers => {
                const key = req.key orelse return error.MissingRequiredField;
                const target = keyspace.hashKey(key);
                const nearest = try self.routing.nearestPeers(target, self.cfg.routing.k);
                defer self.routing.freeNearestPeers(nearest);
                const closer = try self.peersToWire(nearest);
                defer self.allocator.free(closer);

                var provider_views = std.ArrayList(wire.PeerView).empty;
                defer provider_views.deinit(self.allocator);
                for (self.records.getProviders(key, now_ms)) |p| {
                    var addr_views: std.ArrayList([]const u8) = .empty;
                    defer addr_views.deinit(self.allocator);
                    for (p.addrs) |a| try addr_views.append(self.allocator, a);
                    try provider_views.append(self.allocator, .{
                        .id = p.id,
                        .addrs = addr_views.items,
                        .connection = .connected,
                    });
                }

                const wire_bytes = try wire.encode(self.allocator, .{
                    .msg_type = .get_providers,
                    .key = key,
                    .closer_peers = closer,
                    .provider_peers = provider_views.items,
                });
                defer self.allocator.free(wire_bytes);
                return try wire.decodeOwned(self.allocator, wire_bytes, self.cfg.limits);
            },
            .add_provider => {
                const key = req.key orelse return error.MissingRequiredField;
                for (req.provider_peers) |p| {
                    const id = p.id orelse continue;
                    var addr_views: std.ArrayList([]const u8) = .empty;
                    defer addr_views.deinit(self.allocator);
                    for (p.addrs) |a| try addr_views.append(self.allocator, a);
                    try self.records.addProvider(key, id, addr_views.items, now_ms);
                }
                return try self.encodeDecodeOwned(.{
                    .msg_type = .add_provider,
                    .key = key,
                });
            },
            .put_value => {
                const rec = req.record orelse return error.MissingRequiredField;
                const key = req.key orelse rec.key orelse return error.MissingRequiredField;
                const value = rec.value orelse return error.MissingRequiredField;
                const put_result = try self.records.putValue(key, value, now_ms);
                if (put_result == .rejected) {
                    if (self.cfg.on_validation_reject) |cb| {
                        cb(self.cfg.validation_reject_ctx, key, value);
                    }
                }
                return try self.encodeDecodeOwned(.{
                    .msg_type = .put_value,
                    .key = key,
                    .record = .{ .key = key, .value = value },
                });
            },
            .get_value => {
                const key = req.key orelse return error.MissingRequiredField;
                const target = keyspace.hashKey(key);
                const nearest = try self.routing.nearestPeers(target, self.cfg.routing.k);
                defer self.routing.freeNearestPeers(nearest);
                const closer = try self.peersToWire(nearest);
                defer self.allocator.free(closer);
                const value = self.records.getValue(key, now_ms);
                const wire_bytes = try wire.encode(self.allocator, .{
                    .msg_type = .get_value,
                    .key = key,
                    .record = if (value) |v| self.records.recordView(key, v) else null,
                    .closer_peers = closer,
                });
                defer self.allocator.free(wire_bytes);
                return try wire.decodeOwned(self.allocator, wire_bytes, self.cfg.limits);
            },
            .ping => {
                return try self.encodeDecodeOwned(.{ .msg_type = .ping });
            },
        }
    }

    pub fn handleStream(self: *Server, r: *Io.Reader, w: *Io.Writer, now_ms: i64) Error!void {
        if (self.cfg.mode == .client) return error.ClientModeRefused;
        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);
        var req = try wire.decodeOwned(self.allocator, frame, self.cfg.limits);
        defer req.deinit(self.allocator);
        var resp = try self.handleMessage(req, now_ms);
        defer resp.deinit(self.allocator);
        const out = try encodeFromOwned(self.allocator, &resp);
        defer self.allocator.free(out);
        wire.writeLengthPrefixed(w, out) catch return error.IoWriteFailed;
    }
};

test "put_value rejects invalid ipns records" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x44);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const peer = try @import("../../primitives/keypair.zig").peerIdFromKeyPair(a, .{ .ed25519 = kp });
    var b58_buf: [128]u8 = undefined;
    const b58 = try peer.toBase58(&b58_buf);
    const key = try std.fmt.allocPrint(a, "/ipns/{s}", .{b58});
    defer a.free(key);

    var reg = @import("record_validator.zig").Registry.init(a);
    defer reg.deinit();
    var alloc_slot = a;
    try @import("ipns_validator.zig").register(&reg, &alloc_slot);

    var stats: @import("record_validator.zig").Stats = .{};
    var server = try Server.init(a, "local-node", .{
        .records = .{ .validators = &reg, .validation_stats = &stats },
    });
    defer server.deinit();

    const good = try @import("ipns_validator.zig").buildSignedRecord(a, kp, 1, "/ipfs/bafy", "2099-12-31T23:59:59.000000000Z");
    defer a.free(good);
    const req_good = try wire.encode(a, .{
        .msg_type = .put_value,
        .key = key,
        .record = .{ .key = key, .value = good },
    });
    defer a.free(req_good);
    var req1 = try wire.decodeOwned(a, req_good, .standard);
    defer req1.deinit(a);
    var resp1 = try server.handleMessage(req1, 0);
    defer resp1.deinit(a);
    try std.testing.expect(server.records.getValue(key, 0) != null);
    try std.testing.expectEqual(@as(u64, 1), stats.accepted);

    const req_bad = try wire.encode(a, .{
        .msg_type = .put_value,
        .key = key,
        .record = .{ .key = key, .value = "not-ipns" },
    });
    defer a.free(req_bad);
    var req2 = try wire.decodeOwned(a, req_bad, .standard);
    defer req2.deinit(a);
    var resp2 = try server.handleMessage(req2, 0);
    defer resp2.deinit(a);
    try std.testing.expectEqual(@as(u64, 1), stats.rejected);
}

test "server find_node returns closest peers" {
    const a = std.testing.allocator;
    var server = try Server.init(a, "local-node", .{});
    defer server.deinit();
    const addr = [_][]const u8{"/ip4/10.0.0.1/udp/4001/quic-v1"};
    _ = try server.routing.update("peer-1", &addr, .server, 0);
    _ = try server.routing.update("peer-2", &addr, .server, 0);

    const req_wire = try wire.encode(a, .{ .msg_type = .find_node, .key = "target-peer" });
    defer a.free(req_wire);
    var req = try wire.decodeOwned(a, req_wire, .standard);
    defer req.deinit(a);
    var resp = try server.handleMessage(req, 0);
    defer resp.deinit(a);
    try std.testing.expect(resp.closer_peers.len > 0);
}
