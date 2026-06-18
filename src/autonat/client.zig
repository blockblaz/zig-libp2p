//! AutoNAT client: probe scheduling and reachability aggregation (#92, #206).

const std = @import("std");
const wire = @import("wire.zig");
const policy = @import("policy.zig");
const identity = @import("../identity.zig");

pub const Error = wire.Error || std.mem.Allocator.Error;

pub const Config = struct {
    policy: policy.Config = .{},
    /// Milliseconds between active probe rounds (#206).
    probe_interval_ms: u64 = 60 * 1000,
    /// Parallel v1 probes per round (#206).
    parallel_probes: u32 = 3,
    limits: wire.Limits = .standard,
};

/// Result of [`Client.poll`]: embedder should open a stream and send the message.
pub const OutboundProbe = struct {
    version: enum { v1, v2 },
    wire_message: []const u8,
    nonce: u64 = 0,
};

pub const ScheduledProbe = struct {
    peer: identity.PeerId,
    probe: OutboundProbe,
};

pub const ReachabilityChange = struct {
    addr: []const u8,
    status: policy.NatStatus,
};

const PendingProbe = struct {
    peer: identity.PeerId,
    probe: OutboundProbe,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    tracker: policy.ReachabilityTracker,
    addr_trackers: std.StringHashMap(policy.AddressReachability),
    pending_probes: std.ArrayList(PendingProbe) = .empty,
    pending_changes: std.ArrayList(ReachabilityChange) = .empty,
    pending_nonce: ?u64 = null,
    last_node_status: policy.NatStatus = .unknown,
    next_probe_ms: i64 = 0,
    probe_round_seed: u64 = 1,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Client {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .tracker = policy.ReachabilityTracker.init(),
            .addr_trackers = std.StringHashMap(policy.AddressReachability).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        for (self.pending_probes.items) |p| self.freeProbeMessage(p.probe.wire_message);
        self.pending_probes.deinit(self.allocator);
        for (self.pending_changes.items) |c| self.allocator.free(c.addr);
        self.pending_changes.deinit(self.allocator);
        var kit = self.addr_trackers.keyIterator();
        while (kit.next()) |k| self.allocator.free(k.*);
        self.addr_trackers.deinit();
    }

    pub fn natStatus(self: *const Client) policy.NatStatus {
        return self.tracker.natStatus(self.cfg.policy);
    }

    pub fn addressStatus(self: *Client, addr_key: []const u8) policy.NatStatus {
        const tracker = self.addr_trackers.getPtr(addr_key) orelse return .unknown;
        return tracker.status(self.cfg.policy);
    }

    /// Take queued reachability changes (caller frees addrs via [`freeReachabilityChange`]).
    pub fn takeReachabilityChanges(self: *Client) []ReachabilityChange {
        const out = self.pending_changes.toOwnedSlice(self.allocator) catch {
            self.pending_changes.clearRetainingCapacity();
            return &.{};
        };
        self.pending_changes.clearRetainingCapacity();
        return out;
    }

    pub fn freeReachabilityChanges(self: *Client, changes: []ReachabilityChange) void {
        for (changes) |c| self.allocator.free(c.addr);
        self.allocator.free(changes);
    }

    pub fn hasPendingProbe(self: *const Client, peer: identity.PeerId) bool {
        for (self.pending_probes.items) |p| {
            if (p.peer.eql(&peer)) return true;
        }
        return false;
    }

    pub fn takePendingProbe(self: *Client, peer: identity.PeerId) ?OutboundProbe {
        var i: usize = 0;
        while (i < self.pending_probes.items.len) {
            if (self.pending_probes.items[i].peer.eql(&peer)) {
                const p = self.pending_probes.swapRemove(i);
                return p.probe;
            }
            i += 1;
        }
        return null;
    }

    /// Schedule up to `parallel_probes` v1 Dial probes against `servers` (#206).
    pub fn scheduleActiveProbes(
        self: *Client,
        now_ms: i64,
        local_peer: identity.PeerId,
        servers: []const identity.PeerId,
        listen_addrs: []const []const u8,
    ) Error!void {
        if (now_ms < self.next_probe_ms) return;
        if (listen_addrs.len == 0 or servers.len == 0) return;

        self.next_probe_ms = now_ms + @as(i64, @intCast(self.cfg.probe_interval_ms));
        self.probe_round_seed +%= 0x9E3779B97F4A7C15;

        const want = @min(self.cfg.parallel_probes, @as(u32, @intCast(servers.len)));
        if (servers.len <= want) {
            for (servers) |peer| {
                const probe = try self.encodeV1Probe(local_peer, listen_addrs);
                try self.pending_probes.append(self.allocator, .{ .peer = peer, .probe = probe });
            }
            return;
        }

        var picked = std.ArrayList(identity.PeerId).empty;
        defer picked.deinit(self.allocator);

        var prng = std.Random.DefaultPrng.init(self.probe_round_seed);
        const rand = prng.random();
        var mask: u64 = 0;
        var n: u32 = 0;
        while (n < want) : (n += 1) {
            const idx = rand.intRangeLessThan(usize, 0, servers.len);
            const bit: u64 = @as(u64, 1) << @intCast(idx % 64);
            if (mask & bit != 0) continue;
            mask |= bit;
            try picked.append(self.allocator, servers[idx]);
        }

        for (picked.items) |peer| {
            const probe = try self.encodeV1Probe(local_peer, listen_addrs);
            try self.pending_probes.append(self.allocator, .{ .peer = peer, .probe = probe });
        }
    }

    fn encodeV1Probe(self: *Client, peer_id: identity.PeerId, addrs: []const []const u8) Error!OutboundProbe {
        var pid_buf: [128]u8 = undefined;
        const peer_id_bytes = peer_id.toBytes(&pid_buf) catch return error.MessageTooLarge;
        const payload = try wire.encodeV1(self.allocator, .{
            .dial = .{ .peer_id = peer_id_bytes, .addrs = addrs },
        });
        return .{ .version = .v1, .wire_message = payload };
    }

    /// Legacy single-probe API (embedder-driven).
    pub fn poll(
        self: *Client,
        now_ms: i64,
        peer_id: identity.PeerId,
        candidate_addrs: []const []const u8,
        use_v2: bool,
    ) Error!?OutboundProbe {
        if (now_ms < self.next_probe_ms) return null;
        if (candidate_addrs.len == 0) return null;
        self.next_probe_ms = now_ms + @as(i64, @intCast(self.cfg.probe_interval_ms));

        if (use_v2) {
            var filtered = std.ArrayList([]const u8).empty;
            defer filtered.deinit(self.allocator);
            for (candidate_addrs) |addr| {
                if (policy.v2ClientAddrAllowed(self.allocator, addr)) {
                    try filtered.append(self.allocator, addr);
                }
            }
            if (filtered.items.len == 0) return null;

            var nonce: u64 = undefined;
            policy.fillRandomU64(&nonce);
            self.pending_nonce = nonce;

            const payload = try wire.encodeV2RequestMessage(self.allocator, .{
                .dial_request = .{ .addrs = filtered.items, .nonce = nonce },
            });
            return .{ .version = .v2, .wire_message = payload, .nonce = nonce };
        }

        return try self.encodeV1Probe(peer_id, candidate_addrs);
    }

    pub fn handleV1DialResponse(self: *Client, resp: wire.V1DialResponse, listen_addrs: []const []const u8) !void {
        const outcome: policy.ProbeOutcome = switch (resp.status) {
            .ok => .success,
            .e_dial_error => .failure,
            else => return,
        };
        const prev = self.natStatus();
        self.tracker.record(outcome);
        const next = self.natStatus();
        if (prev != next) {
            for (listen_addrs) |addr| {
                try self.queueReachabilityChange(addr, next);
            }
        }
    }

    pub fn handleV2DialResponse(self: *Client, resp: wire.V2DialResponse, addr_key: []const u8) !void {
        if (resp.status != .ok) return;
        const outcome: policy.ProbeOutcome = switch (resp.dial_status) {
            .ok => .success,
            .e_dial_error, .e_dial_back_error => .failure,
            .unused => return,
        };
        const prev_node = self.natStatus();
        self.tracker.record(outcome);
        // getOrPut with the borrowed key; on first insert replace the key slot
        // with an owned dup so it survives the caller's buffer and is freed in
        // deinit. Dup only on insert — duping unconditionally leaks on every
        // repeat probe for an existing address.
        const gop = try self.addr_trackers.getOrPut(addr_key);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, addr_key) catch |e| {
                self.addr_trackers.removeByPtr(gop.key_ptr);
                return e;
            };
            gop.value_ptr.* = policy.AddressReachability.init();
        }
        const prev_addr = gop.value_ptr.status(self.cfg.policy);
        gop.value_ptr.record(outcome);
        const next_addr = gop.value_ptr.status(self.cfg.policy);
        if (prev_addr != next_addr) {
            try self.queueReachabilityChange(addr_key, next_addr);
        }
        const next_node = self.natStatus();
        if (prev_node != next_node) self.last_node_status = next_node;
    }

    fn queueReachabilityChange(self: *Client, addr: []const u8, status: policy.NatStatus) !void {
        const owned = try self.allocator.dupe(u8, addr);
        try self.pending_changes.append(self.allocator, .{ .addr = owned, .status = status });
    }

    pub fn handleV2DialBack(self: *Client, back: wire.V2DialBack) Error!?[]u8 {
        const expected = self.pending_nonce orelse return null;
        if (back.nonce != expected) return null;
        return try wire.encodeV2DialBackResponse(self.allocator, .{ .status = .ok });
    }

    pub fn freeProbeMessage(self: *Client, msg: []const u8) void {
        self.allocator.free(msg);
    }
};

test "client v1 probe encodes dial" {
    const a = std.testing.allocator;
    var client = Client.init(a, .{});
    defer client.deinit();

    const me = try identity.PeerId.random();
    const addrs = [_][]const u8{"/ip4/203.0.113.1/udp/4001/quic-v1"};
    const probe = (try client.poll(0, me, &addrs, false)).?;
    defer client.freeProbeMessage(probe.wire_message);
    try std.testing.expectEqual(.v1, probe.version);
}

test "scheduleActiveProbes queues pending" {
    const a = std.testing.allocator;
    var client = Client.init(a, .{ .parallel_probes = 2 });
    defer client.deinit();

    const me = try identity.PeerId.random();
    const s0 = try identity.PeerId.random();
    const s1 = try identity.PeerId.random();
    const servers = [_]identity.PeerId{ s0, s1 };
    const addrs = [_][]const u8{"/ip4/203.0.113.1/udp/4001/quic-v1"};

    try client.scheduleActiveProbes(0, me, &servers, &addrs);
    const p0 = client.takePendingProbe(s0).?;
    defer client.freeProbeMessage(p0.wire_message);
    const p1 = client.takePendingProbe(s1).?;
    defer client.freeProbeMessage(p1.wire_message);
    try std.testing.expectEqual(.v1, p0.version);
}

test "v2 addr tracker dups key once and frees on deinit" {
    // Exercises the addr_trackers path under the GPA leak check: repeated
    // probes for the same address must not leak a dup each call, and all keys
    // must be freed at deinit.
    const a = std.testing.allocator;
    var client = Client.init(a, .{ .policy = .{ .confidence_threshold = 1, .failure_threshold = 3 } });
    defer client.deinit();

    const addr = "/ip4/203.0.113.7/udp/4001/quic-v1";
    try client.handleV2DialResponse(.{ .status = .ok, .dial_status = .ok }, addr);
    try client.handleV2DialResponse(.{ .status = .ok, .dial_status = .ok }, addr);
    try client.handleV2DialResponse(.{ .status = .ok, .dial_status = .e_dial_error }, "/ip4/198.51.100.2/udp/4001/quic-v1");
    try std.testing.expectEqual(policy.NatStatus.public, client.addressStatus(addr));

    const changes = client.takeReachabilityChanges();
    defer client.freeReachabilityChanges(changes);
}

test "v1 response quorum emits reachability change" {
    const a = std.testing.allocator;
    var client = Client.init(a, .{ .policy = .{ .confidence_threshold = 1, .failure_threshold = 3 } });
    defer client.deinit();

    const addrs = [_][]const u8{"/ip4/203.0.113.1/udp/4001/quic-v1"};
    try client.handleV1DialResponse(.{ .status = .ok }, &addrs);
    const changes = client.takeReachabilityChanges();
    defer client.freeReachabilityChanges(changes);
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqual(policy.NatStatus.public, changes[0].status);
}
