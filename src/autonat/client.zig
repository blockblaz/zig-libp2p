//! AutoNAT client: probe scheduling and reachability aggregation (#92).

const std = @import("std");
const wire = @import("wire.zig");
const policy = @import("policy.zig");
const identity = @import("../identity.zig");

pub const Error = wire.Error || std.mem.Allocator.Error;

pub const Config = struct {
    policy: policy.Config = .{},
    /// Milliseconds between periodic re-probes.
    reprobe_interval_ms: u64 = 5 * 60 * 1000,
    limits: wire.Limits = .standard,
};

/// Result of [`Client.poll`]: embedder should open a stream and send the message.
pub const OutboundProbe = struct {
    version: enum { v1, v2 },
    /// v1: dial message bytes; v2: dial-request message bytes (length-prefixed by embedder).
    wire_message: []const u8,
    /// v2 only: nonce echoed on inbound dial-back.
    nonce: u64 = 0,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    tracker: policy.ReachabilityTracker = .{},
    addr_trackers: std.StringHashMap(policy.AddressReachability),
    pending_nonce: ?u64 = null,
    last_probe_ms: i64 = 0,
    next_probe_ms: i64 = 0,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Client {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .addr_trackers = std.StringHashMap(policy.AddressReachability).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        self.addr_trackers.deinit();
    }

    pub fn natStatus(self: *const Client) policy.NatStatus {
        return self.tracker.natStatus(self.cfg.policy);
    }

    pub fn addressStatus(self: *Client, addr_key: []const u8) policy.NatStatus {
        const gop = self.addr_trackers.getPtr(addr_key) orelse return .unknown;
        return gop.value.status(self.cfg.policy);
    }

    pub fn scheduleProbe(self: *Client, now_ms: i64) void {
        self.next_probe_ms = now_ms;
    }

    /// Returns an outbound probe when due. Caller frees `wire_message` after send.
    pub fn poll(
        self: *Client,
        now_ms: i64,
        peer_id: identity.PeerId,
        candidate_addrs: []const []const u8,
        use_v2: bool,
    ) Error!?OutboundProbe {
        if (now_ms < self.next_probe_ms) return null;
        if (candidate_addrs.len == 0) return null;

        self.last_probe_ms = now_ms;
        self.next_probe_ms = now_ms + @as(i64, @intCast(self.cfg.reprobe_interval_ms));

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
            return .{
                .version = .v2,
                .wire_message = payload,
                .nonce = nonce,
            };
        }

        var pid_buf: [128]u8 = undefined;
        const peer_id_bytes = peer_id.toBytes(&pid_buf) catch return error.MessageTooLarge;

        const payload = try wire.encodeV1(self.allocator, .{
            .dial = .{ .peer_id = peer_id_bytes, .addrs = candidate_addrs },
        });
        return .{
            .version = .v1,
            .wire_message = payload,
        };
    }

    pub fn handleV1DialResponse(self: *Client, resp: wire.V1DialResponse) void {
        switch (resp.status) {
            .ok => self.tracker.record(.success),
            .e_dial_error => self.tracker.record(.failure),
            else => {},
        }
    }

    pub fn handleV2DialResponse(self: *Client, resp: wire.V2DialResponse, addr_key: []const u8) !void {
        if (resp.status != .ok) return;
        const outcome: policy.ProbeOutcome = switch (resp.dial_status) {
            .ok => .success,
            .e_dial_error, .e_dial_back_error => .failure,
            .unused => return,
        };
        self.tracker.record(outcome);
        const gop = try self.addr_trackers.getOrPut(addr_key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.record(outcome);
    }

    /// Inbound v2 dial-back on `/libp2p/autonat/2/dial-back`. Returns response wire bytes.
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
    const decoded = try wire.decodeV1Owned(a, probe.wire_message, .standard);
    defer wire.freeV1Owned(a, decoded);
    switch (decoded) {
        .dial => |d| {
            try std.testing.expectEqual(@as(usize, 1), d.addrs.len);
        },
        else => try std.testing.expect(false),
    }
}
