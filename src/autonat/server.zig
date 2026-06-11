//! AutoNAT server: v1/v2 dial-back handlers with embedder-owned transport (#92).

const std = @import("std");
const Io = std.Io;
const wire = @import("wire.zig");
const policy = @import("policy.zig");

pub const Error = wire.Error || std.mem.Allocator.Error || error{
    IoReadFailed,
    IoWriteFailed,
};

/// Embedder performs the actual dial-back (QUIC/TCP/etc.).
pub const DialBackResult = enum {
    ok,
    dial_error,
    dial_back_error,
};

pub const DialBackFn = *const fn (
    ctx: ?*anyopaque,
    addr_bytes: []const u8,
    nonce: u64,
) DialBackResult;

pub const Config = struct {
    limits: wire.Limits = .standard,
    /// v2 amplification minimum (spec: 30 KiB – 100 KiB).
    amplification_min_bytes: u64 = 30 * 1024,
    amplification_max_bytes: u64 = 100 * 1024,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    dial_back: DialBackFn,
    dial_back_ctx: ?*anyopaque = null,

    pub fn init(allocator: std.mem.Allocator, cfg: Config, dial_back: DialBackFn) Server {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .dial_back = dial_back,
        };
    }

    /// Pick the amplification-cost byte count for a v2 dial-back request, uniformly
    /// in `[amplification_min_bytes, amplification_max_bytes]`. Derived deterministically
    /// from the peer nonce so callers don't need an RNG and so replays of the same
    /// nonce reproduce the same cost. The previous `std.math.clamp(min, 1, max)` shape
    /// always returned `min`, leaving `amplification_max_bytes` dead and making the cost
    /// trivially predictable from the config — the spec says the value MAY be randomized
    /// in-range and rust-libp2p does randomize.
    fn pickAmplificationCost(self: *const Server, nonce: u64) u64 {
        const min_b = @max(@as(u64, 1), self.cfg.amplification_min_bytes);
        const max_b = @max(min_b, self.cfg.amplification_max_bytes);
        const span = max_b - min_b;
        if (span == 0) return min_b;
        // Mix the nonce through a SplitMix64 step so adjacent nonces don't yield adjacent
        // costs; cheaper and dependency-free vs threading a std.Random.
        var x: u64 = nonce +% 0x9E3779B97F4A7C15;
        x = (x ^ (x >> 30)) *% 0xBF58476D1CE4E5B9;
        x = (x ^ (x >> 27)) *% 0x94D049BB133111EB;
        x = x ^ (x >> 31);
        return min_b + (x % (span + 1));
    }

    /// v1 inbound: read length-prefixed Dial, perform filtered dial-backs, write response.
    pub fn handleV1Stream(
        self: *Server,
        r: *Io.Reader,
        w: *Io.Writer,
        observed_ip: policy.IpAddr,
        is_relayed: bool,
    ) Error!void {
        if (is_relayed) {
            try self.writeV1Response(w, .{
                .status = .e_dial_refused,
                .status_text = "relayed connection",
            });
            return;
        }

        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);

        const msg = try wire.decodeV1Owned(self.allocator, frame, self.cfg.limits);
        switch (msg) {
            .dial => |d| {
                defer freeV1Dial(self.allocator, d);
                var any_ok = false;
                var ok_addr: ?[]const u8 = null;
                for (d.addrs) |addr| {
                    if (!policy.v1DialAddrAllowed(self.allocator, observed_ip, addr)) continue;
                    const res = self.dial_back(self.dial_back_ctx, addr, 0);
                    if (res == .ok) {
                        any_ok = true;
                        ok_addr = addr;
                        break;
                    }
                }
                if (any_ok) {
                    try self.writeV1Response(w, .{
                        .status = .ok,
                        .addr = ok_addr,
                    });
                } else {
                    try self.writeV1Response(w, .{ .status = .e_dial_error });
                }
            },
            else => try self.writeV1Response(w, .{ .status = .e_bad_request }),
        }
    }

    fn writeV1Response(self: *Server, w: *Io.Writer, resp: wire.V1DialResponse) Error!void {
        const payload = try wire.encodeV1(self.allocator, .{ .dial_response = resp });
        defer self.allocator.free(payload);
        wire.writeLengthPrefixed(w, payload) catch |e| switch (e) {
            error.WriteFailed => return error.IoWriteFailed,
            else => |x| return x,
        };
    }

    /// v2 inbound on `/libp2p/autonat/2/dial-request` stream (single request cycle).
    pub fn handleV2DialRequestStream(
        self: *Server,
        r: *Io.Reader,
        w: *Io.Writer,
        observed_ip: policy.IpAddr,
    ) Error!void {
        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);

        const msg = try wire.decodeV2RequestMessageOwned(self.allocator, frame, self.cfg.limits);
        switch (msg) {
            .dial_request => |dr| {
                defer freeV2Addrs(self.allocator, dr.addrs);
                const idx = policy.selectV2DialAddrIndex(self.allocator, dr.addrs) orelse {
                    try self.writeV2Message(w, .{
                        .dial_response = .{ .status = .e_dial_refused },
                    });
                    return;
                };
                const addr = dr.addrs[@intCast(idx)];

                if (policy.v2NeedsAmplificationCost(self.allocator, observed_ip, addr)) {
                    const cost = self.pickAmplificationCost(dr.nonce);
                    try self.writeV2Message(w, .{
                        .dial_data_request = .{ .addr_idx = idx, .num_bytes = cost },
                    });
                    var received: u64 = 0;
                    while (received < cost) {
                        const data_frame = try wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes);
                        defer self.allocator.free(data_frame);
                        const data_msg = try wire.decodeV2RequestMessageOwned(self.allocator, data_frame, self.cfg.limits);
                        switch (data_msg) {
                            .dial_data_response => |ddr| {
                                received += @intCast(ddr.data.len);
                                if (ddr.data.len > 0 and ddr.data.ptr != data_frame.ptr) {
                                    // owned slice inside frame — nothing to free separately
                                }
                            },
                            else => return,
                        }
                    }
                }

                const dial_res = self.dial_back(self.dial_back_ctx, addr, dr.nonce);
                const dial_status: wire.V2DialStatus = switch (dial_res) {
                    .ok => .ok,
                    .dial_error => .e_dial_error,
                    .dial_back_error => .e_dial_back_error,
                };
                try self.writeV2Message(w, .{
                    .dial_response = .{
                        .status = .ok,
                        .addr_idx = idx,
                        .dial_status = dial_status,
                    },
                });
            },
            else => try self.writeV2Message(w, .{
                .dial_response = .{ .status = .e_internal_error },
            }),
        }
    }

    /// Server sends DialBack on `/libp2p/autonat/2/dial-back` after outbound dial.
    pub fn writeV2DialBack(self: *Server, w: *Io.Writer, nonce: u64) Error!void {
        const payload = try wire.encodeV2DialBack(self.allocator, .{ .nonce = nonce });
        defer self.allocator.free(payload);
        wire.writeLengthPrefixed(w, payload) catch |e| switch (e) {
            error.WriteFailed => return error.IoWriteFailed,
            else => |x| return x,
        };
    }

    pub fn readV2DialBackResponse(self: *Server, r: *Io.Reader) Error!wire.V2DialBackResponse {
        const frame = wire.readLengthPrefixedAlloc(r, self.allocator, self.cfg.limits.max_frame_bytes) catch |e| switch (e) {
            error.ReadFailed => return error.IoReadFailed,
            else => |x| return x,
        };
        defer self.allocator.free(frame);
        return try wire.decodeV2DialBackResponse(frame);
    }

    fn writeV2Message(self: *Server, w: *Io.Writer, msg: wire.V2RequestMessage) Error!void {
        const payload = try wire.encodeV2RequestMessage(self.allocator, msg);
        defer self.allocator.free(payload);
        wire.writeLengthPrefixed(w, payload) catch |e| switch (e) {
            error.WriteFailed => return error.IoWriteFailed,
            else => |x| return x,
        };
    }
};

fn freeV1Dial(allocator: std.mem.Allocator, d: wire.V1Dial) void {
    if (d.peer_id) |p| allocator.free(p);
    for (d.addrs) |a| allocator.free(a);
}

fn freeV2Addrs(allocator: std.mem.Allocator, addrs: []const []u8) void {
    for (addrs) |a| allocator.free(a);
}

test "v1 server rejects relayed" {
    const a = std.testing.allocator;
    const ServerStub = struct {
        fn dial(ctx: ?*anyopaque, addr: []const u8, nonce: u64) DialBackResult {
            _ = ctx;
            _ = addr;
            _ = nonce;
            return .ok;
        }
    };
    var srv = Server.init(a, .{}, ServerStub.dial);

    var in_buf: [512]u8 = undefined;
    var out_buf: [512]u8 = undefined;
    var w = Io.Writer.fixed(&out_buf);
    var r = Io.Reader.fixed(&in_buf);

    srv.handleV1Stream(&r, &w, .{ .v4 = .{ 203, 0, 113, 1 } }, true) catch {};
}

test "v2 amplification cost spans full [min, max] range" {
    const a = std.testing.allocator;
    const Stub = struct {
        fn dial(ctx: ?*anyopaque, addr: []const u8, nonce: u64) DialBackResult {
            _ = ctx;
            _ = addr;
            _ = nonce;
            return .ok;
        }
    };
    const srv = Server.init(a, .{}, Stub.dial);

    // 10k nonces — distribution must hit at least the lower decile, the upper decile,
    // and a midpoint. Previous `clamp(min, 1, max)` always returned `min`; this test
    // would have caught it (max-decile bucket would stay empty).
    const min_b = srv.cfg.amplification_min_bytes;
    const max_b = srv.cfg.amplification_max_bytes;
    const span = max_b - min_b;
    var saw_low = false;
    var saw_mid = false;
    var saw_high = false;
    var i: u64 = 0;
    while (i < 10_000) : (i += 1) {
        const c = srv.pickAmplificationCost(i);
        try std.testing.expect(c >= min_b and c <= max_b);
        if (c < min_b + span / 10) saw_low = true;
        if (c > max_b - span / 10) saw_high = true;
        if (c >= min_b + span / 3 and c <= max_b - span / 3) saw_mid = true;
    }
    try std.testing.expect(saw_low);
    try std.testing.expect(saw_mid);
    try std.testing.expect(saw_high);
}

test "v2 amplification cost: same nonce reproduces same value" {
    const a = std.testing.allocator;
    const Stub = struct {
        fn dial(ctx: ?*anyopaque, addr: []const u8, nonce: u64) DialBackResult {
            _ = ctx;
            _ = addr;
            _ = nonce;
            return .ok;
        }
    };
    const srv = Server.init(a, .{}, Stub.dial);
    const c1 = srv.pickAmplificationCost(0xdeadbeef);
    const c2 = srv.pickAmplificationCost(0xdeadbeef);
    try std.testing.expectEqual(c1, c2);
}

test "v2 amplification cost: degenerate min==max" {
    const a = std.testing.allocator;
    const Stub = struct {
        fn dial(ctx: ?*anyopaque, addr: []const u8, nonce: u64) DialBackResult {
            _ = ctx;
            _ = addr;
            _ = nonce;
            return .ok;
        }
    };
    const srv = Server.init(a, .{
        .amplification_min_bytes = 50_000,
        .amplification_max_bytes = 50_000,
    }, Stub.dial);
    try std.testing.expectEqual(@as(u64, 50_000), srv.pickAmplificationCost(0));
    try std.testing.expectEqual(@as(u64, 50_000), srv.pickAmplificationCost(0xffff_ffff_ffff_ffff));
}
