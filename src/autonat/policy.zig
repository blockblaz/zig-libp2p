//! NAT reachability policy, address validation, and probe aggregation (#92, #206).

const std = @import("std");
const multiaddr = @import("multiaddr");

pub const NatStatus = enum {
    unknown,
    public,
    private,
};

pub const IpAddr = union(enum) {
    v4: [4]u8,
    v6: [16]u8,
};

pub const Config = struct {
    /// Last-K probe window size per address / node tracker (#206).
    window_size: u32 = 6,
    /// Quorum: ≥ this many successes in the window → public (#206).
    confidence_threshold: u32 = 3,
    /// Quorum: ≥ this many failures in the window → private (#206).
    failure_threshold: u32 = 3,
    /// Legacy alias kept for embedders/tests.
    success_threshold: u32 = 3,
    /// Default probe peer count (issue #92).
    default_probe_peers: u32 = 4,
};

pub const ProbeOutcome = enum {
    success,
    failure,
};

/// Fixed-size ring of the last K probe outcomes (#206).
pub const WindowTracker = struct {
    ring: [8]ProbeOutcome = undefined,
    len: u8 = 0,
    head: u8 = 0,

    pub fn record(self: *WindowTracker, outcome: ProbeOutcome) void {
        if (self.len < 8) {
            self.ring[self.len] = outcome;
            self.len += 1;
            return;
        }
        self.ring[self.head] = outcome;
        self.head = (self.head + 1) % 8;
    }

    pub fn reset(self: *WindowTracker) void {
        self.len = 0;
        self.head = 0;
    }

    pub fn count(self: WindowTracker, outcome: ProbeOutcome) u32 {
        var n: u32 = 0;
        const cap: u8 = 8;
        if (self.len < cap) {
            for (self.ring[0..self.len]) |slot| {
                if (slot == outcome) n += 1;
            }
            return n;
        }
        var i: u8 = 0;
        while (i < cap) : (i += 1) {
            const idx = (self.head + i) % cap;
            if (self.ring[idx] == outcome) n += 1;
        }
        return n;
    }

    pub fn status(self: WindowTracker, cfg: Config) NatStatus {
        const successes = self.count(.success);
        const failures = self.count(.failure);
        if (successes >= cfg.confidence_threshold) return .public;
        if (failures >= cfg.failure_threshold) return .private;
        return .unknown;
    }
};

/// Per-address probe window for v2-style reachability (#206).
pub const AddressReachability = struct {
    tracker: WindowTracker = .{},

    pub fn init() AddressReachability {
        return .{};
    }

    pub fn record(self: *AddressReachability, outcome: ProbeOutcome) void {
        self.tracker.record(outcome);
    }

    pub fn status(self: AddressReachability, cfg: Config) NatStatus {
        return self.tracker.status(cfg);
    }

    pub fn reset(self: *AddressReachability) void {
        self.tracker.reset();
    }
};

/// Node-level NAT status from aggregated v1 probes (#206 sliding window).
pub const ReachabilityTracker = struct {
    tracker: WindowTracker = .{},

    pub fn init() ReachabilityTracker {
        return .{};
    }

    pub fn record(self: *ReachabilityTracker, outcome: ProbeOutcome) void {
        self.tracker.record(outcome);
    }

    pub fn natStatus(self: ReachabilityTracker, cfg: Config) NatStatus {
        return self.tracker.status(cfg);
    }

    pub fn reset(self: *ReachabilityTracker) void {
        self.tracker.reset();
    }
};

/// RFC 1918 + loopback + link-local checks for v2 client filtering.
pub fn isPrivateIp(ip: IpAddr) bool {
    return switch (ip) {
        .v4 => |b| {
            if (b[0] == 10) return true;
            if (b[0] == 172 and b[1] >= 16 and b[1] <= 31) return true;
            if (b[0] == 192 and b[1] == 168) return true;
            if (b[0] == 127) return true;
            if (b[0] == 169 and b[1] == 254) return true;
            return false;
        },
        .v6 => |b| {
            if (std.mem.allEqual(u8, &b, 0) and b[15] == 1) return true;
            if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return true;
            if ((b[0] & 0xfe) == 0xfc) return true;
            return false;
        },
    };
}

/// Extract the first /ip4 or /ip6 component from a human-readable multiaddr string.
pub fn extractIpFromMultiaddr(allocator: std.mem.Allocator, addr: []const u8) !?IpAddr {
    var ma = try multiaddr.Multiaddr.fromString(allocator, addr);
    defer ma.deinit();
    return ipFromMultiaddr(&ma);
}

fn ipFromMultiaddr(ma: *const multiaddr.Multiaddr) ?IpAddr {
    var it = ma.iterator();
    while (true) {
        const p = it.next() catch return null;
        const proto = p orelse break;
        switch (proto) {
            .Ip4 => |addr| return .{ .v4 = addr.bytes },
            .Ip6 => |addr| return .{ .v6 = addr.bytes },
            else => {},
        }
    }
    return null;
}

/// Fill 8 random bytes (for v2 nonces).
pub fn fillRandomU64(out: *u64) void {
    const builtin = @import("builtin");
    var bytes: [8]u8 = undefined;
    if (builtin.link_libc) {
        std.c.arc4random_buf(&bytes, bytes.len);
    } else if (builtin.os.tag == .linux) {
        var off: usize = 0;
        while (off < bytes.len) {
            const rc = std.os.linux.getrandom(bytes[off..].ptr, bytes.len - off, 0);
            const e = std.posix.errno(rc);
            if (e == .SUCCESS) {
                off += @intCast(rc);
            } else if (e == .INTR) {
                continue;
            } else {
                @panic("getrandom failed");
            }
        }
    } else {
        @compileError("fillRandomU64 requires libc or Linux getrandom");
    }
    out.* = std.mem.readInt(u64, &bytes, .little);
}

pub fn ipAddrsEqual(a: IpAddr, b: IpAddr) bool {
    return switch (a) {
        .v4 => |av| switch (b) {
            .v4 => |bv| std.mem.eql(u8, &av, &bv),
            else => false,
        },
        .v6 => |av| switch (b) {
            .v6 => |bv| std.mem.eql(u8, &av, &bv),
            else => false,
        },
    };
}

pub fn v1DialAddrAllowed(allocator: std.mem.Allocator, observed_ip: IpAddr, addr: []const u8) bool {
    const target = extractIpFromMultiaddr(allocator, addr) catch return false;
    const ip = target orelse return false;
    return ipAddrsEqual(observed_ip, ip);
}

pub fn v2ClientAddrAllowed(allocator: std.mem.Allocator, addr: []const u8) bool {
    const ip = extractIpFromMultiaddr(allocator, addr) catch return false;
    return ip != null and !isPrivateIp(ip.?);
}

pub fn selectV2DialAddrIndex(allocator: std.mem.Allocator, addrs: []const []const u8) ?u32 {
    for (addrs, 0..) |a, i| {
        if (v2ClientAddrAllowed(allocator, a)) return @intCast(i);
    }
    return null;
}

pub fn v2NeedsAmplificationCost(allocator: std.mem.Allocator, observed_ip: IpAddr, addr: []const u8) bool {
    const target = extractIpFromMultiaddr(allocator, addr) catch return true;
    const ip = target orelse return true;
    return !ipAddrsEqual(observed_ip, ip);
}

test "private ip detection" {
    try std.testing.expect(isPrivateIp(.{ .v4 = .{ 10, 0, 0, 1 } }));
    try std.testing.expect(isPrivateIp(.{ .v4 = .{ 192, 168, 1, 1 } }));
    try std.testing.expect(!isPrivateIp(.{ .v4 = .{ 8, 8, 8, 8 } }));
}

test "window quorum resists single flip" {
    const cfg: Config = .{ .window_size = 6, .confidence_threshold = 3, .failure_threshold = 3 };
    var t = ReachabilityTracker.init();
    t.record(.success);
    try std.testing.expectEqual(NatStatus.unknown, t.natStatus(cfg));
    t.record(.failure);
    t.record(.failure);
    try std.testing.expectEqual(NatStatus.unknown, t.natStatus(cfg));
    t.record(.success);
    t.record(.success);
    t.record(.success);
    try std.testing.expectEqual(NatStatus.public, t.natStatus(cfg));
}

test "window private quorum" {
    const cfg: Config = .{};
    var t = ReachabilityTracker.init();
    t.record(.failure);
    t.record(.failure);
    try std.testing.expectEqual(NatStatus.unknown, t.natStatus(cfg));
    t.record(.failure);
    try std.testing.expectEqual(NatStatus.private, t.natStatus(cfg));
}

test "v1 dial addr must match observed ip" {
    const a = std.testing.allocator;
    const obs: IpAddr = .{ .v4 = .{ 203, 0, 113, 5 } };
    try std.testing.expect(v1DialAddrAllowed(a, obs, "/ip4/203.0.113.5/udp/4001/quic-v1"));
    try std.testing.expect(!v1DialAddrAllowed(a, obs, "/ip4/198.51.100.1/udp/4001/quic-v1"));
}
