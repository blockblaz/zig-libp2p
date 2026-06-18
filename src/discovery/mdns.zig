//! libp2p mDNS LAN peer discovery (#207).
//!
//! Spec: https://github.com/libp2p/specs/blob/master/discovery/mdns.md

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const libc = std.c;

const ip_add_membership: i32 = switch (builtin.os.tag) {
    .linux => 35,
    else => 12,
};
const ipv6_join_group: i32 = switch (builtin.os.tag) {
    .linux => 20,
    else => 12,
};
const recv_flags_dontwait: u32 = switch (builtin.os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos => 0x80,
    else => 0x40,
};
const dns_wire = @import("dns_wire.zig");
const identity = @import("../identity.zig");
const multiaddr_mod = @import("multiaddr");
const quic_posix_udp = @import("../transport/quic_posix_udp.zig");
const feed_addr = @import("../transport/zquic_feed_addr.zig");
const wall_time = @import("../wall_time.zig");

pub const dns = dns_wire;

pub const default_service_name = "_p2p._udp.local";
pub const default_ttl: u32 = 120;

pub const DiscoverySource = enum {
    mdns,
};

pub const PeerDiscovery = struct {
    peer: identity.PeerId,
    addrs: [][]const u8,
    source: DiscoverySource = .mdns,
};

pub const Config = struct {
    query_interval_ms: i64 = 10_000,
    /// Suppress re-emitting the same peer within this window.
    discovery_cooldown_ms: i64 = 5_000,
    /// Minimum gap between multicast responses to queries.
    response_cooldown_ms: i64 = 1_000,
    enable_ipv4: bool = true,
    enable_ipv6: bool = true,
    /// When set, passed to `IP_ADD_MEMBERSHIP` / `IPV6_JOIN_GROUP`.
    interface_index: ?u32 = null,
    service_name: []const u8 = default_service_name,
    port: u16 = 5353,
    /// When false, skip opening UDP sockets (unit tests inject datagrams).
    live_sockets: bool = true,
};

pub const Error = dns_wire.Error || std.mem.Allocator.Error || identity.ParseError || error{
    SocketFailed,
    BindFailed,
    MulticastJoinFailed,
    SendFailed,
    RecvFailed,
    PeerIdFormatFailed,
};

const SeenPeer = struct {
    last_seen_ms: i64,
    last_announced_ms: i64,
};

pub const Service = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    local_peer: identity.PeerId,
    peer_name: []u8,
    peer_fqdn: []u8,
    listen_addrs: std.ArrayList([]u8) = .empty,
    sock_v4: ?posix.socket_t = null,
    sock_v6: ?posix.socket_t = null,
    last_query_ms: i64 = std.math.minInt(i64),
    last_response_ms: i64 = std.math.minInt(i64),
    seen: std.StringHashMap(SeenPeer),
    pending: std.ArrayList(PeerDiscovery) = .empty,
    send_buf: [9_000]u8 = undefined,
    recv_buf: [9_000]u8 = undefined,

    pub fn init(
        allocator: std.mem.Allocator,
        local_peer: identity.PeerId,
        cfg: Config,
    ) Error!Service {
        var self: Service = .{
            .allocator = allocator,
            .cfg = cfg,
            .local_peer = local_peer,
            .peer_name = &.{},
            .peer_fqdn = &.{},
            .seen = std.StringHashMap(SeenPeer).init(allocator),
        };
        try self.generatePeerName();
        if (cfg.live_sockets and builtin.os.tag != .wasi) {
            if (cfg.enable_ipv4) self.sock_v4 = try openSocket(.ipv4, cfg);
            if (cfg.enable_ipv6) self.sock_v6 = try openSocket(.ipv6, cfg);
        }
        return self;
    }

    pub fn deinit(self: *Service) void {
        if (self.sock_v4) |s| quic_posix_udp.close(s);
        if (self.sock_v6) |s| quic_posix_udp.close(s);
        self.allocator.free(self.peer_name);
        self.allocator.free(self.peer_fqdn);
        for (self.listen_addrs.items) |a| self.allocator.free(a);
        self.listen_addrs.deinit(self.allocator);
        var sit = self.seen.iterator();
        while (sit.next()) |e| self.allocator.free(e.key_ptr.*);
        self.seen.deinit();
        self.clearPending();
        self.* = undefined;
        self.peer_name = &.{};
        self.peer_fqdn = &.{};
    }

    pub fn setListenAddrs(self: *Service, addrs: []const []const u8) Error!void {
        for (self.listen_addrs.items) |a| self.allocator.free(a);
        self.listen_addrs.clearRetainingCapacity();
        for (addrs) |a| {
            if (!isAdvertisableAddr(a)) continue;
            try self.listen_addrs.append(self.allocator, try self.allocator.dupe(u8, a));
        }
    }

    pub fn addListenAddr(self: *Service, addr: []const u8) Error!void {
        if (!isAdvertisableAddr(addr)) return;
        for (self.listen_addrs.items) |a| {
            if (std.mem.eql(u8, a, addr)) return;
        }
        try self.listen_addrs.append(self.allocator, try self.allocator.dupe(u8, addr));
    }

    /// Periodic tick: multicast query, recv datagrams, return new discoveries.
    pub fn tick(self: *Service, now_ms: i64) Error![]PeerDiscovery {
        if (elapsedMs(now_ms, self.last_query_ms) >= self.cfg.query_interval_ms) {
            try self.broadcastQuery();
            self.last_query_ms = now_ms;
        }
        try self.recvLive();
        const out = try self.pending.toOwnedSlice(self.allocator);
        self.pending = .empty;
        return out;
    }

    pub fn freeDiscoveries(self: *Service, discoveries: []PeerDiscovery) void {
        for (discoveries) |*d| self.freeDiscovery(d);
        self.allocator.free(discoveries);
    }

    pub fn freeDiscovery(self: *Service, d: *PeerDiscovery) void {
        for (d.addrs) |a| self.allocator.free(a);
        self.allocator.free(d.addrs);
        d.addrs = &.{};
    }

    /// Inject a datagram (used by unit tests and embedders wrapping custom I/O).
    pub fn handleDatagram(self: *Service, data: []const u8, now_ms: i64) Error!void {
        var msg = try dns_wire.decode(self.allocator, data);
        defer dns_wire.freeMessage(self.allocator, &msg);

        if (msg.is_response) {
            try self.ingestResponse(&msg, now_ms);
            return;
        }
        try self.maybeRespond(&msg, now_ms);
    }

    fn clearPending(self: *Service) void {
        for (self.pending.items) |*d| self.freeDiscovery(d);
        self.pending.clearRetainingCapacity();
    }

    fn generatePeerName(self: *Service) Error!void {
        const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        var seed: u64 = 0x6D646E730044;
        var peer_buf: [64]u8 = undefined;
        if (self.local_peer.toBytes(&peer_buf)) |peer_bytes| {
            for (peer_bytes, 0..) |b, i| seed ^= @as(u64, b) << @intCast((i % 8) * 8);
        } else |_| {
            seed ^= 0xAAAA;
        }
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        var name: [32]u8 = undefined;
        for (&name) |*c| c.* = alphabet[rnd.intRangeAtMost(u8, 0, @intCast(alphabet.len - 1))];
        self.peer_name = try self.allocator.dupe(u8, &name);
        const fqdn_len = self.peer_name.len + 1 + self.cfg.service_name.len;
        const fqdn = try self.allocator.alloc(u8, fqdn_len);
        @memcpy(fqdn[0..self.peer_name.len], self.peer_name);
        fqdn[self.peer_name.len] = '.';
        @memcpy(fqdn[self.peer_name.len + 1 ..], self.cfg.service_name);
        self.peer_fqdn = fqdn;
    }

    fn broadcastQuery(self: *Service) Error!void {
        const wire = try dns_wire.encode(self.allocator, .{
            .questions = &.{
                .{ .qname = self.cfg.service_name, .qtype = .ptr, .qclass = .in },
            },
        });
        defer self.allocator.free(wire);
        try self.sendMulticast(wire);
    }

    fn maybeRespond(self: *Service, msg: *const dns_wire.Message, now_ms: i64) Error!void {
        if (elapsedMs(now_ms, self.last_response_ms) < self.cfg.response_cooldown_ms) return;
        if (self.listen_addrs.items.len == 0) return;

        var respond = false;
        for (msg.questions) |q| {
            if (q.qtype == .ptr and namesEqual(q.qname, self.cfg.service_name)) {
                respond = true;
                break;
            }
            if (q.qtype == .txt and namesEqual(q.qname, self.peer_fqdn)) {
                respond = true;
                break;
            }
        }
        if (!respond) return;

        const wire = try self.buildAnnouncement(msg.id);
        defer self.allocator.free(wire);
        try self.sendMulticast(wire);
        self.last_response_ms = now_ms;
    }

    pub fn buildAnnouncement(self: *Service, id: u16) Error![]u8 {
        const ptr_rdata = try dns_wire.encodePtrRdata(self.allocator, self.peer_fqdn);
        defer self.allocator.free(ptr_rdata);

        var additionals: std.ArrayList(dns_wire.ResourceRecord) = .empty;
        errdefer {
            for (additionals.items) |rr| self.allocator.free(rr.rdata);
            additionals.deinit(self.allocator);
        }

        var peer_b58_buf: [128]u8 = undefined;
        const peer_b58 = self.local_peer.toBase58(&peer_b58_buf) catch return error.PeerIdFormatFailed;

        for (self.listen_addrs.items) |addr| {
            const txt_value = try std.fmt.allocPrint(self.allocator, "dnsaddr={s}/p2p/{s}", .{ addr, peer_b58 });
            defer self.allocator.free(txt_value);
            const txt_rdata = try dns_wire.encodeTxtRdata(self.allocator, txt_value);
            try additionals.append(self.allocator, .{
                .name = self.peer_fqdn,
                .rtype = .txt,
                .rclass = .in,
                .ttl = default_ttl,
                .rdata = txt_rdata,
            });
        }

        const wire = try dns_wire.encode(self.allocator, .{
            .id = id,
            .is_response = true,
            .authoritative = true,
            .answers = &.{
                .{
                    .name = self.cfg.service_name,
                    .rtype = .ptr,
                    .rclass = .in,
                    .ttl = default_ttl,
                    .rdata = ptr_rdata,
                },
            },
            .additionals = additionals.items,
        });
        for (additionals.items) |rr| self.allocator.free(rr.rdata);
        additionals.deinit(self.allocator);
        return wire;
    }

    fn ingestResponse(self: *Service, msg: *const dns_wire.Message, now_ms: i64) Error!void {
        inline for (.{ msg.answers, msg.additionals }) |section| {
            for (section) |rr| {
                if (rr.rtype == .txt) {
                    for (rr.txt_strings) |txt| {
                        try self.ingestTxt(txt, now_ms);
                    }
                }
            }
        }
    }

    fn ingestTxt(self: *Service, txt: []const u8, now_ms: i64) Error!void {
        const prefix = "dnsaddr=";
        if (!std.mem.startsWith(u8, txt, prefix)) return;
        const addr_str = txt[prefix.len..];
        if (!isAcceptableDiscoveredAddr(addr_str)) return;

        var ma = multiaddr_mod.Multiaddr.fromString(self.allocator, addr_str) catch return;
        defer ma.deinit();
        const peer = peerFromMultiaddr(&ma) orelse return;
        if (peer.eql(&self.local_peer)) return;

        var peer_b58_buf: [128]u8 = undefined;
        const peer_b58 = peer.toBase58(&peer_b58_buf) catch return error.PeerIdFormatFailed;
        const peer_key = try self.allocator.dupe(u8, peer_b58);
        errdefer self.allocator.free(peer_key);

        const gop = try self.seen.getOrPut(peer_key);
        if (gop.found_existing) {
            self.allocator.free(peer_key);
            if (now_ms - gop.value_ptr.last_announced_ms < self.cfg.discovery_cooldown_ms) return;
            gop.value_ptr.last_seen_ms = now_ms;
            gop.value_ptr.last_announced_ms = now_ms;
        } else {
            gop.value_ptr.* = .{ .last_seen_ms = now_ms, .last_announced_ms = now_ms };
        }

        const owned_addr = try self.allocator.dupe(u8, addr_str);
        errdefer self.allocator.free(owned_addr);
        try self.pending.append(self.allocator, .{
            .peer = peer,
            .addrs = try self.allocator.alloc([]const u8, 1),
            .source = .mdns,
        });
        const last = &self.pending.items[self.pending.items.len - 1];
        last.addrs[0] = owned_addr;
    }

    fn recvLive(self: *Service) Error!void {
        const now_ms = wall_time.milliTimestamp();
        if (self.sock_v4) |sock| {
            while (true) {
                const n = feed_addr.recvfrom(sock, &self.recv_buf, recv_flags_dontwait, null, null) catch |e| switch (e) {
                    error.WouldBlock => break,
                    else => return error.RecvFailed,
                };
                try self.handleDatagram(self.recv_buf[0..n], now_ms);
            }
        }
        if (self.sock_v6) |sock| {
            while (true) {
                const n = feed_addr.recvfrom(sock, &self.recv_buf, recv_flags_dontwait, null, null) catch |e| switch (e) {
                    error.WouldBlock => break,
                    else => return error.RecvFailed,
                };
                try self.handleDatagram(self.recv_buf[0..n], now_ms);
            }
        }
    }

    fn sendMulticast(self: *Service, wire: []const u8) Error!void {
        if (wire.len > self.send_buf.len) return error.SendFailed;
        @memcpy(self.send_buf[0..wire.len], wire);
        if (self.sock_v4) |sock| {
            const dest = posix.sockaddr.in{
                .family = posix.AF.INET,
                .port = std.mem.nativeToBig(u16, self.cfg.port),
                .addr = std.mem.nativeToBig(u32, 0xE00000FB), // 224.0.0.251
                .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
            };
            try udpSendto(sock, self.send_buf[0..wire.len], @ptrCast(&dest), @sizeOf(posix.sockaddr.in));
        }
        if (self.sock_v6) |sock| {
            const dest = posix.sockaddr.in6{
                .family = posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, self.cfg.port),
                .flowinfo = 0,
                .addr = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB },
                .scope_id = self.cfg.interface_index orelse 0,
            };
            try udpSendto(sock, self.send_buf[0..wire.len], @ptrCast(&dest), @sizeOf(posix.sockaddr.in6));
        }
    }

    const IpFamily = enum { ipv4, ipv6 };

    const Ipv4Mreq = extern struct {
        multiaddr: [4]u8,
        interface: [4]u8,
    };

    const Ipv6Mreq = extern struct {
        multiaddr: [16]u8,
        interface: u32,
    };

    fn openSocket(family: IpFamily, cfg: Config) Error!posix.socket_t {
        const sock = switch (family) {
            .ipv4 => quic_posix_udp.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch return error.SocketFailed,
            .ipv6 => quic_posix_udp.socket(posix.AF.INET6, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch return error.SocketFailed,
        };

        const one: c_int = 1;
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
        if (@hasDecl(posix.SO, "REUSEPORT")) {
            posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&one)) catch {};
        }

        switch (family) {
            .ipv4 => {
                const addr = posix.sockaddr.in{
                    .family = posix.AF.INET,
                    .port = std.mem.nativeToBig(u16, cfg.port),
                    .addr = std.mem.nativeToBig(u32, 0),
                    .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
                };
                quic_posix_udp.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch {
                    quic_posix_udp.close(sock);
                    return error.BindFailed;
                };
                const mreq = Ipv4Mreq{
                    .multiaddr = .{ 224, 0, 0, 251 },
                    .interface = .{ 0, 0, 0, 0 },
                };
                posix.setsockopt(sock, posix.IPPROTO.IP, ip_add_membership, std.mem.asBytes(&mreq)) catch {
                    quic_posix_udp.close(sock);
                    return error.MulticastJoinFailed;
                };
            },
            .ipv6 => {
                const addr = posix.sockaddr.in6{
                    .family = posix.AF.INET6,
                    .port = std.mem.nativeToBig(u16, cfg.port),
                    .flowinfo = 0,
                    .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    .scope_id = cfg.interface_index orelse 0,
                };
                quic_posix_udp.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in6)) catch {
                    quic_posix_udp.close(sock);
                    return error.BindFailed;
                };
                const mreq = Ipv6Mreq{
                    .multiaddr = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB },
                    .interface = cfg.interface_index orelse 0,
                };
                posix.setsockopt(sock, posix.IPPROTO.IPV6, ipv6_join_group, std.mem.asBytes(&mreq)) catch {
                    quic_posix_udp.close(sock);
                    return error.MulticastJoinFailed;
                };
            },
        }

        return sock;
    }
};

fn elapsedMs(now_ms: i64, since_ms: i64) i64 {
    if (since_ms == std.math.minInt(i64)) return std.math.maxInt(i64);
    return now_ms - since_ms;
}

fn udpSendto(sock: posix.socket_t, buf: []const u8, dest: *const posix.sockaddr, dest_len: posix.socklen_t) Error!void {
    const system = posix.system;
    const rc = system.sendto(sock, buf.ptr, buf.len, 0, dest, dest_len);
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        else => return error.SendFailed,
    }
}

fn namesEqual(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

pub fn isAdvertisableAddr(addr: []const u8) bool {
    if (std.mem.startsWith(u8, addr, "/ip4/127.") or std.mem.startsWith(u8, addr, "/ip4/0.0.0.0")) return false;
    if (std.mem.startsWith(u8, addr, "/ip6/::1") or std.mem.startsWith(u8, addr, "/ip6/0:0:0:0:0:0:0:1")) return false;
    return true;
}

pub fn isAcceptableDiscoveredAddr(addr: []const u8) bool {
    return isAdvertisableAddr(addr);
}

pub fn peerFromMultiaddr(ma: *const multiaddr_mod.Multiaddr) ?identity.PeerId {
    var iter = ma.iterator();
    while (iter.next() catch return null) |proto| {
        switch (proto) {
            .P2P => |id| return id,
            else => {},
        }
    }
    return null;
}

test "parse dnsaddr TXT into peer discovery" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const a = std.testing.allocator;
    const local = try identity.PeerId.random();
    var svc = try Service.init(a, local, .{ .live_sockets = false });
    defer svc.deinit();

    const remote = try identity.PeerId.random();
    var remote_b58_buf: [128]u8 = undefined;
    const remote_b58 = try remote.toBase58(&remote_b58_buf);
    const addr = try std.fmt.allocPrint(a, "/ip4/192.168.1.10/udp/4001/quic-v1/p2p/{s}", .{remote_b58});
    defer a.free(addr);
    const txt = try std.fmt.allocPrint(a, "dnsaddr={s}", .{addr});
    defer a.free(txt);

    const packet = try buildTxtResponse(a, txt);
    defer a.free(packet);
    try svc.handleDatagram(packet, 1_000);
    const discoveries = try svc.tick(1_000);
    defer svc.freeDiscoveries(discoveries);
    try std.testing.expect(discoveries.len >= 1);
    try std.testing.expect(discoveries[0].peer.eql(&remote));
}

test "query/response round trip between two services" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const a = std.testing.allocator;
    const peer_a = try identity.PeerId.random();
    const peer_b = try identity.PeerId.random();

    var a_svc = try Service.init(a, peer_a, .{ .live_sockets = false });
    defer a_svc.deinit();
    var b_svc = try Service.init(a, peer_b, .{ .live_sockets = false });
    defer b_svc.deinit();

    try a_svc.setListenAddrs(&.{
        "/ip4/192.168.0.2/udp/4001/quic-v1",
    });
    try b_svc.setListenAddrs(&.{
        "/ip4/192.168.0.3/udp/4002/quic-v1",
    });

    const query = try dns_wire.encode(a, .{
        .questions = &.{
            .{ .qname = default_service_name, .qtype = .ptr, .qclass = .in },
        },
    });
    defer a.free(query);

    try a_svc.handleDatagram(query, 0);
    const resp = try a_svc.buildAnnouncement(0);
    defer a.free(resp);

    try b_svc.handleDatagram(resp, 5_000);
    const found = try b_svc.tick(5_000);
    defer b_svc.freeDiscoveries(found);
    try std.testing.expect(found.len >= 1);
    try std.testing.expect(found[0].peer.eql(&peer_a));
}

/// Test/helper: build a minimal mDNS TXT discovery response packet.
pub fn buildTxtResponsePacket(allocator: std.mem.Allocator, txt: []const u8) ![]u8 {
    return buildTxtResponse(allocator, txt);
}

fn buildTxtResponse(allocator: std.mem.Allocator, txt: []const u8) ![]u8 {
    const peer_fqdn = "peerx._p2p._udp.local";
    const txt_rdata = try dns_wire.encodeTxtRdata(allocator, txt);
    defer allocator.free(txt_rdata);
    const ptr_rdata = try dns_wire.encodePtrRdata(allocator, peer_fqdn);
    defer allocator.free(ptr_rdata);
    return try dns_wire.encode(allocator, .{
        .is_response = true,
        .authoritative = true,
        .answers = &.{
            .{
                .name = default_service_name,
                .rtype = .ptr,
                .rclass = .in,
                .ttl = default_ttl,
                .rdata = ptr_rdata,
            },
        },
        .additionals = &.{
            .{
                .name = peer_fqdn,
                .rtype = .txt,
                .rclass = .in,
                .ttl = default_ttl,
                .rdata = txt_rdata,
            },
        },
    });
}
