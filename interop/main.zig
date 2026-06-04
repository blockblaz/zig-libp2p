//! libp2p [unified-testing](https://github.com/libp2p/unified-testing) transport interop
//! (TCP + TLS + Yamux + ping). Phase 1: container binary + Redis coordination.

const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const zl = @import("zig_libp2p");
const multiaddr = @import("multiaddr");
const mux_link = @import("mux_link.zig");
const redis_client = @import("redis_client.zig");

const tcp = zl.transport.tcp;
const tcp_tls = zl.transport.tcp_tls;
const libp2p_tls_cert = zl.security.libp2p_tls_cert;

const Ed25519 = std.crypto.sign.Ed25519;

const Env = struct {
    is_dialer: bool,
    redis_host: []const u8,
    redis_port: u16,
    listener_ip: []const u8,
    test_key: ?[]const u8,
    timeout_secs: u64,
    debug: bool,
    transport: []const u8,
    secure_channel: ?[]const u8,
    muxer: ?[]const u8,
};

pub fn main() !void {
    if (builtin.single_threaded) return;
    if (builtin.os.tag == .wasi) return;

    const gpa = std.heap.page_allocator;
    const env = try parseEnv(gpa);
    defer freeEnv(gpa, env);

    if (!std.mem.eql(u8, env.transport, "tcp")) {
        std.log.err("unsupported TRANSPORT={s} (expected tcp)", .{env.transport});
        return error.UnsupportedConfig;
    }
    const secure = env.secure_channel orelse {
        std.log.err("SECURE_CHANNEL required for tcp transport", .{});
        return error.UnsupportedConfig;
    };
    if (!std.mem.eql(u8, secure, "tls")) {
        std.log.err("unsupported SECURE_CHANNEL={s} (expected tls)", .{secure});
        return error.UnsupportedConfig;
    }
    const mux = env.muxer orelse {
        std.log.err("MUXER required for tcp transport", .{});
        return error.UnsupportedConfig;
    };
    if (!std.mem.eql(u8, mux, "yamux")) {
        std.log.err("unsupported MUXER={s} (expected yamux)", .{mux});
        return error.UnsupportedConfig;
    }

    var io_impl = Io.Threaded.init(gpa, .{ .async_limit = Io.Limit.limited(8) });
    defer io_impl.deinit();
    const io = io_impl.io();

    var identity = try generateIdentity(gpa);
    defer identity.deinit(gpa);

    if (env.is_dialer) {
        try runDialer(gpa, io, env, &identity);
    } else {
        try runListener(gpa, io, env, &identity);
    }
}

const Identity = struct {
    host_kp: Ed25519.KeyPair,
    local_peer_id: zl.peer_id.PeerId,
    owned_cert: tcp_tls.OwnedCertKeyPair,
    now_sec: i64,

    fn deinit(self: *Identity, allocator: std.mem.Allocator) void {
        _ = self.local_peer_id;
        self.owned_cert.deinit(allocator);
    }
};

fn randomBytes32(out: *[32]u8) void {
    if (builtin.link_libc) {
        std.c.arc4random_buf(out.ptr, out.len);
        return;
    }
    @memset(out, 0x42);
}

fn generateIdentity(allocator: std.mem.Allocator) !Identity {
    var seed: [32]u8 = undefined;
    randomBytes32(&seed);
    const host_kp = try Ed25519.KeyPair.generateDeterministic(seed);

    const HostSigner = struct {
        kp: Ed25519.KeyPair,
        fn sign(ctx: ?*anyopaque, message: []const u8, out_sig: *[64]u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            out_sig.* = (try self.kp.sign(message, null)).toBytes();
        }
    };
    var signer = HostSigner{ .kp = host_kp };
    const now_sec = @divTrunc(zl.wall_time.milliTimestamp(), 1000);
    var cert_seed: [32]u8 = undefined;
    randomBytes32(&cert_seed);

    var gen = try libp2p_tls_cert.generate(allocator, .{
        .host_identity = .{
            .ed25519 = .{
                .public_key_bytes = host_kp.public_key.bytes,
                .sign = HostSigner.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now_sec - 3600,
        .not_after_sec = now_sec + 365 * 24 * 3600,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(allocator);

    const cert_pem = try libp2p_tls_cert.certDerToPem(allocator, gen.cert_der);
    defer allocator.free(cert_pem);
    const key_pem = try libp2p_tls_cert.ed25519SeedToPem(allocator, gen.cert_key_seed);
    defer allocator.free(key_pem);

    const owned_cert = try tcp_tls.certKeyPairFromPem(allocator, cert_pem, key_pem, now_sec);
    const host: zl.keypair.KeyPair = .{ .ed25519 = host_kp };
    const local_peer_id = try zl.keypair.peerIdFromKeyPair(allocator, host);

    return .{
        .host_kp = host_kp,
        .local_peer_id = local_peer_id,
        .owned_cert = owned_cert,
        .now_sec = now_sec,
    };
}

fn redisListenerKey(allocator: std.mem.Allocator, env: Env) ![]u8 {
    if (env.test_key) |tk| {
        return std.fmt.allocPrint(allocator, "{s}_listener_multiaddr", .{tk});
    }
    return allocator.dupe(u8, "listenerAddr");
}

fn runListener(allocator: std.mem.Allocator, io: Io, env: Env, id: *Identity) !void {
    var bind_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    var server = try tcp.listen(&bind_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const ma_str = try formatListenerMultiaddr(allocator, env.listener_ip, port, &id.local_peer_id);
    defer allocator.free(ma_str);

    var redis = try redis_client.Client.connect(allocator, io, env.redis_host, env.redis_port);
    defer redis.deinit();

    const redis_key = try redisListenerKey(allocator, env);
    defer allocator.free(redis_key);

    redis.del(redis_key) catch {};
    try redis.rpush(redis_key, ma_str);
    if (env.debug) std.log.debug("listener published {s} -> {s}", .{ redis_key, ma_str });

    const deadline_ms = zl.wall_time.milliTimestamp() + @as(i64, @intCast(env.timeout_secs * 1000));
    while (zl.wall_time.milliTimestamp() < deadline_ms) {
        const st = tcp.acceptTuned(&server, io, .{}) catch continue;
        defer st.close(io);
        _ = try handleConn(allocator, io, st, id, null, .responder, deadline_ms);
        return;
    }
    return error.Timeout;
}

fn runDialer(allocator: std.mem.Allocator, io: Io, env: Env, id: *Identity) !void {
    var redis = try redis_client.Client.connect(allocator, io, env.redis_host, env.redis_port);
    defer redis.deinit();

    const redis_key = try redisListenerKey(allocator, env);
    defer allocator.free(redis_key);

    const ma_bytes = try redis.blpop(allocator, redis_key, env.timeout_secs);
    defer allocator.free(ma_bytes);
    if (env.debug) std.log.debug("dialer got multiaddr: {s}", .{ma_bytes});

    const handshake_start_ms = zl.wall_time.milliTimestamp();
    var dial_addr = try multiaddrToNetAddress(allocator, ma_bytes);
    defer dial_addr.deinit(allocator);

    var client = try tcp.dial(&dial_addr.addr, io, .{});
    defer client.close(io);

    const ping_rtt_ms = try handleConn(
        allocator,
        io,
        client,
        id,
        dial_addr.expected_peer,
        .initiator,
        handshake_start_ms + @as(i64, @intCast(env.timeout_secs * 1000)),
    );
    const handshake_plus_one_rtt_ms = @as(f64, @floatFromInt(zl.wall_time.milliTimestamp() - handshake_start_ms));

    std.debug.print("latency:\n", .{});
    std.debug.print("  handshake_plus_one_rtt: {d:.3}\n", .{handshake_plus_one_rtt_ms});
    std.debug.print("  ping_rtt: {d:.3}\n", .{@as(f64, @floatFromInt(ping_rtt_ms))});
    std.debug.print("  unit: ms\n", .{});
}

fn handleConn(
    allocator: std.mem.Allocator,
    io: Io,
    stream: net.Stream,
    id: *Identity,
    expected_remote: ?zl.peer_id.PeerId,
    role: enum { initiator, responder },
    deadline_ms: i64,
) !u64 {
    var scratch_r: [65536]u8 = undefined;
    var scratch_w: [65536]u8 = undefined;
    var r = net.Stream.reader(stream, io, &scratch_r);
    var w = net.Stream.writer(stream, io, &scratch_w);

    var hs = switch (role) {
        .initiator => try tcp_tls.negotiateInitiator(
            allocator,
            &r.interface,
            &w.interface,
            id.now_sec,
            expected_remote,
            &id.owned_cert.pair,
        ),
        .responder => try tcp_tls.negotiateResponder(
            allocator,
            &r.interface,
            &w.interface,
            &id.owned_cert.pair,
            id.now_sec,
            expected_remote,
        ),
    };
    var link = mux_link.Link{
        .allocator = allocator,
        .session = switch (role) {
            .initiator => zl.transport.yamux.Session.init(allocator, .{ .keep_alive_interval_ms = 0 }, .initiator),
            .responder => zl.transport.yamux.Session.init(allocator, .{ .keep_alive_interval_ms = 0 }, .responder),
        },
        .channel = undefined,
        .r = &r.interface,
        .w = &w.interface,
    };
    std.mem.swap(tcp_tls.SecureChannel, &link.channel, &hs.channel);
    hs.channel.recv_acc = .empty;
    defer link.deinit();

    try link.negotiateYamux(switch (role) {
        .initiator => .initiator,
        .responder => .responder,
    });

    return switch (role) {
        .initiator => try link.runDialerPing(deadline_ms),
        .responder => {
            try link.runListenerPing(deadline_ms);
            return 0;
        },
    };
}

const ParsedDial = struct {
    addr: net.IpAddress,
    expected_peer: ?zl.peer_id.PeerId,

    fn deinit(_: *ParsedDial, _: std.mem.Allocator) void {}
};

fn multiaddrToNetAddress(allocator: std.mem.Allocator, ma_str: []const u8) !ParsedDial {
    var ma = try multiaddr.Multiaddr.fromString(allocator, ma_str);
    defer ma.deinit();

    var ip4: ?[4]u8 = null;
    var ip6: ?[16]u8 = null;
    var port: ?u16 = null;
    var peer: ?zl.peer_id.PeerId = null;

    var it = ma.iterator();
    while (try it.next()) |p| {
        switch (p) {
            .Ip4 => |b| ip4 = b.bytes,
            .Ip6 => |b| ip6 = b.bytes,
            .Tcp => |pt| port = pt,
            .P2P => |pid| peer = pid,
            else => {},
        }
    }
    const pt = port orelse return error.InvalidMultiaddr;

    const addr: net.IpAddress = if (ip4) |b|
        .{ .ip4 = .{ .bytes = b, .port = pt } }
    else if (ip6) |b|
        .{ .ip6 = .{ .bytes = b, .port = pt } }
    else
        return error.InvalidMultiaddr;

    return .{ .addr = addr, .expected_peer = peer };
}

fn formatListenerMultiaddr(allocator: std.mem.Allocator, ip: []const u8, port: u16, peer: *const zl.peer_id.PeerId) ![]u8 {
    const ip_bytes = try parseIpv4(ip);
    var ma = multiaddr.Multiaddr.init(allocator);
    try ma.push(.{ .Ip4 = .{ .bytes = ip_bytes, .port = 0 } });
    try ma.push(.{ .Tcp = port });
    try ma.push(.{ .P2P = peer.* });
    return ma.toString(allocator);
}

fn parseIpv4(ip: []const u8) ![4]u8 {
    var parts: [4]u8 = undefined;
    var idx: usize = 0;
    var start: usize = 0;
    for (ip, 0..) |c, i| {
        if (c == '.') {
            if (idx >= 4) return error.InvalidAddress;
            parts[idx] = try std.fmt.parseInt(u8, ip[start..i], 10);
            idx += 1;
            start = i + 1;
        }
    }
    if (idx != 3) return error.InvalidAddress;
    parts[3] = try std.fmt.parseInt(u8, ip[start..], 10);
    return parts;
}

fn envOwned(allocator: std.mem.Allocator, key: []const u8) ?[]u8 {
    const zkey = allocator.dupeZ(u8, key) catch return null;
    defer allocator.free(zkey);
    const raw = std.c.getenv(zkey) orelse return null;
    return allocator.dupe(u8, std.mem.span(raw)) catch null;
}

fn parseEnv(allocator: std.mem.Allocator) !Env {
    const is_dialer_str = envOwned(allocator, "IS_DIALER") orelse envOwned(allocator, "is_dialer") orelse return error.MissingIsDialer;
    defer allocator.free(is_dialer_str);
    const is_dialer = parseBoolSlice(is_dialer_str);

    const redis_addr_owned = envOwned(allocator, "REDIS_ADDR") orelse envOwned(allocator, "redis_addr") orelse try allocator.dupe(u8, "transport-redis:6379");
    defer allocator.free(redis_addr_owned);
    const listener_ip = envOwned(allocator, "LISTENER_IP") orelse envOwned(allocator, "ip") orelse try allocator.dupe(u8, "0.0.0.0");
    const test_key = envOwned(allocator, "TEST_KEY");
    const timeout_str = envOwned(allocator, "TEST_TIMEOUT_SECS") orelse envOwned(allocator, "test_timeout_seconds") orelse try allocator.dupe(u8, "180");
    defer allocator.free(timeout_str);
    const debug_str = envOwned(allocator, "DEBUG") orelse try allocator.dupe(u8, "false");
    defer allocator.free(debug_str);
    const debug = parseBoolSlice(debug_str);
    const transport = envOwned(allocator, "TRANSPORT") orelse envOwned(allocator, "transport") orelse try allocator.dupe(u8, "tcp");
    const secure_channel = envOwned(allocator, "SECURE_CHANNEL") orelse envOwned(allocator, "security");
    const muxer = envOwned(allocator, "MUXER") orelse envOwned(allocator, "muxer");

    var redis_parts = std.mem.splitScalar(u8, redis_addr_owned, ':');
    const redis_host = try allocator.dupe(u8, redis_parts.next() orelse return error.InvalidRedisAddr);
    const redis_port = try std.fmt.parseInt(u16, redis_parts.next() orelse "6379", 10);
    const timeout_secs = try std.fmt.parseInt(u64, timeout_str, 10);

    return .{
        .is_dialer = is_dialer,
        .redis_host = redis_host,
        .redis_port = redis_port,
        .listener_ip = listener_ip,
        .test_key = test_key,
        .timeout_secs = timeout_secs,
        .debug = debug,
        .transport = transport,
        .secure_channel = secure_channel,
        .muxer = muxer,
    };
}

fn freeEnv(allocator: std.mem.Allocator, env: Env) void {
    allocator.free(env.redis_host); // duped in parseEnv
    allocator.free(env.listener_ip);
    if (env.test_key) |k| allocator.free(k);
    allocator.free(env.transport);
    if (env.secure_channel) |s| allocator.free(s);
    if (env.muxer) |m| allocator.free(m);
}

fn parseBoolSlice(s: []const u8) bool {
    return std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "1");
}

const MissingIsDialer = error{MissingIsDialer};
const UnsupportedConfig = error{UnsupportedConfig};
const InvalidMultiaddr = error{InvalidMultiaddr};
const InvalidRedisAddr = error{InvalidRedisAddr};
const InvalidAddress = error{InvalidAddress};
const Timeout = error{Timeout};
