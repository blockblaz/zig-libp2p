//! Multistream-select for [`libp2p_noise.multistream_protocol_id`] then Noise XX + identity handshake.
//!
//! Kept separate from [`libp2p_noise.zig`] so this module can import [`transport/stream_multistream.zig`]
//! without a circular dependency with [`transport/transport_error.zig`] (which already imports `libp2p_noise`).

const std = @import("std");
const builtin = @import("builtin");
const pid = @import("peer_id");
const errors = @import("../../errors.zig");
const keypair = @import("../../keypair.zig");
const sm = @import("../../transport/stream_multistream.zig");
const noise = @import("libp2p_noise.zig");
const tcp = @import("../../transport/tcp.zig");

const Io = std.Io;
const net = Io.net;

pub const UpgradeError = sm.StreamHandshakeError || noise.Error;

/// Lossy map for embedders that only surface [`errors.TransportError`] (plus OOM).
pub fn toTransportError(err: UpgradeError) (errors.TransportError || std.mem.Allocator.Error) {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.DialFailed => error.DialFailed,
        error.Unreachable => error.Unreachable,
        error.ProtocolNegotiationFailed => error.ProtocolNegotiationFailed,
        error.SecurityUpgradeFailed => error.SecurityUpgradeFailed,
        error.ReadFailed, error.WriteFailed => error.DialFailed,
        error.EndOfStream => error.DialFailed,
        else => error.SecurityUpgradeFailed,
    };
}

/// Initiator: multistream `/noise`, then [`noise.handshakeInitiator`].
pub fn negotiateInitiator(
    allocator: std.mem.Allocator,
    io: std.Io,
    prologue: []const u8,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    host: keypair.KeyPair,
    noise_static: std.crypto.dh.X25519.KeyPair,
    stream_muxers: []const []const u8,
    expected_remote: ?pid.PeerId,
    scratch: []u8,
    payload_scratch: []u8,
    mux_list: *std.ArrayList([]const u8),
) UpgradeError!noise.HandshakeResult {
    try sm.initiatorHandshakeMultistream(r, w, noise.multistream_protocol_id, allocator);
    return try noise.handshakeInitiator(
        allocator,
        io,
        prologue,
        r,
        w,
        host,
        noise_static,
        stream_muxers,
        expected_remote,
        scratch,
        payload_scratch,
        mux_list,
    );
}

/// Responder: multistream `/noise`, then [`noise.handshakeResponder`].
pub fn negotiateResponder(
    allocator: std.mem.Allocator,
    io: std.Io,
    prologue: []const u8,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    host: keypair.KeyPair,
    noise_static: std.crypto.dh.X25519.KeyPair,
    stream_muxers: []const []const u8,
    expected_remote: ?pid.PeerId,
    scratch: []u8,
    payload_scratch: []u8,
    mux_list: *std.ArrayList([]const u8),
) UpgradeError!noise.HandshakeResult {
    try sm.responderHandshakeMultistream(r, w, noise.multistream_protocol_id, allocator);
    return try noise.handshakeResponder(
        allocator,
        io,
        prologue,
        r,
        w,
        host,
        noise_static,
        stream_muxers,
        expected_remote,
        scratch,
        payload_scratch,
        mux_list,
    );
}

test "/noise protocol id valid for multistream-select" {
    const neg = @import("../../transport/multistream_negotiate.zig");
    try neg.validateProtocolId(noise.multistream_protocol_id);
}

test "toTransportError maps negotiation failure" {
    try std.testing.expectEqual(
        errors.TransportError.ProtocolNegotiationFailed,
        toTransportError(error.ProtocolNegotiationFailed),
    );
}

fn skipDarwinTcpLoopbackNoise() bool {
    return switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos => true,
        else => false,
    };
}

test "Noise XX + multistream over TCP loopback" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;
    if (skipDarwinTcpLoopbackNoise()) return error.SkipZigTest;

    const a = std.testing.allocator;
    var io_impl = Io.Threaded.init(a, .{ .async_limit = Io.Limit.limited(8) });
    defer io_impl.deinit();
    const io = io_impl.io();

    var sk_i: [32]u8 = undefined;
    @memset(&sk_i, 0x11);
    const ed_i = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(sk_i);
    const host_i: keypair.KeyPair = .{ .ed25519 = ed_i };

    var sk_r: [32]u8 = undefined;
    @memset(&sk_r, 0x22);
    const ed_r = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(sk_r);
    const host_r: keypair.KeyPair = .{ .ed25519 = ed_r };

    var ns_i: [32]u8 = undefined;
    @memset(&ns_i, 0x33);
    const noise_i = try std.crypto.dh.X25519.KeyPair.generateDeterministic(ns_i);

    var ns_r: [32]u8 = undefined;
    @memset(&ns_r, 0x44);
    const noise_r = try std.crypto.dh.X25519.KeyPair.generateDeterministic(ns_r);

    const expected_remote = try keypair.peerIdFromKeyPair(a, host_r);

    var bind_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    var server = try tcp.listen(&bind_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const Server = struct {
        fn run(
            srv: *net.Server,
            io_inner: Io,
            host: keypair.KeyPair,
            noise_static: std.crypto.dh.X25519.KeyPair,
        ) void {
            const st = tcp.acceptTuned(srv, io_inner, .{}) catch return;
            defer st.close(io_inner);
            var scratch_r: [65536]u8 = undefined;
            var scratch_w: [65536]u8 = undefined;
            var payload_scratch: [16384]u8 = undefined;
            var mux = std.ArrayList([]const u8).empty;
            defer mux.deinit(a);
            var r = net.Stream.reader(st, io_inner, &scratch_r);
            var w = net.Stream.writer(st, io_inner, &scratch_w);
            const muxers = [_][]const u8{"/yamux/1.0.0"};
            const hs = negotiateResponder(
                a,
                io_inner,
                "",
                &r.interface,
                &w.interface,
                host,
                noise_static,
                &muxers,
                null,
                &scratch_r,
                &payload_scratch,
                &mux,
            ) catch return;
            var ct_buf: [4096]u8 = undefined;
            var pt_buf: [4096]u8 = undefined;
            const plain = hs.channel.readTransport(&r.interface, &ct_buf, &pt_buf) catch return;
            if (!std.mem.eql(u8, plain, "noise-payload")) return;
        }
    };

    const thr = try std.Thread.spawn(.{}, Server.run, .{ &server, io, host_r, noise_r });
    defer thr.join();

    const connect_addr: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    var client = try tcp.dial(&connect_addr, io, .{});
    defer client.close(io);

    var scratch_r: [65536]u8 = undefined;
    var scratch_w: [65536]u8 = undefined;
    var payload_scratch: [16384]u8 = undefined;
    var mux = std.ArrayList([]const u8).empty;
    defer mux.deinit(a);
    var r = net.Stream.reader(client, io, &scratch_r);
    var w = net.Stream.writer(client, io, &scratch_w);
    const muxers = [_][]const u8{"/yamux/1.0.0"};

    const hs = try negotiateInitiator(
        a,
        io,
        "",
        &r.interface,
        &w.interface,
        host_i,
        noise_i,
        &muxers,
        expected_remote,
        &scratch_r,
        &payload_scratch,
        &mux,
    );
    try std.testing.expect(hs.remote_peer_id.eql(&expected_remote));

    var wscratch: [256]u8 = undefined;
    try hs.channel.writeTransport(&w.interface, "noise-payload", &wscratch);
}
