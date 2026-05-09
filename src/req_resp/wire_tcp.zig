//! TCP byte-stream harness for Lean `ssz_snappy` req/resp: one connection = one logical libp2p-style
//! substream — multistream-select 1.0.0 on the socket, then length-prefixed snappy frames from
//! [`wire_framing`] (#40).
//!
//! This is not a multiplexer: each request should use a **fresh** TCP connection (or open a new
//! QUIC bidirectional stream and run [`req_resp.wire_quic`]). [`transport.tcp`] provides the
//! multistream helpers used here.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;

const errors = @import("../errors.zig");
const protocol = @import("../protocol.zig");
const tcp = @import("../transport/tcp.zig");
const framing = @import("wire_framing.zig");

pub const WireTcpError = errors.TransportError ||
    tcp.ApplyStreamSocketTuningError ||
    tcp.StreamHandshakeError ||
    errors.ReqRespError;

pub const ExchangeLimits = framing.ExchangeLimits;

/// Initiator: multistream for `protocol_id`, send one unary request, read one unary response.
/// Caller owns returned `ssz` and must close `stream` when done.
pub fn initiatorUnaryExchange(
    allocator: std.mem.Allocator,
    io: Io,
    stream: net.Stream,
    protocol_id: []const u8,
    uncompressed_request: []const u8,
    scratch_r: []u8,
    scratch_w: []u8,
    limits: ExchangeLimits,
) (WireTcpError || std.mem.Allocator.Error)!framing.UnaryResponse {
    try tcp.initiatorHandshakeMultistream(stream, io, protocol_id, scratch_r, scratch_w, allocator);
    var w = net.Stream.writer(stream, io, scratch_w);
    var r = net.Stream.reader(stream, io, scratch_r);
    return try framing.initiatorUnaryAfterHandshake(allocator, &r.interface, &w.interface, scratch_r, uncompressed_request, limits);
}

/// Initiator: after multistream + request (same as [`initiatorUnaryExchange`]), read `count` unary
/// responses back-to-back on the same stream (e.g. blocks-by-range chunks).
pub fn initiatorReadResponseSequence(
    allocator: std.mem.Allocator,
    io: Io,
    stream: net.Stream,
    protocol_id: []const u8,
    uncompressed_request: []const u8,
    scratch_r: []u8,
    scratch_w: []u8,
    limits: ExchangeLimits,
    count: usize,
) (WireTcpError || std.mem.Allocator.Error)![][]u8 {
    try tcp.initiatorHandshakeMultistream(stream, io, protocol_id, scratch_r, scratch_w, allocator);
    var w = net.Stream.writer(stream, io, scratch_w);
    var r = net.Stream.reader(stream, io, scratch_r);
    return try framing.initiatorReadResponsesAfterHandshake(allocator, &r.interface, &w.interface, scratch_r, uncompressed_request, limits, count);
}

/// Responder: multistream for `protocol_id`, read one unary request, write `count` unary responses
/// (code 0, uncompressed bodies), then return the decoded request SSZ (caller frees).
pub fn responderUnarySequence(
    allocator: std.mem.Allocator,
    io: Io,
    stream: net.Stream,
    protocol_id: []const u8,
    scratch_r: []u8,
    scratch_w: []u8,
    limits: ExchangeLimits,
    response_bodies: []const []const u8,
) (WireTcpError || std.mem.Allocator.Error)![]u8 {
    try tcp.responderHandshakeMultistream(stream, io, protocol_id, scratch_r, scratch_w, allocator);
    var r = net.Stream.reader(stream, io, scratch_r);
    var w = net.Stream.writer(stream, io, scratch_w);
    return try framing.responderUnarySequenceAfterHandshake(allocator, &r.interface, &w.interface, scratch_r, limits, response_bodies);
}

fn skipDarwinTcpLoopback() bool {
    return switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos => true,
        else => false,
    };
}

test "wire_tcp status unary over loopback" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;
    if (skipDarwinTcpLoopback()) return error.SkipZigTest;

    const a = std.testing.allocator;
    var io_impl = Io.Threaded.init(a, .{ .async_limit = Io.Limit.limited(8) });
    defer io_impl.deinit();
    const io = io_impl.io();

    var bind_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    var server = try tcp.listen(&bind_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const proto = protocol.status_v1;
    const limits: ExchangeLimits = .{};

    const Server = struct {
        fn run(srv: *net.Server, io_inner: Io) void {
            const st = tcp.acceptTuned(srv, io_inner, .{}) catch return;
            defer st.close(io_inner);
            var scratch_r: [8192]u8 = undefined;
            var scratch_w: [8192]u8 = undefined;
            const req = responderUnarySequence(a, io_inner, st, proto, &scratch_r, &scratch_w, limits, &.{"status-ok-payload"}) catch return;
            defer a.free(req);
        }
    };

    const thr = try std.Thread.spawn(.{}, Server.run, .{ &server, io });
    defer thr.join();

    const connect_addr: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    var client = try tcp.dial(&connect_addr, io, .{});
    defer client.close(io);
    var scratch_r: [8192]u8 = undefined;
    var scratch_w: [8192]u8 = undefined;

    const got = try initiatorUnaryExchange(a, io, client, proto, "status-req", &scratch_r, &scratch_w, limits);
    defer a.free(got.ssz);
    try std.testing.expectEqual(@as(u8, 0), got.code);
    try std.testing.expectEqualStrings("status-ok-payload", got.ssz);
}

test "wire_tcp multi response on one stream" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;
    if (skipDarwinTcpLoopback()) return error.SkipZigTest;

    const a = std.testing.allocator;
    var io_impl = Io.Threaded.init(a, .{ .async_limit = Io.Limit.limited(8) });
    defer io_impl.deinit();
    const io = io_impl.io();

    var bind_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    var server = try tcp.listen(&bind_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const proto = protocol.blocks_by_range_v1;
    const limits: ExchangeLimits = .{};
    const chunks = [_][]const u8{ "block-0", "block-1", "block-2" };

    const Server = struct {
        fn run(srv: *net.Server, io_inner: Io) void {
            const st = tcp.acceptTuned(srv, io_inner, .{}) catch return;
            defer st.close(io_inner);
            var scratch_r: [8192]u8 = undefined;
            var scratch_w: [8192]u8 = undefined;
            const req = responderUnarySequence(a, io_inner, st, proto, &scratch_r, &scratch_w, limits, &chunks) catch return;
            defer a.free(req);
        }
    };

    const thr = try std.Thread.spawn(.{}, Server.run, .{ &server, io });
    defer thr.join();

    const connect_addr: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    var client = try tcp.dial(&connect_addr, io, .{});
    defer client.close(io);
    var scratch_r: [8192]u8 = undefined;
    var scratch_w: [8192]u8 = undefined;

    const parts = try initiatorReadResponseSequence(a, io, client, proto, "range-req", &scratch_r, &scratch_w, limits, chunks.len);
    defer {
        for (parts) |p| a.free(p);
        a.free(parts);
    }
    try std.testing.expectEqual(@as(usize, 3), parts.len);
    for (chunks, parts) |exp, got| {
        try std.testing.expectEqualStrings(exp, got);
    }
}

test "wire_tcp two connections two handshakes" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;
    if (skipDarwinTcpLoopback()) return error.SkipZigTest;

    const a = std.testing.allocator;
    var io_impl = Io.Threaded.init(a, .{ .async_limit = Io.Limit.limited(8) });
    defer io_impl.deinit();
    const io = io_impl.io();

    var bind_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    var server = try tcp.listen(&bind_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const proto = protocol.status_v1;
    const limits: ExchangeLimits = .{};

    const Server = struct {
        fn run(srv: *net.Server, io_inner: Io) void {
            for (0..2) |_| {
                const st = tcp.acceptTuned(srv, io_inner, .{}) catch return;
                defer st.close(io_inner);
                var scratch_r: [8192]u8 = undefined;
                var scratch_w: [8192]u8 = undefined;
                const req = responderUnarySequence(a, io_inner, st, proto, &scratch_r, &scratch_w, limits, &.{"ack"}) catch return;
                defer a.free(req);
            }
        }
    };

    const thr = try std.Thread.spawn(.{}, Server.run, .{ &server, io });
    defer thr.join();

    const connect_addr: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    var scratch_r: [8192]u8 = undefined;
    var scratch_w: [8192]u8 = undefined;

    for (0..2) |_| {
        var client = try tcp.dial(&connect_addr, io, .{});
        defer client.close(io);
        const got = try initiatorUnaryExchange(a, io, client, proto, "r", &scratch_r, &scratch_w, limits);
        defer a.free(got.ssz);
        try std.testing.expectEqualStrings("ack", got.ssz);
    }
}
