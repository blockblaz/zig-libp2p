//! TCP byte-stream harness for Lean `ssz_snappy` req/resp: one connection = one logical libp2p-style
//! substream — multistream-select 1.0.0 on the socket, then length-prefixed snappy frames from
//! [`snappy_wire`] / [`frame`] (#40).
//!
//! This is not a multiplexer: each request should use a **fresh** TCP connection (or open a new
//! QUIC bidirectional stream and run the same multistream + framing on its `std.Io.Reader` /
//! `Writer` pair). [`transport.tcp`] provides the multistream helpers used here.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;

const errors = @import("../errors.zig");
const frame = @import("frame.zig");
const protocol = @import("../protocol.zig");
const snappy_wire = @import("snappy_wire.zig");
const tcp = @import("../transport/tcp.zig");

pub const WireTcpError = errors.TransportError ||
    tcp.ApplyStreamSocketTuningError ||
    tcp.StreamHandshakeError ||
    errors.ReqRespError;

pub const ExchangeLimits = struct {
    /// Max bytes buffered while scanning one unary message.
    max_accumulated: usize = 16 * 1024 * 1024,
    /// Max bytes per `readSliceShort` slice.
    read_chunk: usize = 4096,
};

/// Returns wire length of the first complete unary response in `wire` (header + snappy suffix).
fn firstUnaryResponseWireLen(allocator: std.mem.Allocator, wire: []const u8) (errors.ReqRespError || std.mem.Allocator.Error)!usize {
    const h = try frame.parseResponseHeader(wire);
    const hdr_len = wire.len - h.payload.len;
    if (h.payload.len == 0) return error.IncompleteStream;

    var i: usize = 1;
    while (i <= h.payload.len) : (i += 1) {
        const plain = snappy_wire.decompressFramed(allocator, h.payload[0..i]) catch continue;
        defer allocator.free(plain);
        if (plain.len == h.declared_len) {
            return hdr_len + i;
        }
    }
    return error.IncompleteStream;
}

fn readMoreInto(
    acc: *std.ArrayList(u8),
    r: *Io.Reader,
    allocator: std.mem.Allocator,
    scratch: []u8,
    limits: ExchangeLimits,
) (errors.ReqRespError || std.mem.Allocator.Error)!void {
    const chunk = scratch[0..@min(scratch.len, limits.read_chunk)];
    const n = r.readSliceShort(chunk) catch return error.IoError;
    if (n == 0) return error.Disconnected;
    const new_len = acc.items.len + n;
    if (new_len > limits.max_accumulated) return error.PayloadTooLarge;
    try acc.appendSlice(allocator, chunk[0..n]);
}

fn readOneUnaryRequest(
    allocator: std.mem.Allocator,
    r: *Io.Reader,
    scratch: []u8,
    limits: ExchangeLimits,
) (errors.ReqRespError || std.mem.Allocator.Error)![]u8 {
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);
    while (true) {
        try readMoreInto(&acc, r, allocator, scratch, limits);
        if (snappy_wire.decodeRequestSsz(allocator, acc.items)) |ssz| {
            return ssz;
        } else |err| switch (err) {
            error.IncompleteHeader => continue,
            error.InvalidData => continue,
            else => |e| return e,
        }
    }
}

fn readOneUnaryResponse(
    allocator: std.mem.Allocator,
    r: *Io.Reader,
    scratch: []u8,
    limits: ExchangeLimits,
) (errors.ReqRespError || std.mem.Allocator.Error)!struct { code: u8, ssz: []u8 } {
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);
    while (true) {
        try readMoreInto(&acc, r, allocator, scratch, limits);
        const frame_len = firstUnaryResponseWireLen(allocator, acc.items) catch |err| switch (err) {
            error.IncompleteStream => continue,
            else => |e| return e,
        };
        return try snappy_wire.decodeResponseSsz(allocator, acc.items[0..frame_len]);
    }
}

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
) (WireTcpError || std.mem.Allocator.Error)!struct { code: u8, ssz: []u8 } {
    try tcp.initiatorHandshakeMultistream(stream, io, protocol_id, scratch_r, scratch_w, allocator);
    const wire_req = try snappy_wire.buildRequestWire(allocator, uncompressed_request);
    defer allocator.free(wire_req);
    var w = net.Stream.writer(stream, io, scratch_w);
    try Io.Writer.writeAll(&w.interface, wire_req);
    try Io.Writer.flush(&w.interface);

    var r = net.Stream.reader(stream, io, scratch_r);
    const got = try readOneUnaryResponse(allocator, &r.interface, scratch_r, limits);
    return got;
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
    const wire_req = try snappy_wire.buildRequestWire(allocator, uncompressed_request);
    defer allocator.free(wire_req);
    var w = net.Stream.writer(stream, io, scratch_w);
    try Io.Writer.writeAll(&w.interface, wire_req);
    try Io.Writer.flush(&w.interface);

    var r = net.Stream.reader(stream, io, scratch_r);
    var i: usize = 0;
    const out = try allocator.alloc([]u8, count);
    errdefer {
        for (out[0..i]) |s| allocator.free(s);
        allocator.free(out);
    }
    while (i < count) : (i += 1) {
        const got = try readOneUnaryResponse(allocator, &r.interface, scratch_r, limits);
        if (got.code != 0) {
            allocator.free(got.ssz);
            for (out[0..i]) |s| allocator.free(s);
            allocator.free(out);
            return error.InvalidData;
        }
        out[i] = got.ssz;
    }
    return out;
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
    const req_ssz = try readOneUnaryRequest(allocator, &r.interface, scratch_r, limits);
    errdefer allocator.free(req_ssz);

    var w = net.Stream.writer(stream, io, scratch_w);
    for (response_bodies) |body| {
        const wire = try snappy_wire.buildResponseWire(allocator, 0, body);
        defer allocator.free(wire);
        try Io.Writer.writeAll(&w.interface, wire);
    }
    try Io.Writer.flush(&w.interface);
    return req_ssz;
}

test "wire_tcp status unary over loopback" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var io_impl = Io.Threaded.init(a, .{});
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

    const a = std.testing.allocator;
    var io_impl = Io.Threaded.init(a, .{});
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

    const a = std.testing.allocator;
    var io_impl = Io.Threaded.init(a, .{});
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
