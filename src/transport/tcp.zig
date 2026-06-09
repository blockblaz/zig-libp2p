//! Plain TCP transport helpers on top of Zig 0.16 `std.Io.net` (listen / dial).
//!
//! Socket tuning (`TCP_NODELAY`, `SO_SNDBUF` / `SO_RCVBUF`) uses `std.posix.setsockopt` on
//! non-Windows targets. On Windows, tuning is skipped until a dedicated path exists.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;
const errors = @import("../errors.zig");
const sm = @import("stream_multistream.zig");
const terr = @import("transport_error.zig");
const posix = std.posix;
const c = std.c;

/// Label used in multistream-select examples/tests for a raw TCP byte stream (mirrors `/quic-v1` style).
pub const multistream_protocol_id: []const u8 = "/tcp";

/// Kernel-level options applied to outbound streams and to sockets accepted from [`listen`].
pub const StreamSocketTuning = struct {
    /// When true, set `TCP_NODELAY` on POSIX (ignored on Windows).
    tcp_nodelay: bool = true,
    send_buffer_bytes: ?u32 = null,
    recv_buffer_bytes: ?u32 = null,
};

pub const ApplyStreamSocketTuningError = error{SocketTuningFailed};

pub fn applyStreamSocketTuning(handle: net.Socket.Handle, tuning: StreamSocketTuning) ApplyStreamSocketTuningError!void {
    if (builtin.os.tag == .windows) return;
    if (!tuning.tcp_nodelay and tuning.send_buffer_bytes == null and tuning.recv_buffer_bytes == null) return;

    if (tuning.tcp_nodelay) {
        const on: c_int = 1;
        posix.setsockopt(handle, c.IPPROTO.TCP, c.TCP.NODELAY, std.mem.asBytes(&on)) catch return error.SocketTuningFailed;
    }
    if (tuning.send_buffer_bytes) |sz| {
        const v: c_int = @intCast(sz);
        posix.setsockopt(handle, c.SOL.SOCKET, c.SO.SNDBUF, std.mem.asBytes(&v)) catch return error.SocketTuningFailed;
    }
    if (tuning.recv_buffer_bytes) |sz| {
        const v: c_int = @intCast(sz);
        posix.setsockopt(handle, c.SOL.SOCKET, c.SO.RCVBUF, std.mem.asBytes(&v)) catch return error.SocketTuningFailed;
    }
}

pub const ListenOptions = struct {
    kernel_backlog: u31 = net.default_kernel_backlog,
    reuse_address: bool = true,
};

pub const ConnectOptions = struct {
    timeout: Io.Timeout = .none,
    tuning: StreamSocketTuning = .{},
};

pub fn listen(address: *const net.IpAddress, io: Io, options: ListenOptions) errors.TransportError!net.Server {
    return net.IpAddress.listen(address, io, .{
        .kernel_backlog = options.kernel_backlog,
        .reuse_address = options.reuse_address,
        .mode = .stream,
        .protocol = .tcp,
    }) catch |e| return terr.fromIpListen(e);
}

pub fn dial(
    address: *const net.IpAddress,
    io: Io,
    options: ConnectOptions,
) (errors.TransportError || ApplyStreamSocketTuningError)!net.Stream {
    var stream = net.IpAddress.connect(address, io, .{
        .mode = .stream,
        .protocol = .tcp,
        .timeout = options.timeout,
    }) catch |e| return terr.fromIpConnect(e);
    applyStreamSocketTuning(stream.socket.handle, options.tuning) catch |err| {
        stream.close(io);
        return err;
    };
    return stream;
}

pub fn acceptTuned(
    server: *net.Server,
    io: Io,
    tuning: StreamSocketTuning,
) (errors.TransportError || ApplyStreamSocketTuningError)!net.Stream {
    var stream = server.accept(io) catch |e| return terr.fromServerAccept(e);
    applyStreamSocketTuning(stream.socket.handle, tuning) catch |err| {
        stream.close(io);
        return err;
    };
    return stream;
}

/// First multistream-select messages on a new TCP stream: `/multistream/1.0.0\n` then `protocol_id\n`.
pub const appendFirstStreamInitiatorHandshake = sm.appendFirstStreamInitiatorHandshake;

pub const StreamHandshakeError = sm.StreamHandshakeError;

/// Run the initiator side of multistream-select 1.0.0 for `protocol_id` on a connected TCP stream.
pub fn initiatorHandshakeMultistream(
    stream: net.Stream,
    io: Io,
    protocol_id: []const u8,
    scratch_r: []u8,
    scratch_w: []u8,
    allocator: std.mem.Allocator,
) StreamHandshakeError!void {
    var r = net.Stream.reader(stream, io, scratch_r);
    var w = net.Stream.writer(stream, io, scratch_w);
    return sm.initiatorHandshakeMultistream(&r.interface, &w.interface, protocol_id, allocator, null);
}

/// Run the responder side: accept multistream, echo header, accept one protocol offer, reply if supported.
pub fn responderHandshakeMultistream(
    stream: net.Stream,
    io: Io,
    supported_protocol_id: []const u8,
    scratch_r: []u8,
    scratch_w: []u8,
    allocator: std.mem.Allocator,
) StreamHandshakeError!void {
    var r = net.Stream.reader(stream, io, scratch_r);
    var w = net.Stream.writer(stream, io, scratch_w);
    return sm.responderHandshakeMultistream(&r.interface, &w.interface, supported_protocol_id, allocator, null);
}

test "tcp identifiers" {
    try std.testing.expect(std.mem.startsWith(u8, multistream_protocol_id, "/"));
    try std.testing.expect(multistream_protocol_id.len > 1);
}

test "tcp listen dial multistream round trip" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;
    if (switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos => true,
        else => false,
    }) return error.SkipZigTest;

    const a = std.testing.allocator;
    var io_impl = Io.Threaded.init(a, .{ .async_limit = Io.Limit.limited(8) });
    defer io_impl.deinit();
    const io = io_impl.io();

    var bind_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    var server = try listen(&bind_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const ServerThreadErr = errors.TransportError || ApplyStreamSocketTuningError || sm.StreamHandshakeError;

    const tuning: StreamSocketTuning = .{ .tcp_nodelay = true, .send_buffer_bytes = 1 << 16, .recv_buffer_bytes = 1 << 16 };

    const ServerCtx = struct {
        server: *net.Server,
        io_inner: Io,
        tuning_inner: StreamSocketTuning,
        err: ?ServerThreadErr = null,

        fn run(ctx: *@This()) void {
            const st = acceptTuned(ctx.server, ctx.io_inner, ctx.tuning_inner) catch |e| {
                ctx.err = e;
                return;
            };
            defer st.close(ctx.io_inner);
            var scratch_r: [2048]u8 = undefined;
            var scratch_w: [2048]u8 = undefined;
            responderHandshakeMultistream(st, ctx.io_inner, multistream_protocol_id, &scratch_r, &scratch_w, a) catch |e| {
                ctx.err = e;
            };
        }
    };

    var ctx: ServerCtx = .{
        .server = &server,
        .io_inner = io,
        .tuning_inner = tuning,
    };
    const thr = try std.Thread.spawn(.{}, ServerCtx.run, .{&ctx});
    defer thr.join();

    const connect_addr: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    var client = try dial(&connect_addr, io, .{ .tuning = tuning });
    defer client.close(io);

    var scratch_r: [2048]u8 = undefined;
    var scratch_w: [2048]u8 = undefined;
    try initiatorHandshakeMultistream(client, io, multistream_protocol_id, &scratch_r, &scratch_w, a);
    try std.testing.expect(ctx.err == null);
}
