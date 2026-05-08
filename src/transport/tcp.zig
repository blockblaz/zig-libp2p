//! Plain TCP transport helpers on top of Zig 0.16 `std.Io.net` (listen / dial).
//!
//! Socket tuning (`TCP_NODELAY`, `SO_SNDBUF` / `SO_RCVBUF`) uses `std.posix.setsockopt` on
//! non-Windows targets. On Windows, tuning is skipped until a dedicated path exists.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;
const neg = @import("multistream_negotiate.zig");
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

pub fn listen(address: *const net.IpAddress, io: Io, options: ListenOptions) net.IpAddress.ListenError!net.Server {
    return net.IpAddress.listen(address, io, .{
        .kernel_backlog = options.kernel_backlog,
        .reuse_address = options.reuse_address,
        .mode = .stream,
        .protocol = .tcp,
    });
}

pub fn dial(
    address: *const net.IpAddress,
    io: Io,
    options: ConnectOptions,
) (net.IpAddress.ConnectError || ApplyStreamSocketTuningError)!net.Stream {
    var stream = try net.IpAddress.connect(address, io, .{
        .mode = .stream,
        .protocol = .tcp,
        .timeout = options.timeout,
    });
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
) (net.Server.AcceptError || ApplyStreamSocketTuningError)!net.Stream {
    var stream = try server.accept(io);
    applyStreamSocketTuning(stream.socket.handle, tuning) catch |err| {
        stream.close(io);
        return err;
    };
    return stream;
}

/// First multistream-select messages on a new TCP stream: `/multistream/1.0.0\n` then `protocol_id\n`.
pub fn appendFirstStreamInitiatorHandshake(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol_id: []const u8,
) (neg.NegotiateError || std.mem.Allocator.Error)!void {
    try neg.initiatorSendMultistreamHeader(write, allocator);
    try neg.initiatorSendProtocol(write, allocator, protocol_id);
}

pub const StreamHandshakeError = neg.NegotiateError || Io.Writer.Error || Io.Reader.ShortError || std.mem.Allocator.Error;

const handshake_accum_cap = 1024;

fn compactConsumed(acc: *std.ArrayList(u8), allocator: std.mem.Allocator, rem: []const u8) std.mem.Allocator.Error!void {
    const consumed = acc.items.len - rem.len;
    try acc.replaceRange(allocator, 0, consumed, &.{});
}

fn readMoreHandshake(acc: *std.ArrayList(u8), r: *Io.Reader, allocator: std.mem.Allocator) StreamHandshakeError!void {
    if (acc.items.len >= handshake_accum_cap) return error.LineTooLong;
    var chunk: [512]u8 = undefined;
    const n = try r.readSliceShort(&chunk);
    if (n == 0) return error.MissingNewline;
    try acc.appendSlice(allocator, chunk[0..n]);
    if (acc.items.len > handshake_accum_cap) return error.LineTooLong;
}

/// Run the initiator side of multistream-select 1.0.0 for `protocol_id` on a connected TCP stream.
pub fn initiatorHandshakeMultistream(
    stream: net.Stream,
    io: Io,
    protocol_id: []const u8,
    scratch_r: []u8,
    scratch_w: []u8,
    allocator: std.mem.Allocator,
) StreamHandshakeError!void {
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);

    var r = net.Stream.reader(stream, io, scratch_r);
    var w = net.Stream.writer(stream, io, scratch_w);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try appendFirstStreamInitiatorHandshake(&out, allocator, protocol_id);
    try Io.Writer.writeAll(&w.interface, out.items);
    try Io.Writer.flush(&w.interface);

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.initiatorReadPeerMultistream(&rem, neg.default_max_body_len)) |_| {
            try compactConsumed(&acc, allocator, rem);
            break;
        } else |err| switch (err) {
            error.MissingNewline => try readMoreHandshake(&acc, &r.interface, allocator),
            else => return err,
        }
    }

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.initiatorReadProtocolAck(&rem, protocol_id, neg.default_max_body_len)) |_| {
            try compactConsumed(&acc, allocator, rem);
            return;
        } else |err| switch (err) {
            error.MissingNewline => try readMoreHandshake(&acc, &r.interface, allocator),
            else => return err,
        }
    }
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
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);

    var r = net.Stream.reader(stream, io, scratch_r);
    var w = net.Stream.writer(stream, io, scratch_w);

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.responderReadMultistreamOffer(&rem, neg.default_max_body_len)) |_| {
            try compactConsumed(&acc, allocator, rem);
            break;
        } else |err| switch (err) {
            error.MissingNewline => try readMoreHandshake(&acc, &r.interface, allocator),
            else => return err,
        }
    }

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try neg.responderSendMultistreamHeader(&out, allocator);
    try Io.Writer.writeAll(&w.interface, out.items);
    try Io.Writer.flush(&w.interface);

    while (true) {
        var rem: []const u8 = acc.items;
        const offered = neg.responderReadProtocolOffer(&rem, neg.default_max_body_len) catch |err| switch (err) {
            error.MissingNewline => {
                try readMoreHandshake(&acc, &r.interface, allocator);
                continue;
            },
            else => return err,
        };
        try compactConsumed(&acc, allocator, rem);
        out.clearRetainingCapacity();
        try neg.responderReplyProtocol(&out, allocator, offered, supported_protocol_id);
        try Io.Writer.writeAll(&w.interface, out.items);
        try Io.Writer.flush(&w.interface);
        return;
    }
}

test "tcp identifiers" {
    try std.testing.expect(std.mem.startsWith(u8, multistream_protocol_id, "/"));
    try std.testing.expect(multistream_protocol_id.len > 1);
}

test "tcp listen dial multistream round trip" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var io_impl = Io.Threaded.init(a, .{});
    defer io_impl.deinit();
    const io = io_impl.io();

    var bind_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    var server = try listen(&bind_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const ServerCtx = struct {
        server: *net.Server,
        io: Io,
        tuning: StreamSocketTuning,
        err: ?anyerror = null,

        fn run(ctx: *@This()) void {
            const st = acceptTuned(ctx.server, ctx.io, ctx.tuning) catch |e| {
                ctx.err = e;
                return;
            };
            defer st.close(ctx.io);
            var scratch_r: [2048]u8 = undefined;
            var scratch_w: [2048]u8 = undefined;
            responderHandshakeMultistream(st, ctx.io, multistream_protocol_id, &scratch_r, &scratch_w, std.testing.allocator) catch |e| {
                ctx.err = e;
            };
        }
    };

    var ctx: ServerCtx = .{
        .server = &server,
        .io = io,
        .tuning = .{ .tcp_nodelay = true, .send_buffer_bytes = 1 << 16, .recv_buffer_bytes = 1 << 16 },
    };
    const thr = try std.Thread.spawn(.{}, ServerCtx.run, .{&ctx});
    defer thr.join();

    const connect_addr: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    var client = try dial(&connect_addr, io, .{ .tuning = ctx.tuning });
    defer client.close(io);

    var scratch_r: [2048]u8 = undefined;
    var scratch_w: [2048]u8 = undefined;
    try initiatorHandshakeMultistream(client, io, multistream_protocol_id, &scratch_r, &scratch_w, a);
    try std.testing.expect(ctx.err == null);
}
