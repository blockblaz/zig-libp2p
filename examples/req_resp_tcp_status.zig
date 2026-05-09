//! One-shot Lean status req/resp over TCP loopback (multistream + ssz_snappy).
//!
//! On Darwin, `std.Io.Threaded` accept/dial across threads is unreliable in this
//! layout (hangs). The program exits successfully after printing a skip notice; run
//! the same logic on Linux or exercise `req_resp.wire_tcp` tests there.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;
const zl = @import("zig_libp2p");

pub fn main() !void {
    if (builtin.single_threaded) return;
    if (builtin.os.tag == .wasi) return;

    if (switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos => true,
        else => false,
    }) {
        std.debug.print(
            "example-req-resp-tcp-status: skipped on Darwin (Io.Threaded TCP loopback hangs); see src/req_resp/wire_tcp.zig tests on Linux.\n",
            .{},
        );
        return;
    }

    const gpa = std.heap.page_allocator;
    var io_impl = Io.Threaded.init(gpa, .{ .async_limit = Io.Limit.limited(8) });
    defer io_impl.deinit();
    const io = io_impl.io();

    var bind_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    var server = try zl.transport.tcp.listen(&bind_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const limits: zl.req_resp.wire_tcp.ExchangeLimits = .{};

    const Server = struct {
        fn run(srv: *net.Server, io_inner: Io, alloc: std.mem.Allocator, lim: zl.req_resp.wire_tcp.ExchangeLimits) void {
            const st = zl.transport.tcp.acceptTuned(srv, io_inner, .{}) catch return;
            defer st.close(io_inner);
            var scratch_r: [8192]u8 = undefined;
            var scratch_w: [8192]u8 = undefined;
            const req = zl.req_resp.wire_tcp.responderUnarySequence(
                alloc,
                io_inner,
                st,
                zl.protocol.status_v1,
                &scratch_r,
                &scratch_w,
                lim,
                &.{"status-ok-payload"},
            ) catch return;
            defer alloc.free(req);
        }
    }.run;

    const thr = try std.Thread.spawn(.{}, Server.run, .{ &server, io, gpa, limits });
    defer thr.join();

    const connect_addr: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    var client = try zl.transport.tcp.dial(&connect_addr, io, .{});
    defer client.close(io);
    var scratch_r: [8192]u8 = undefined;
    var scratch_w: [8192]u8 = undefined;

    const got = try zl.req_resp.wire_tcp.initiatorUnaryExchange(
        gpa,
        io,
        client,
        zl.protocol.status_v1,
        "status-req",
        &scratch_r,
        &scratch_w,
        limits,
    );
    defer gpa.free(got.ssz);
    if (got.code != 0) return error.BadStatus;
    if (!std.mem.eql(u8, got.ssz, "status-ok-payload")) return error.BadPayload;

    std.debug.print("status unary ok ({d} byte body)\n", .{got.ssz.len});
}
