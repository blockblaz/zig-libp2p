const std = @import("std");
const Io = std.Io;
const zl = @import("zig_libp2p");

pub fn main() !void {
    const a = std.heap.page_allocator;
    const relay_id = try zl.identity.PeerId.random();
    const client_peer = try zl.identity.PeerId.random();

    var srv = zl.relay.Server.init(a, .{
        .relay_addrs = &.{"/ip4/203.0.113.1/udp/4001/quic-v1"},
    }, relay_id);
    defer srv.deinit();

    var client = zl.relay.Client.init(a, .{});
    defer client.deinit();

    var in_buf: [4096]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var w_in = Io.Writer.fixed(&in_buf);
    const req = try client.buildReserveRequest();
    defer a.free(req);
    try zl.relay.wire.writeLengthPrefixed(&w_in, req);
    var r = Io.Reader.fixed(in_buf[0..w_in.end]);
    var w_out = Io.Writer.fixed(&out_buf);
    try srv.handleHopStream(&r, &w_out, client_peer, false);

    var resp_r = Io.Reader.fixed(out_buf[0..w_out.end]);
    const frame = try zl.relay.wire.readLengthPrefixedAlloc(&resp_r, a, zl.relay.wire.Limits.standard.max_frame_bytes);
    defer a.free(frame);
    try client.parseReserveResponse(frame, relay_id);
    std.debug.print("relay_membuf: reservation ok expire={d}\n", .{client.reservation.?.expire_unix});
}
