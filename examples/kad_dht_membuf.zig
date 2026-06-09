//! kad-dht FIND_NODE round-trip over in-memory `std.Io` buffers (no TCP).

const std = @import("std");
const Io = std.Io;
const zl = @import("zig_libp2p");

pub fn main() !void {
    const a = std.heap.page_allocator;

    var server = try zl.kad_dht.Server.init(a, "dht-local", .{});
    defer server.deinit();

    const addr = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};
    _ = try server.routingTable().update("peer-near", &addr, .server, 0);
    _ = try server.routingTable().update("peer-far", &addr, .server, 0);

    const req_bytes = try zl.kad_dht.wire.encode(a, .{
        .msg_type = .find_node,
        .key = "target-peer-id",
    });
    defer a.free(req_bytes);

    var in_buf: [4096]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var w_in = Io.Writer.fixed(&in_buf);
    try zl.kad_dht.wire.writeLengthPrefixed(&w_in, req_bytes);

    var r = Io.Reader.fixed(in_buf[0..w_in.end]);
    var w_out = Io.Writer.fixed(&out_buf);
    try server.handleStream(&r, &w_out, 0);

    var r_out = Io.Reader.fixed(out_buf[0..w_out.end]);
    const frame = try zl.kad_dht.wire.readLengthPrefixedAlloc(&r_out, a, zl.kad_dht.wire.Limits.standard.max_frame_bytes);
    defer a.free(frame);
    var resp = try zl.kad_dht.wire.decodeOwned(a, frame, .standard);
    defer resp.deinit(a);

    if (resp.closer_peers.len == 0) return error.NoCloserPeers;
    std.debug.print("kad-dht find_node ok ({d} closer peers)\n", .{resp.closer_peers.len});
}
