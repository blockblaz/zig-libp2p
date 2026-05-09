//! Ping 1.0.0 echo using fixed `std.Io` reader/writer buffers (no TCP).

const std = @import("std");
const Io = std.Io;
const zl = @import("zig_libp2p");

pub fn main() !void {
    var inbound: [zl.ping.payload_len]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xcafe_babe);
    prng.random().bytes(&inbound);
    var r = Io.Reader.fixed(&inbound);
    var outbound: [zl.ping.payload_len]u8 = undefined;
    var wr = Io.Writer.fixed(&outbound);
    try zl.ping.handleInbound(&r, &wr);
    if (!std.mem.eql(u8, &inbound, &outbound)) return error.PingEchoMismatch;
    std.debug.print("ping echo ok ({d} bytes)\n", .{zl.ping.payload_len});
}
