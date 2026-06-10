const std = @import("std");
const zl = @import("zig_libp2p");

pub fn main() !void {
    const a = std.heap.page_allocator;
    const obs = [_][]const u8{"/ip4/1.2.3.4/udp/4001/quic-v1"};
    var coord = zl.dcutr.Coordinator.init(a, .{}, .initiator);
    defer coord.deinit();
    // Use a real-ish base so half-RTT scheduling lands within polling range.
    coord.connect_sent_ms = zl.wall_time.milliTimestamp();
    const reply = try zl.dcutr.wire.encode(a, .{ .msg_type = .connect, .obs_addrs = &obs });
    defer a.free(reply);
    const sync = try coord.onRemoteConnectReply(reply);
    defer a.free(sync);
    // Coordinator schedules a dial at half-RTT. Poll past the deadline (now+1s)
    // so we get an owned DirectDialRequest back.
    var dial = coord.pollDial(zl.wall_time.milliTimestamp() + 1000) orelse return error.UnexpectedNull;
    defer dial.deinit(a);
    std.debug.print("dcutr_membuf: scheduled dial addrs={d} fire_at={d}\n", .{ dial.addrs.len, dial.fire_at_ms });
}
