const std = @import("std");
const zl = @import("zig_libp2p");

pub fn main() !void {
    const a = std.heap.page_allocator;
    const obs = [_][]const u8{"/ip4/1.2.3.4/udp/4001/quic-v1"};
    var coord = zl.dcutr.Coordinator.init(a, .{}, .initiator);
    defer coord.deinit();
    coord.connect_sent_ms = 0;
    const reply = try zl.dcutr.wire.encode(a, .{ .msg_type = .connect, .obs_addrs = &obs });
    defer a.free(reply);
    const sync = try coord.onRemoteConnectReply(reply);
    defer a.free(sync);
    const dial = coord.pending_dial orelse return error.UnexpectedNull;
    std.debug.print("dcutr_membuf: scheduled dial addrs={d} fire_at={d}\n", .{ dial.addrs.len, dial.fire_at_ms });
}
