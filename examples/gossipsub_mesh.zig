//! Minimal gossipsub: subscribe, accept GRAFT, observe mesh size (no real network).

const std = @import("std");
const zl = @import("zig_libp2p");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    const me = try zl.identity.PeerId.random();
    var g = try zl.gossipsub.runtime.Gossipsub.init(gpa, .{ .local_peer_id = me });
    defer g.deinit();

    try g.subscribe("blocks");
    const sub_d = g.popOutboxDelivery().?;
    defer gpa.free(sub_d.wire);
    if (sub_d.to != null) return error.ExpectedBroadcastSubscribe;

    const remote = try zl.identity.PeerId.random();
    g.onPeerConnected(remote);

    const ctl = try zl.gossipsub.control.encodeGraft(gpa, "blocks");
    defer gpa.free(ctl);
    const graft_rpc = try zl.gossipsub.rpc.encodeControlOnlyRpc(gpa, ctl);
    defer gpa.free(graft_rpc);
    try g.handleInboundRpc(remote, graft_rpc);

    std.debug.print("mesh peers on \"blocks\": {?}\n", .{g.meshPeerCountForTopic("blocks")});
}
