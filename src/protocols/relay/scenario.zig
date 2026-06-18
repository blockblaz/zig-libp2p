//! In-process three-node relay scenario (A reserves on R, B connects via R) (#91).
//!
//! HOP CONNECT is now intentionally rejected by `Server.handleHopStream`
//! (the real bridge path lives in `transport/quic_relay_live.zig`), so this
//! test asserts the expected `unexpected_message` status on the connect leg
//! rather than `ok`.

const std = @import("std");
const Io = std.Io;
const identity = @import("../../primitives/identity.zig");
const wire = @import("wire.zig");
const server = @import("server.zig");
const client = @import("client.zig");

test "three-node reserve then connect (connect rejected at protocol layer)" {
    const a = std.testing.allocator;
    const relay_id = try identity.PeerId.random();
    const peer_a = try identity.PeerId.random();
    const peer_b = try identity.PeerId.random();

    var relay_srv = server.Server.init(a, .{
        .relay_addrs = &.{"/ip4/203.0.113.1/udp/4001/quic-v1"},
    }, relay_id);
    defer relay_srv.deinit();

    // Peer A reserves on relay R.
    var a_client = client.Client.init(a, .{});
    defer a_client.deinit();
    var hop_in: [4096]u8 = undefined;
    var hop_out: [4096]u8 = undefined;
    var hop_w = Io.Writer.fixed(&hop_in);
    const reserve_req = try a_client.buildReserveRequest();
    defer a.free(reserve_req);
    try wire.writeLengthPrefixed(&hop_w, reserve_req);
    var hop_r = Io.Reader.fixed(hop_in[0..hop_w.end]);
    var hop_w_out = Io.Writer.fixed(&hop_out);
    try relay_srv.handleHopStream(&hop_r, &hop_w_out, peer_a, false);
    var hop_resp_r = Io.Reader.fixed(hop_out[0..hop_w_out.end]);
    const reserve_frame = try wire.readLengthPrefixedAlloc(&hop_resp_r, a, wire.Limits.standard.max_frame_bytes);
    defer a.free(reserve_frame);
    try a_client.parseReserveResponse(reserve_frame, relay_id);
    try std.testing.expect(a_client.reservation != null);

    // Peer B connects to A through R. CONNECT is rejected by the protocol
    // layer — bridging happens in the transport layer (LiveRelay), which
    // routes CONNECT before handleHopStream sees it.
    var b_client = client.Client.init(a, .{});
    const connect_req = try b_client.buildConnectRequest(peer_a);
    defer a.free(connect_req);
    hop_w = Io.Writer.fixed(&hop_in);
    hop_w_out = Io.Writer.fixed(&hop_out);
    hop_w.end = 0;
    hop_w_out.end = 0;
    try wire.writeLengthPrefixed(&hop_w, connect_req);
    hop_r = Io.Reader.fixed(hop_in[0..hop_w.end]);
    try relay_srv.handleHopStream(&hop_r, &hop_w_out, peer_b, false);
    hop_resp_r = Io.Reader.fixed(hop_out[0..hop_w_out.end]);
    const connect_frame = try wire.readLengthPrefixedAlloc(&hop_resp_r, a, wire.Limits.standard.max_frame_bytes);
    defer a.free(connect_frame);
    var connect_msg = try wire.decodeHopOwned(a, connect_frame, .standard);
    defer connect_msg.deinit(a);
    try std.testing.expectEqual(wire.Status.unexpected_message, connect_msg.status.?);
}
