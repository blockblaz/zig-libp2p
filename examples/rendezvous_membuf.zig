//! Rendezvous register + discover round-trip over in-memory `std.Io` buffers.

const std = @import("std");
const Io = std.Io;
const zl = @import("zig_libp2p");

pub fn main() !void {
    const a = std.heap.page_allocator;

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x55);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    var pk = zl.identity.PublicKey{ .type = .ED25519, .data = &kp.public_key.bytes };
    const peer = try zl.identity.PeerId.fromPublicKey(a, &pk);

    var peer_id_buf: [128]u8 = undefined;
    const peer_id_bytes = try peer.toBytes(&peer_id_buf);
    const rec_wire = try zl.identify.encodePeerRecordTestWire(a, peer_id_bytes, 1);
    defer a.free(rec_wire);
    const spr = try zl.identify.encodeSignedPeerRecordTestWire(a, kp, rec_wire, .{});
    defer a.free(spr);

    var server = zl.rendezvous.Server.init(a, .{});
    defer server.deinit();
    var client = zl.rendezvous.Client.init(a, .{});

    var req_buf: [8192]u8 = undefined;
    var resp_buf: [8192]u8 = undefined;

    var req_w = Io.Writer.fixed(&req_buf);
    try client.writeRegister(&req_w, "my-app", spr, null);
    var srv_r = Io.Reader.fixed(req_buf[0..req_w.end]);
    var srv_w = Io.Writer.fixed(&resp_buf);
    try server.handleStream(&srv_r, &srv_w, peer, 0);
    var cli_r = Io.Reader.fixed(resp_buf[0..srv_w.end]);
    const ttl = try client.readRegisterResponse(&cli_r);

    @memset(&req_buf, 0);
    @memset(&resp_buf, 0);
    req_w = Io.Writer.fixed(&req_buf);
    try client.writeDiscover(&req_w, "my-app", null, null);
    srv_r = Io.Reader.fixed(req_buf[0..req_w.end]);
    srv_w = Io.Writer.fixed(&resp_buf);
    try server.handleStream(&srv_r, &srv_w, peer, 0);
    cli_r = Io.Reader.fixed(resp_buf[0..srv_w.end]);
    var discovered = try client.readDiscoverResponse(&cli_r);
    defer discovered.deinit(a);

    std.debug.print("rendezvous discover ok ({d} peers, ttl={d}s)\n", .{ discovered.peers.len, ttl });
}
