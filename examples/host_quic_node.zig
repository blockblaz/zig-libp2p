//! Worked example: a Lean-consensus-flavoured libp2p node built from
//! `zig_libp2p.host.Host` + a QUIC listener.
//!
//! What this shows:
//!   1. Construct a `Host` (bundles Swarm + Gossipsub + ReqResp + ConnMgr).
//!   2. Wire it to a `QuicListener`'s lifecycle callbacks.
//!   3. Drive the listener + heartbeat in a loop.
//!   4. Subscribe to a topic, publish, and drain a `peer_connected` event.
//!   5. Shut down cleanly.
//!
//! This file is compile-only under `zig build examples` (it doesn't run
//! against a real socket because that needs a TLS cert/key pair). Embedders
//! adapting this for production should:
//!   - Replace the `runOnce` body with their own listen loop;
//!   - Plumb their config (listen multiaddr, bootnodes, fork digest, ...) into
//!     the `HostConfig` / `QuicListener.listen` calls;
//!   - Wire the `on_inbound_stream_ready` hook to read the negotiated stream,
//!     run multistream-select, and dispatch to either `host.handleGossipRpc`
//!     (for `/meshsub/1.1.0`) or `host.registerInboundReqRespChannel` (for the
//!     `/leanconsensus/req/...` family).

const std = @import("std");
const zl = @import("zig_libp2p");

const Host = zl.host.Host;

/// Per-node context: the Host pointer rides on the QUIC lifecycle hook ctx.
const NodeCtx = struct {
    host: *Host,
    /// Monotonic per-connection counter we hand to ConnectionManager.
    next_conn_id: zl.connection_manager.ConnectionId = 1,
};

fn onConnectionEstablished(ctx_opaque: ?*anyopaque, slot: usize, conn: *anyopaque) void {
    _ = slot;
    _ = conn;
    const ctx: *NodeCtx = @ptrCast(@alignCast(ctx_opaque.?));
    const conn_id = ctx.next_conn_id;
    ctx.next_conn_id += 1;
    // In a real node the peer id is read from the libp2p TLS extension after
    // the handshake completes (see `transport.quic_peer_identity`); here we
    // just synthesize one so the example compiles.
    const peer = zl.identity.PeerId.random() catch return;
    ctx.host.onConnectionEstablished(conn_id, peer, .inbound) catch {};
}

fn onConnectionClosed(ctx_opaque: ?*anyopaque, slot: usize) void {
    _ = slot;
    const ctx: *NodeCtx = @ptrCast(@alignCast(ctx_opaque.?));
    // Production code keeps a `slot → (conn_id, peer)` map populated in
    // `onConnectionEstablished` so it can hand the right pair back here.
    const conn_id: zl.connection_manager.ConnectionId = 0;
    const peer = zl.identity.PeerId.random() catch return;
    ctx.host.onConnectionClosed(zl.wall_time.milliTimestamp(), conn_id, peer, .remote_close) catch {};
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    const me = try zl.identity.PeerId.random();

    var host = try Host.create(.{
        .allocator = gpa,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    try host.startBackground();
    if (!host.waitUntilReady(5_000)) return error.HostNotReady;

    try host.subscribe("/leanconsensus/beacon_block/0xdeadbeef/ssz_snappy");

    // Drain whatever the bring-up queued (subscribe broadcasts, peer_connected,
    // log lines from the swarm worker) so the example finishes cleanly.
    var ctx = NodeCtx{ .host = host };
    try host.onConnectionEstablished(99, try zl.identity.PeerId.random(), .outbound);
    var drained_count: u32 = 0;
    while (host.nextEvent(100) catch null) |evt| {
        var e = evt;
        defer e.deinit(gpa);
        drained_count += 1;
        std.debug.print("host_quic_node: drained {s}\n", .{@tagName(std.meta.activeTag(e))});
    }

    // Shape of the QUIC wiring (commented out — needs real cert/key + bind).
    //
    // var ma = try zl.multiaddr.Multiaddr.fromString(gpa, "/ip4/0.0.0.0/udp/0/quic-v1");
    // defer ma.deinit();
    // var listener = try zl.transport.quic_endpoint.QuicListener.listen(gpa, ma, .{
    //     .cert_path = "node.crt",
    //     .key_path = "node.key",
    // });
    // defer listener.deinit();
    // listener.lifecycle = .{
    //     .ctx = &ctx,
    //     .on_connection_established = onConnectionEstablished,
    //     .on_connection_closed = onConnectionClosed,
    // };
    //
    // var recv_buf: [65536]u8 = undefined;
    // const deadline_ms = zl.wall_time.milliTimestamp() + 20_000;
    // while (zl.wall_time.milliTimestamp() < deadline_ms) {
    //     try listener.drive(&recv_buf, 50);
    //     try host.runPeriodicTicks(zl.wall_time.milliTimestamp());
    //     while (host.nextEvent(0) catch null) |drained| { defer drained.deinit(gpa); }
    // }

    _ = &ctx;
    _ = &onConnectionEstablished;
    _ = &onConnectionClosed;

    host.shutdown();
    while (host.nextEvent(1_000) catch null) |evt| {
        var e = evt;
        defer e.deinit(gpa);
        if (std.meta.activeTag(e) == .swarm_closed) {
            std.debug.print("host_quic_node: clean shutdown ({d} events drained)\n", .{drained_count});
            return;
        }
    }
}
