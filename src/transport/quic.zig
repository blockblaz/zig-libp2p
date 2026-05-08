//! QUIC transport helpers for libp2p (tracking issue #37).
//!
//! zquic listen/dial loops and connection types are still embedder-owned: use
//! [`quic_v1.libp2pZquicServerConfig`] / [`quic_v1.libp2pZquicClientConfig`] with
//! `zquic.transport.io.Server` / `Client`, then run [`stream_multistream`] on each new
//! raw application bidirectional stream.
//!
//! This module adds multiaddr parsing for typical `/udp/.../quic-v1` dial targets.

const std = @import("std");
const multiaddr = @import("multiaddr");
const peer_id_mod = @import("peer_id");

pub const quic_v1 = @import("quic_v1.zig");
pub const stream_multistream = @import("stream_multistream.zig");

const net = std.Io.net;

/// IP + UDP port + optional `/p2p` expectation after `/quic-v1`.
pub const QuicV1Endpoint = struct {
    address: net.IpAddress,
    expected_peer: ?peer_id_mod.PeerId = null,
};

pub const ParseQuicV1EndpointError = error{
    MissingIp,
    MissingUdpPort,
    MissingQuicV1Component,
} || multiaddr.multiaddr.Error;

/// Extract host/port and optional PeerId from a multiaddr that includes `/udp/.../quic-v1`.
/// Ignores unrelated components (for example `/p2p-circuit`) except those matched above.
pub fn parseQuicV1Endpoint(ma: multiaddr.Multiaddr) ParseQuicV1EndpointError!QuicV1Endpoint {
    var iter = ma.iterator();
    var ip4: ?net.Ip4Address = null;
    var ip6: ?net.Ip6Address = null;
    var udp_port: ?u16 = null;
    var saw_quic_v1 = false;
    var peer: ?peer_id_mod.PeerId = null;

    while (try iter.next()) |proto| {
        switch (proto) {
            .Ip4 => |a| ip4 = a,
            .Ip6 => |a| ip6 = a,
            .Udp => |p| udp_port = p,
            .QuicV1 => saw_quic_v1 = true,
            .P2P => |id| peer = id,
            else => {},
        }
    }

    if (!saw_quic_v1) return error.MissingQuicV1Component;
    const port = udp_port orelse return error.MissingUdpPort;

    const address: net.IpAddress = if (ip4) |v| .{
        .ip4 = .{ .bytes = v.bytes, .port = port },
    } else if (ip6) |v| .{
        .ip6 = .{
            .bytes = v.bytes,
            .port = port,
            .flow = v.flow,
            .interface = v.interface,
        },
    } else return error.MissingIp;

    return .{ .address = address, .expected_peer = peer };
}

test "parse quic-v1 ipv4 multiaddr" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1");
    defer ma.deinit();

    const ep = try parseQuicV1Endpoint(ma);
    try std.testing.expectEqual(@as(u16, 4001), ep.address.getPort());
    try std.testing.expect(ep.expected_peer == null);
    switch (ep.address) {
        .ip4 => |x| try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, x.bytes),
        else => return error.TestFailed,
    }
}

test "parse quic-v1 rejects missing udp" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/quic-v1");
    defer ma.deinit();

    try std.testing.expectError(error.MissingUdpPort, parseQuicV1Endpoint(ma));
}

test "parse quic-v1 rejects missing ip" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/udp/4001/quic-v1");
    defer ma.deinit();

    try std.testing.expectError(error.MissingIp, parseQuicV1Endpoint(ma));
}
