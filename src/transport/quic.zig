//! QUIC transport helpers for libp2p (tracking issue #37).
//!
//! Typical flow:
//! 1. [`parseQuicV1Endpoint`] from a dial multiaddr, or the same for listen.
//! 2. [`initLibp2pQuicServerFromMultiaddr`] or bind with [`bindUdpSocket`] + `zquic.transport.io.Server.initFromSocket`.
//! 3. [`initLibp2pQuicClientFromMultiaddr`] or [`initLibp2pQuicClientFromEndpoint`] for an IPv4 dial target (zquic client socket is IPv4 today).
//! 4. After QUIC + TLS, open raw app bidi streams (`zquic.transport.io.rawAllocateNextLocalBidiStream`, …).
//! 5. Run [`stream_multistream.initiatorHandshakeMultistream`] / [`responderHandshakeMultistream`] on each stream
//!    using [`quic_raw_stream_io.RawAppBidiClient`] or [`RawAppBidiServer`] I/O adapters (see module [`quic_raw_stream_io`]),
//!    or use [`ping_wire_quic`] / [`req_resp.wire_quic`] for ping / ssz_snappy req/resp on a raw stream.
//!
//! This module adds multiaddr parsing for typical `/udp/.../quic-v1` dial and listen addresses.
//! For listen / dial / [`drive`] / accept over UDP, see [`quic_endpoint`] (#15).
//! Issue #37 helpers: [`quic_endpoint.listenMultiaddr`], [`quic_endpoint.dialMultiaddr`], [`quic_endpoint.dialExtended`],
//! [`quic_endpoint.QuicLifecycleHooks`], [`stream_multistream.responderHandshakeMultistreamAmong`].
//! QUIC TLS PeerId (dialer): [`quic_peer_identity`].

const std = @import("std");
const multiaddr = @import("multiaddr");
const peer_id_mod = @import("peer_id");
const zquic = @import("zquic");

pub const quic_v1 = @import("quic_v1.zig");
pub const stream_multistream = @import("stream_multistream.zig");
pub const quic_raw_stream_io = @import("quic_raw_stream_io.zig");

const net = std.Io.net;
const posix = std.posix;
const ZIo = zquic.transport.io;
const quic_posix_udp = @import("quic_posix_udp.zig");

const protocol_iter_next_err = @typeInfo(@typeInfo(@TypeOf(multiaddr.ProtocolIterator.next)).@"fn".return_type.?).error_union.error_set;

/// IP + UDP port + optional `/p2p` expectation after `/quic-v1`.
pub const QuicV1Endpoint = struct {
    address: net.IpAddress,
    expected_peer: ?peer_id_mod.PeerId = null,
};

pub const ParseQuicV1EndpointError = error{
    MissingIp,
    MissingUdpPort,
    MissingQuicV1Component,
} || multiaddr.multiaddr.Error || protocol_iter_next_err;

/// zquic `Client.init` / event loop is IPv4 UDP only in the current pin; use IPv6 once zquic grows an IPv6 client socket path.
pub const Libp2pQuicClientDialError = error{ZquicClientIpv4Only};

pub const BindUdpSocketError = quic_posix_udp.SocketError || quic_posix_udp.BindError;

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

/// Format the IP portion of `address` for `zquic` `ClientConfig.host` (dotted quad for IPv4).
pub fn formatZquicDialHost(address: net.IpAddress, buf: []u8) (Libp2pQuicClientDialError || std.fmt.BufPrintError)![]const u8 {
    return switch (address) {
        .ip4 => |v| try std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{
            v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3],
        }),
        .ip6 => error.ZquicClientIpv4Only,
    };
}

/// Create a datagram socket bound to `address` (IPv4 or IPv6). Caller usually passes it to [`ZIo.Server.initFromSocket`].
pub fn bindUdpSocket(address: net.IpAddress) BindUdpSocketError!posix.socket_t {
    return switch (address) {
        .ip4 => |v| {
            const sock = try quic_posix_udp.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
            errdefer quic_posix_udp.close(sock);
            var sa: posix.sockaddr.in = .{
                .port = std.mem.nativeToBig(u16, v.port),
                .addr = @bitCast(v.bytes),
            };
            try quic_posix_udp.bind(sock, @ptrCast(&sa), @sizeOf(@TypeOf(sa)));
            return sock;
        },
        .ip6 => |v| {
            const sock = try quic_posix_udp.socket(posix.AF.INET6, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
            errdefer quic_posix_udp.close(sock);
            var sa: posix.sockaddr.in6 = .{
                .port = std.mem.nativeToBig(u16, v.port),
                .flowinfo = v.flow,
                .addr = v.bytes,
                .scope_id = v.interface.index,
            };
            try quic_posix_udp.bind(sock, @ptrCast(&sa), @sizeOf(@TypeOf(sa)));
            return sock;
        },
    };
}

/// `Server.initFromSocket` with [`quic_v1.libp2pZquicServerConfig`], binding from multiaddr `/udp/.../quic-v1`.
/// `Libp2pZquicServerOptions.port` is overwritten by the UDP port in the multiaddr.
pub fn initLibp2pQuicServerFromMultiaddr(
    allocator: std.mem.Allocator,
    ma: multiaddr.Multiaddr,
    options: quic_v1.Libp2pZquicServerOptions,
) !*ZIo.Server {
    const ep = try parseQuicV1Endpoint(ma);
    const sock = try bindUdpSocket(ep.address);
    errdefer quic_posix_udp.close(sock);

    var cfg_opts = options;
    cfg_opts.port = ep.address.getPort();
    const cfg = quic_v1.libp2pZquicServerConfig(cfg_opts);
    return ZIo.Server.initFromSocket(allocator, cfg, sock, true);
}

/// Options shared with [`quic_v1.Libp2pZquicClientOptions`] except `host` / `port` (taken from the endpoint).
pub const Libp2pZquicClientDialOptions = struct {
    keylog_path: ?[]const u8 = null,
    qlog_dir: ?[]const u8 = null,
    cubic: bool = false,
    v2: bool = false,
    client_cert_path: []const u8 = "",
    client_key_path: []const u8 = "",
    /// In-memory PEM-encoded client cert/key (zquic v1.6.6). When non-null
    /// zquic parses these bytes and never reads the matching `*_path` from
    /// disk. Borrowed for the duration of [`ZIo.Client.init`].
    client_cert_pem: ?[]const u8 = null,
    client_key_pem: ?[]const u8 = null,
};

/// Build a [`ZIo.Client`] for an IPv4 [`QuicV1Endpoint`] using the libp2p QUIC presets.
pub fn initLibp2pQuicClientFromEndpoint(
    allocator: std.mem.Allocator,
    ep: QuicV1Endpoint,
    dial_options: Libp2pZquicClientDialOptions,
) !ZIo.Client {
    var host_buf: [15]u8 = undefined;
    const host = try formatZquicDialHost(ep.address, &host_buf);
    const cfg = quic_v1.libp2pZquicClientConfig(.{
        .host = host,
        .port = ep.address.getPort(),
        .keylog_path = dial_options.keylog_path,
        .qlog_dir = dial_options.qlog_dir,
        .cubic = dial_options.cubic,
        .v2 = dial_options.v2,
        .client_cert_path = dial_options.client_cert_path,
        .client_key_path = dial_options.client_key_path,
        .client_cert_pem = dial_options.client_cert_pem,
        .client_key_pem = dial_options.client_key_pem,
    });
    return ZIo.Client.init(allocator, cfg);
}

/// Same as [`initLibp2pQuicClientFromEndpoint`] after [`parseQuicV1Endpoint`]. Symmetric with [`initLibp2pQuicServerFromMultiaddr`].
pub fn initLibp2pQuicClientFromMultiaddr(
    allocator: std.mem.Allocator,
    ma: multiaddr.Multiaddr,
    dial_options: Libp2pZquicClientDialOptions,
) !ZIo.Client {
    const ep = try parseQuicV1Endpoint(ma);
    return initLibp2pQuicClientFromEndpoint(allocator, ep, dial_options);
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

test "parse quic-v1 ipv4 multiaddr captures p2p" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();

    const ep = try parseQuicV1Endpoint(ma);
    const want = try peer_id_mod.PeerId.fromString(a, "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    try std.testing.expect(ep.expected_peer != null);
    try std.testing.expect(ep.expected_peer.?.eql(&want));
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

test "format zquic dial host ipv4" {
    var buf: [15]u8 = undefined;
    const s = try formatZquicDialHost(.{ .ip4 = .{
        .bytes = .{ 10, 0, 0, 1 },
        .port = 4001,
    } }, &buf);
    try std.testing.expectEqualStrings("10.0.0.1", s);
}

test "bindUdpSocket ipv4 loopback" {
    const sock = try bindUdpSocket(.{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = 0,
    } });
    defer quic_posix_udp.close(sock);
}
