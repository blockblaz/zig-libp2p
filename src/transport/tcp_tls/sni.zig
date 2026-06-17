//! TLS 1.3 SNI (Server Name Indication) from libp2p dial multiaddrs (#208).
//!
//! libp2p TLS does not validate SNI on the server; the client sends a
//! peer-aware name so TLS-terminating front doors can route correctly.

const std = @import("std");
const multiaddr = @import("multiaddr");

/// Fallback SNI when no dial authority or `/p2p` is available.
pub const default_server_name: []const u8 = "libp2p";

/// Reject bytes that would break the TLS SNI extension (control chars, non-printable).
fn isSafeSniHost(name: []const u8) bool {
    if (name.len == 0 or name.len > 255) return false;
    for (name) |b| {
        if (b == '\r' or b == '\n' or b == 0) return false;
        if (b != '\t' and (b < 0x20 or b == 0x7f)) return false;
    }
    return true;
}

fn formatIp4Literal(addr: std.Io.net.Ip4Address, out: []u8) ?[]const u8 {
    return std.fmt.bufPrint(out, "{}.{}.{}.{}", .{
        addr.bytes[0], addr.bytes[1], addr.bytes[2], addr.bytes[3],
    }) catch null;
}

fn formatIp6Literal(addr: std.Io.net.Ip6Address, out: []u8) ?[]const u8 {
    const b = addr.bytes;
    return std.fmt.bufPrint(out, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
        b[0], b[1], b[2],  b[3],  b[4],  b[5],  b[6],  b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    }) catch null;
}

/// Extract a TLS SNI host from `ma`.
///
/// Priority: DNS name (`/dns`, `/dns4`, `/dns6`) → IP literal (`/ip4`, `/ip6`)
/// → `/p2p` PeerId base58. DNS names are borrowed from the multiaddr bytes;
/// IP and PeerId names are written into `out`.
///
/// Returns `null` when no usable name exists.
pub fn serverNameFromMultiaddr(ma: multiaddr.Multiaddr, out: []u8) ?[]const u8 {
    var iter = ma.iterator();
    var dns_name: ?[]const u8 = null;
    var ip4_addr: ?std.Io.net.Ip4Address = null;
    var ip6_addr: ?std.Io.net.Ip6Address = null;
    var peer: ?@import("peer_id").PeerId = null;

    while (iter.next() catch return null) |proto| {
        switch (proto) {
            .Dns, .Dns4, .Dns6 => |name| dns_name = name,
            .Ip4 => |a| ip4_addr = a,
            .Ip6 => |a| ip6_addr = a,
            .P2P => |id| peer = id,
            else => {},
        }
    }

    if (dns_name) |n| {
        if (!isSafeSniHost(n)) return null;
        return n;
    }
    if (ip4_addr) |v| return formatIp4Literal(v, out);
    if (ip6_addr) |v| return formatIp6Literal(v, out);
    if (peer) |id| return id.toBase58(out) catch null;
    return null;
}

/// Resolve the TLS SNI string for an initiator handshake.
///
/// `explicit` wins when non-empty and safe. Otherwise `dial_multiaddr` is
/// consulted. Falls back to [`default_server_name`].
pub fn resolveTlsServerName(
    dial_multiaddr: ?multiaddr.Multiaddr,
    explicit: ?[]const u8,
    out: []u8,
) []const u8 {
    if (explicit) |s| {
        if (isSafeSniHost(s)) return s;
    }
    if (dial_multiaddr) |ma| {
        if (serverNameFromMultiaddr(ma, out)) |s| return s;
    }
    return default_server_name;
}

test "serverNameFromMultiaddr: dns authority" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/dns/example.com/tcp/443/tls/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("example.com", serverNameFromMultiaddr(ma, &buf).?);
}

test "serverNameFromMultiaddr: dns4 authority" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/dns4/relay.example/tcp/4001/tls");
    defer ma.deinit();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("relay.example", serverNameFromMultiaddr(ma, &buf).?);
}

test "serverNameFromMultiaddr: ip4 authority beats p2p" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/ip4/203.0.113.7/tcp/4001/tls/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("203.0.113.7", serverNameFromMultiaddr(ma, &buf).?);
}

test "serverNameFromMultiaddr: ip6 authority" {
    const a = std.testing.allocator;
    const ip6 = std.Io.net.Ip6Address{
        .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .port = 0,
    };
    var ma = try multiaddr.Multiaddr.fromProtocols(a, &.{ .{ .Ip6 = ip6 }, .{ .Tcp = 443 }, .Tls });
    defer ma.deinit();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("2001:0db8:0000:0000:0000:0000:0000:0001", serverNameFromMultiaddr(ma, &buf).?);
}

test "serverNameFromMultiaddr: p2p-only fallback" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA");
    defer ma.deinit();
    var buf: [128]u8 = undefined;
    const sni = serverNameFromMultiaddr(ma, &buf).?;
    try std.testing.expectEqualStrings("12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA", sni);
}

test "serverNameFromMultiaddr: empty multiaddr returns null" {
    const a = std.testing.allocator;
    var ma = multiaddr.Multiaddr.init(a);
    defer ma.deinit();
    var buf: [128]u8 = undefined;
    try std.testing.expect(serverNameFromMultiaddr(ma, &buf) == null);
}

test "resolveTlsServerName: defaults to libp2p" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(default_server_name, resolveTlsServerName(null, null, &buf));
}

test "resolveTlsServerName: explicit override" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("edge.example", resolveTlsServerName(null, "edge.example", &buf));
}

test "resolveTlsServerName: dial multiaddr when explicit absent" {
    const a = std.testing.allocator;
    var ma = try multiaddr.Multiaddr.fromString(a, "/dns/node.example/tcp/4001/tls");
    defer ma.deinit();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("node.example", resolveTlsServerName(ma, null, &buf));
}
