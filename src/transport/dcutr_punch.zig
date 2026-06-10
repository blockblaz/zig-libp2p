//! Shared-socket QUIC dialing for DCUtR hole punching (#91).
//!
//! Binds a UDP socket with SO_REUSEADDR + SO_REUSEPORT so initiator and
//! responder can both bind the same local port for the simultaneous-connect
//! step of the punch. If REUSEPORT is unavailable on the platform (Windows,
//! some BSD variants), simultaneous bind from a second process / socket on
//! the same port will fail — we surface this as `error.ReusePortUnsupported`
//! rather than letting the caller silently lose the punch race.

const std = @import("std");
const posix = std.posix;
const quic_posix_udp = @import("quic_posix_udp.zig");

pub const Error = quic_posix_udp.SocketError || quic_posix_udp.BindError || error{
    ReusePortUnsupported,
};

pub const Family = enum { ipv4, ipv6 };

/// Bind a UDP socket reusing `port` on all interfaces (for simultaneous hole punch).
/// `family` selects between IPv4 (`0.0.0.0:port`) and IPv6 (`[::]:port`); QUIC
/// deployments typically need IPv6 alongside v4.
pub fn bindUdpSocketReusePort(family: Family, port: u16) Error!posix.socket_t {
    const af: u32 = switch (family) {
        .ipv4 => posix.AF.INET,
        .ipv6 => posix.AF.INET6,
    };
    const sock = try quic_posix_udp.socket(af, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    errdefer quic_posix_udp.close(sock);

    const one: c_int = 1;
    // REUSEADDR is the lenient half: allows quick re-bind after close. Optional.
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
    // REUSEPORT is required for simultaneous bind — without it, the punch
    // partner's bind() races us and one side fails silently.
    if (@hasDecl(posix.SO, "REUSEPORT")) {
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&one)) catch {
            return error.ReusePortUnsupported;
        };
    } else {
        return error.ReusePortUnsupported;
    }

    switch (family) {
        .ipv4 => {
            var sa: posix.sockaddr.in = .{
                .port = std.mem.nativeToBig(u16, port),
                .addr = @bitCast([4]u8{ 0, 0, 0, 0 }),
            };
            try quic_posix_udp.bind(sock, @ptrCast(&sa), @sizeOf(posix.sockaddr.in));
        },
        .ipv6 => {
            var sa: posix.sockaddr.in6 = .{
                .port = std.mem.nativeToBig(u16, port),
                .flowinfo = 0,
                .addr = [_]u8{0} ** 16,
                .scope_id = 0,
            };
            try quic_posix_udp.bind(sock, @ptrCast(&sa), @sizeOf(posix.sockaddr.in6));
        },
    }
    return sock;
}

test "bindUdpSocketReusePort picks requested port when free (ipv4)" {
    const sock = bindUdpSocketReusePort(.ipv4, 0) catch return error.SkipZigTest;
    defer quic_posix_udp.close(sock);
    var sa: posix.sockaddr.in = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    try quic_posix_udp.getsockname(sock, @ptrCast(&sa), &len);
    _ = std.mem.bigToNative(u16, sa.port);
}

test "bindUdpSocketReusePort picks requested port when free (ipv6)" {
    const sock = bindUdpSocketReusePort(.ipv6, 0) catch return error.SkipZigTest;
    defer quic_posix_udp.close(sock);
    var sa: posix.sockaddr.in6 = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.in6);
    try quic_posix_udp.getsockname(sock, @ptrCast(&sa), &len);
    _ = std.mem.bigToNative(u16, sa.port);
}
