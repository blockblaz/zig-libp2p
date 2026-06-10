//! Shared-socket QUIC dialing for DCUtR hole punching (#91).

const std = @import("std");
const posix = std.posix;
const quic_posix_udp = @import("quic_posix_udp.zig");

pub const Error = quic_posix_udp.SocketError || quic_posix_udp.BindError || error{
    ReusePortUnsupported,
};

/// Bind a UDP socket reusing `port` on all interfaces (for simultaneous hole punch).
pub fn bindUdpSocketReusePort(port: u16) Error!posix.socket_t {
    const sock = try quic_posix_udp.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    errdefer quic_posix_udp.close(sock);

    const one: c_int = 1;
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
    if (@hasDecl(posix.SO, "REUSEPORT")) {
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&one)) catch {};
    }

    var sa: posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast([4]u8{ 0, 0, 0, 0 }),
    };
    try quic_posix_udp.bind(sock, @ptrCast(&sa), @sizeOf(posix.sockaddr.in));
    return sock;
}

test "bindUdpSocketReusePort picks requested port when free" {
    const sock = bindUdpSocketReusePort(0) catch return error.SkipZigTest;
    defer quic_posix_udp.close(sock);
    var sa: posix.sockaddr.in = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    try quic_posix_udp.getsockname(sock, @ptrCast(&sa), &len);
    _ = std.mem.bigToNative(u16, sa.port);
}
