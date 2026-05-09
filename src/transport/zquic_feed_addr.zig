//! Layout copy of zquic `src/compat.zig` `Address` + UDP `recvfrom` for [`quic_endpoint`].
//! zquic does not re-export `compat` on its module root; we cannot add a second module pointing at
//! the same file. Keep `Address` byte-compatible with zquic's pin and use `@bitCast` into
//! `Server.feedPacket`, `Client.startHandshake`, and `Client.processPendingWork`.
//!
//! Zig 0.16 does not expose `std.posix.recvfrom`; this mirrors zquic's `compat.recvfrom` (`posix.system`).

const std = @import("std");
const posix = std.posix;
const system = posix.system;

inline fn checkRc(rc: anytype) posix.E {
    return posix.errno(rc);
}

pub const Address = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,

    pub fn initIp4(addr: [4]u8, port: u16) Address {
        return .{ .in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @bitCast(addr),
            .zero = [_]u8{0} ** 8,
        } };
    }
};

pub const RecvFromError = error{
    WouldBlock,
    SystemResources,
    ConnectionResetByPeer,
    ConnectionRefused,
    SocketUnconnected,
} || posix.UnexpectedError;

pub fn recvfrom(
    sock: posix.socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*posix.sockaddr,
    addrlen: ?*posix.socklen_t,
) RecvFromError!usize {
    while (true) {
        const rc = system.recvfrom(sock, buf.ptr, buf.len, flags, src_addr, addrlen);
        switch (checkRc(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionResetByPeer,
            .CONNREFUSED => return error.ConnectionRefused,
            .NOTCONN => return error.SocketUnconnected,
            .NOMEM, .NOBUFS => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}
