//! UDP `socket` / `bind` / `getsockname` via `posix.system`, matching zquic `compat` where Zig 0.16
//! dropped the old `std.posix` helpers.

const std = @import("std");
const posix = std.posix;
const system = posix.system;

inline fn checkRc(rc: anytype) posix.E {
    return posix.errno(rc);
}

pub const SocketError = error{
    AccessDenied,
    AddressFamilyUnsupported,
    ProtocolUnsupportedBySystem,
    ProtocolFamilyUnavailable,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
} || posix.UnexpectedError;

pub fn socket(domain: u32, sock_type: u32, protocol: u32) SocketError!posix.socket_t {
    const rc = system.socket(domain, sock_type, protocol);
    switch (checkRc(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => return error.AccessDenied,
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .INVAL => return error.ProtocolFamilyUnavailable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .PROTONOSUPPORT => return error.ProtocolUnsupportedBySystem,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const BindError = error{
    AccessDenied,
    AddressInUse,
    AddressNotAvailable,
    AlreadyBound,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    NotDir,
    SystemResources,
} || posix.UnexpectedError;

pub fn close(sock: posix.socket_t) void {
    _ = system.close(sock);
}

pub fn getsockname(sock: posix.socket_t, addr: *posix.sockaddr, addrlen: *posix.socklen_t) posix.GetSockNameError!void {
    const rc = system.getsockname(sock, addr, addrlen);
    switch (checkRc(rc)) {
        .SUCCESS => return,
        .BADF, .FAULT, .INVAL => unreachable,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .NOTCONN => return error.SocketUnconnected,
        .NETDOWN => return error.NetworkDown,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub fn bind(sock: posix.socket_t, addr: *const posix.sockaddr, len: posix.socklen_t) BindError!void {
    const rc = system.bind(sock, addr, len);
    switch (checkRc(rc)) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .INVAL => return error.AlreadyBound,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}
