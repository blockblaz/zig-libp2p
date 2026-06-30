//! Layout copy of zquic `src/compat.zig` `Address` + UDP `recvfrom` for [`quic_endpoint`].
//! zquic does not re-export `compat` on its module root; we cannot add a second module pointing at
//! the same file. Keep `Address` byte-compatible with zquic's pin and use `@bitCast` into
//! `Server.feedPacket`, `Client.startHandshake`, and `Client.processPendingWork`.
//!
//! Zig 0.16 does not expose `std.posix.recvfrom`; this mirrors zquic's `compat.recvfrom` (`posix.system`).

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const posix = std.posix;
const system = posix.system;

/// Process-global latch: set once `recvmmsg(2)` is observed unsupported
/// (`ENOSYS`/`EOPNOTSUPP`), after which every reader uses the per-datagram
/// `recvfrom` loop for the rest of the run instead of repeating the failing
/// syscall on every poll. The Shadow simulator's syscall shim does not
/// implement `recvmmsg`, which otherwise silently yields zero datagrams (no
/// QUIC handshake ever completes — see issue #291).
var recvmmsg_unsupported = std.atomic.Value(bool).init(false);

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

/// Largest UDP datagram we will receive (matches `shard_ring.max_datagram_bytes`
/// and exceeds zquic's `max_datagram_size`).
pub const max_datagram_bytes: usize = 2048;
/// Datagrams pulled per `recvmmsg(2)` syscall.
pub const recv_batch_size: usize = 64;

const RecvSlot = struct {
    buf: [max_datagram_bytes]u8 = undefined,
    len: usize = 0,
    addr: Address = undefined,
};

/// Batched non-blocking UDP receive. On Linux a single `recvmmsg(2)` pulls up to
/// `recv_batch_size` datagrams already queued in the kernel buffer — ~64× fewer
/// syscalls than per-datagram `recvfrom`, so the drive/demux thread drains the
/// socket fast enough to keep `SO_RCVBUF` from overflowing under a high inbound
/// packet rate (31-peer gossip). quinn/rust-libp2p use the same recvmmsg path;
/// the prior per-`recvfrom` loop here was the throughput regression that let the
/// kernel drop millions of datagrams → QUIC loss → cwnd collapse → no finality.
/// ~134 KiB — heap-allocate one per socket-reading thread (demux / drive); never
/// shared (the listen socket has a single reader by construction).
pub const RecvBatch = struct {
    slots: [recv_batch_size]RecvSlot = undefined,

    /// Receive every datagram currently queued (up to `recv_batch_size`),
    /// non-blocking. Returns the count; 0 if none are ready or on error.
    pub fn recv(self: *RecvBatch, sock: posix.socket_t) usize {
        if (builtin.target.os.tag == .linux) return self.recvLinux(sock);
        return self.recvPortable(sock);
    }

    fn recvLinux(self: *RecvBatch, sock: posix.socket_t) usize {
        // The Shadow simulator does not implement recvmmsg(2). Under `-Dshadow`
        // skip it entirely and use the portable per-datagram recvfrom loop, so
        // the QUIC endpoint actually receives handshake packets (#291).
        if (comptime build_options.shadow) return self.recvPortable(sock);
        // Outside a Shadow build the same gap can appear in restricted sandboxes
        // (seccomp); once we see ENOSYS we latch and fall back for the rest of
        // the run rather than repeating a syscall that will never succeed.
        if (recvmmsg_unsupported.load(.monotonic)) return self.recvPortable(sock);

        const linux = std.os.linux;
        var iovecs: [recv_batch_size]posix.iovec = undefined;
        var addrs: [recv_batch_size]posix.sockaddr.storage = undefined;
        var msgs: [recv_batch_size]linux.mmsghdr = undefined;
        for (0..recv_batch_size) |i| {
            iovecs[i] = .{ .base = &self.slots[i].buf, .len = max_datagram_bytes };
            msgs[i] = .{
                .hdr = .{
                    .name = @ptrCast(&addrs[i]),
                    .namelen = @sizeOf(posix.sockaddr.storage),
                    .iov = @ptrCast(&iovecs[i]),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .len = 0,
            };
        }
        // MSG_DONTWAIT: read all queued datagrams and return immediately (the
        // tail recvmsg hits EAGAIN, which recvmmsg reports as the count so far).
        const rc = linux.recvmmsg(@intCast(sock), msgs[0..].ptr, recv_batch_size, linux.MSG.DONTWAIT, null);
        // `recvmmsg` here is the raw `std.os.linux` syscall, which returns
        // `-errno` directly. Decode with `linux.E.init` — NOT `posix.errno`,
        // which assumes the libc `-1`-and-read-errno convention (this module
        // links libc) and would misread a raw `-EAGAIN` return as `.SUCCESS`,
        // then index `slots` with a garbage count.
        switch (linux.E.init(rc)) {
            .SUCCESS => {},
            // No datagrams queued, or interrupted — normal, try again next poll.
            .AGAIN, .INTR => return 0,
            // recvmmsg unavailable (Shadow / seccomp). Latch and fall back so we
            // never again silently return zero packets when data is waiting.
            .NOSYS, .OPNOTSUPP => {
                recvmmsg_unsupported.store(true, .monotonic);
                return self.recvPortable(sock);
            },
            // Transient errors (e.g. a queued ICMP port-unreachable surfacing as
            // ECONNREFUSED): drop this batch, the next poll retries.
            else => return 0,
        }
        const n: usize = @intCast(rc);
        for (0..n) |i| {
            self.slots[i].len = msgs[i].len;
            self.slots[i].addr = .{ .any = @as(*const posix.sockaddr, @ptrCast(&addrs[i])).* };
        }
        return n;
    }

    fn recvPortable(self: *RecvBatch, sock: posix.socket_t) usize {
        const MSG_DONTWAIT: u32 = if (@hasDecl(posix.MSG, "DONTWAIT")) posix.MSG.DONTWAIT else 0;
        var count: usize = 0;
        while (count < recv_batch_size) {
            var sa: posix.sockaddr.storage = undefined;
            var sl: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const n = recvfrom(sock, &self.slots[count].buf, MSG_DONTWAIT, @ptrCast(&sa), &sl) catch break;
            self.slots[count].len = n;
            self.slots[count].addr = .{ .any = @as(*const posix.sockaddr, @ptrCast(&sa)).* };
            count += 1;
        }
        return count;
    }

    /// One datagram filled by the last `recv` (i in `0..return-of-recv`).
    pub fn slot(self: *RecvBatch, i: usize) struct { data: []u8, addr: Address } {
        return .{ .data = self.slots[i].buf[0..self.slots[i].len], .addr = self.slots[i].addr };
    }
};
