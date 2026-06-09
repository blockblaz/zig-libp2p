//! Synchronous POSIX TCP read/write adapters for libp2p handshakes.
//!
//! `Io.Threaded` + `net.Stream.reader`/`writer` can stall indefinitely on
//! cross-process TCP (see `src/root.zig`). Interop uses blocking socket I/O
//! for stream upgrades while keeping `Io.Threaded` for listen/dial/accept only.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const posix = std.posix;
const system = posix.system;
const c = std.c;

const max_iovecs_len = 8;

fn applyTcpNoDelay(handle: net.Socket.Handle) void {
    if (@import("builtin").os.tag == .windows) return;
    const on: c_int = 1;
    posix.setsockopt(handle, c.IPPROTO.TCP, c.TCP.NODELAY, std.mem.asBytes(&on)) catch {};
}

pub const Pair = struct {
    reader: Reader,
    writer: Writer,

    pub fn init(stream: net.Stream, read_buf: []u8, write_buf: []u8) Pair {
        applyTcpNoDelay(stream.socket.handle);
        return .{
            .reader = Reader.init(stream, read_buf),
            .writer = Writer.init(stream, write_buf),
        };
    }
};

pub const Reader = struct {
    interface: Io.Reader,
    handle: net.Socket.Handle,

    pub fn init(stream: net.Stream, buffer: []u8) Reader {
        return .{
            .handle = stream.socket.handle,
            .interface = .{
                .vtable = &.{
                    .stream = streamImpl,
                    .readVec = readVecImpl,
                },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn streamImpl(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try io_w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVecImpl(io_r, &data);
        io_w.advance(n);
        return n;
    }

    fn readVecImpl(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const self: *Reader = @alignCast(@fieldParentPtr("interface", io_r));
        var iovecs_buffer: [max_iovecs_len][]u8 = undefined;
        const dest_n, const data_size = try io_r.writableVector(&iovecs_buffer, data);
        const dest = iovecs_buffer[0..dest_n];
        std.debug.assert(dest[0].len > 0);
        const n = posix.read(self.handle, dest[0]) catch return error.ReadFailed;
        if (n == 0) return error.EndOfStream;
        if (n > data_size) {
            io_r.end += n - data_size;
            return data_size;
        }
        return n;
    }
};

pub const Writer = struct {
    interface: Io.Writer,
    handle: net.Socket.Handle,

    pub fn init(stream: net.Stream, buffer: []u8) Writer {
        _ = buffer;
        return .{
            .handle = stream.socket.handle,
            .interface = .{
                .vtable = &.{
                    .drain = drainImpl,
                },
                .buffer = &.{},
                .end = 0,
            },
        };
    }

    fn drainImpl(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
        const buffered = io_w.buffered();
        const n = writeAll(self.handle, buffered, data, splat) catch return error.WriteFailed;
        return io_w.consume(n);
    }

    fn writeAll(handle: net.Socket.Handle, buffered: []const u8, data: []const []const u8, splat: usize) !usize {
        var total: usize = 0;
        if (buffered.len > 0) {
            try writeExact(handle, buffered);
            total += buffered.len;
        }
        for (data, 0..) |chunk, i| {
            if (chunk.len == 0) continue;
            const reps = if (i + 1 == data.len) splat else 1;
            var rep: usize = 0;
            while (rep < reps) : (rep += 1) {
                try writeExact(handle, chunk);
                total += chunk.len;
            }
        }
        return total;
    }

    fn writeExact(handle: net.Socket.Handle, bytes: []const u8) !void {
        var off: usize = 0;
        while (off < bytes.len) {
            const rc = system.write(handle, bytes.ptr + off, bytes.len - off);
            if (@as(isize, @bitCast(rc)) < 0) return error.WriteFailed;
            const n: usize = @intCast(rc);
            if (n == 0) return error.WriteFailed;
            off += n;
        }
    }
};
