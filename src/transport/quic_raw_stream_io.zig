//! `std.Io.Reader` / `std.Io.Writer` adapters for **one** zquic raw application
//! bidirectional stream (see `zquic.transport.io` `raw_application_streams`).
//!
//! The zquic stack appends inbound bytes into a per-stream buffer; these adapters
//! track a local consume cursor. **Callers must run the QUIC recv path** (`Server.run`,
//! `Client` recv loop, or `feedPacket`) so data appears before multistream-select reads;
//! otherwise [`Io.Reader.readSliceShort`] fails with [`error.ReadFailed`].
//!
//! Outbound frames use `fin = false` so a single multistream negotiation does not
//! half-close the QUIC stream; close explicitly at the protocol layer when required.

const std = @import("std");
const Io = std.Io;
const zquic = @import("zquic");
const ZIo = zquic.transport.io;

/// Conservative STREAM payload chunk for [`ZIo.Client.sendRawStreamData`] /
/// [`ZIo.Server.sendRawStreamData`] so frames stay below common path MTUs.
pub const raw_stream_send_chunk_len: usize = 1200;

fn emitChunks(
    ctx: anytype,
    comptime sendFn: fn (@TypeOf(ctx), []const u8) void,
    slice: []const u8,
) usize {
    var off: usize = 0;
    var sent: usize = 0;
    while (off < slice.len) {
        const n = @min(raw_stream_send_chunk_len, slice.len - off);
        sendFn(ctx, slice[off..][0..n]);
        off += n;
        sent += n;
    }
    return sent;
}

fn clientRawReaderStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const self: *RawAppBidiClient = @fieldParentPtr("reader_scratch", r.buffer.ptr);
    const buf = self.client.rawAppRecvBuffer(self.stream_id) orelse return error.ReadFailed;
    if (self.read_cursor >= buf.len) return error.ReadFailed;
    const avail = buf[self.read_cursor..];
    const max_out: usize = if (limit == .unlimited) avail.len else @min(avail.len, @intFromEnum(limit));
    const n = try w.write(avail[0..max_out]);
    self.read_cursor += n;
    return n;
}

fn clientRawWriterDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const self: *RawAppBidiClient = @fieldParentPtr("writer_anchor", w.buffer.ptr);
    if (data.len == 0) return 0;
    var total: usize = 0;
    const send = struct {
        fn f(ctx: *RawAppBidiClient, chunk: []const u8) void {
            ctx.client.sendRawStreamData(ctx.stream_id, ctx.send_offset, chunk, false);
            ctx.send_offset += @intCast(chunk.len);
        }
    }.f;
    for (data[0 .. data.len - 1]) |bytes| {
        total += emitChunks(self, send, bytes);
    }
    const last = data[data.len - 1];
    var r: usize = 0;
    while (r < splat) : (r += 1) {
        total += emitChunks(self, send, last);
    }
    return total;
}

fn serverRawReaderStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const self: *RawAppBidiServer = @fieldParentPtr("reader_scratch", r.buffer.ptr);
    const buf = ZIo.rawAppRecvBuffer(self.conn, self.stream_id) orelse return error.ReadFailed;
    if (self.read_cursor >= buf.len) return error.ReadFailed;
    const avail = buf[self.read_cursor..];
    const max_out: usize = if (limit == .unlimited) avail.len else @min(avail.len, @intFromEnum(limit));
    const n = try w.write(avail[0..max_out]);
    self.read_cursor += n;
    return n;
}

fn serverRawWriterDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const self: *RawAppBidiServer = @fieldParentPtr("writer_anchor", w.buffer.ptr);
    if (data.len == 0) return 0;
    var total: usize = 0;
    const send = struct {
        fn f(ctx: *RawAppBidiServer, chunk: []const u8) void {
            ctx.server.sendRawStreamData(ctx.conn, ctx.stream_id, ctx.send_offset, chunk, false);
            ctx.send_offset += @intCast(chunk.len);
        }
    }.f;
    for (data[0 .. data.len - 1]) |bytes| {
        total += emitChunks(self, send, bytes);
    }
    const last = data[data.len - 1];
    var rep: usize = 0;
    while (rep < splat) : (rep += 1) {
        total += emitChunks(self, send, last);
    }
    return total;
}

const client_reader_vtable = Io.Reader.VTable{
    .stream = clientRawReaderStream,
};

const client_writer_vtable = Io.Writer.VTable{
    .drain = clientRawWriterDrain,
    .flush = Io.Writer.noopFlush,
    .rebase = Io.Writer.defaultRebase,
};

const server_reader_vtable = Io.Reader.VTable{
    .stream = serverRawReaderStream,
};

const server_writer_vtable = Io.Writer.VTable{
    .drain = serverRawWriterDrain,
    .flush = Io.Writer.noopFlush,
    .rebase = Io.Writer.defaultRebase,
};

/// Multistream-select I/O for a client-initiated raw bidi stream on [`ZIo.Client`].
pub const RawAppBidiClient = struct {
    client: *ZIo.Client,
    stream_id: u64,
    send_offset: u64 = 0,
    read_cursor: usize = 0,
    reader_scratch: [2048]u8 = undefined,
    writer_anchor: [1]u8 = .{0},

    pub fn reader(self: *RawAppBidiClient) Io.Reader {
        return .{
            .vtable = &client_reader_vtable,
            .buffer = self.reader_scratch[0..],
            .seek = 0,
            .end = 0,
        };
    }

    pub fn writer(self: *RawAppBidiClient) Io.Writer {
        return .{
            .vtable = &client_writer_vtable,
            .buffer = self.writer_anchor[0..0],
            .end = 0,
        };
    }
};

/// Multistream-select I/O for a raw bidi stream on [`ZIo.Server`] + [`ZIo.ConnState`].
pub const RawAppBidiServer = struct {
    server: *ZIo.Server,
    conn: *ZIo.ConnState,
    stream_id: u64,
    send_offset: u64 = 0,
    read_cursor: usize = 0,
    reader_scratch: [2048]u8 = undefined,
    writer_anchor: [1]u8 = .{0},

    pub fn reader(self: *RawAppBidiServer) Io.Reader {
        return .{
            .vtable = &server_reader_vtable,
            .buffer = self.reader_scratch[0..],
            .seek = 0,
            .end = 0,
        };
    }

    pub fn writer(self: *RawAppBidiServer) Io.Writer {
        return .{
            .vtable = &server_writer_vtable,
            .buffer = self.writer_anchor[0..0],
            .end = 0,
        };
    }
};
