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
    comptime sendFn: fn (@TypeOf(ctx), []const u8) usize,
    slice: []const u8,
) usize {
    var off: usize = 0;
    var sent: usize = 0;
    while (off < slice.len) {
        const n = @min(raw_stream_send_chunk_len, slice.len - off);
        const chunk = slice[off..][0..n];
        const accepted = sendFn(ctx, chunk);
        if (accepted == 0) break;
        off += accepted;
        sent += accepted;
    }
    return sent;
}

fn clientRawReaderStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const self: *RawAppBidiClient = @alignCast(@fieldParentPtr("reader_scratch", @as(*[2048]u8, @ptrCast(@alignCast(r.buffer.ptr)))));
    const buf = self.client.rawAppRecvBuffer(self.stream_id) orelse return error.ReadFailed;
    if (self.read_cursor >= buf.len) return error.ReadFailed;
    const avail = buf[self.read_cursor..];
    const max_out: usize = if (limit == .unlimited) avail.len else @min(avail.len, @intFromEnum(limit));
    const n = try w.write(avail[0..max_out]);
    self.read_cursor += n;
    return n;
}

fn clientRawWriterDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const self: *RawAppBidiClient = @alignCast(@fieldParentPtr("writer_buf", @as(*[2048]u8, @ptrCast(@alignCast(w.buffer.ptr)))));
    const send = struct {
        fn f(ctx: *RawAppBidiClient, chunk: []const u8) usize {
            const accepted = ctx.client.sendRawStreamData(ctx.stream_id, ctx.send_offset, chunk, false);
            ctx.send_offset += @intCast(accepted);
            return accepted;
        }
    }.f;
    // Honor `std.Io.Writer`: bytes already copied into `buffer[0..end]` must be sent before `data`.
    if (w.end != 0) {
        _ = emitChunks(self, send, w.buffer[0..w.end]);
        w.end = 0;
    }
    if (data.len == 0) return 0;
    var total: usize = 0;
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
    const self: *RawAppBidiServer = @alignCast(@fieldParentPtr("reader_scratch", @as(*[2048]u8, @ptrCast(@alignCast(r.buffer.ptr)))));
    const buf = self.recvBuffer() orelse return error.ReadFailed;
    if (self.read_cursor >= buf.len) return error.ReadFailed;
    const avail = buf[self.read_cursor..];
    const max_out: usize = if (limit == .unlimited) avail.len else @min(avail.len, @intFromEnum(limit));
    const n = try w.write(avail[0..max_out]);
    self.read_cursor += n;
    return n;
}

fn serverRawWriterDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const self: *RawAppBidiServer = @alignCast(@fieldParentPtr("writer_buf", @as(*[2048]u8, @ptrCast(@alignCast(w.buffer.ptr)))));
    const send = struct {
        fn f(ctx: *RawAppBidiServer, chunk: []const u8) usize {
            if (ctx.client) |c| {
                const accepted = c.sendRawStreamData(ctx.stream_id, ctx.send_offset, chunk, false);
                ctx.send_offset += @intCast(accepted);
                return accepted;
            }
            // `Server.sendRawStreamData` returns the number of payload bytes
            // the QUIC stack accepted (either flushed on the wire or queued in
            // `pending_stream_sends`).  Treating an unconditional `chunk.len`
            // as accepted — as we did before zquic v1.7.9 — silently punches a
            // hole in the stream whenever the pending queue is exhausted (the
            // STREAM offset advances past bytes that never reach the peer, so
            // the receiver hangs forever waiting for the gap).
            const accepted = ctx.server.sendRawStreamData(ctx.conn, ctx.stream_id, ctx.send_offset, chunk, false);
            ctx.send_offset += @intCast(accepted);
            return accepted;
        }
    }.f;
    if (w.end != 0) {
        _ = emitChunks(self, send, w.buffer[0..w.end]);
        w.end = 0;
    }
    if (data.len == 0) return 0;
    var total: usize = 0;
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
    .flush = Io.Writer.defaultFlush,
    .rebase = Io.Writer.defaultRebase,
};

const server_reader_vtable = Io.Reader.VTable{
    .stream = serverRawReaderStream,
};

const server_writer_vtable = Io.Writer.VTable{
    .drain = serverRawWriterDrain,
    .flush = Io.Writer.defaultFlush,
    .rebase = Io.Writer.defaultRebase,
};

/// Multistream-select I/O for a client-initiated raw bidi stream on [`ZIo.Client`].
pub const RawAppBidiClient = struct {
    client: *ZIo.Client,
    stream_id: u64,
    send_offset: u64 = 0,
    read_cursor: usize = 0,
    reader_scratch: [2048]u8 = undefined,
    /// Large enough to hold a typical multistream line + protocol id in one buffered `writeAll`,
    /// so `flush` emits one STREAM frame per negotiation step. A 1-byte buffer produced many
    /// tiny frames; the client stack drops out-of-order frames (gap) and never recovers.
    writer_buf: [2048]u8 = undefined,

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
            .buffer = self.writer_buf[0..],
            .end = 0,
        };
    }

    /// Bytes queued by zquic for this stream that this adapter has not yet consumed.
    pub fn unreadRecvLen(self: *const RawAppBidiClient) usize {
        const buf = self.client.rawAppRecvBuffer(self.stream_id) orelse return 0;
        return buf.len - self.read_cursor;
    }

    /// Half-close the send direction: emit a STREAM FIN (empty payload) at the
    /// current `send_offset`, leaving the receive side open for the response.
    /// The libp2p req/resp convention is that the requester writes its request
    /// then closes its write side; go-libp2p responders read the request to EOF
    /// before replying, so without this FIN they block and the request times
    /// out. rust-libp2p replies eagerly so this is a no-op for it. Send only —
    /// the caller keeps reading the response via `reader()`.
    pub fn finishSend(self: *RawAppBidiClient) void {
        _ = self.client.sendRawStreamData(self.stream_id, self.send_offset, &[_]u8{}, true);
    }

    /// Send `data` on the raw stream with FIN set on the last chunk (go-libp2p identify expects EOF).
    pub fn writeAllFin(self: *RawAppBidiClient, data: []const u8) void {
        if (data.len == 0) {
            _ = self.client.sendRawStreamData(self.stream_id, self.send_offset, &[_]u8{}, true);
            return;
        }
        var off: usize = 0;
        while (off < data.len) {
            const n = @min(raw_stream_send_chunk_len, data.len - off);
            const chunk = data[off..][0..n];
            const fin = off + n >= data.len;
            const accepted = self.client.sendRawStreamData(self.stream_id, self.send_offset, chunk, fin);
            if (accepted == 0) break;
            self.send_offset += @intCast(accepted);
            off += accepted;
        }
    }
};

/// Multistream-select I/O for a raw bidi stream on [`ZIo.Server`] + [`ZIo.ConnState`].
///
/// When `client` is non-null this struct is used for a *remote-initiated* bidi stream on an
/// *outbound* (client-side) QUIC connection — e.g. a gossipsub `/meshsub/1.1.0` stream that
/// the remote peer opened on the connection zeam dialed. In that mode `server` is never
/// dereferenced for sends; all writes go through `client` instead.  `conn` is always a valid
/// `ConnState` pointer (points to `client.conn` for the client case) and is used for reads.
pub const RawAppBidiServer = struct {
    server: *ZIo.Server,
    conn: *ZIo.ConnState,
    stream_id: u64,
    /// Non-null when this adapter wraps a remote-initiated stream on an outbound QUIC
    /// connection. Writes use `ZIo.Client.sendRawStreamData` instead of `ZIo.Server.sendRawStreamData`.
    client: ?*ZIo.Client = null,
    send_offset: u64 = 0,
    read_cursor: usize = 0,
    reader_scratch: [2048]u8 = undefined,
    writer_buf: [2048]u8 = undefined,

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
            .buffer = self.writer_buf[0..],
            .end = 0,
        };
    }

    /// Bytes queued by zquic for this stream that this adapter has not yet consumed.
    pub fn unreadRecvLen(self: *const RawAppBidiServer) usize {
        const buf = self.recvBuffer() orelse return 0;
        return buf.len - self.read_cursor;
    }

    /// Pending receive buffer for this stream.
    ///
    /// When `client` is set this is a *remote-initiated* stream on an outbound (client-side)
    /// QUIC connection — the inbound bytes live in the client's `raw_app_recv` slot table.
    /// Otherwise this is an ordinary inbound stream on a listener-side connection and the
    /// bytes live in `conn.raw_app_streams`.
    pub fn recvBuffer(self: *const RawAppBidiServer) ?[]const u8 {
        if (self.client) |c| return c.rawAppRecvBuffer(self.stream_id);
        return ZIo.rawAppRecvBuffer(self.conn, self.stream_id);
    }

    /// Whether the peer has sent FIN on this stream. Routes to the client-side helper when
    /// the adapter is wrapping a remote-initiated stream on an outbound connection.
    pub fn finReceived(self: *const RawAppBidiServer) bool {
        if (self.client) |c| return c.rawAppStreamFinReceived(self.stream_id);
        return ZIo.rawAppStreamFinReceived(self.conn, self.stream_id);
    }

    /// Whether the peer has FIN'd AND every byte up to the final size has been
    /// contiguously reassembled (stronger than `finReceived`: a bare 0-byte FIN
    /// frame can be processed ahead of cwnd-queued payload). Used by the req/resp
    /// engine to decide a response is complete without racing the trailing data.
    pub fn fullyReceived(self: *const RawAppBidiServer) bool {
        if (self.client) |c| return c.rawAppStreamFullyReceived(self.stream_id);
        return ZIo.rawAppStreamFullyReceived(self.conn, self.stream_id);
    }

    /// Release the zquic-side raw_app slot so the per-connection table doesn't fill up.
    pub fn release(self: *RawAppBidiServer, allocator: std.mem.Allocator) bool {
        if (self.client) |c| return c.releaseRawAppStream(self.stream_id);
        return ZIo.releaseRawAppStream(self.conn, self.stream_id, allocator);
    }

    /// Send `data` on the raw stream with FIN set on the last chunk (go-libp2p identify expects EOF).
    pub fn writeAllFin(self: *RawAppBidiServer, data: []const u8) void {
        if (self.client) |c| {
            if (data.len == 0) {
                _ = c.sendRawStreamData(self.stream_id, self.send_offset, &[_]u8{}, true);
                return;
            }
            var off: usize = 0;
            while (off < data.len) {
                const n = @min(raw_stream_send_chunk_len, data.len - off);
                const chunk = data[off..][0..n];
                const fin = off + n >= data.len;
                const accepted = c.sendRawStreamData(self.stream_id, self.send_offset, chunk, fin);
                if (accepted == 0) break;
                self.send_offset += @intCast(accepted);
                off += accepted;
            }
            return;
        }
        if (data.len == 0) {
            _ = self.server.sendRawStreamData(self.conn, self.stream_id, self.send_offset, &[_]u8{}, true);
            return;
        }
        var off: usize = 0;
        while (off < data.len) {
            const n = @min(raw_stream_send_chunk_len, data.len - off);
            const chunk = data[off..][0..n];
            const fin = off + n >= data.len;
            const accepted = self.server.sendRawStreamData(self.conn, self.stream_id, self.send_offset, chunk, fin);
            // zquic now returns the bytes it accepted; bail rather than
            // advancing past a refusal — the caller treats writeAllFin as
            // best-effort and a subsequent retry on the same stream will
            // resume from the unmodified `send_offset`.
            if (accepted == 0) break;
            self.send_offset += @intCast(accepted);
            off += accepted;
        }
    }
};
