//! Yamux session pump over a TLS [`SecureChannel`] plus stream-level multistream ping.

const std = @import("std");
const Io = std.Io;
const zl = @import("zig_libp2p");

const tcp_tls = zl.transport.tcp_tls;
const sm = zl.transport.stream_multistream;
const yamux = zl.transport.yamux;
const ping = zl.ping;

pub const Error = error{
    ProtocolError,
    Timeout,
    EndOfStream,
    StreamClosed,
} || tcp_tls.stream_upgrade.UpgradeError || yamux.SessionError || yamux.Stream.WriteError || yamux.Stream.ReadError || ping.WireError || std.mem.Allocator.Error;

pub const Link = struct {
    allocator: std.mem.Allocator,
    session: yamux.Session,
    channel: tcp_tls.SecureChannel,
    r: *Io.Reader,
    w: *Io.Writer,
    ct_buf: [tcp_tls.stream_upgrade.input_buffer_len]u8 = undefined,
    pt_buf: [4096]u8 = undefined,
    wscratch: [tcp_tls.stream_upgrade.output_buffer_len]u8 = undefined,

    pub fn deinit(self: *Link) void {
        self.session.deinit();
        self.channel.deinit(self.allocator);
    }

    pub fn pump(self: *Link) Error!void {
        const out = self.session.pendingOutbound();
        if (out.len > 0) {
            try self.channel.write(self.w, out, &self.wscratch);
            self.session.consumeOutbound(out.len);
        }
        const plain = self.channel.read(self.r, self.allocator, &self.ct_buf, &self.pt_buf) catch |e| switch (e) {
            error.EndOfStream => return,
            else => return e,
        };
        try self.session.feed(plain);
    }

    pub fn negotiateYamux(self: *Link, role: enum { initiator, responder }) Error!void {
        switch (role) {
            .initiator => try self.initiatorYamuxMultistream(),
            .responder => try self.responderYamuxMultistream(),
        }
    }

    fn channelWriteAll(self: *Link, plaintext: []const u8) Error!void {
        try self.channel.write(self.w, plaintext, &self.wscratch);
    }

    fn channelReadAppend(self: *Link, acc: *std.ArrayList(u8)) Error!void {
        if (acc.items.len >= sm.handshake_accum_cap) return error.ProtocolError;
        const plain = self.channel.read(self.r, self.allocator, &self.ct_buf, &self.pt_buf) catch |e| switch (e) {
            error.EndOfStream => return error.EndOfStream,
            else => return e,
        };
        try acc.appendSlice(self.allocator, plain);
        if (acc.items.len > sm.handshake_accum_cap) return error.ProtocolError;
    }

    fn initiatorYamuxMultistream(self: *Link) Error!void {
        const neg = zl.transport.multistream_negotiate;
        var out = std.ArrayList(u8).empty;
        defer out.deinit(self.allocator);
        sm.appendFirstStreamInitiatorHandshake(&out, self.allocator, yamux.multistream_protocol_id) catch return error.ProtocolError;
        try self.channelWriteAll(out.items);

        var acc = std.ArrayList(u8).empty;
        defer acc.deinit(self.allocator);
        while (true) {
            var rem: []const u8 = acc.items;
            if (neg.initiatorReadPeerMultistream(&rem, neg.default_max_body_len)) |_| {
                try compactConsumed(&acc, rem);
                break;
            } else |err| switch (err) {
                error.MissingNewline => try self.channelReadAppend(&acc),
                else => return error.ProtocolError,
            }
        }
        while (true) {
            var rem: []const u8 = acc.items;
            if (neg.initiatorReadProtocolAck(&rem, yamux.multistream_protocol_id, neg.default_max_body_len)) |_| {
                try compactConsumed(&acc, rem);
                break;
            } else |err| switch (err) {
                error.MissingNewline => try self.channelReadAppend(&acc),
                else => return error.ProtocolError,
            }
        }
        if (acc.items.len > 0) try self.session.feed(acc.items);
    }

    fn responderYamuxMultistream(self: *Link) Error!void {
        const neg = zl.transport.multistream_negotiate;
        var acc = std.ArrayList(u8).empty;
        defer acc.deinit(self.allocator);
        var peer_framing: ?neg.Framing = null;

        while (true) {
            var rem: []const u8 = acc.items;
            if (neg.responderReadMultistreamOffer(&rem, neg.default_max_body_len)) |_| {
                try compactConsumed(&acc, rem);
                break;
            } else |err| switch (err) {
                error.MissingNewline => {
                    try self.channelReadAppend(&acc);
                    if (acc.items.len > 0) peer_framing = neg.detectFraming(acc.items[0]);
                },
                else => return error.ProtocolError,
            }
        }
        const framing = peer_framing orelse .legacy;

        const offered: []const u8 = while (true) {
            var rem_probe: []const u8 = acc.items;
            if (neg.responderReadProtocolOffer(&rem_probe, neg.default_max_body_len)) |off| {
                try compactConsumed(&acc, rem_probe);
                break off;
            } else |err| switch (err) {
                error.MissingNewline => try self.channelReadAppend(&acc),
                else => return error.ProtocolError,
            }
        };

        var out = std.ArrayList(u8).empty;
        defer out.deinit(self.allocator);
        neg.responderSendMultistreamHeaderFramed(&out, self.allocator, framing) catch return error.ProtocolError;
        neg.responderReplyProtocolFramed(&out, self.allocator, offered, yamux.multistream_protocol_id, framing) catch return error.ProtocolError;
        try self.channelWriteAll(out.items);
        if (acc.items.len > 0) try self.session.feed(acc.items);
    }

    pub fn runDialerPing(self: *Link, deadline_ms: i64) Error!u64 {
        const stream = try self.session.openStream();
        try self.pumpUntil(deadline_ms, streamIsEstablished, stream);

        const t_ping_start: i64 = @intCast(zl.wall_time.milliTimestamp());
        try self.initiatorPingOnStream(stream, deadline_ms);
        const t_ping_end: i64 = @intCast(zl.wall_time.milliTimestamp());
        return @intCast(t_ping_end - t_ping_start);
    }

    pub fn runListenerPing(self: *Link, deadline_ms: i64) Error!void {
        while (zl.wall_time.milliTimestamp() < deadline_ms) {
            try self.pump();
            if (self.session.acceptStream()) |stream| {
                try self.responderPingOnStream(stream, deadline_ms);
                return;
            }
        }
        return error.Timeout;
    }

    fn streamIsEstablished(_: i64, stream: *yamux.Stream) bool {
        return stream.state == .established;
    }

    fn pumpUntil(self: *Link, deadline_ms: i64, comptime pred: *const fn (i64, *yamux.Stream) bool, stream: *yamux.Stream) Error!void {
        while (zl.wall_time.milliTimestamp() < deadline_ms) {
            if (pred(deadline_ms, stream)) return;
            try self.pump();
        }
        return error.Timeout;
    }

    fn streamWriteAll(self: *Link, stream: *yamux.Stream, bytes: []const u8, deadline_ms: i64) Error!void {
        var off: usize = 0;
        while (off < bytes.len) {
            if (zl.wall_time.milliTimestamp() >= deadline_ms) return error.Timeout;
            try self.pump();
            const n = stream.write(bytes[off..]) catch |e| switch (e) {
                error.StreamClosed => return error.StreamClosed,
                else => return e,
            };
            off += n;
        }
        try self.pump();
    }

    fn streamReadAppend(self: *Link, stream: *yamux.Stream, acc: *std.ArrayList(u8), deadline_ms: i64) Error!void {
        var tmp: [1024]u8 = undefined;
        while (zl.wall_time.milliTimestamp() < deadline_ms) {
            try self.pump();
            const n = stream.read(&tmp) catch |e| switch (e) {
                error.StreamClosed => return error.EndOfStream,
            };
            if (n == 0) continue;
            try acc.appendSlice(self.allocator, tmp[0..n]);
            return;
        }
        return error.Timeout;
    }

    fn initiatorPingOnStream(self: *Link, stream: *yamux.Stream, deadline_ms: i64) Error!void {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(self.allocator);
        sm.appendFirstStreamInitiatorHandshake(&out, self.allocator, ping.multistream_protocol_id) catch return error.ProtocolError;
        try self.streamWriteAll(stream, out.items, deadline_ms);

        var acc = std.ArrayList(u8).empty;
        defer acc.deinit(self.allocator);
        const neg = zl.transport.multistream_negotiate;
        while (zl.wall_time.milliTimestamp() < deadline_ms) {
            var rem: []const u8 = acc.items;
            if (neg.initiatorReadPeerMultistream(&rem, neg.default_max_body_len)) |_| {
                try compactConsumed(&acc, rem);
                break;
            } else |err| switch (err) {
                error.MissingNewline => try self.streamReadAppend(stream, &acc, deadline_ms),
                else => return error.ProtocolError,
            }
        }
        while (zl.wall_time.milliTimestamp() < deadline_ms) {
            var rem: []const u8 = acc.items;
            if (neg.initiatorReadProtocolAck(&rem, ping.multistream_protocol_id, neg.default_max_body_len)) |_| {
                try compactConsumed(&acc, rem);
                break;
            } else |err| switch (err) {
                error.MissingNewline => try self.streamReadAppend(stream, &acc, deadline_ms),
                else => return error.ProtocolError,
            }
        }

        var payload: [ping.payload_len]u8 = undefined;
        ping.randomPayload(&payload);
        try self.streamWriteAll(stream, &payload, deadline_ms);

        var echo: [ping.payload_len]u8 = undefined;
        var got: usize = 0;
        while (got < echo.len) {
            if (zl.wall_time.milliTimestamp() >= deadline_ms) return error.Timeout;
            try self.pump();
            const n = stream.read(echo[got..]) catch |e| switch (e) {
                error.StreamClosed => return error.StreamClosed,
            };
            if (n == 0) continue;
            got += n;
        }
        if (!std.mem.eql(u8, &payload, &echo)) return error.ProtocolError;
    }

    fn responderPingOnStream(self: *Link, stream: *yamux.Stream, deadline_ms: i64) Error!void {
        var acc = std.ArrayList(u8).empty;
        defer acc.deinit(self.allocator);
        const neg = zl.transport.multistream_negotiate;
        while (zl.wall_time.milliTimestamp() < deadline_ms) {
            var rem: []const u8 = acc.items;
            if (neg.responderReadMultistreamOffer(&rem, neg.default_max_body_len)) |_| {
                try compactConsumed(&acc, rem);
                break;
            } else |err| switch (err) {
                error.MissingNewline => try self.streamReadAppend(stream, &acc, deadline_ms),
                else => return error.ProtocolError,
            }
        }
        const offered: []const u8 = while (zl.wall_time.milliTimestamp() < deadline_ms) {
            var rem_offer: []const u8 = acc.items;
            if (neg.responderReadProtocolOffer(&rem_offer, neg.default_max_body_len)) |off| {
                try compactConsumed(&acc, rem_offer);
                break off;
            } else |err| switch (err) {
                error.MissingNewline => try self.streamReadAppend(stream, &acc, deadline_ms),
                else => return error.ProtocolError,
            }
        } else return error.Timeout;

        var out = std.ArrayList(u8).empty;
        defer out.deinit(self.allocator);
        try neg.responderSendMultistreamHeader(&out, self.allocator);
        neg.responderReplyProtocol(&out, self.allocator, offered, ping.multistream_protocol_id) catch return error.ProtocolError;
        try self.streamWriteAll(stream, out.items, deadline_ms);

        var buf: [ping.payload_len]u8 = undefined;
        var got: usize = 0;
        while (got < buf.len) {
            if (zl.wall_time.milliTimestamp() >= deadline_ms) return error.Timeout;
            try self.pump();
            const n = stream.read(buf[got..]) catch |e| switch (e) {
                error.StreamClosed => return error.StreamClosed,
            };
            if (n == 0) continue;
            got += n;
        }
        try self.streamWriteAll(stream, &buf, deadline_ms);
    }

    fn compactConsumed(acc: *std.ArrayList(u8), rem: []const u8) Error!void {
        const consumed = acc.items.len - rem.len;
        if (consumed > 0) {
            std.mem.copyForwards(u8, acc.items[0..rem.len], acc.items[consumed..]);
            acc.shrinkRetainingCapacity(rem.len);
        }
    }
};
