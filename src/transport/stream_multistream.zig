//! Multistream-select 1.0.0 on generic `std.Io.Reader` / `std.Io.Writer` pairs.
//!
//! Use for each new application stream (TCP `std.Io.net.Stream`, zquic raw QUIC stream,
//! or any other byte stream) so every substream negotiates its protocol independently.

const std = @import("std");
const Io = std.Io;
const errors = @import("../errors.zig");
const ms = @import("../multistream.zig");
const neg = @import("multistream_negotiate.zig");
const terr = @import("transport_error.zig");

pub const handshake_accum_cap: usize = 1024;

/// First messages on a new stream: `/multistream/1.0.0\n` then `protocol_id\n`.
pub fn appendFirstStreamInitiatorHandshake(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol_id: []const u8,
) (neg.NegotiateError || std.mem.Allocator.Error)!void {
    try neg.initiatorSendMultistreamHeader(write, allocator);
    try neg.initiatorSendProtocol(write, allocator, protocol_id);
}

/// Like [`appendFirstStreamInitiatorHandshake`] but uses go-multistream v0.5 delimited tokens.
pub fn appendFirstStreamInitiatorHandshakeFramed(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol_id: []const u8,
    framing: neg.Framing,
) (neg.NegotiateError || std.mem.Allocator.Error)!void {
    try neg.initiatorSendMultistreamHeaderFramed(write, allocator, framing);
    try neg.initiatorSendProtocolFramed(write, allocator, protocol_id, framing);
}

/// Wire size of [`appendFirstStreamInitiatorHandshake`] output for length-based QUIC pumping.
pub fn initiatorFirstWriteWireLen(protocol_id: []const u8) neg.NegotiateError!usize {
    try neg.validateProtocolId(protocol_id);
    return ms.multistream_1_0_0.len + protocol_id.len + 1;
}

/// Wire size of the responder's successful multistream reply (header + `protocol_id\n`).
pub fn responderSuccessReplyWireLen(protocol_id: []const u8) neg.NegotiateError!usize {
    try neg.validateProtocolId(protocol_id);
    return ms.multistream_1_0_0.len + protocol_id.len + 1;
}

pub const StreamHandshakeError = errors.TransportError || std.mem.Allocator.Error;

fn compactConsumed(acc: *std.ArrayList(u8), allocator: std.mem.Allocator, rem: []const u8) std.mem.Allocator.Error!void {
    const consumed = acc.items.len - rem.len;
    try acc.replaceRange(allocator, 0, consumed, &.{});
}

fn notePeerFraming(framing: *?neg.Framing, acc: []const u8) void {
    if (framing.* == null and acc.len > 0) framing.* = neg.detectFraming(acc[0]);
}

fn readMoreHandshake(acc: *std.ArrayList(u8), r: *Io.Reader, allocator: std.mem.Allocator) StreamHandshakeError!void {
    if (acc.items.len >= handshake_accum_cap) return error.ProtocolNegotiationFailed;
    // `readSliceShort` keeps pulling until the slice is full or the stream ends. For finite
    // buffered sources (QUIC recv buffer drained into `Io.Reader`), that can call `stream`
    // again after all bytes were moved to the reader scratch and surface `ReadFailed`.
    // One byte per step matches multistream line parsing and avoids over-reading.
    var byte: [1]u8 = undefined;
    const n = r.readSliceShort(&byte) catch |e| return terr.fromMultistreamStreamLayer(e);
    if (n == 0) return error.ProtocolNegotiationFailed;
    try acc.appendSlice(allocator, &byte);
    if (acc.items.len > handshake_accum_cap) return error.ProtocolNegotiationFailed;
}

/// Like [`readMoreHandshake`], but returns `false` when the stream layer has no byte yet (`ReadFailed`).
fn tryReadMoreHandshake(acc: *std.ArrayList(u8), r: *Io.Reader, allocator: std.mem.Allocator) StreamHandshakeError!bool {
    if (acc.items.len >= handshake_accum_cap) return error.ProtocolNegotiationFailed;
    var byte: [1]u8 = undefined;
    const n = r.readSliceShort(&byte) catch |e| switch (e) {
        error.ReadFailed => return false,
    };
    if (n == 0) return error.ProtocolNegotiationFailed;
    try acc.appendSlice(allocator, &byte);
    if (acc.items.len > handshake_accum_cap) return error.ProtocolNegotiationFailed;
    return true;
}

/// Initiator: send multistream header + `protocol_id`, then read peer header and ack.
pub fn initiatorHandshakeMultistream(
    r: *Io.Reader,
    w: *Io.Writer,
    protocol_id: []const u8,
    allocator: std.mem.Allocator,
) StreamHandshakeError!void {
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    appendFirstStreamInitiatorHandshake(&out, allocator, protocol_id) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => |err| return terr.fromMultistreamStreamLayer(err),
    };
    Io.Writer.writeAll(w, out.items) catch |e| return terr.fromMultistreamStreamLayer(e);
    Io.Writer.flush(w) catch |e| return terr.fromMultistreamStreamLayer(e);

    return initiatorHandshakeMultistreamReadPhase(r, w, protocol_id, allocator);
}

/// Initiator: after [`appendFirstStreamInitiatorHandshake`] was written and flushed, read peer header and protocol ack.
pub fn initiatorHandshakeMultistreamReadPhase(
    r: *Io.Reader,
    w: *Io.Writer,
    protocol_id: []const u8,
    allocator: std.mem.Allocator,
) StreamHandshakeError!void {
    _ = w;
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.initiatorReadPeerMultistream(&rem, neg.default_max_body_len)) |_| {
            try compactConsumed(&acc, allocator, rem);
            break;
        } else |err| switch (err) {
            error.MissingNewline => try readMoreHandshake(&acc, r, allocator),
            else => return terr.fromMultistreamStreamLayer(err),
        }
    }

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.initiatorReadProtocolAck(&rem, protocol_id, neg.default_max_body_len)) |_| {
            try compactConsumed(&acc, allocator, rem);
            return;
        } else |err| switch (err) {
            error.MissingNewline => try readMoreHandshake(&acc, r, allocator),
            else => return terr.fromMultistreamStreamLayer(err),
        }
    }
}

/// Responder: read multistream offer, send header, read protocol, reply with ack or `na`.
pub fn responderHandshakeMultistream(
    r: *Io.Reader,
    w: *Io.Writer,
    supported_protocol_id: []const u8,
    allocator: std.mem.Allocator,
) StreamHandshakeError!void {
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);
    var peer_framing: ?neg.Framing = null;

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.responderReadMultistreamOffer(&rem, neg.default_max_body_len)) |_| {
            try compactConsumed(&acc, allocator, rem);
            break;
        } else |err| switch (err) {
            error.MissingNewline => {
                try readMoreHandshake(&acc, r, allocator);
                notePeerFraming(&peer_framing, acc.items);
            },
            else => return terr.fromMultistreamStreamLayer(err),
        }
    }
    const framing = peer_framing orelse .legacy;

    // After the multistream offer line, `acc` often holds only that line: the protocol
    // id may still sit in the QUIC recv buffer. Pull bytes until we can parse the
    // protocol offer or the buffer is empty; if complete, send header+ack in **one**
    // write (avoids a tiny second STREAM frame that loopback was losing at 22/36 bytes).
    while (true) {
        var rem_probe: []const u8 = acc.items;
        const offered_prefetch = neg.responderReadProtocolOffer(&rem_probe, neg.default_max_body_len) catch |err| switch (err) {
            error.MissingNewline => @as(?[]const u8, null),
            else => |e| return terr.fromMultistreamStreamLayer(e),
        };
        if (offered_prefetch) |offered| {
            // `offered` borrows from `acc`; build the wire reply before `compactConsumed` mutates `acc`.
            var out = std.ArrayList(u8).empty;
            defer out.deinit(allocator);
            neg.responderSendMultistreamHeaderFramed(&out, allocator, framing) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |err| return terr.fromMultistreamStreamLayer(err),
            };
            neg.responderReplyProtocolFramed(&out, allocator, offered, supported_protocol_id, framing) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |err| return terr.fromMultistreamStreamLayer(err),
            };
            try compactConsumed(&acc, allocator, rem_probe);
            Io.Writer.writeAll(w, out.items) catch |e| return terr.fromMultistreamStreamLayer(e);
            Io.Writer.flush(w) catch |e| return terr.fromMultistreamStreamLayer(e);
            return;
        }
        const pulled = try tryReadMoreHandshake(&acc, r, allocator);
        if (!pulled) return error.DialFailed;
        notePeerFraming(&peer_framing, acc.items);
    }

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    neg.responderSendMultistreamHeaderFramed(&out, allocator, framing) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => |err| return terr.fromMultistreamStreamLayer(err),
    };
    Io.Writer.writeAll(w, out.items) catch |e| return terr.fromMultistreamStreamLayer(e);
    Io.Writer.flush(w) catch |e| return terr.fromMultistreamStreamLayer(e);

    while (true) {
        var rem: []const u8 = acc.items;
        const offered = neg.responderReadProtocolOffer(&rem, neg.default_max_body_len) catch |err| switch (err) {
            error.MissingNewline => {
                try readMoreHandshake(&acc, r, allocator);
                continue;
            },
            else => return terr.fromMultistreamStreamLayer(err),
        };
        try compactConsumed(&acc, allocator, rem);
        out.clearRetainingCapacity();
        neg.responderReplyProtocolFramed(&out, allocator, offered, supported_protocol_id, framing) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |err| return terr.fromMultistreamStreamLayer(err),
        };
        Io.Writer.writeAll(w, out.items) catch |e| return terr.fromMultistreamStreamLayer(e);
        Io.Writer.flush(w) catch |e| return terr.fromMultistreamStreamLayer(e);
        return;
    }
}

/// Responder: same as [`responderHandshakeMultistream`], but accept the first matching protocol in `candidates`.
/// Returns the index into `candidates` on success. If the offered protocol is not listed, sends `na` and returns [`error.ProtocolNegotiationFailed`].
pub fn responderHandshakeMultistreamAmong(
    r: *Io.Reader,
    w: *Io.Writer,
    candidates: []const []const u8,
    allocator: std.mem.Allocator,
) StreamHandshakeError!usize {
    if (candidates.len == 0) return error.ProtocolNegotiationFailed;

    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);
    var peer_framing: ?neg.Framing = null;

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.responderReadMultistreamOffer(&rem, neg.default_max_body_len)) |_| {
            try compactConsumed(&acc, allocator, rem);
            break;
        } else |err| switch (err) {
            error.MissingNewline => {
                try readMoreHandshake(&acc, r, allocator);
                notePeerFraming(&peer_framing, acc.items);
            },
            else => return terr.fromMultistreamStreamLayer(err),
        }
    }
    const framing = peer_framing orelse .legacy;

    while (true) {
        var rem_probe: []const u8 = acc.items;
        const offered_prefetch = neg.responderReadProtocolOffer(&rem_probe, neg.default_max_body_len) catch |err| switch (err) {
            error.MissingNewline => @as(?[]const u8, null),
            else => |e| return terr.fromMultistreamStreamLayer(e),
        };
        if (offered_prefetch) |offered| {
            var out = std.ArrayList(u8).empty;
            defer out.deinit(allocator);
            neg.responderSendMultistreamHeaderFramed(&out, allocator, framing) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |err| return terr.fromMultistreamStreamLayer(err),
            };
            const picked = neg.responderReplyProtocolAmongFramed(&out, allocator, offered, candidates, framing) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |err| return terr.fromMultistreamStreamLayer(err),
            };
            try compactConsumed(&acc, allocator, rem_probe);
            Io.Writer.writeAll(w, out.items) catch |e| return terr.fromMultistreamStreamLayer(e);
            Io.Writer.flush(w) catch |e| return terr.fromMultistreamStreamLayer(e);
            return picked orelse return terr.fromMultistreamStreamLayer(error.ProtocolNotSupported);
        }
        const pulled = try tryReadMoreHandshake(&acc, r, allocator);
        if (!pulled) return error.DialFailed;
        notePeerFraming(&peer_framing, acc.items);
    }

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    neg.responderSendMultistreamHeaderFramed(&out, allocator, framing) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => |err| return terr.fromMultistreamStreamLayer(err),
    };
    Io.Writer.writeAll(w, out.items) catch |e| return terr.fromMultistreamStreamLayer(e);
    Io.Writer.flush(w) catch |e| return terr.fromMultistreamStreamLayer(e);

    while (true) {
        var rem: []const u8 = acc.items;
        const offered = neg.responderReadProtocolOffer(&rem, neg.default_max_body_len) catch |err| switch (err) {
            error.MissingNewline => {
                try readMoreHandshake(&acc, r, allocator);
                continue;
            },
            else => return terr.fromMultistreamStreamLayer(err),
        };
        try compactConsumed(&acc, allocator, rem);
        out.clearRetainingCapacity();
        const picked = neg.responderReplyProtocolAmongFramed(&out, allocator, offered, candidates, framing) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |err| return terr.fromMultistreamStreamLayer(err),
        };
        Io.Writer.writeAll(w, out.items) catch |e| return terr.fromMultistreamStreamLayer(e);
        Io.Writer.flush(w) catch |e| return terr.fromMultistreamStreamLayer(e);
        return picked orelse return terr.fromMultistreamStreamLayer(error.ProtocolNotSupported);
    }
}

test "responderHandshakeMultistreamAmong matches second candidate" {
    const a = std.testing.allocator;
    const ping_mod = @import("../ping.zig");
    const wire = "/multistream/1.0.0\n" ++ "/ipfs/ping/1.0.0\n";
    var r = Io.Reader.fixed(wire);
    var aw: Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    const cands: []const []const u8 = &.{ "/meshsub/1.1.0", ping_mod.multistream_protocol_id };
    const ix = try responderHandshakeMultistreamAmong(&r, &aw.writer, cands, a);
    try std.testing.expectEqual(@as(usize, 1), ix);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), ping_mod.multistream_protocol_id) != null);
}

test "responderHandshakeMultistreamAmong na for unknown protocol" {
    const a = std.testing.allocator;
    const wire = "/multistream/1.0.0\n/weird/proto\n";
    var r = Io.Reader.fixed(wire);
    var aw: Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    const cands: []const []const u8 = &.{"/meshsub/1.1.0"};
    try std.testing.expectError(error.ProtocolNegotiationFailed, responderHandshakeMultistreamAmong(&r, &aw.writer, cands, a));
}
