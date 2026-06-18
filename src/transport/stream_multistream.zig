//! Multistream-select 1.0.0 on generic `std.Io.Reader` / `std.Io.Writer` pairs.
//!
//! Use for each new application stream (TCP `std.Io.net.Stream`, zquic raw QUIC stream,
//! or any other byte stream) so every substream negotiates its protocol independently.

const std = @import("std");
const Io = std.Io;
const errors = @import("../primitives/errors.zig");
const ms = @import("../primitives/multistream.zig");
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

/// On success, move any unread bytes still in the handshake accumulator to `tail` (e.g. go
/// MSSelect may flush multistream tokens and application data in one write).
fn finishAmongWithTail(
    acc: *std.ArrayList(u8),
    r: *Io.Reader,
    allocator: std.mem.Allocator,
    tail: ?*std.ArrayList(u8),
) StreamHandshakeError!void {
    if (tail == null) return;
    try drainReaderTail(acc, r, allocator);
    finishAmongWithTailMove(acc, tail.?);
}

fn drainReaderTail(acc: *std.ArrayList(u8), r: *Io.Reader, allocator: std.mem.Allocator) StreamHandshakeError!void {
    while (true) {
        if (acc.items.len >= handshake_accum_cap) return error.ProtocolNegotiationFailed;
        var byte: [1]u8 = undefined;
        const n = r.readSliceShort(&byte) catch break;
        if (n == 0) break;
        try acc.appendSlice(allocator, &byte);
        if (acc.items.len > handshake_accum_cap) return error.ProtocolNegotiationFailed;
    }
}

fn finishAmongWithTailMove(acc: *std.ArrayList(u8), tail: *std.ArrayList(u8)) void {
    tail.* = acc.*;
    acc.* = .empty;
}

/// On success, move unread handshake bytes to `tail` without blocking on more stream input.
fn preserveAccTailOnly(acc: *std.ArrayList(u8), tail: ?*std.ArrayList(u8)) void {
    if (tail == null) return;
    finishAmongWithTailMove(acc, tail.?);
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
    tail: ?*std.ArrayList(u8),
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

    return initiatorHandshakeMultistreamReadPhase(r, w, protocol_id, allocator, tail);
}

/// Initiator: after [`appendFirstStreamInitiatorHandshake`] was written and flushed, read peer header and protocol ack.
pub fn initiatorHandshakeMultistreamReadPhase(
    r: *Io.Reader,
    w: *Io.Writer,
    protocol_id: []const u8,
    allocator: std.mem.Allocator,
    tail: ?*std.ArrayList(u8),
) StreamHandshakeError!void {
    _ = w;
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);
    var peer_framing: ?neg.Framing = null;

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.initiatorReadPeerMultistream(&rem, neg.default_max_body_len)) |_| {
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
    // Auto-detect on the multistream header line is safe — that line is 19
    // bytes (delimited length 0x13), never colliding with the 0x2F = '/'
    // edge case. Subsequent reads must use the detected framing because
    // the protocol-ack token MAY be 47 bytes (delimited length 0x2F = '/'),
    // which would mis-classify if we kept auto-detecting per token. See
    // [`neg.readNegotiationToken`] for the full collision discussion.
    const framing = peer_framing orelse .legacy;

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.initiatorReadProtocolAckFramed(&rem, protocol_id, neg.default_max_body_len, framing)) |_| {
            try compactConsumed(&acc, allocator, rem);
            preserveAccTailOnly(&acc, tail);
            return;
        } else |err| switch (err) {
            error.MissingNewline => try readMoreHandshake(&acc, r, allocator),
            else => return terr.fromMultistreamStreamLayer(err),
        }
    }
}

/// Outcome of one [`initiatorMeshsubFallbackStep`] call.
pub const MeshsubFallbackResult = enum {
    /// Responder accepted a `/meshsub/*` version — negotiation complete.
    accepted,
    /// Not enough bytes buffered yet (or a re-offer was just sent); call again
    /// next tick once more data has arrived.
    incomplete,
    /// Every candidate in `offers` was rejected with `na` — no common version.
    exhausted,
};

/// Multi-tick initiator `/meshsub` negotiation **with version fallback**.
///
/// The caller must already have written the multistream header + `offers[0]`
/// (see [`appendFirstStreamInitiatorHandshakeFramed`]). Each tick, this pulls
/// the buffered reply, consumes the peer's multistream header once
/// (tracked via `header_done`), then reads the protocol ack:
///   * a `/meshsub/*` line  → `.accepted`
///   * `na`                 → advance `offer_idx` and write the next candidate
///                            (`offers[offer_idx]`); returns `.incomplete`
///   * not enough bytes yet → `.incomplete`
///
/// Returns `.exhausted` when `na` is received for the last candidate. This is
/// what lets zeam interop with peers (e.g. lantern / go-libp2p) that don't
/// support the newest `/meshsub` version zeam offers first: instead of tearing
/// the connection down on the first `na`, it negotiates down to a common one.
/// QUIC peers use delimited framing for acks.
pub fn initiatorMeshsubFallbackStep(
    r: *Io.Reader,
    w: *Io.Writer,
    allocator: std.mem.Allocator,
    header_done: *bool,
    offers: []const []const u8,
    offer_idx: *usize,
    tail: ?*std.ArrayList(u8),
) StreamHandshakeError!MeshsubFallbackResult {
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);
    try drainReaderTail(&acc, r, allocator);

    if (!header_done.*) {
        var rem: []const u8 = acc.items;
        neg.initiatorReadPeerMultistream(&rem, neg.default_max_body_len) catch |err| switch (err) {
            error.MissingNewline => return .incomplete,
            else => return terr.fromMultistreamStreamLayer(err),
        };
        try compactConsumed(&acc, allocator, rem);
        header_done.* = true;
    }

    while (true) {
        var rem: []const u8 = acc.items;
        const tok = neg.readNegotiationTokenFramed(&rem, neg.default_max_body_len, .delimited) catch |err| switch (err) {
            error.MissingNewline => return .incomplete,
            else => return terr.fromMultistreamStreamLayer(err),
        };
        if (std.mem.startsWith(u8, tok, "/meshsub/")) {
            try compactConsumed(&acc, allocator, rem);
            preserveAccTailOnly(&acc, tail);
            return .accepted;
        }
        if (std.mem.eql(u8, tok, "na")) {
            try compactConsumed(&acc, allocator, rem);
            offer_idx.* += 1;
            if (offer_idx.* >= offers.len) return .exhausted;
            var out = std.ArrayList(u8).empty;
            defer out.deinit(allocator);
            neg.initiatorSendProtocolFramed(&out, allocator, offers[offer_idx.*], .delimited) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |er| return terr.fromMultistreamStreamLayer(er),
            };
            Io.Writer.writeAll(w, out.items) catch |e| return terr.fromMultistreamStreamLayer(e);
            Io.Writer.flush(w) catch |e| return terr.fromMultistreamStreamLayer(e);
            // The next reply is a fresh round-trip; it is usually not buffered
            // yet, so the next loop read returns `.incomplete` and we resume
            // on a later tick.
            continue;
        }
        return terr.fromMultistreamStreamLayer(error.ProtocolNotSupported);
    }
}

/// Initiator read phase for `/meshsub/*` streams: accepts any `/meshsub/` ack line.
pub fn initiatorHandshakeMeshsubReadPhase(
    r: *Io.Reader,
    w: *Io.Writer,
    allocator: std.mem.Allocator,
    tail: ?*std.ArrayList(u8),
) StreamHandshakeError!void {
    _ = w;
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);
    var peer_framing: ?neg.Framing = null;

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.initiatorReadPeerMultistream(&rem, neg.default_max_body_len)) |_| {
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
        var rem: []const u8 = acc.items;
        if (neg.initiatorReadMeshsubProtocolAckFramed(&rem, neg.default_max_body_len, framing)) |_| {
            try compactConsumed(&acc, allocator, rem);
            preserveAccTailOnly(&acc, tail);
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
    tail: ?*std.ArrayList(u8),
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
        // Use detected framing — see comment in `responderHandshakeMultistreamAmong`.
        const offered_prefetch = neg.responderReadProtocolOfferFramed(&rem_probe, neg.default_max_body_len, framing) catch |err| switch (err) {
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
            preserveAccTailOnly(&acc, tail);
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
        const offered = neg.responderReadProtocolOfferFramed(&rem, neg.default_max_body_len, framing) catch |err| switch (err) {
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
        preserveAccTailOnly(&acc, tail);
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
    tail: ?*std.ArrayList(u8),
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
        // Use the framing detected from the multistream offer line — auto
        // detecting per-token mis-classifies protocols whose delimited
        // length byte happens to equal '/' (0x2F = 47), which is exactly
        // the wire size of `/leanconsensus/req/blocks_by_root/1/ssz_snappy`
        // and `/leanconsensus/req/blocks_by_range/1/ssz_snappy`.
        const offered_prefetch = neg.responderReadProtocolOfferFramed(&rem_probe, neg.default_max_body_len, framing) catch |err| switch (err) {
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
            try finishAmongWithTail(&acc, r, allocator, tail);
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
        const offered = neg.responderReadProtocolOfferFramed(&rem, neg.default_max_body_len, framing) catch |err| switch (err) {
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
        try finishAmongWithTail(&acc, r, allocator, tail);
        return picked orelse return terr.fromMultistreamStreamLayer(error.ProtocolNotSupported);
    }
}

test "responderHandshakeMultistreamAmong matches second candidate" {
    const a = std.testing.allocator;
    const ping_mod = @import("../protocols/ping/ping.zig");
    const wire = "/multistream/1.0.0\n" ++ "/ipfs/ping/1.0.0\n";
    var r = Io.Reader.fixed(wire);
    var aw: Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    const cands: []const []const u8 = &.{ "/meshsub/1.1.0", ping_mod.multistream_protocol_id };
    const ix = try responderHandshakeMultistreamAmong(&r, &aw.writer, cands, a, null);
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
    try std.testing.expectError(error.ProtocolNegotiationFailed, responderHandshakeMultistreamAmong(&r, &aw.writer, cands, a, null));
}

test "responderHandshakeMultistreamAmong handles 47-byte delimited protocol (length byte == '/')" {
    // Regression for the framing-detection collision: a delimited token
    // whose body is 46 bytes has total wire length 47 = 0x2F = '/'. Naive
    // first-byte auto-detection mis-classifies it as a legacy line and
    // mis-parses, causing the responder to reply `na` for protocols it
    // actually supports (e.g. `/leanconsensus/req/blocks_by_root/1/ssz_snappy`).
    const a = std.testing.allocator;
    const proto_47 = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";
    try std.testing.expectEqual(@as(usize, 46), proto_47.len);

    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    try neg.initiatorSendMultistreamHeaderFramed(&wire, a, .delimited);
    try neg.initiatorSendProtocolFramed(&wire, a, proto_47, .delimited);
    // Sanity check: the protocol token's length byte is exactly '/'.
    const ms_header_len = std.mem.indexOfScalar(u8, wire.items, '\n').? + 1;
    try std.testing.expectEqual(@as(u8, '/'), wire.items[ms_header_len]);

    var r = Io.Reader.fixed(wire.items);
    var aw: Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    const cands: []const []const u8 = &.{proto_47};
    const ix = try responderHandshakeMultistreamAmong(&r, &aw.writer, cands, a, null);
    try std.testing.expectEqual(@as(usize, 0), ix);
    // Must NOT contain the legacy `na\n` rejection.
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "\nna\n") == null);
}

test "initiatorHandshakeMultistreamReadPhase handles 47-byte delimited ack (length byte == '/')" {
    const a = std.testing.allocator;
    const proto_47 = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";
    try std.testing.expectEqual(@as(usize, 46), proto_47.len);

    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    try neg.responderSendMultistreamHeaderFramed(&wire, a, .delimited);
    try neg.responderReplyProtocolFramed(&wire, a, proto_47, proto_47, .delimited);

    var r = Io.Reader.fixed(wire.items);
    var aw: Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    try initiatorHandshakeMultistreamReadPhase(&r, &aw.writer, proto_47, a, null);
}

test "responderHandshakeMultistreamAmong preserves trailing app bytes (go MSSelect)" {
    const a = std.testing.allocator;
    const ping_mod = @import("../protocols/ping/ping.zig");
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    try neg.initiatorSendMultistreamHeaderFramed(&wire, a, .delimited);
    try neg.initiatorSendProtocolFramed(&wire, a, ping_mod.multistream_protocol_id, .delimited);
    const payload = [_]u8{0x11} ** ping_mod.payload_len;
    try wire.appendSlice(a, &payload);

    var r = Io.Reader.fixed(wire.items);
    var aw: Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    var tail = std.ArrayList(u8).empty;
    defer tail.deinit(a);
    const cands: []const []const u8 = &.{ "/meshsub/1.1.0", ping_mod.multistream_protocol_id };
    const ix = try responderHandshakeMultistreamAmong(&r, &aw.writer, cands, a, &tail);
    try std.testing.expectEqual(@as(usize, 1), ix);
    try std.testing.expectEqual(payload.len, tail.items.len);
    try std.testing.expectEqualSlices(u8, &payload, tail.items);
}

test "initiatorMeshsubFallbackStep negotiates down to a supported version on na" {
    const a = std.testing.allocator;
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    // Responder: header, `na` for /meshsub/1.3.0, then accepts /meshsub/1.2.0.
    try neg.responderSendMultistreamHeaderFramed(&wire, a, .delimited);
    try neg.responderReplyProtocolFramed(&wire, a, "/meshsub/1.3.0", "/meshsub/1.2.0", .delimited); // na
    try neg.responderReplyProtocolFramed(&wire, a, "/meshsub/1.2.0", "/meshsub/1.2.0", .delimited); // ack

    var r = Io.Reader.fixed(wire.items);
    var aw: Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    const offers: []const []const u8 = &.{ "/meshsub/1.3.0", "/meshsub/1.2.0", "/meshsub/1.1.0" };
    var header_done = false;
    var offer_idx: usize = 0;
    const res = try initiatorMeshsubFallbackStep(&r, &aw.writer, a, &header_done, offers, &offer_idx, null);
    try std.testing.expectEqual(MeshsubFallbackResult.accepted, res);
    try std.testing.expectEqual(@as(usize, 1), offer_idx); // advanced past 1.3.0 to 1.2.0
    try std.testing.expect(header_done);
}

test "initiatorMeshsubFallbackStep exhausts when peer supports no offered version" {
    const a = std.testing.allocator;
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    try neg.responderSendMultistreamHeaderFramed(&wire, a, .delimited);
    try neg.responderReplyProtocolFramed(&wire, a, "/meshsub/1.3.0", "/other/1", .delimited); // na
    try neg.responderReplyProtocolFramed(&wire, a, "/meshsub/1.2.0", "/other/1", .delimited); // na
    try neg.responderReplyProtocolFramed(&wire, a, "/meshsub/1.1.0", "/other/1", .delimited); // na

    var r = Io.Reader.fixed(wire.items);
    var aw: Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    const offers: []const []const u8 = &.{ "/meshsub/1.3.0", "/meshsub/1.2.0", "/meshsub/1.1.0" };
    var header_done = false;
    var offer_idx: usize = 0;
    const res = try initiatorMeshsubFallbackStep(&r, &aw.writer, a, &header_done, offers, &offer_idx, null);
    try std.testing.expectEqual(MeshsubFallbackResult.exhausted, res);
}
