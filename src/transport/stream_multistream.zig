//! Multistream-select 1.0.0 on generic `std.Io.Reader` / `std.Io.Writer` pairs.
//!
//! Use for each new application stream (TCP `std.Io.net.Stream`, zquic raw QUIC stream,
//! or any other byte stream) so every substream negotiates its protocol independently.

const std = @import("std");
const Io = std.Io;
const errors = @import("../errors.zig");
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

pub const StreamHandshakeError = errors.TransportError || std.mem.Allocator.Error;

fn compactConsumed(acc: *std.ArrayList(u8), allocator: std.mem.Allocator, rem: []const u8) std.mem.Allocator.Error!void {
    const consumed = acc.items.len - rem.len;
    try acc.replaceRange(allocator, 0, consumed, &.{});
}

fn readMoreHandshake(acc: *std.ArrayList(u8), r: *Io.Reader, allocator: std.mem.Allocator) StreamHandshakeError!void {
    if (acc.items.len >= handshake_accum_cap) return error.ProtocolNegotiationFailed;
    var chunk: [512]u8 = undefined;
    const n = r.readSliceShort(&chunk) catch |e| return terr.fromMultistreamStreamLayer(e);
    if (n == 0) return error.ProtocolNegotiationFailed;
    try acc.appendSlice(allocator, chunk[0..n]);
    if (acc.items.len > handshake_accum_cap) return error.ProtocolNegotiationFailed;
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
    try appendFirstStreamInitiatorHandshake(&out, allocator, protocol_id);
    Io.Writer.writeAll(w, out.items) catch |e| return terr.fromMultistreamStreamLayer(e);
    Io.Writer.flush(w) catch |e| return terr.fromMultistreamStreamLayer(e);

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

    while (true) {
        var rem: []const u8 = acc.items;
        if (neg.responderReadMultistreamOffer(&rem, neg.default_max_body_len)) |_| {
            try compactConsumed(&acc, allocator, rem);
            break;
        } else |err| switch (err) {
            error.MissingNewline => try readMoreHandshake(&acc, r, allocator),
            else => return terr.fromMultistreamStreamLayer(err),
        }
    }

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try neg.responderSendMultistreamHeader(&out, allocator);
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
        try neg.responderReplyProtocol(&out, allocator, offered, supported_protocol_id);
        Io.Writer.writeAll(w, out.items) catch |e| return terr.fromMultistreamStreamLayer(e);
        Io.Writer.flush(w) catch |e| return terr.fromMultistreamStreamLayer(e);
        return;
    }
}
