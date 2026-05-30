//! Multistream-select 1.0.0 negotiation on a byte stream (e.g. first QUIC bidi stream).
//!
//! All reads are **bounded** by `max_body_len` (maximum bytes before `\n`, excluding the newline)
//! so a peer cannot force unbounded buffering.

const std = @import("std");
const ms = @import("../multistream.zig");

/// Default maximum negotiation line body length (bytes before `\n`). Same as `multistream.max_protocol_id_body_bytes`.
pub const default_max_body_len: usize = ms.max_protocol_id_body_bytes;

pub const NegotiateError = error{
    LineTooLong,
    MissingNewline,
    InvalidMultistreamVersion,
    ProtocolNotSupported,
    InvalidProtocolLine,
};

fn multistreamVersionLine() []const u8 {
    return ms.multistream_1_0_0[0 .. ms.multistream_1_0_0.len - 1];
}

/// Protocol id must be non-empty printable ASCII (no control chars), suitable for libp2p paths.
pub fn validateProtocolId(id: []const u8) NegotiateError!void {
    if (id.len == 0) return error.InvalidProtocolLine;
    if (id.len > default_max_body_len) return error.InvalidProtocolLine;
    for (id) |c| {
        if (c < 0x20 or c == 0x7f) return error.InvalidProtocolLine;
    }
}

/// Consume one `\n`-terminated line from `remaining`, trim like multistream-select, enforce `max_body_len`.
/// The line body (bytes before `\n`) may be at most `max_body_len` bytes.
pub fn readNegotiationLine(remaining: *[]const u8, max_body_len: usize) NegotiateError![]const u8 {
    const buf = remaining.*;
    for (buf, 0..) |c, i| {
        if (c == '\n') {
            if (i > max_body_len) return error.LineTooLong;
            const raw = buf[0..i];
            remaining.* = buf[i + 1 ..];
            return ms.trimNegotiationLine(raw);
        }
    }
    if (buf.len > max_body_len) return error.LineTooLong;
    return error.MissingNewline;
}

fn appendMultistreamHeader(write: *std.ArrayList(u8), allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
    try write.appendSlice(allocator, ms.multistream_1_0_0);
}

fn appendProtocolLine(write: *std.ArrayList(u8), allocator: std.mem.Allocator, protocol_id: []const u8) (NegotiateError || std.mem.Allocator.Error)!void {
    try validateProtocolId(protocol_id);
    try write.appendSlice(allocator, protocol_id);
    try write.append(allocator, '\n');
}

/// Append the initiator's first message: `/multistream/1.0.0\n`.
pub fn initiatorSendMultistreamHeader(write: *std.ArrayList(u8), allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
    try appendMultistreamHeader(write, allocator);
}

/// After the peer's multistream header is available in `remaining`, verify it and consume it.
pub fn initiatorReadPeerMultistream(remaining: *[]const u8, max_body_len: usize) NegotiateError!void {
    const line = try readNegotiationLine(remaining, max_body_len);
    if (!std.mem.eql(u8, line, multistreamVersionLine())) return error.InvalidMultistreamVersion;
}

/// Append the desired protocol id (with `\n`).
pub fn initiatorSendProtocol(write: *std.ArrayList(u8), allocator: std.mem.Allocator, protocol_id: []const u8) (NegotiateError || std.mem.Allocator.Error)!void {
    try appendProtocolLine(write, allocator, protocol_id);
}

/// Read the responder's answer: same protocol id, or `na` (not available).
pub fn initiatorReadProtocolAck(remaining: *[]const u8, expected_protocol: []const u8, max_body_len: usize) NegotiateError!void {
    try validateProtocolId(expected_protocol);
    const line = try readNegotiationLine(remaining, max_body_len);
    if (std.mem.eql(u8, line, "na")) return error.ProtocolNotSupported;
    if (!std.mem.eql(u8, line, expected_protocol)) return error.ProtocolNotSupported;
}

// ── Responder (listener) side ───────────────────────────────────────────────

/// Read initiator's `/multistream/1.0.0\n` and consume it.
pub fn responderReadMultistreamOffer(remaining: *[]const u8, max_body_len: usize) NegotiateError!void {
    const line = try readNegotiationLine(remaining, max_body_len);
    if (!std.mem.eql(u8, line, multistreamVersionLine())) return error.InvalidMultistreamVersion;
}

/// Respond with `/multistream/1.0.0\n`.
pub fn responderSendMultistreamHeader(write: *std.ArrayList(u8), allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
    try appendMultistreamHeader(write, allocator);
}

/// Read the protocol the initiator requests.
pub fn responderReadProtocolOffer(remaining: *[]const u8, max_body_len: usize) NegotiateError![]const u8 {
    const line = try readNegotiationLine(remaining, max_body_len);
    try validateProtocolId(line);
    return line;
}

/// Reply with the same protocol line if supported, otherwise `na\n`.
pub fn responderReplyProtocol(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    offered: []const u8,
    supported: []const u8,
) (NegotiateError || std.mem.Allocator.Error)!void {
    try validateProtocolId(offered);
    try validateProtocolId(supported);
    if (std.mem.eql(u8, offered, supported)) {
        try appendProtocolLine(write, allocator, offered);
    } else {
        try write.appendSlice(allocator, "na\n");
    }
}

/// Reply with the offered protocol line if it appears in `candidates`, otherwise `na\n`.
/// Returns the index in `candidates` when acknowledged, or `null` when `na` was sent.
pub fn responderReplyProtocolAmong(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    offered: []const u8,
    candidates: []const []const u8,
) (NegotiateError || std.mem.Allocator.Error)!?usize {
    try validateProtocolId(offered);
    for (candidates, 0..) |p, i| {
        try validateProtocolId(p);
        if (std.mem.eql(u8, offered, p)) {
            try appendProtocolLine(write, allocator, offered);
            return i;
        }
    }
    try write.appendSlice(allocator, "na\n");
    return null;
}

test "responderReplyProtocolAmong picks first match" {
    const a = std.testing.allocator;
    var w = std.ArrayList(u8).empty;
    defer w.deinit(a);
    const cands: []const []const u8 = &.{ "/foo/a", "/foo/b" };
    try std.testing.expectEqual(@as(?usize, 0), try responderReplyProtocolAmong(&w, a, "/foo/a", cands));
    try std.testing.expectEqualStrings("/foo/a\n", w.items);
}

test "responderReplyProtocolAmong sends na when no match" {
    const a = std.testing.allocator;
    var w = std.ArrayList(u8).empty;
    defer w.deinit(a);
    const cands: []const []const u8 = &.{ "/foo/a", "/foo/b" };
    try std.testing.expectEqual(@as(?usize, null), try responderReplyProtocolAmong(&w, a, "/other", cands));
    try std.testing.expectEqualStrings("na\n", w.items);
}

test "readNegotiationLine happy" {
    const rem: []const u8 = "/foo/bar\nleftover";
    var p: []const u8 = rem;
    const line = try readNegotiationLine(&p, default_max_body_len);
    try std.testing.expectEqualStrings("/foo/bar", line);
    try std.testing.expectEqualStrings("leftover", p);
}

test "readNegotiationLine trim and cr" {
    const rem: []const u8 = "  /p  \r\n";
    var p = rem;
    const line = try readNegotiationLine(&p, default_max_body_len);
    try std.testing.expectEqualStrings("/p", line);
    try std.testing.expectEqual(@as(usize, 0), p.len);
}

test "readNegotiationLine line too long" {
    var buf: [default_max_body_len + 3]u8 = undefined;
    // Body length default_max_body_len + 1 then newline → exceeds cap.
    @memset(buf[0 .. default_max_body_len + 2], 'a');
    buf[default_max_body_len + 2] = '\n';
    var p: []const u8 = buf[0 .. default_max_body_len + 3];
    try std.testing.expectError(error.LineTooLong, readNegotiationLine(&p, default_max_body_len));
}

test "readNegotiationLine missing newline" {
    var p: []const u8 = "no-newline";
    try std.testing.expectError(error.MissingNewline, readNegotiationLine(&p, default_max_body_len));
}

test "validateProtocolId rejects control" {
    try std.testing.expectError(error.InvalidProtocolLine, validateProtocolId("\x01"));
    try std.testing.expectError(error.InvalidProtocolLine, validateProtocolId(""));
}

fn compactAfterRead(list: *std.ArrayList(u8), allocator: std.mem.Allocator, tail: []const u8) std.mem.Allocator.Error!void {
    list.clearRetainingCapacity();
    try list.appendSlice(allocator, tail);
}

test "full handshake initiator as client quic-v1" {
    const a = std.testing.allocator;
    var to_server = std.ArrayList(u8).empty;
    defer to_server.deinit(a);
    var to_client = std.ArrayList(u8).empty;
    defer to_client.deinit(a);

    const proto = @import("quic_v1.zig").multistream_protocol_id;

    try initiatorSendMultistreamHeader(&to_server, a);

    var rs: []const u8 = to_server.items;
    try responderReadMultistreamOffer(&rs, default_max_body_len);
    try compactAfterRead(&to_server, a, rs);

    try responderSendMultistreamHeader(&to_client, a);

    var rc: []const u8 = to_client.items;
    try initiatorReadPeerMultistream(&rc, default_max_body_len);
    try compactAfterRead(&to_client, a, rc);

    try initiatorSendProtocol(&to_server, a, proto);
    rs = to_server.items;
    const offered = try responderReadProtocolOffer(&rs, default_max_body_len);
    // Assert and consume before `compactAfterRead` — the helper reallocates
    // `to_server`'s backing buffer, which would dangle `offered` if used after.
    try std.testing.expectEqualStrings(proto, offered);
    try responderReplyProtocol(&to_client, a, offered, proto);
    try compactAfterRead(&to_server, a, rs);

    rc = to_client.items;
    try initiatorReadProtocolAck(&rc, proto, default_max_body_len);
    try compactAfterRead(&to_client, a, rc);
}

test "responder rejects unknown protocol with na" {
    const a = std.testing.allocator;
    var to_server = std.ArrayList(u8).empty;
    defer to_server.deinit(a);
    var to_client = std.ArrayList(u8).empty;
    defer to_client.deinit(a);

    try initiatorSendMultistreamHeader(&to_server, a);
    var rs: []const u8 = to_server.items;
    try responderReadMultistreamOffer(&rs, default_max_body_len);
    try compactAfterRead(&to_server, a, rs);

    try responderSendMultistreamHeader(&to_client, a);

    var rc: []const u8 = to_client.items;
    try initiatorReadPeerMultistream(&rc, default_max_body_len);
    try compactAfterRead(&to_client, a, rc);

    try initiatorSendProtocol(&to_server, a, "/unknown/proto");
    rs = to_server.items;
    const offered = try responderReadProtocolOffer(&rs, default_max_body_len);
    try compactAfterRead(&to_server, a, rs);
    try responderReplyProtocol(&to_client, a, offered, "/quic-v1");

    rc = to_client.items;
    try std.testing.expectError(error.ProtocolNotSupported, initiatorReadProtocolAck(&rc, "/unknown/proto", default_max_body_len));
}

test "wrong multistream version from peer" {
    const a = std.testing.allocator;
    var to_client = std.ArrayList(u8).empty;
    defer to_client.deinit(a);
    try to_client.appendSlice(a, "/multistream/2.0.0\n");

    var rc: []const u8 = to_client.items;
    try std.testing.expectError(error.InvalidMultistreamVersion, initiatorReadPeerMultistream(&rc, default_max_body_len));
}
