//! Multistream-select 1.0.0 negotiation on a byte stream (e.g. first QUIC bidi stream).
//!
//! All reads are **bounded** by `max_body_len` (maximum bytes before `\n`, excluding the newline)
//! so a peer cannot force unbounded buffering.

const std = @import("std");
const ms = @import("../multistream.zig");
const proto_wire = @import("../protobuf/wire.zig");

/// go-multistream v0.5+ length-prefixes each token as `uvarint(len+1) + token + '\n'`.
/// Legacy libp2p stacks use bare `token + '\n'` lines only.
pub const Framing = enum {
    legacy,
    delimited,
};

pub fn detectFraming(first_byte: u8) Framing {
    return if (first_byte == '/') .legacy else .delimited;
}

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

fn readDelimitedToken(remaining: *[]const u8, max_body_len: usize) NegotiateError![]const u8 {
    const len_dec = proto_wire.decodeVarUInt64(remaining.*) catch return error.InvalidProtocolLine;
    remaining.* = remaining.*[len_dec.len..];
    const total_len = len_dec.value;
    if (total_len == 0) return error.InvalidProtocolLine;
    if (total_len > max_body_len + 1) return error.LineTooLong;
    if (remaining.len < total_len) return error.MissingNewline;
    const chunk = remaining.*[0..total_len];
    remaining.* = remaining.*[total_len..];
    if (chunk[chunk.len - 1] != '\n') return error.MissingNewline;
    const body = chunk[0 .. chunk.len - 1];
    if (body.len > max_body_len) return error.LineTooLong;
    return ms.trimNegotiationLine(body);
}

/// Read one negotiation token using the given framing.
pub fn readNegotiationTokenFramed(remaining: *[]const u8, max_body_len: usize, framing: Framing) NegotiateError![]const u8 {
    if (remaining.*.len == 0) return error.MissingNewline;
    return switch (framing) {
        .legacy => readNegotiationLine(remaining, max_body_len),
        .delimited => readDelimitedToken(remaining, max_body_len),
    };
}

/// Auto-detect framing from the first byte (legacy lines start with `/`,
/// legacy `na` starts with `n`) and read one token.
///
/// CAUTION: the `/` heuristic collides with delimited framing whenever the
/// varint length byte happens to equal 0x2F = '/' — i.e. a token whose total
/// wire length is 47 bytes. Many lean / Ethereum consensus protocol ids hit
/// this exactly (`/leanconsensus/req/blocks_by_root/1/ssz_snappy` and
/// `/leanconsensus/req/blocks_by_range/1/ssz_snappy` are both 46-byte bodies
/// + `\n` = 47). Only use this when the framing is genuinely unknown — i.e.
/// for the very first token on a stream. After the multistream offer has
/// been parsed, the framing is known and [`readNegotiationTokenFramed`]
/// must be used instead.
pub fn readNegotiationToken(remaining: *[]const u8, max_body_len: usize) NegotiateError![]const u8 {
    if (remaining.*.len == 0) return error.MissingNewline;
    if (remaining.*[0] == '/' or std.mem.startsWith(u8, remaining.*, "na")) {
        return readNegotiationLine(remaining, max_body_len);
    }
    return readDelimitedToken(remaining, max_body_len);
}

fn appendDelimitedToken(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    token: []const u8,
) (NegotiateError || std.mem.Allocator.Error)!void {
    try validateProtocolId(token);
    try proto_wire.appendVarUInt64(write, allocator, token.len + 1);
    try write.appendSlice(allocator, token);
    try write.append(allocator, '\n');
}

fn appendNegotiationToken(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    token: []const u8,
    framing: Framing,
) (NegotiateError || std.mem.Allocator.Error)!void {
    return switch (framing) {
        .legacy => appendProtocolLine(write, allocator, token),
        .delimited => appendDelimitedToken(write, allocator, token),
    };
}

fn appendMultistreamHeader(write: *std.ArrayList(u8), allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
    try write.appendSlice(allocator, ms.multistream_1_0_0);
}

fn appendProtocolLine(write: *std.ArrayList(u8), allocator: std.mem.Allocator, protocol_id: []const u8) (NegotiateError || std.mem.Allocator.Error)!void {
    try validateProtocolId(protocol_id);
    try write.appendSlice(allocator, protocol_id);
    try write.append(allocator, '\n');
}

/// Append the initiator's first message: `/multistream/1.0.0\n` (legacy) or delimited equivalent.
pub fn initiatorSendMultistreamHeader(write: *std.ArrayList(u8), allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
    try appendMultistreamHeader(write, allocator);
}

pub fn initiatorSendMultistreamHeaderFramed(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    framing: Framing,
) (NegotiateError || std.mem.Allocator.Error)!void {
    try appendNegotiationToken(write, allocator, multistreamVersionLine(), framing);
}

/// After the peer's multistream header is available in `remaining`, verify it and consume it.
pub fn initiatorReadPeerMultistream(remaining: *[]const u8, max_body_len: usize) NegotiateError!void {
    const line = try readNegotiationToken(remaining, max_body_len);
    if (!std.mem.eql(u8, line, multistreamVersionLine())) return error.InvalidMultistreamVersion;
}

/// Append the desired protocol id (with `\n` or delimited framing).
pub fn initiatorSendProtocol(write: *std.ArrayList(u8), allocator: std.mem.Allocator, protocol_id: []const u8) (NegotiateError || std.mem.Allocator.Error)!void {
    try appendProtocolLine(write, allocator, protocol_id);
}

pub fn initiatorSendProtocolFramed(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol_id: []const u8,
    framing: Framing,
) (NegotiateError || std.mem.Allocator.Error)!void {
    try appendNegotiationToken(write, allocator, protocol_id, framing);
}

/// Read the responder's answer: same protocol id, or `na` (not available).
pub fn initiatorReadProtocolAck(remaining: *[]const u8, expected_protocol: []const u8, max_body_len: usize) NegotiateError!void {
    try validateProtocolId(expected_protocol);
    const line = try readNegotiationToken(remaining, max_body_len);
    if (std.mem.eql(u8, line, "na")) return error.ProtocolNotSupported;
    if (!std.mem.eql(u8, line, expected_protocol)) return error.ProtocolNotSupported;
}

/// Read the responder's answer using the negotiated framing.
pub fn initiatorReadProtocolAckFramed(remaining: *[]const u8, expected_protocol: []const u8, max_body_len: usize, framing: Framing) NegotiateError!void {
    try validateProtocolId(expected_protocol);
    const line = try readNegotiationTokenFramed(remaining, max_body_len, framing);
    if (std.mem.eql(u8, line, "na")) return error.ProtocolNotSupported;
    if (!std.mem.eql(u8, line, expected_protocol)) return error.ProtocolNotSupported;
}

// ── Responder (listener) side ───────────────────────────────────────────────

/// Read initiator's `/multistream/1.0.0\n` and consume it.
pub fn responderReadMultistreamOffer(remaining: *[]const u8, max_body_len: usize) NegotiateError!void {
    const line = try readNegotiationToken(remaining, max_body_len);
    if (!std.mem.eql(u8, line, multistreamVersionLine())) return error.InvalidMultistreamVersion;
}

/// Respond with `/multistream/1.0.0\n` (legacy) or delimited equivalent.
pub fn responderSendMultistreamHeader(write: *std.ArrayList(u8), allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
    try appendMultistreamHeader(write, allocator);
}

pub fn responderSendMultistreamHeaderFramed(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    framing: Framing,
) (NegotiateError || std.mem.Allocator.Error)!void {
    try appendNegotiationToken(write, allocator, multistreamVersionLine(), framing);
}

/// Read the protocol the initiator requests, auto-detecting framing.
///
/// Prefer [`responderReadProtocolOfferFramed`] once the multistream offer
/// has been parsed and the framing is known; auto-detect is unsafe for
/// 46-byte protocol ids (see [`readNegotiationToken`]).
pub fn responderReadProtocolOffer(remaining: *[]const u8, max_body_len: usize) NegotiateError![]const u8 {
    const line = try readNegotiationToken(remaining, max_body_len);
    try validateProtocolId(line);
    return line;
}

/// Read the protocol the initiator requests using the negotiated framing.
pub fn responderReadProtocolOfferFramed(remaining: *[]const u8, max_body_len: usize, framing: Framing) NegotiateError![]const u8 {
    const line = try readNegotiationTokenFramed(remaining, max_body_len, framing);
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

pub fn responderReplyProtocolFramed(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    offered: []const u8,
    supported: []const u8,
    framing: Framing,
) (NegotiateError || std.mem.Allocator.Error)!void {
    try validateProtocolId(offered);
    try validateProtocolId(supported);
    if (std.mem.eql(u8, offered, supported)) {
        try appendNegotiationToken(write, allocator, offered, framing);
    } else {
        try appendNegotiationToken(write, allocator, "na", framing);
    }
}

pub fn responderReplyProtocolAmongFramed(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    offered: []const u8,
    candidates: []const []const u8,
    framing: Framing,
) (NegotiateError || std.mem.Allocator.Error)!?usize {
    try validateProtocolId(offered);
    for (candidates, 0..) |p, i| {
        try validateProtocolId(p);
        if (std.mem.eql(u8, offered, p)) {
            try appendNegotiationToken(write, allocator, offered, framing);
            return i;
        }
    }
    try appendNegotiationToken(write, allocator, "na", framing);
    return null;
}

test "readDelimitedToken go-multistream wire" {
    // uvarint(19) + "/multistream/1.0.0" + '\n' — go-libp2p v0.5 framing.
    const wire = [_]u8{ 0x13, '/', 'm', 'u', 'l', 't', 'i', 's', 't', 'r', 'e', 'a', 'm', '/', '1', '.', '0', '.', '0', '\n' };
    var rem: []const u8 = &wire;
    const tok = try readDelimitedToken(&rem, default_max_body_len);
    try std.testing.expectEqualStrings("/multistream/1.0.0", tok);
    try std.testing.expect(rem.len == 0);
}

test "responderReplyProtocolAmongFramed delimited" {
    const a = std.testing.allocator;
    var w = std.ArrayList(u8).empty;
    defer w.deinit(a);
    const cands: []const []const u8 = &.{ "/ipfs/id/1.0.0", "/ipfs/ping/1.0.0" };
    try std.testing.expectEqual(@as(?usize, 0), try responderReplyProtocolAmongFramed(&w, a, "/ipfs/id/1.0.0", cands, .delimited));
    try std.testing.expectEqual(@as(usize, 0x0f), w.items[0]); // uvarint(15) for "/ipfs/id/1.0.0\n"
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
