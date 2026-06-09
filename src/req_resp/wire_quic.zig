//! QUIC raw **bidirectional stream** harness for Lean `ssz_snappy` req/resp (#40).
//!
//! After zquic reports `ConnState.phase == .connected`, allocate a client-initiated bidi stream with
//! [`zquic.transport.io.rawAllocateNextLocalBidiStream`], wrap it in [`transport.quic_raw_stream_io`],
//! then run the same multistream + framing as [`wire_tcp`]:
//!
//! 1. [`transport.stream_multistream.initiatorHandshakeMultistream`] or [`responderHandshakeMultistream`]
//!    on the stream [`std.Io.Reader`] / [`Writer`].
//! 2. [`wire_framing`] unary request/response helpers.
//!
//! **Embedding requirement:** zquic does not read UDP implicitly from these adapters. Between stream
//! reads and writes the embedder must run the usual zquic receive path (`feedPacket` / `processPacket`
//! / `processPendingWork`) so handshake and payload bytes actually move. TCP [`wire_tcp`] avoids this
//! because the kernel buffers the full byte stream.

const std = @import("std");
const Io = std.Io;

const errors = @import("../errors.zig");
const framing = @import("wire_framing.zig");
const stream_multistream = @import("../transport/stream_multistream.zig");
const quic_raw_stream_io = @import("../transport/quic_raw_stream_io.zig");

const zquic = @import("zquic");
const ZIo = zquic.transport.io;

pub const WireQuicError = errors.TransportError ||
    stream_multistream.StreamHandshakeError ||
    errors.ReqRespError;

pub const ExchangeLimits = framing.ExchangeLimits;

/// Initiator: multistream on an already-open raw bidi stream, then one unary request/response.
pub fn initiatorUnaryExchange(
    allocator: std.mem.Allocator,
    client: *ZIo.Client,
    stream_id: u64,
    protocol_id: []const u8,
    uncompressed_request: []const u8,
    scratch_r: []u8,
    limits: ExchangeLimits,
) (WireQuicError || std.mem.Allocator.Error)!framing.UnaryResponse {
    var raw = quic_raw_stream_io.RawAppBidiClient{
        .client = client,
        .stream_id = stream_id,
    };
    var r = raw.reader();
    var w = raw.writer();
    try stream_multistream.initiatorHandshakeMultistream(&r, &w, protocol_id, allocator, null);
    return try framing.initiatorUnaryAfterHandshake(allocator, &r, &w, scratch_r, uncompressed_request, limits);
}

/// Initiator: multistream, then one request and `count` back-to-back success responses (code 0).
pub fn initiatorReadResponseSequence(
    allocator: std.mem.Allocator,
    client: *ZIo.Client,
    stream_id: u64,
    protocol_id: []const u8,
    uncompressed_request: []const u8,
    scratch_r: []u8,
    limits: ExchangeLimits,
    count: usize,
) (WireQuicError || std.mem.Allocator.Error)![][]u8 {
    var raw = quic_raw_stream_io.RawAppBidiClient{
        .client = client,
        .stream_id = stream_id,
    };
    var r = raw.reader();
    var w = raw.writer();
    try stream_multistream.initiatorHandshakeMultistream(&r, &w, protocol_id, allocator, null);
    return try framing.initiatorReadResponsesAfterHandshake(allocator, &r, &w, scratch_r, uncompressed_request, limits, count);
}

/// Responder: multistream on the server-side raw bidi stream, then one unary read and `response_bodies`.
pub fn responderUnarySequence(
    allocator: std.mem.Allocator,
    server: *ZIo.Server,
    conn: *ZIo.ConnState,
    stream_id: u64,
    protocol_id: []const u8,
    scratch_r: []u8,
    limits: ExchangeLimits,
    response_bodies: []const []const u8,
) (WireQuicError || std.mem.Allocator.Error)![]u8 {
    var raw = quic_raw_stream_io.RawAppBidiServer{
        .server = server,
        .conn = conn,
        .stream_id = stream_id,
    };
    var r = raw.reader();
    var w = raw.writer();
    try stream_multistream.responderHandshakeMultistream(&r, &w, protocol_id, allocator, null);
    return try framing.responderUnarySequenceAfterHandshake(allocator, &r, &w, scratch_r, limits, response_bodies);
}
