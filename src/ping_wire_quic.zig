//! Ping (`/ipfs/ping/1.0.0`) on a zquic **raw** bidirectional stream after multistream-select (#37).
//!
//! Same embedding rules as [`req_resp.wire_quic`]: pump the zquic UDP receive path between reads
//! and writes so handshake and ping bytes make progress.

const std = @import("std");

const ping = @import("ping.zig");
const quic_raw_stream_io = @import("transport/quic_raw_stream_io.zig");
const stream_multistream = @import("transport/stream_multistream.zig");

const zquic = @import("zquic");
const ZIo = zquic.transport.io;

pub const WireQuicPingError = ping.WireError || stream_multistream.StreamHandshakeError;

/// Initiator: negotiate ping on an open raw bidi stream, then one ping/pong; returns RTT in ms.
pub fn initiatorPingRoundTripMs(
    allocator: std.mem.Allocator,
    client: *ZIo.Client,
    stream_id: u64,
) (WireQuicPingError || std.mem.Allocator.Error)!u64 {
    var raw = quic_raw_stream_io.RawAppBidiClient{
        .client = client,
        .stream_id = stream_id,
    };
    var r = raw.reader();
    var w = raw.writer();
    try stream_multistream.initiatorHandshakeMultistream(&r, &w, ping.multistream_protocol_id, allocator, null);
    var payload: [ping.payload_len]u8 = undefined;
    return try ping.initiatorRoundTripMs(&r, &w, &payload);
}

/// Responder: accept ping protocol on a server raw bidi stream, echo one payload.
pub fn responderHandleInbound(
    allocator: std.mem.Allocator,
    server: *ZIo.Server,
    conn: *ZIo.ConnState,
    stream_id: u64,
) (WireQuicPingError || std.mem.Allocator.Error)!void {
    var raw = quic_raw_stream_io.RawAppBidiServer{
        .server = server,
        .conn = conn,
        .stream_id = stream_id,
    };
    var r = raw.reader();
    var w = raw.writer();
    try stream_multistream.responderHandshakeMultistream(&r, &w, ping.multistream_protocol_id, allocator, null);
    try ping.handleInbound(&r, &w);
}
