//! Multistream-select for [`libp2p_noise.multistream_protocol_id`] then Noise XX + identity handshake.
//!
//! Kept separate from [`libp2p_noise.zig`] so this module can import [`transport/stream_multistream.zig`]
//! without a circular dependency with [`transport/transport_error.zig`] (which already imports `libp2p_noise`).

const std = @import("std");
const pid = @import("peer_id");
const errors = @import("../../errors.zig");
const keypair = @import("../../keypair.zig");
const sm = @import("../../transport/stream_multistream.zig");
const noise = @import("libp2p_noise.zig");

pub const UpgradeError = sm.StreamHandshakeError || noise.Error;

/// Lossy map for embedders that only surface [`errors.TransportError`] (plus OOM).
pub fn toTransportError(err: UpgradeError) (errors.TransportError || std.mem.Allocator.Error) {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.DialFailed => error.DialFailed,
        error.Unreachable => error.Unreachable,
        error.ProtocolNegotiationFailed => error.ProtocolNegotiationFailed,
        error.SecurityUpgradeFailed => error.SecurityUpgradeFailed,
        error.ReadFailed, error.WriteFailed => error.DialFailed,
        error.EndOfStream => error.DialFailed,
        else => error.SecurityUpgradeFailed,
    };
}

/// Initiator: multistream `/noise`, then [`noise.handshakeInitiator`].
pub fn negotiateInitiator(
    allocator: std.mem.Allocator,
    io: std.Io,
    prologue: []const u8,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    host: keypair.KeyPair,
    noise_static: std.crypto.dh.X25519.KeyPair,
    stream_muxers: []const []const u8,
    expected_remote: ?pid.PeerId,
    scratch: []u8,
    payload_scratch: []u8,
    mux_list: *std.ArrayList([]const u8),
) UpgradeError!noise.HandshakeResult {
    try sm.initiatorHandshakeMultistream(r, w, noise.multistream_protocol_id, allocator);
    return try noise.handshakeInitiator(
        allocator,
        io,
        prologue,
        r,
        w,
        host,
        noise_static,
        stream_muxers,
        expected_remote,
        scratch,
        payload_scratch,
        mux_list,
    );
}

/// Responder: multistream `/noise`, then [`noise.handshakeResponder`].
pub fn negotiateResponder(
    allocator: std.mem.Allocator,
    io: std.Io,
    prologue: []const u8,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    host: keypair.KeyPair,
    noise_static: std.crypto.dh.X25519.KeyPair,
    stream_muxers: []const []const u8,
    expected_remote: ?pid.PeerId,
    scratch: []u8,
    payload_scratch: []u8,
    mux_list: *std.ArrayList([]const u8),
) UpgradeError!noise.HandshakeResult {
    try sm.responderHandshakeMultistream(r, w, noise.multistream_protocol_id, allocator);
    return try noise.handshakeResponder(
        allocator,
        io,
        prologue,
        r,
        w,
        host,
        noise_static,
        stream_muxers,
        expected_remote,
        scratch,
        payload_scratch,
        mux_list,
    );
}

test "/noise protocol id valid for multistream-select" {
    const neg = @import("../../transport/multistream_negotiate.zig");
    try neg.validateProtocolId(noise.multistream_protocol_id);
}

test "toTransportError maps negotiation failure" {
    try std.testing.expectEqual(
        errors.TransportError.ProtocolNegotiationFailed,
        toTransportError(error.ProtocolNegotiationFailed),
    );
}
