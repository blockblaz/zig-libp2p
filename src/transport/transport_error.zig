//! Map `std.Io.net`, multistream-select I/O, and **zquic** failures into [`errors.TransportError`] (#45 follow-up).

const std = @import("std");
const errors = @import("../errors.zig");
const neg = @import("multistream_negotiate.zig");
const libp2p_tls = @import("../security/libp2p_tls.zig");
const zquic = @import("zquic");
const net = std.Io.net;
const Io = std.Io;

/// Errors from [`zquic.transport.io.Server.init`] / [`zquic.transport.io.Client.init`].
pub const ZquicIoSetupError = @typeInfo(
    @typeInfo(@TypeOf(zquic.transport.io.Server.init)).@"fn".return_type.?,
).error_union.error_set || @typeInfo(
    @typeInfo(@TypeOf(zquic.transport.io.Client.init)).@"fn".return_type.?,
).error_union.error_set;

/// Errors from [`zquic.transport.io.Server.run`] / [`zquic.transport.io.Client.run`].
pub const ZquicRunError = @typeInfo(
    @typeInfo(@TypeOf(zquic.transport.io.Server.run)).@"fn".return_type.?,
).error_union.error_set || @typeInfo(
    @typeInfo(@TypeOf(zquic.transport.io.Client.run)).@"fn".return_type.?,
).error_union.error_set;

pub fn fromIpConnect(err: net.IpAddress.ConnectError) errors.TransportError {
    return switch (err) {
        error.HostUnreachable,
        error.NetworkUnreachable,
        => error.Unreachable,
        else => error.DialFailed,
    };
}

pub fn fromIpListen(err: net.IpAddress.ListenError) errors.TransportError {
    return switch (err) {
        error.NetworkDown => error.Unreachable,
        else => error.DialFailed,
    };
}

pub fn fromServerAccept(err: net.Server.AcceptError) errors.TransportError {
    return switch (err) {
        error.NetworkDown => error.Unreachable,
        else => error.DialFailed,
    };
}

pub const MultistreamStreamLayerError = neg.NegotiateError || Io.Writer.Error || Io.Reader.ShortError;

/// Multistream framing / version / `na` vs protocol id, and bounded I/O during handshake.
pub fn fromMultistreamStreamLayer(err: MultistreamStreamLayerError) errors.TransportError {
    return switch (err) {
        error.ProtocolNotSupported,
        error.InvalidMultistreamVersion,
        error.InvalidProtocolLine,
        error.LineTooLong,
        error.MissingNewline,
        => error.ProtocolNegotiationFailed,
        error.ReadFailed,
        error.WriteFailed,
        => error.DialFailed,
    };
}

pub fn fromLibp2pTls(_: libp2p_tls.Error) errors.TransportError {
    return error.SecurityUpgradeFailed;
}

// ── zquic (RFC 9000 wire codes, stream limits, demo I/O setup) ─────────────

/// Opening a local stream past the peer's `MAX_STREAMS` limit (`rawAllocateNextLocalBidiStream`, etc.).
pub const ZquicOpenLocalStreamError = zquic.transport.io.OpenLocalStreamError;

pub fn fromZquicOpenLocalStream(err: ZquicOpenLocalStreamError) errors.TransportError {
    return switch (err) {
        error.StreamLimitExceeded => error.ProtocolNegotiationFailed,
    };
}

/// Maps QUIC `TRANSPORT_ERROR` wire codes (RFC 9000 §20.1) after a connection close.
pub fn fromZquicWireTransport(code: zquic.types.TransportError) errors.TransportError {
    return switch (code) {
        .no_error => error.DialFailed,
        .connection_refused => error.DialFailed,
        .no_viable_path => error.Unreachable,
        .crypto_buffer_exceeded,
        .key_update_error,
        .aead_limit_reached,
        => error.SecurityUpgradeFailed,
        .protocol_violation,
        .transport_parameter_error,
        .flow_control_error,
        .stream_limit_error,
        .stream_state_error,
        .final_size_error,
        .frame_encoding_error,
        .connection_id_limit_error,
        .invalid_token,
        => error.ProtocolNegotiationFailed,
        .internal_error,
        .application_error,
        => error.DialFailed,
        else => error.DialFailed,
    };
}

/// Lossy mapping for [`zquic.transport.io.Server.init`] / [`zquic.transport.io.Client.init`].
/// **OOM** is passed through.
pub fn fromZquicIoSetup(err: ZquicIoSetupError) (errors.TransportError || std.mem.Allocator.Error) {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.CertReadFailed,
        error.NoCertificate,
        error.NoCertEnd,
        error.MissingEndMarker,
        => error.SecurityUpgradeFailed,
        error.NetworkUnreachable,
        error.HostUnreachable,
        => error.Unreachable,
        error.AddressNotAvailable => error.Unreachable,
        error.ConnectionRefused => error.DialFailed,
        error.Timeout => error.DialFailed,
        else => error.DialFailed,
    };
}

/// Lossy mapping for [`zquic.transport.io.Server.run`] / [`zquic.transport.io.Client.run`].
pub fn fromZquicRun(err: ZquicRunError) (errors.TransportError || std.mem.Allocator.Error) {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.HandshakeTimeout => error.SecurityUpgradeFailed,
        error.HostNotFound => error.DialFailed,
        error.NetworkUnreachable,
        error.HostUnreachable,
        => error.Unreachable,
        error.AddressNotAvailable => error.Unreachable,
        error.ConnectionRefused => error.DialFailed,
        error.Timeout => error.DialFailed,
        else => error.DialFailed,
    };
}

test "fromZquicWireTransport maps connection_refused" {
    try std.testing.expect(fromZquicWireTransport(.connection_refused) == error.DialFailed);
}

test "fromZquicOpenLocalStream maps stream limit" {
    try std.testing.expect(fromZquicOpenLocalStream(error.StreamLimitExceeded) == error.ProtocolNegotiationFailed);
}

test "fromZquicIoSetup typed cert failure" {
    try std.testing.expect(fromZquicIoSetup(error.CertReadFailed) == error.SecurityUpgradeFailed);
}
