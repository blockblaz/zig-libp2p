//! Map `std.Io.net` and multistream-select I/O failures into [`errors.TransportError`] (#45 follow-up).

const std = @import("std");
const errors = @import("../errors.zig");
const neg = @import("multistream_negotiate.zig");
const libp2p_tls = @import("../security/libp2p_tls.zig");
const net = std.Io.net;
const Io = std.Io;

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
