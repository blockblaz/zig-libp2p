//! Typed payloads for peer connection / disconnection / dial failure events (#38).

const errors = @import("errors.zig");
const identity = @import("identity.zig");

pub const Direction = enum {
    inbound,
    outbound,
};

pub const DisconnectReason = enum {
    timeout,
    remote_close,
    local_close,
    err,
};

/// Dial or transport handshake failure (distinct from [`DisconnectReason`] on an established conn).
pub const ConnectionFailureResult = union(enum) {
    timeout,
    err: errors.TransportError,
};

pub const PeerConnectedPayload = struct {
    peer: identity.PeerId,
    direction: Direction,
};

pub const PeerDisconnectedPayload = struct {
    peer: identity.PeerId,
    direction: Direction,
    reason: DisconnectReason,
};

pub const PeerConnectionFailedPayload = struct {
    peer: ?identity.PeerId,
    direction: Direction,
    result: ConnectionFailureResult,
};
