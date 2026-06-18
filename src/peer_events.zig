//! Typed payloads for peer connection / disconnection / dial failure events (#38).

const errors = @import("errors.zig");
const identity = @import("identity.zig");

pub const Direction = enum {
    inbound,
    outbound,
    /// Transport has not classified direction yet (#38).
    unknown,
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
    /// True when the session rides a circuit-relay v2 hop (#205).
    via_relay: bool = false,
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

pub const DiscoverySource = enum {
    mdns,
    rendezvous,
};

pub const PeerDiscoveredPayload = struct {
    peer: identity.PeerId,
    addrs: [][]const u8,
    source: DiscoverySource,
    /// Rendezvous namespace when [`source`] is `.rendezvous` (#209).
    namespace: ?[]const u8 = null,
};
