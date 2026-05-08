//! Event-shaped error carriers for embedder loops (#45): `kind` fields use layered error sets so
//! callers can `switch` without `anyerror`.

const std = @import("std");
const errors = @import("errors.zig");

/// Req/resp (or stream codec) failure surfaced as an event.
pub const ReqRespFailure = struct {
    kind: errors.ReqRespError,
};

/// Gossipsub codec / mesh reservation failure surfaced as an event.
pub const GossipsubFailure = struct {
    kind: errors.GossipsubError,
};

/// Transport dial / listen / security / QUIC mapping failure surfaced as an event.
pub const TransportFailure = struct {
    kind: errors.TransportError,
};

test "req resp failure kind is switchable" {
    const e: ReqRespFailure = .{ .kind = error.InvalidData };
    switch (e.kind) {
        error.InvalidData => {},
        else => try std.testing.expect(false),
    }
}
