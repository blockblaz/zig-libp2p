//! DHT client vs server mode (#93).
//!
//! Server-mode nodes accept inbound kad streams and are added to routing tables.
//! Client-mode nodes query only (typical for NATed peers per AutoNAT).

const autonat = @import("../autonat/root.zig");

pub const Mode = enum {
    client,
    server,
};

pub fn fromNatStatus(status: autonat.NatStatus) Mode {
    return switch (status) {
        .public => .server,
        .private, .unknown => .client,
    };
}

test "mode from autonat status" {
    try @import("std").testing.expect(fromNatStatus(.public) == .server);
    try @import("std").testing.expect(fromNatStatus(.private) == .client);
}
