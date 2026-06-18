//! Circuit-relay multiaddr parsing and construction (#91).
//!
//! The `multiaddr` dependency supports `.P2pCircuit` in its binary codec but
//! rejects `p2p-circuit` in `fromString`. This module splits circuit addresses
//! locally and reassembles them programmatically.

const std = @import("std");
const multiaddr = @import("multiaddr");
const identity = @import("../../primitives/identity.zig");

const protocol_iter_next_err = @typeInfo(@typeInfo(@TypeOf(multiaddr.ProtocolIterator.next)).@"fn".return_type.?).error_union.error_set;
const ma_push_err = @typeInfo(@typeInfo(@TypeOf(multiaddr.Multiaddr.push)).@"fn".return_type.?).error_union.error_set;
const ma_from_string_err = @typeInfo(@typeInfo(@TypeOf(multiaddr.Multiaddr.fromString)).@"fn".return_type.?).error_union.error_set;
const ma_to_string_err = @typeInfo(@typeInfo(@TypeOf(multiaddr.Multiaddr.toString)).@"fn".return_type.?).error_union.error_set;

pub const Error = error{
    NotCircuitAddress,
    MissingRelayPeer,
    MissingTargetPeer,
    InvalidCircuitLayout,
    InvalidMultiaddr,
} || std.mem.Allocator.Error || multiaddr.multiaddr.Error || protocol_iter_next_err || ma_push_err || ma_from_string_err || ma_to_string_err;

pub const RelayedAddr = struct {
    /// Relay transport address including trailing `/p2p/<relay-id>`.
    relay_ma: multiaddr.Multiaddr,
    relay_id: identity.PeerId,
    target_id: identity.PeerId,

    pub fn deinit(self: *RelayedAddr) void {
        self.relay_ma.deinit();
        self.* = undefined;
    }

    /// Build `/…/p2p/<relay>/p2p-circuit/p2p/<target>` from parts.
    pub fn build(
        allocator: std.mem.Allocator,
        relay_ma: *const multiaddr.Multiaddr,
        target_id: identity.PeerId,
    ) Error!multiaddr.Multiaddr {
        var out = multiaddr.Multiaddr.init(allocator);
        errdefer out.deinit();
        var iter = relay_ma.iterator();
        while (try iter.next()) |proto| {
            try out.push(proto);
        }
        try out.push(.P2pCircuit);
        try out.push(.{ .P2P = target_id });
        return out;
    }

    pub fn toString(self: *const RelayedAddr, allocator: std.mem.Allocator) Error![]u8 {
        var ma = try build(allocator, &self.relay_ma, self.target_id);
        defer ma.deinit();
        return try ma.toString(allocator);
    }
};

/// Returns true when `ma` contains a `/p2p-circuit` component.
pub fn isCircuit(ma: *const multiaddr.Multiaddr) bool {
    var iter = ma.iterator();
    while (iter.next()) |maybe_proto| {
        const proto = maybe_proto orelse break;
        if (proto == .P2pCircuit) return true;
    } else |_| return false;
    return false;
}

/// Split a binary multiaddr at the first `/p2p-circuit` marker.
pub fn splitCircuit(allocator: std.mem.Allocator, ma: *const multiaddr.Multiaddr) Error!RelayedAddr {
    var relay_part = multiaddr.Multiaddr.init(allocator);
    errdefer relay_part.deinit();
    var saw_circuit = false;
    var relay_id: ?identity.PeerId = null;
    var target_id: ?identity.PeerId = null;

    var iter = ma.iterator();
    while (try iter.next()) |proto| {
        if (proto == .P2pCircuit) {
            saw_circuit = true;
            continue;
        }
        if (!saw_circuit) {
            switch (proto) {
                .P2P => |id| relay_id = id,
                else => try relay_part.push(proto),
            }
        } else {
            switch (proto) {
                .P2P => |id| {
                    if (target_id != null) return error.InvalidCircuitLayout;
                    target_id = id;
                },
                else => return error.InvalidCircuitLayout,
            }
        }
    }
    if (!saw_circuit) return error.NotCircuitAddress;
    const r_id = relay_id orelse return error.MissingRelayPeer;
    const t_id = target_id orelse return error.MissingTargetPeer;
    return .{
        .relay_ma = relay_part,
        .relay_id = r_id,
        .target_id = t_id,
    };
}

const circuit_token = "/p2p-circuit";

/// Parse a circuit multiaddr string by splitting on `/p2p-circuit`.
pub fn fromString(allocator: std.mem.Allocator, s: []const u8) Error!RelayedAddr {
    const idx = std.mem.indexOf(u8, s, circuit_token) orelse return error.NotCircuitAddress;
    const relay_str = s[0..idx];
    const target_str = s[idx + circuit_token.len ..];
    if (target_str.len == 0 or target_str[0] != '/') return error.InvalidCircuitLayout;

    var relay_ma = try multiaddr.Multiaddr.fromString(allocator, relay_str);
    errdefer relay_ma.deinit();

    var target_ma = try multiaddr.Multiaddr.fromString(allocator, target_str);
    errdefer target_ma.deinit();

    const relay_id = peerIdFromMultiaddr(&relay_ma) orelse return error.MissingRelayPeer;
    const target_id = peerIdFromMultiaddr(&target_ma) orelse return error.MissingTargetPeer;
    target_ma.deinit();

    return .{
        .relay_ma = relay_ma,
        .relay_id = relay_id,
        .target_id = target_id,
    };
}

fn peerIdFromMultiaddr(ma: *const multiaddr.Multiaddr) ?identity.PeerId {
    var iter = ma.iterator();
    var last: ?identity.PeerId = null;
    while (iter.next()) |maybe_proto| {
        const proto = maybe_proto orelse break;
        switch (proto) {
            .P2P => |id| last = id,
            else => {},
        }
    } else |_| return null;
    return last;
}

/// Dial string for reaching the relay (transport addr without trailing `/p2p`).
pub fn relayDialString(allocator: std.mem.Allocator, relay_ma: *const multiaddr.Multiaddr) Error![]u8 {
    var out = multiaddr.Multiaddr.init(allocator);
    defer out.deinit();
    var iter = relay_ma.iterator();
    while (try iter.next()) |proto| {
        switch (proto) {
            .P2P => {},
            else => try out.push(proto),
        }
    }
    return try out.toString(allocator);
}

test "split circuit binary multiaddr round trip" {
    const a = std.testing.allocator;
    const relay_id = try identity.PeerId.random();
    const target_id = try identity.PeerId.random();
    var relay = try multiaddr.Multiaddr.fromString(a, "/ip4/203.0.113.1/udp/4001/quic-v1");
    defer relay.deinit();
    try relay.push(.{ .P2P = relay_id });
    var circuit_ma = try RelayedAddr.build(a, &relay, target_id);
    defer circuit_ma.deinit();
    try std.testing.expect(isCircuit(&circuit_ma));
    var split = try splitCircuit(a, &circuit_ma);
    defer split.deinit();
    try std.testing.expect(split.relay_id.eql(&relay_id));
    try std.testing.expect(split.target_id.eql(&target_id));
}

test "fromString splits on p2p-circuit token" {
    const a = std.testing.allocator;
    const relay_id = try identity.PeerId.random();
    const target_id = try identity.PeerId.random();
    var relay_b58: [64]u8 = undefined;
    var target_b58: [64]u8 = undefined;
    const relay_str = try relay_id.toBase58(&relay_b58);
    const target_str = try target_id.toBase58(&target_b58);
    const s = try std.fmt.allocPrint(
        a,
        "/ip4/203.0.113.1/udp/4001/quic-v1/p2p/{s}/p2p-circuit/p2p/{s}",
        .{ relay_str, target_str },
    );
    defer a.free(s);
    var parsed = try fromString(a, s);
    defer parsed.deinit();
    try std.testing.expect(parsed.relay_id.eql(&relay_id));
    try std.testing.expect(parsed.target_id.eql(&target_id));
    const dial = try relayDialString(a, &parsed.relay_ma);
    defer a.free(dial);
    try std.testing.expectEqualStrings("/ip4/203.0.113.1/udp/4001/quic-v1", dial);
}
