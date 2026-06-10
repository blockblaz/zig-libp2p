//! Relay stream bridging helpers and circuit dial planning (#91).

const std = @import("std");
const Io = std.Io;
const identity = @import("../identity.zig");
const relay = @import("../relay/root.zig");
const bridge = @import("../relay/bridge.zig");

pub const Error = bridge.Error || relay.circuit_addr.Error || error{
    RelayDialFailed,
    InvalidCircuitAddress,
};

/// Parsed plan for dialing a peer through a circuit multiaddr.
pub const CircuitDialPlan = struct {
    relay_dial_addr: []u8,
    relay_id: identity.PeerId,
    target_id: identity.PeerId,

    pub fn deinit(self: *CircuitDialPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.relay_dial_addr);
        self.* = undefined;
    }
};

pub fn planCircuitDial(allocator: std.mem.Allocator, circuit_addr_str: []const u8) Error!CircuitDialPlan {
    var parsed = try relay.circuit_addr.fromString(allocator, circuit_addr_str);
    defer parsed.deinit();
    const dial = try relay.circuit_addr.relayDialString(allocator, &parsed.relay_ma);
    return .{
        .relay_dial_addr = dial,
        .relay_id = parsed.relay_id,
        .target_id = parsed.target_id,
    };
}

/// Pump relayed bytes between hop-side and stop-side streams until both EOF
/// or the byte budget is exhausted. Returns the number of bytes pumped this
/// call so callers can subtract from a per-bridge `data_bytes` budget.
///
/// `bytes_budget == null` means unbounded. Stops early once the cumulative
/// pumped bytes meet or exceed the budget — the caller should then tear down
/// the bridge so the partner sees the close.
pub fn bridgeStreamsUntilClosed(
    hop_r: *Io.Reader,
    hop_w: *Io.Writer,
    stop_r: *Io.Reader,
    stop_w: *Io.Writer,
    buf: []u8,
    max_rounds: usize,
    bytes_budget: ?u64,
) Error!u64 {
    var pumped: u64 = 0;
    var rounds: usize = 0;
    while (rounds < max_rounds) : (rounds += 1) {
        const a = bridge.pumpOnce(hop_r, stop_w, buf) catch |e| switch (e) {
            error.IoReadFailed, error.IoWriteFailed => break,
            else => |x| return x,
        };
        const b = bridge.pumpOnce(stop_r, hop_w, buf) catch |e| switch (e) {
            error.IoReadFailed, error.IoWriteFailed => break,
            else => |x| return x,
        };
        pumped += @as(u64, a) + @as(u64, b);
        if (a == 0 and b == 0) break;
        if (bytes_budget) |budget| {
            if (pumped >= budget) break;
        }
    }
    return pumped;
}

test "plan circuit dial strips relay transport" {
    const a = std.testing.allocator;
    const relay_id = try identity.PeerId.random();
    const target_id = try identity.PeerId.random();
    var rb: [64]u8 = undefined;
    var tb: [64]u8 = undefined;
    const rs = try relay_id.toBase58(&rb);
    const ts = try target_id.toBase58(&tb);
    const s = try std.fmt.allocPrint(a, "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/{s}/p2p-circuit/p2p/{s}", .{ rs, ts });
    defer a.free(s);
    var plan = try planCircuitDial(a, s);
    defer plan.deinit(a);
    try std.testing.expect(plan.relay_id.eql(&relay_id));
    try std.testing.expect(plan.target_id.eql(&target_id));
}
