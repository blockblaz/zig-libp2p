//! Circuit Relay v2 — reservation, hop/stop bridging (#91).
//!
//! Spec: https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md

pub const wire = @import("wire.zig");
pub const circuit_addr = @import("circuit_addr.zig");
pub const reservation = @import("reservation.zig");
pub const bridge = @import("bridge.zig");
pub const server = @import("server.zig");
pub const client = @import("client.zig");

pub const Server = server.Server;
pub const ServerConfig = server.Config;
pub const Client = client.Client;
pub const ClientConfig = client.Config;
pub const OpenStopFn = server.OpenStopFn;
pub const OpenStopResult = server.OpenStopResult;
pub const RelayedAddr = circuit_addr.RelayedAddr;
pub const ReservationStore = reservation.Store;

pub const hop_protocol_id = wire.hop_protocol_id;
pub const stop_protocol_id = wire.stop_protocol_id;

test {
    _ = @import("wire.zig");
    _ = @import("circuit_addr.zig");
    _ = @import("reservation.zig");
    _ = @import("bridge.zig");
    _ = @import("server.zig");
    _ = @import("client.zig");
    _ = @import("scenario.zig");
}
