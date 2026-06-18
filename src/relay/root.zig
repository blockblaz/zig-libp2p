//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/relay/root.zig");

pub const Client = _shim_src.Client;
pub const ClientConfig = _shim_src.ClientConfig;
pub const OpenStopFn = _shim_src.OpenStopFn;
pub const OpenStopResult = _shim_src.OpenStopResult;
pub const RelayedAddr = _shim_src.RelayedAddr;
pub const ReservationStore = _shim_src.ReservationStore;
pub const Server = _shim_src.Server;
pub const ServerConfig = _shim_src.ServerConfig;
pub const bridge = _shim_src.bridge;
pub const circuit_addr = _shim_src.circuit_addr;
pub const client = _shim_src.client;
pub const hop_protocol_id = _shim_src.hop_protocol_id;
pub const reservation = _shim_src.reservation;
pub const server = _shim_src.server;
pub const stop_protocol_id = _shim_src.stop_protocol_id;
pub const wire = _shim_src.wire;
