//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./protocols/ping/ping.zig");

pub const Ping = _shim_src.Ping;
pub const PingConfig = _shim_src.PingConfig;
pub const PingPoll = _shim_src.PingPoll;
pub const WireError = _shim_src.WireError;
pub const default_interval_ms = _shim_src.default_interval_ms;
pub const default_max_missed_pings = _shim_src.default_max_missed_pings;
pub const default_timeout_ms = _shim_src.default_timeout_ms;
pub const handleInbound = _shim_src.handleInbound;
pub const handleInboundPrefixed = _shim_src.handleInboundPrefixed;
pub const initiatorRoundTripMs = _shim_src.initiatorRoundTripMs;
pub const multistream_protocol_id = _shim_src.multistream_protocol_id;
pub const payload_len = _shim_src.payload_len;
pub const protocol_line = _shim_src.protocol_line;
pub const randomPayload = _shim_src.randomPayload;
pub const readPayload = _shim_src.readPayload;
pub const writePayload = _shim_src.writePayload;
