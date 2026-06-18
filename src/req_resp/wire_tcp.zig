//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/req_resp/wire_tcp.zig");

pub const ExchangeLimits = _shim_src.ExchangeLimits;
pub const WireTcpError = _shim_src.WireTcpError;
pub const initiatorReadResponseSequence = _shim_src.initiatorReadResponseSequence;
pub const initiatorUnaryExchange = _shim_src.initiatorUnaryExchange;
pub const responderUnarySequence = _shim_src.responderUnarySequence;
