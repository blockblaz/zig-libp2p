//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/req_resp/wire_framing.zig");

pub const ExchangeLimits = _shim_src.ExchangeLimits;
pub const FramingError = _shim_src.FramingError;
pub const UnaryResponse = _shim_src.UnaryResponse;
pub const initiatorReadResponsesAfterHandshake = _shim_src.initiatorReadResponsesAfterHandshake;
pub const initiatorUnaryAfterHandshake = _shim_src.initiatorUnaryAfterHandshake;
pub const readOneUnaryRequest = _shim_src.readOneUnaryRequest;
pub const readOneUnaryResponse = _shim_src.readOneUnaryResponse;
pub const responderUnarySequenceAfterHandshake = _shim_src.responderUnarySequenceAfterHandshake;
pub const writeUnaryRequestFlush = _shim_src.writeUnaryRequestFlush;
