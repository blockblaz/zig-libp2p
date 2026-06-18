//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./primitives/multistream.zig");

pub const ProtocolLineError = _shim_src.ProtocolLineError;
pub const max_protocol_id_body_bytes = _shim_src.max_protocol_id_body_bytes;
pub const multistream_1_0_0 = _shim_src.multistream_1_0_0;
pub const trimNegotiationLine = _shim_src.trimNegotiationLine;
pub const writeProtocolLine = _shim_src.writeProtocolLine;
pub const writeProtocolLineWithMax = _shim_src.writeProtocolLineWithMax;
