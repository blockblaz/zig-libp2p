//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./primitives/varint.zig");

pub const DecodeError = _shim_src.DecodeError;
pub const append = _shim_src.append;
pub const decode = _shim_src.decode;
pub const decodeAt = _shim_src.decodeAt;
pub const decodeAtRelaxed = _shim_src.decodeAtRelaxed;
pub const decodeNonNegativeI32 = _shim_src.decodeNonNegativeI32;
pub const decodeRelaxed = _shim_src.decodeRelaxed;
pub const encode = _shim_src.encode;
pub const encodeToScratch = _shim_src.encodeToScratch;
pub const encodedLen = _shim_src.encodedLen;
pub const max_encoding_bytes = _shim_src.max_encoding_bytes;
pub const max_len = _shim_src.max_len;
