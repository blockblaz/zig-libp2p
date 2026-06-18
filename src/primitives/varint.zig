//! Backward-compatible re-export of the unsigned varint codec from
//! [`zig-varint`](https://github.com/ch4r10t33r/zig-varint).
//!
//! The actual implementation lives in `zig_varint.unsigned`; this file keeps
//! the previous in-tree symbol names so existing call sites
//! (`varint.encodeToScratch`, `varint.decode`, `varint.DecodeError`,
//! `varint.max_encoding_bytes`) compile unchanged.

const unsigned = @import("zig_varint").unsigned;

pub const max_encoding_bytes = unsigned.max_encoding_bytes;
pub const max_len = unsigned.max_len;
pub const DecodeError = unsigned.DecodeError;

pub const encodeToScratch = unsigned.encodeToScratch;
pub const encode = unsigned.encode;
pub const encodedLen = unsigned.encodedLen;
pub const append = unsigned.append;
pub const decode = unsigned.decode;
pub const decodeRelaxed = unsigned.decodeRelaxed;
pub const decodeAt = unsigned.decodeAt;
pub const decodeAtRelaxed = unsigned.decodeAtRelaxed;
pub const decodeNonNegativeI32 = unsigned.decodeNonNegativeI32;

test {
    _ = unsigned;
}
