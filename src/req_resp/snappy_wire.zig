//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/req_resp/snappy_wire.zig");

pub const FrameError = _shim_src.FrameError;
pub const ReqRespError = _shim_src.ReqRespError;
pub const WireError = _shim_src.WireError;
pub const buildRequestWire = _shim_src.buildRequestWire;
pub const buildResponseWire = _shim_src.buildResponseWire;
pub const compressBlock = _shim_src.compressBlock;
pub const compressFramed = _shim_src.compressFramed;
pub const decodeRequestSsz = _shim_src.decodeRequestSsz;
pub const decodeResponseSsz = _shim_src.decodeResponseSsz;
pub const decompressBlock = _shim_src.decompressBlock;
pub const decompressFramed = _shim_src.decompressFramed;
pub const decompressFramedMax = _shim_src.decompressFramedMax;
