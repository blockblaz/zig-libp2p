//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/req_resp/frame.zig");

pub const FrameError = _shim_src.FrameError;
pub const appendRequestPrefix = _shim_src.appendRequestPrefix;
pub const appendResponsePrefix = _shim_src.appendResponsePrefix;
pub const max_rpc_message_size = _shim_src.max_rpc_message_size;
pub const max_stream_accumulated_bytes = _shim_src.max_stream_accumulated_bytes;
pub const parseRequestHeader = _shim_src.parseRequestHeader;
pub const parseResponseHeader = _shim_src.parseResponseHeader;
