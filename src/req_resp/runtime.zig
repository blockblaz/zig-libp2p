//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/req_resp/runtime.zig");

pub const Error = _shim_src.Error;
pub const ReqResp = _shim_src.ReqResp;
pub const ReqRespConfig = _shim_src.ReqRespConfig;
