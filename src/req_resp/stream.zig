//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/req_resp/stream.zig");

pub const FrameError = _shim_src.FrameError;
pub const InboundBuffer = _shim_src.InboundBuffer;
pub const PoppedRequest = _shim_src.PoppedRequest;
pub const PoppedResponse = _shim_src.PoppedResponse;
pub const RpcUnaryRequest = _shim_src.RpcUnaryRequest;
pub const RpcUnaryResponse = _shim_src.RpcUnaryResponse;
pub const consumePrefix = _shim_src.consumePrefix;
pub const default_max_capacity = _shim_src.default_max_capacity;
pub const peekRpcUnaryRequest = _shim_src.peekRpcUnaryRequest;
pub const peekRpcUnaryResponse = _shim_src.peekRpcUnaryResponse;
pub const scanCompleteRequest = _shim_src.scanCompleteRequest;
pub const scanCompleteResponse = _shim_src.scanCompleteResponse;
