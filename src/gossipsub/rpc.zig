//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/gossipsub/rpc.zig");

pub const Error = _shim_src.Error;
pub const SubscribeView = _shim_src.SubscribeView;
pub const decodeControlPayload = _shim_src.decodeControlPayload;
pub const decodeFirstPublish = _shim_src.decodeFirstPublish;
pub const decodeFirstSubscribe = _shim_src.decodeFirstSubscribe;
pub const decodePublishes = _shim_src.decodePublishes;
pub const decodeSubscribes = _shim_src.decodeSubscribes;
pub const deinitSubscribeView = _shim_src.deinitSubscribeView;
pub const encodeControlOnlyRpc = _shim_src.encodeControlOnlyRpc;
pub const encodeEmptyControlRpc = _shim_src.encodeEmptyControlRpc;
pub const encodePublish = _shim_src.encodePublish;
pub const encodeSubscribe = _shim_src.encodeSubscribe;
pub const freePublishBlobs = _shim_src.freePublishBlobs;
pub const freeSubscribeViews = _shim_src.freeSubscribeViews;
