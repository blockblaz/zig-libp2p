//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./core/host.zig");

pub const AutonatHostConfig = _shim_src.AutonatHostConfig;
pub const AutonatProbeDispatch = _shim_src.AutonatProbeDispatch;
pub const GossipsubError = _shim_src.GossipsubError;
pub const Host = _shim_src.Host;
pub const HostConfig = _shim_src.HostConfig;
pub const IdentifyConfig = _shim_src.IdentifyConfig;
pub const IdentifyPushDispatch = _shim_src.IdentifyPushDispatch;
pub const InitError = _shim_src.InitError;
pub const MdnsHostConfig = _shim_src.MdnsHostConfig;
pub const SwarmBootConfig = _shim_src.SwarmBootConfig;
pub const default_max_identify_push_per_tick = _shim_src.default_max_identify_push_per_tick;
