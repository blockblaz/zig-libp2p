//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/autonat/root.zig");

pub const Client = _shim_src.Client;
pub const ClientConfig = _shim_src.ClientConfig;
pub const Config = _shim_src.Config;
pub const DialBackFn = _shim_src.DialBackFn;
pub const DialBackResult = _shim_src.DialBackResult;
pub const IpAddr = _shim_src.IpAddr;
pub const NatStatus = _shim_src.NatStatus;
pub const OutboundProbe = _shim_src.OutboundProbe;
pub const ReachabilityChange = _shim_src.ReachabilityChange;
pub const ReachabilityTracker = _shim_src.ReachabilityTracker;
pub const ScheduledProbe = _shim_src.ScheduledProbe;
pub const Server = _shim_src.Server;
pub const ServerConfig = _shim_src.ServerConfig;
pub const client = _shim_src.client;
pub const policy = _shim_src.policy;
pub const server = _shim_src.server;
pub const v1_multistream_protocol_id = _shim_src.v1_multistream_protocol_id;
pub const v1_protocol_line = _shim_src.v1_protocol_line;
pub const v2_dial_back_id = _shim_src.v2_dial_back_id;
pub const v2_dial_request_id = _shim_src.v2_dial_request_id;
pub const wire = _shim_src.wire;
