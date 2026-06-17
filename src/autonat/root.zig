//! libp2p AutoNAT — NAT / address reachability probing (#92).
//!
//! Implements wire codecs and client/server logic for:
//! - **v1** (`/libp2p/autonat/1.0.0`) — node-level NAT status
//! - **v2** (`/libp2p/autonat/2/dial-request`, `/libp2p/autonat/2/dial-back`) — per-address reachability
//!
//! Spec: https://github.com/libp2p/specs/blob/master/autonat/README.md
//!
//! Transport dial-backs remain embedder-owned via [`server.DialBackFn`]; this module
//! handles protobuf framing, security policy, and reachability aggregation.

pub const wire = @import("wire.zig");
pub const policy = @import("policy.zig");
pub const client = @import("client.zig");
pub const server = @import("server.zig");

pub const NatStatus = policy.NatStatus;
pub const IpAddr = policy.IpAddr;
pub const Config = policy.Config;
pub const ReachabilityTracker = policy.ReachabilityTracker;
pub const Client = client.Client;
pub const ClientConfig = client.Config;
pub const Server = server.Server;
pub const ServerConfig = server.Config;
pub const DialBackFn = server.DialBackFn;
pub const DialBackResult = server.DialBackResult;

pub const v1_protocol_line = wire.v1_protocol_line;
pub const v1_multistream_protocol_id = wire.v1_multistream_protocol_id;
pub const v2_dial_request_id = wire.v2_dial_request_id;
pub const v2_dial_back_id = wire.v2_dial_back_id;

pub const OutboundProbe = client.OutboundProbe;
pub const ReachabilityChange = client.ReachabilityChange;
pub const ScheduledProbe = client.ScheduledProbe;

test {
    _ = @import("wire.zig");
    _ = @import("policy.zig");
    _ = @import("client.zig");
    _ = @import("server.zig");
}
