//! libp2p Rendezvous protocol (#209).
//!
//! Spec: https://github.com/libp2p/specs/blob/master/rendezvous/README.md

pub const wire = @import("wire.zig");
pub const store = @import("store.zig");
pub const server = @import("server.zig");
pub const client = @import("client.zig");

pub const Server = server.Server;
pub const ServerConfig = server.Config;
pub const Client = client.Client;
pub const ClientConfig = client.Config;
pub const DiscoverResult = client.DiscoverResult;
pub const DiscoveredPeer = client.DiscoveredPeer;
pub const Store = store.Store;
pub const StoreConfig = store.Config;

pub const protocol_line = wire.protocol_line;
pub const protocol_id = wire.protocol_id;

test {
    _ = @import("wire.zig");
    _ = @import("store.zig");
    _ = @import("server.zig");
    _ = @import("client.zig");
}
