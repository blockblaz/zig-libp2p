//! libp2p Kademlia DHT (kad-dht) — routing, queries, and wire handlers (#93).
//!
//! Protocol: `/ipfs/kad/1.0.0` (and per-network variants such as `/lan/kad/1.0.0`).
//! Spec: https://github.com/libp2p/specs/tree/master/kad-dht
//!
//! Transport stream I/O and outbound RPC dials remain embedder-owned via
//! [`server.Server.handleStream`] and [`query.QueryPeerFn`].

pub const keyspace = @import("keyspace.zig");
pub const mode = @import("mode.zig");
pub const routing_table = @import("routing_table.zig");
pub const wire = @import("wire.zig");
pub const record_store = @import("record_store.zig");
pub const query = @import("query.zig");
pub const server = @import("server.zig");
pub const client = @import("client.zig");

pub const Key = keyspace.Key;
pub const Mode = mode.Mode;
pub const NatStatus = @import("../autonat/root.zig").NatStatus;
pub const modeFromNatStatus = mode.fromNatStatus;

pub const RoutingTable = routing_table.RoutingTable;
pub const RoutingConfig = routing_table.Config;
pub const RecordStore = record_store.RecordStore;
pub const RecordConfig = record_store.Config;
pub const QueryEngine = query.QueryEngine;
pub const QueryConfig = query.Config;
pub const QueryPeerFn = query.QueryPeerFn;
pub const Server = server.Server;
pub const ServerConfig = server.Config;
pub const Client = client.Client;
pub const ClientConfig = client.Config;
pub const BootstrapPeer = client.BootstrapPeer;

pub const protocol_line = wire.protocol_line;
pub const protocol_id = wire.protocol_id;
pub const lan_protocol_line = wire.lan_protocol_line;

pub const MessageType = wire.MessageType;
pub const MessageView = wire.MessageView;
pub const MessageOwned = wire.MessageOwned;
pub const PeerView = wire.PeerView;
pub const RecordView = wire.RecordView;

test {
    _ = @import("keyspace.zig");
    _ = @import("mode.zig");
    _ = @import("routing_table.zig");
    _ = @import("wire.zig");
    _ = @import("record_store.zig");
    _ = @import("query.zig");
    _ = @import("server.zig");
    _ = @import("client.zig");
}
