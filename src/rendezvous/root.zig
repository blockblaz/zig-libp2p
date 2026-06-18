//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/rendezvous/root.zig");

pub const Client = _shim_src.Client;
pub const ClientConfig = _shim_src.ClientConfig;
pub const DiscoverResult = _shim_src.DiscoverResult;
pub const DiscoveredPeer = _shim_src.DiscoveredPeer;
pub const Store = _shim_src.Store;
pub const StoreConfig = _shim_src.StoreConfig;
pub const Server = _shim_src.Server;
pub const ServerConfig = _shim_src.ServerConfig;
pub const protocol_line = _shim_src.protocol_line;
pub const protocol_id = _shim_src.protocol_id;
pub const client = _shim_src.client;
pub const server = _shim_src.server;
pub const store = _shim_src.store;
pub const wire = _shim_src.wire;
