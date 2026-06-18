//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/gossipsub/config.zig");

pub const duplicate_cache_ttl_ms = _shim_src.duplicate_cache_ttl_ms;
pub const fanout_ttl_ms = _shim_src.fanout_ttl_ms;
pub const gossip_lazy = _shim_src.gossip_lazy;
pub const heartbeat_interval_ms = _shim_src.heartbeat_interval_ms;
pub const history_length = _shim_src.history_length;
pub const max_payload_size_bytes = _shim_src.max_payload_size_bytes;
pub const max_transmit_size_bytes = _shim_src.max_transmit_size_bytes;
pub const mesh_n = _shim_src.mesh_n;
pub const mesh_n_high = _shim_src.mesh_n_high;
pub const mesh_n_low = _shim_src.mesh_n_low;
pub const prune_backoff_cap_ms = _shim_src.prune_backoff_cap_ms;
pub const prune_backoff_default_ms = _shim_src.prune_backoff_default_ms;
pub const unsubscribe_backoff_ms = _shim_src.unsubscribe_backoff_ms;
