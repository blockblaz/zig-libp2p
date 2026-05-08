//! Zeam / libp2p-gossipsub tuning constants (#39). Values match the behavioural contract in the
//! tracking issue; the full mesh runtime is still being built out.

/// Target mesh size per topic.
pub const mesh_n: u8 = 8;
pub const mesh_n_low: u8 = 6;
pub const mesh_n_high: u8 = 12;

/// Random peers per heartbeat for lazy gossip (IHave).
pub const gossip_lazy: u8 = 6;

/// Heartbeat period in milliseconds.
pub const heartbeat_interval_ms: i64 = 700;

/// Duplicate suppression window in milliseconds.
pub const duplicate_cache_ttl_ms: i64 = 24_000;

/// Heartbeats worth of message IDs to remember for lazy gossip.
pub const history_length: u8 = 6;

/// Upper bound on serialized gossipsub message size (publish path), per #39:
/// `max(snappy(10 MiB) + 1 KiB, 1 MiB)`.
pub const max_transmit_size_bytes: usize = @max(10 * 1024 * 1024 + 1024, 1024 * 1024);
