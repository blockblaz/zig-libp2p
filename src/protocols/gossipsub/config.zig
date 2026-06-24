//! Zeam / libp2p-gossipsub tuning constants (#39). Values match the behavioural contract in the
//! tracking issue; the full mesh runtime is still being built out.

/// Target mesh size per topic.
pub const mesh_n: u8 = 8;
/// Mesh maintenance floor (libp2p-standard 6). The heartbeat grafts a topic's
/// mesh toward `mesh_n` when it drops below this. The earlier blanket floor of
/// 8 (to converge the sparse per-subnet `attestation_<n>` topics — only ~8
/// members each — to a full mesh) also densified the dense `block`/`aggregate`
/// topics (all 31 nodes), raising block-forward duplication and per-stream
/// backpressure. That is now handled PER-TOPIC in `heartbeatInner`: a sparse
/// topic (where current mesh + available candidates <= `mesh_n`) grafts EVERY
/// available subscriber (full mesh — the finality property), while a dense
/// topic uses this standard [`mesh_n_low`, `mesh_n_high`] band. So the floor
/// returns to 6 without losing the sparse-subnet convergence.
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

/// Upper bound on serialized gossipsub message size (publish path), per #39.
/// Matches ethlambda `MAX_COMPRESSED_PAYLOAD_SIZE` (consensus-specs max_message_size
/// snappy headroom): `32 + 10 MiB + 10 MiB/6 + 1024` (~12 MiB).
pub const max_payload_size_bytes: usize = 10 * 1024 * 1024;
pub const max_transmit_size_bytes: usize = 32 + max_payload_size_bytes + max_payload_size_bytes / 6 + 1024;

/// Default PRUNE back-off when a peer sends PRUNE without an explicit `backoff_seconds`
/// (libp2p gossipsub v1.1 spec recommends 1 minute).
pub const prune_backoff_default_ms: i64 = 60_000;

/// Upper bound applied to peer-supplied `backoff_seconds` to prevent griefing via
/// abusive long back-offs that would lock us out of a peer indefinitely.
pub const prune_backoff_cap_ms: i64 = 15 * 60_000;

/// Back-off after local `unsubscribe` before the same topic may be subscribed again
/// (libp2p gossipsub v1.1 `UnsubscribeBackoff`, default 10 s).
pub const unsubscribe_backoff_ms: i64 = 10_000;

/// TTL for fanout peer sets on topics we publish to but do not subscribe to
/// (libp2p gossipsub v1.1 `FANOUT_TTL`, default 60 s).
pub const fanout_ttl_ms: i64 = 60_000;
