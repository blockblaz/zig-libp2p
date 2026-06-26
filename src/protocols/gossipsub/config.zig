//! Zeam / libp2p-gossipsub tuning constants (#39). Values match the behavioural contract in the
//! tracking issue; the full mesh runtime is still being built out.

/// Target mesh size per topic.
pub const mesh_n: u8 = 8;
/// Mesh maintenance floor. Heartbeat GRAFTs whenever a topic's mesh drops below
/// this, topping it back up to this many peers (`runtime.zig` uses `mesh_n_low`
/// as BOTH the trigger and the graft target). Set to `mesh_n` (8), not the
/// libp2p-standard 6, on purpose: the lean per-subnet `attestation_<n>` topics
/// are SPARSE — only the 8 validators assigned to a subnet subscribe. With a
/// floor of 6, an aggregator's subnet mesh parks at 6 of its 7 fellow-subnet
/// peers, so it only ever sees ~5-6/8 attestations, never reaches the 2/3
/// quorum, and finality stalls (observed live: subnetN=5-6/8, mesh_peers=18=3
/// topics x 6). A floor of 8 forces the maintenance heartbeat to keep grafting
/// the remaining real subnet members as they connect, so the sparse subnet mesh
/// converges to (near-)complete and the aggregator sees the full 8/8. The dense
/// `block`/`aggregate` topics (all 31 nodes subscribe) are unaffected in
/// reachability and merely run a slightly denser mesh; `mesh_n_high` (12) still
/// bounds the ceiling, so the hysteresis band is [8,12].
pub const mesh_n_low: u8 = 8;
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
