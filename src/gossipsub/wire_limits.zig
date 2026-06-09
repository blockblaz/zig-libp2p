//! Size limits for gossipsub protobuf decode paths that face **untrusted** wire input.
//! Sized for hash-sig Lean blocks (~3 MiB snappy on the wire today) with headroom
//! below [`config.max_transmit_size_bytes`] (~10 MiB publish cap).

/// Maximum length-delimited field taken from an outer `RPC` message (publish blob, control blob, …).
pub const max_rpc_length_delimited_bytes: usize = 16 * 1024 * 1024;

/// Declared gossip frame length above this is treated as griefing: the inbound
/// QUIC stream is dropped rather than buffering unbounded bytes.
pub const max_gossip_frame_declared_absolute_bytes: usize = 128 * 1024 * 1024;

/// Maximum nested protobuf payload for one control entry (`ControlIHave`, `ControlIWant`, …).
pub const max_control_entry_bytes: usize = 1024 * 1024;

/// Topic string length (subscription, graft, message, …).
pub const max_topic_str_bytes: usize = 4096;

/// One gossipsub message id (opaque bytes on the wire).
pub const max_message_id_bytes: usize = 256;

/// Repeated message ids inside a single `IHave` / `IWant` / `IDontWant` entry.
pub const max_message_ids_per_entry: usize = 8192;

/// Nested `ControlExtensions` message (`ControlMessage.extensions`, field 6).
pub const max_control_extensions_blob_bytes: usize = 4096;

/// One `SubOpts` nested message inside `subscriptions`.
pub const max_subopts_blob_bytes: usize = 64 * 1024;

/// Full `Message` protobuf wire passed to `message.decode`.
pub const max_gossip_message_wire_bytes: usize = max_rpc_length_delimited_bytes;

pub const max_gossip_message_data_bytes: usize = max_rpc_length_delimited_bytes;
pub const max_gossip_message_from_bytes: usize = 128;
/// `Message.topic` (field 4); same bound as subscription / graft topics.
pub const max_gossip_message_topic_bytes: usize = max_topic_str_bytes;
pub const max_gossip_message_seqno_bytes: usize = 128;
pub const max_gossip_message_signature_bytes: usize = 8192;
pub const max_gossip_message_key_bytes: usize = 8192;
