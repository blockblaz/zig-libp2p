//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/gossipsub/wire_limits.zig");

pub const max_control_entry_bytes = _shim_src.max_control_entry_bytes;
pub const max_control_extensions_blob_bytes = _shim_src.max_control_extensions_blob_bytes;
pub const max_gossip_frame_declared_absolute_bytes = _shim_src.max_gossip_frame_declared_absolute_bytes;
pub const max_gossip_message_data_bytes = _shim_src.max_gossip_message_data_bytes;
pub const max_gossip_message_from_bytes = _shim_src.max_gossip_message_from_bytes;
pub const max_gossip_message_key_bytes = _shim_src.max_gossip_message_key_bytes;
pub const max_gossip_message_seqno_bytes = _shim_src.max_gossip_message_seqno_bytes;
pub const max_gossip_message_signature_bytes = _shim_src.max_gossip_message_signature_bytes;
pub const max_gossip_message_topic_bytes = _shim_src.max_gossip_message_topic_bytes;
pub const max_gossip_message_wire_bytes = _shim_src.max_gossip_message_wire_bytes;
pub const max_message_id_bytes = _shim_src.max_message_id_bytes;
pub const max_message_ids_per_entry = _shim_src.max_message_ids_per_entry;
pub const max_rpc_length_delimited_bytes = _shim_src.max_rpc_length_delimited_bytes;
pub const max_subopts_blob_bytes = _shim_src.max_subopts_blob_bytes;
pub const max_topic_str_bytes = _shim_src.max_topic_str_bytes;
