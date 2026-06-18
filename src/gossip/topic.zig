//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/gossip/topic.zig");

pub const DecodeError = _shim_src.DecodeError;
pub const GossipEncoding = _shim_src.GossipEncoding;
pub const GossipTopic = _shim_src.GossipTopic;
pub const GossipTopicKind = _shim_src.GossipTopicKind;
pub const LeanNetworkTopic = _shim_src.LeanNetworkTopic;
pub const SubnetId = _shim_src.SubnetId;
pub const topic_prefix = _shim_src.topic_prefix;
