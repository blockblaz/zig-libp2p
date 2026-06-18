//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/gossipsub/peer_score.zig");

pub const Direction = _shim_src.Direction;
pub const TopicParams = _shim_src.TopicParams;
pub const Params = _shim_src.Params;
pub const Tracker = _shim_src.Tracker;
