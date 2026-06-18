//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/gossipsub/message_id.zig");

pub const writeMessageId = _shim_src.writeMessageId;
