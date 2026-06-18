//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/gossipsub/message.zig");

pub const Error = _shim_src.Error;
pub const MessageOwned = _shim_src.MessageOwned;
pub const MessageView = _shim_src.MessageView;
pub const decode = _shim_src.decode;
pub const encode = _shim_src.encode;
