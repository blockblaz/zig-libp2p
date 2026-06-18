//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./quic/posix_udp.zig");

pub const SocketError = _shim_src.SocketError;
pub const socket = _shim_src.socket;
pub const BindError = _shim_src.BindError;
pub const close = _shim_src.close;
pub const getsockname = _shim_src.getsockname;
pub const bind = _shim_src.bind;
