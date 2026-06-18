//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./quic/raw_stream_io.zig");

pub const raw_stream_send_chunk_len = _shim_src.raw_stream_send_chunk_len;
pub const RawAppBidiClient = _shim_src.RawAppBidiClient;
pub const RawAppBidiServer = _shim_src.RawAppBidiServer;
