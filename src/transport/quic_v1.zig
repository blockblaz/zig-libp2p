//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./quic/v1.zig");

pub const multistream_protocol_id = _shim_src.multistream_protocol_id;
pub const tls_alpn = _shim_src.tls_alpn;
pub const Libp2pZquicServerOptions = _shim_src.Libp2pZquicServerOptions;
pub const libp2pZquicServerConfig = _shim_src.libp2pZquicServerConfig;
pub const Libp2pZquicClientOptions = _shim_src.Libp2pZquicClientOptions;
pub const libp2pZquicClientConfig = _shim_src.libp2pZquicClientConfig;
pub const appendFirstBidiStreamInitiatorHandshake = _shim_src.appendFirstBidiStreamInitiatorHandshake;
