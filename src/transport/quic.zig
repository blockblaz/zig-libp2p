//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./quic/quic.zig");

pub const quic_v1 = _shim_src.quic_v1;
pub const stream_multistream = _shim_src.stream_multistream;
pub const quic_raw_stream_io = _shim_src.quic_raw_stream_io;
pub const QuicV1Endpoint = _shim_src.QuicV1Endpoint;
pub const ParseQuicV1EndpointError = _shim_src.ParseQuicV1EndpointError;
pub const Libp2pQuicClientDialError = _shim_src.Libp2pQuicClientDialError;
pub const BindUdpSocketError = _shim_src.BindUdpSocketError;
pub const parseQuicV1Endpoint = _shim_src.parseQuicV1Endpoint;
pub const formatZquicDialHost = _shim_src.formatZquicDialHost;
pub const bindUdpSocket = _shim_src.bindUdpSocket;
pub const initLibp2pQuicServerFromMultiaddr = _shim_src.initLibp2pQuicServerFromMultiaddr;
pub const Libp2pZquicClientDialOptions = _shim_src.Libp2pZquicClientDialOptions;
pub const initLibp2pQuicClientInPlace = _shim_src.initLibp2pQuicClientInPlace;
pub const initLibp2pQuicClientFromEndpoint = _shim_src.initLibp2pQuicClientFromEndpoint;
pub const initLibp2pQuicClientFromMultiaddr = _shim_src.initLibp2pQuicClientFromMultiaddr;
