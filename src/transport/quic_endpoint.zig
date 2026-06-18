//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./quic/endpoint.zig");

pub const max_tracked_peer_bidi_streams = _shim_src.max_tracked_peer_bidi_streams;
pub const InboundStreamScan = _shim_src.InboundStreamScan;
pub const popNextUnreportedPeerBidiStream = _shim_src.popNextUnreportedPeerBidiStream;
pub const popNextUnreportedServerBidiStream = _shim_src.popNextUnreportedServerBidiStream;
pub const QuicLifecycleHooks = _shim_src.QuicLifecycleHooks;
pub const OverCapPolicy = _shim_src.OverCapPolicy;
pub const QuicListener = _shim_src.QuicListener;
pub const QuicOutbound = _shim_src.QuicOutbound;
pub const QuicOutboundDialOptions = _shim_src.QuicOutboundDialOptions;
pub const dialExtended = _shim_src.dialExtended;
pub const dialMultiaddr = _shim_src.dialMultiaddr;
pub const listenMultiaddr = _shim_src.listenMultiaddr;
pub const DriveError = _shim_src.DriveError;
pub const loopbackPingOnce = _shim_src.loopbackPingOnce;
pub const loopbackPingTwoStreams = _shim_src.loopbackPingTwoStreams;
