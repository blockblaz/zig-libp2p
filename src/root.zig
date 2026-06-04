//! Pure-Zig libp2p-oriented networking helpers for Lean Ethereum clients.
//!
//! Add this package in `build.zig.zon`, then `b.dependency("zig_libp2p", …)`
//! and `dep.module("zig_libp2p")` on your executable or library module.

pub const errors = @import("errors.zig");
pub const metrics = @import("metrics.zig");
pub const layer_events = @import("layer_events.zig");
pub const peer_events = @import("peer_events.zig");
pub const connection_manager = @import("connection_manager.zig");
pub const swarm = @import("swarm.zig");
pub const host = @import("host.zig");
/// Canonical node bundle from [#31](https://github.com/ch4r10t33r/zig-libp2p/issues/31); same as [`host.Host`](host.zig).
pub const Node = host.Host;
/// Configuration for [`Node`]($).
pub const NodeConfig = host.HostConfig;
pub const wall_time = @import("wall_time.zig");
pub const protocol = @import("protocol.zig");
pub const varint = @import("varint.zig");
pub const addr_list = @import("addr_list.zig");
pub const multistream = @import("multistream.zig");
pub const ping = @import("ping.zig");
pub const ping_wire_quic = @import("ping_wire_quic.zig");
pub const identify = @import("identify.zig");

pub const gossip = struct {
    pub const topic = @import("gossip/topic.zig");
};

pub const gossipsub = struct {
    pub const config = @import("gossipsub/config.zig");
    pub const message_id = @import("gossipsub/message_id.zig");
    pub const duplicate_cache = @import("gossipsub/duplicate_cache.zig");
    pub const runtime = @import("gossipsub/runtime.zig");
    pub const rpc = @import("gossipsub/rpc.zig");
    pub const control = @import("gossipsub/control.zig");
    pub const message = @import("gossipsub/message.zig");
    pub const wire_limits = @import("gossipsub/wire_limits.zig");
};

pub const protobuf = struct {
    pub const wire = @import("protobuf/wire.zig");
};

/// Libp2p peer IDs (`blockblaz/peer-id`), same pin as `multiaddr-zig`.
pub const peer_id = @import("peer_id");
pub const identity = @import("identity.zig");
pub const keypair = @import("keypair.zig");

/// Block Snappy (`zig_snappy`), same module name as in Zeam.
pub const snappyz = @import("snappyz");
/// Snappy framing for libp2p streams (`snappyframesz`).
pub const snappyframesz = @import("snappyframesz");

pub const req_resp = struct {
    pub const frame = @import("req_resp/frame.zig");
    pub const stream = @import("req_resp/stream.zig");
    pub const snappy_wire = @import("req_resp/snappy_wire.zig");
    pub const runtime = @import("req_resp/runtime.zig");
    pub const wire_framing = @import("req_resp/wire_framing.zig");
    pub const wire_tcp = @import("req_resp/wire_tcp.zig");
    pub const wire_quic = @import("req_resp/wire_quic.zig");
};

pub const transport = struct {
    pub const quic_v1 = @import("transport/quic_v1.zig");
    pub const quic = @import("transport/quic.zig");
    pub const quic_raw_stream_io = @import("transport/quic_raw_stream_io.zig");
    pub const quic_endpoint = @import("transport/quic_endpoint.zig");
    pub const quic_peer_identity = @import("transport/quic_peer_identity.zig");
    pub const quic_runtime = @import("transport/quic_runtime.zig");
    pub const stream_multistream = @import("transport/stream_multistream.zig");
    pub const tcp = @import("transport/tcp.zig");
    pub const tcp_tls = @import("transport/tcp_tls.zig");
    pub const multistream_negotiate = @import("transport/multistream_negotiate.zig");
    pub const transport_error = @import("transport/transport_error.zig");
    pub const yamux = @import("transport/yamux/root.zig");
    pub const mplex = @import("transport/mplex/root.zig");
};

pub const security = struct {
    pub const libp2p_tls = @import("security/libp2p_tls.zig");
    pub const libp2p_tls_cert = @import("security/libp2p_tls_cert.zig");
    pub const noise = struct {
        pub const protocol = @import("security/noise/protocol.zig");
        pub const payload = @import("security/noise/payload.zig");
        pub const identity = @import("security/noise/identity.zig");
        pub const libp2p = @import("security/noise/libp2p_noise.zig");
        pub const stream_upgrade = @import("security/noise/stream_upgrade.zig");
    };
};

/// Pure-Zig QUIC/TLS stack ([zquic](https://github.com/ch4r10t33r/zquic)), Zig 0.16–pinned in `build.zig.zon`.
pub const zquic = @import("zquic");

test {
    _ = @import("wire_boundaries.zig");
    _ = @import("transport/yamux/root.zig");
    _ = @import("transport/yamux/frame.zig");
    _ = @import("transport/yamux/session.zig");
    _ = @import("transport/mplex/root.zig");
    _ = @import("transport/mplex/frame.zig");
    _ = @import("transport/mplex/session.zig");
    // Force discovery of modules whose tests would otherwise be skipped because
    // nothing references them from already-discovered modules. This is the test
    // analyzer's dead-code-elimination behaviour in Zig 0.16: tests in modules
    // declared only through `pub const X = @import(…)` aren't pulled into the
    // test binary unless the module is actually consumed somewhere. Adding the
    // file here is the minimal force-discovery hook.
    //
    // Note: more modules can and should be added (#TBD-tracking-issue), but each
    // addition currently surfaces latent compile errors that have been masked by
    // the same elimination, so they need to be fixed alongside.
    _ = @import("gossipsub/runtime.zig");
    _ = @import("gossipsub/config.zig");
    _ = @import("gossipsub/duplicate_cache.zig");
    _ = @import("gossipsub/message_id.zig");
    _ = @import("identify.zig");
    _ = @import("connection_manager.zig");
    _ = @import("metrics.zig");
    _ = @import("security/libp2p_tls.zig");
    _ = @import("security/libp2p_tls_cert.zig");
    _ = @import("security/noise/identity.zig");
    _ = @import("security/noise/libp2p_noise.zig");
    _ = @import("security/noise/payload.zig");
    _ = @import("security/noise/protocol.zig");
    // The following files run TCP/QUIC loopback handshakes on real OS
    // threads via `Io.Threaded` and are deliberately *not* in test discovery:
    // the same parallel accept/dial ordering that already forces the example
    // smoke step to run serially (`build.zig` comment "Parallel runs were
    // observed to hang indefinitely") also hangs the test runner on Linux CI.
    // Their wire-level logic is covered by sibling modules that don't open
    // real sockets (`noise/identity.zig`, `noise/protocol.zig`,
    // `noise/payload.zig`, `transport/over_cap.zig`, `req_resp/frame.zig`,
    // `req_resp/stream.zig`, etc.).
    //   - security/noise/stream_upgrade.zig
    //   - transport/quic_endpoint.zig
    //   - transport/tcp.zig
    //   - transport/tcp_tls/stream_upgrade.zig (loopback; not force-discovered)
    //   - req_resp/wire_tcp.zig
    _ = @import("transport/tcp_tls.zig");
    _ = @import("transport/over_cap.zig");
    _ = @import("transport/multistream_negotiate.zig");
    _ = @import("transport/quic.zig");
    _ = @import("transport/quic_peer_identity.zig");
    _ = @import("transport/quic_raw_stream_io.zig");
    _ = @import("transport/quic_runtime.zig");
    _ = @import("transport/quic_v1.zig");
    _ = @import("transport/stream_multistream.zig");
    _ = @import("transport/transport_error.zig");
    _ = @import("transport/zquic_feed_addr.zig");
    _ = @import("transport/quic_posix_udp.zig");
    _ = @import("multistream.zig");
    _ = @import("swarm.zig");
    _ = @import("host.zig");
    _ = @import("identity.zig");
    _ = @import("keypair.zig");
    _ = @import("ping.zig");
    _ = @import("ping_wire_quic.zig");
    _ = @import("addr_list.zig");
    _ = @import("protocol.zig");
    _ = @import("varint.zig");
    _ = @import("layer_events.zig");
    _ = @import("peer_events.zig");
    _ = @import("errors.zig");
    _ = @import("protobuf/wire.zig");
    _ = @import("gossip/topic.zig");
    _ = @import("gossipsub/control.zig");
    _ = @import("gossipsub/message.zig");
    _ = @import("gossipsub/rpc.zig");
    _ = @import("gossipsub/wire_limits.zig");
    _ = @import("req_resp/frame.zig");
    _ = @import("req_resp/stream.zig");
    _ = @import("req_resp/snappy_wire.zig");
    _ = @import("req_resp/runtime.zig");
    _ = @import("req_resp/wire_framing.zig");
    // `req_resp/wire_tcp.zig` excluded — see TCP loopback note above.
    _ = @import("req_resp/wire_quic.zig");
    _ = @import("wall_time.zig");
}
