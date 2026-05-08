//! Pure-Zig libp2p-oriented networking helpers for Lean Ethereum clients.
//!
//! Add this package in `build.zig.zon`, then `b.dependency("zig_libp2p", …)`
//! and `dep.module("zig_libp2p")` on your executable or library module.

pub const errors = @import("errors.zig");
pub const layer_events = @import("layer_events.zig");
pub const protocol = @import("protocol.zig");
pub const varint = @import("varint.zig");
pub const addr_list = @import("addr_list.zig");
pub const multistream = @import("multistream.zig");
pub const ping = @import("ping.zig");
pub const identify = @import("identify.zig");

pub const gossip = struct {
    pub const topic = @import("gossip/topic.zig");
};

pub const gossipsub = struct {
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
};

pub const transport = struct {
    pub const quic_v1 = @import("transport/quic_v1.zig");
    pub const quic = @import("transport/quic.zig");
    pub const stream_multistream = @import("transport/stream_multistream.zig");
    pub const tcp = @import("transport/tcp.zig");
    pub const multistream_negotiate = @import("transport/multistream_negotiate.zig");
    pub const transport_error = @import("transport/transport_error.zig");
};

pub const security = struct {
    pub const libp2p_tls = @import("security/libp2p_tls.zig");
};

/// Pure-Zig QUIC/TLS stack ([zquic](https://github.com/ch4r10t33r/zquic)), Zig 0.16–pinned in `build.zig.zon`.
pub const zquic = @import("zquic");
