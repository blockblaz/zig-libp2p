//! QUIC runtime configuration and protocol constants.

const std = @import("std");

const host_mod = @import("../../core/host.zig");
const wall_time = @import("../../primitives/wall_time.zig");
const protocol_mod = @import("../../primitives/protocol.zig");
const varint = @import("../../primitives/varint.zig");
const wire_framing = @import("../../protocols/req_resp/wire_framing.zig");
const gossipsub_wire_limits = @import("../../protocols/gossipsub/wire_limits.zig");
const relay_mod = @import("../../protocols/relay/root.zig");
const dcutr_mod = @import("../../protocols/dcutr/root.zig");
const autonat_mod = @import("../../protocols/autonat/root.zig");
const identify_mod = @import("../../protocols/identify/identify.zig");
const ping_mod = @import("../../protocols/ping/ping.zig");

/// Canonical gossipsub multistream protocol id zeam uses for *outgoing* streams.
/// Inbound streams accept the wider `/meshsub/1.0.0`–`/meshsub/1.3.0` set so we can interop
/// with rust-libp2p peers (e.g. ethlambda) that offer the highest version they support first
/// and tear the stream down on `na` without trying lower versions.
pub const meshsub_protocol_id: []const u8 = "/meshsub/1.1.0";
pub const meshsub_protocol_id_v10: []const u8 = "/meshsub/1.0.0";
pub const meshsub_protocol_id_v12: []const u8 = "/meshsub/1.2.0";
pub const meshsub_protocol_id_v13: []const u8 = "/meshsub/1.3.0";
/// Protocol id offered on zeam-initiated `/meshsub` streams. Offer the highest
/// version first so rust-libp2p's responder can pick the newest it supports;
/// the ack may be any `/meshsub/*` (see [`initiatorHandshakeMeshsubReadPhase`]).
pub const meshsub_initiator_offer: []const u8 = meshsub_protocol_id_v13;
/// Versions offered on a zeam-initiated `/meshsub` stream, newest first. The
/// first is sent up-front; on a `na` reply the negotiation falls back to the
/// next via [`stream_multistream.initiatorMeshsubFallbackStep`]. Lantern
/// (c-lean-libp2p) and go-libp2p only support `/meshsub/1.1.0` and
/// `/meshsub/1.2.0`, so without this fallback zeam's single 1.3.0 offer is
/// rejected and the connection flaps. `[0]` must equal `meshsub_initiator_offer`.
pub const meshsub_offer_fallbacks = [_][]const u8{
    meshsub_protocol_id_v13, // /meshsub/1.3.0 — ethlambda / zeam
    meshsub_protocol_id_v12, // /meshsub/1.2.0 — lantern, go-libp2p, rust-libp2p
    meshsub_protocol_id, //     /meshsub/1.1.0 — oldest standard fallback
};

/// Per-stream inbound accumulator caps (#119).
pub const max_inbound_gossip_acc_bytes: usize =
    gossipsub_wire_limits.max_rpc_length_delimited_bytes + varint.max_encoding_bytes + 4096;
pub const max_inbound_req_acc_bytes: usize = (wire_framing.ExchangeLimits{}).max_accumulated;

pub const identify_protocol_id: []const u8 = std.mem.trimEnd(u8, identify_mod.protocol_line, "\n");
pub const identify_push_protocol_id: []const u8 = std.mem.trimEnd(u8, identify_mod.push_protocol_line, "\n");
pub const autonat_protocol_id: []const u8 = autonat_mod.v1_multistream_protocol_id;

pub const supported_protocols: [14][]const u8 = .{
    // Meshsub variants first, highest version preferred so rust-libp2p's offer of the
    // newest version is accepted on the first round. Any of these maps to the same
    // gossipsub-1.1 dispatch path because newer wire fields are protobuf-additive and
    // ignored by a 1.1 decoder.
    meshsub_protocol_id_v13,
    meshsub_protocol_id_v12,
    meshsub_protocol_id, // /meshsub/1.1.0 — canonical, also offered by our initiator
    meshsub_protocol_id_v10,
    protocol_mod.blocks_by_root_v1,
    protocol_mod.blocks_by_range_v1,
    protocol_mod.status_v1,
    relay_mod.wire.hop_protocol_id,
    relay_mod.wire.stop_protocol_id,
    dcutr_mod.wire.protocol_id,
    autonat_protocol_id,
    identify_protocol_id,
    ping_mod.multistream_protocol_id,
    identify_push_protocol_id,
};

/// Last index in `supported_protocols` that should be dispatched as the gossipsub
/// `/meshsub/*` path. Used by `normalizeProtocolIndex` to collapse the four versioned
/// entries onto `proto_meshsub`.
pub const proto_meshsub_last_index: usize = 3;
pub const proto_meshsub: usize = 0;
pub const proto_relay_hop: usize = 7;
pub const proto_relay_stop: usize = 8;
pub const proto_dcutr: usize = 9;
pub const proto_autonat: usize = 10;
pub const proto_identify: usize = 11;
pub const proto_ping: usize = 12;
pub const proto_identify_push: usize = 13;

/// Map a `supported_protocols` index returned by the multistream responder onto the
/// canonical per-protocol dispatch index. Today this only collapses the four meshsub
/// variants onto `proto_meshsub`; non-meshsub indices are returned unchanged.
pub fn normalizeProtocolIndex(ix: usize) usize {
    if (ix <= proto_meshsub_last_index) return proto_meshsub;
    return ix;
}
pub const max_inbound_relay_acc_bytes: usize = relay_mod.wire.Limits.standard.max_frame_bytes + varint.max_encoding_bytes + 64;

pub const PemError = error{
    PemNoBegin,
    PemNoEnd,
};

/// TLS identity material for zquic (file paths or in-memory PEM). See #129.
pub const TlsPemSource = union(enum) {
    /// PEM files on disk. Paths are borrowed until [`QuicRuntime.destroy`].
    paths: struct {
        cert_path: []const u8,
        key_path: []const u8,
    },
    /// In-memory PEM. As of zig-libp2p v0.1.5 the bytes are threaded straight
    /// through to zquic v1.6.6's `ServerConfig.cert_pem` / `key_pem` and
    /// `ClientConfig.client_cert_pem` / `client_key_pem` (ch4r10t33r/zquic#129)
    /// — nothing is written to disk. Bytes are borrowed until
    /// [`QuicRuntime.destroy`].
    pem_bytes: struct {
        cert_pem: []const u8,
        key_pem: []const u8,
    },
};

/// Internal resolution of a [`TlsPemSource`]: borrows the embedder's slices
/// directly — paths for the `.paths` arm, PEM bytes for the `.pem_bytes` arm
/// — and threads them straight to zquic's `ServerConfig` / `ClientConfig`
/// `cert_path|key_path` or `cert_pem|key_pem` fields (zquic v1.6.6, see
/// ch4r10t33r/zquic#129). Never touches disk for the bytes case.
pub const ResolvedTlsPem = union(enum) {
    paths: struct {
        cert_path: []const u8,
        key_path: []const u8,
    },
    bytes: struct {
        cert_pem: []const u8,
        key_pem: []const u8,
    },
};

pub fn resolveTlsPemSource(src: TlsPemSource) ResolvedTlsPem {
    return switch (src) {
        .paths => |p| .{ .paths = .{ .cert_path = p.cert_path, .key_path = p.key_path } },
        .pem_bytes => |pb| .{ .bytes = .{ .cert_pem = pb.cert_pem, .key_pem = pb.key_pem } },
    };
}

pub const QuicRuntimeOptions = struct {
    allocator: std.mem.Allocator,
    /// Wired-up [`host_mod.Host`]. The runtime calls into
    /// `host.handleGossipRpc`, `host.registerInboundReqRespChannel`,
    /// `host.onConnectionEstablished`, `host.onDialFailure`, etc.
    host: *host_mod.Host,
    /// Server + client TLS PEM (paths on disk or in-memory bytes). #129
    tls_pem: TlsPemSource,
    /// Listen multiaddr (e.g. `/ip4/0.0.0.0/udp/0/quic-v1`).
    listen_multiaddr: []const u8,
    /// Wall-clock millisecond getter; defaults to [`wall_time.milliTimestamp`].
    now_ms_fn: *const fn () i64 = wall_time.milliTimestamp,
    /// Per-iteration poll timeout for the drive loop.
    poll_timeout_ms: u32 = 50,
    /// Number of drive-loop shards (quinn model). Connections are partitioned
    /// across this many drive threads to break single-thread saturation at a
    /// full mesh. One demux thread reads the shared listen socket and routes
    /// each datagram to the owning shard's ring (by shard-tagged CID byte for
    /// 1-RTT, by source-address hash for long-header Initials). Clamped to
    /// `[1, 8]` and rounded down to a power of two. `1` reproduces the
    /// single-thread behaviour exactly (mask 0, demux is a no-op router).
    ///
    /// NOTE: the default is `1` until the cross-shard gossip outbox + per-shard
    /// hook-queue routing (Phase 3) land — with `> 1` a directed gossip delivery
    /// or a hook command for a peer owned by a different shard is drained by the
    /// wrong shard's drive thread and dropped. The N-thread demux/ring/dial-
    /// routing machinery is wired and active when this is raised; raising it is
    /// gated on Phase 3.
    drive_shards: u8 = 1,
    /// Circuit relay v2 server/client (#91).
    relay: RelayRuntimeOptions = .{},
    /// DCUtR hole punching over relayed connections (#91).
    dcutr: DcutrRuntimeOptions = .{},
    autonat: AutonatRuntimeOptions = .{},
};

pub const RelayRuntimeOptions = struct {
    enable_server: bool = true,
    enable_client: bool = true,
    /// When set, auto-reserve on this relay multiaddr after startup.
    auto_reserve_relay: ?[]const u8 = null,
};

pub const DcutrRuntimeOptions = struct {
    enable: bool = true,
    /// Observed addresses sent in DCUtR CONNECT (defaults to listen addr).
    local_obs_addrs: []const []const u8 = &.{},
};

pub const AutonatRuntimeOptions = struct {
    enable: bool = true,
};
