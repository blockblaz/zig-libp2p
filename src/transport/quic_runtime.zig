//! Bundled libp2p QUIC transport runtime: composes [`QuicListener`],
//! [`QuicOutbound`], multistream-select, wire framing, the swarm command
//! dispatch hook, and the libp2p TLS cert generator into a single drop-in
//! that an embedder can start, hand a [`host_mod.Host`], and use without
//! writing the accept loop, dial flow, or per-stream protocol dispatch.
//!
//! Status: minimum-viable. Both the req/resp send/receive path and the
//! gossipsub publish / receive path are implemented end-to-end — the
//! corresponding loopback tests at the bottom of this file are the truth
//! gate. TLS identity is configured via [`TlsPemSource`] (on-disk PEM paths or
//! in-memory PEM bytes materialized for zquic on create; #129). Outbound gossip
//! uses one persistent `/meshsub/1.1.0` stream per peer on the **outbound**
//! (locally-dialed) QUIC connection; SUBSCRIBE and publish RPCs share that
//! stream. Inbound `/meshsub/1.1.0` streams drain length-prefixed frames into
//! [`host_mod.Host.handleGossipRpc`] with the verified sender peer id.

const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.quic_runtime);

const multiaddr = @import("multiaddr");

const errors_mod = @import("../errors.zig");
const host_mod = @import("../host.zig");
const identity = @import("../identity.zig");
const peer_events = @import("../peer_events.zig");
const protocol_mod = @import("../protocol.zig");
const swarm_mod = @import("../swarm.zig");
const connection_manager_mod = @import("../connection_manager.zig");
const wall_time = @import("../wall_time.zig");

const quic = @import("quic.zig");
const quic_v1 = @import("quic_v1.zig");
const quic_endpoint = @import("quic_endpoint.zig");
const quic_peer_identity = @import("quic_peer_identity.zig");
const quic_raw_stream_io = @import("quic_raw_stream_io.zig");
const stream_multistream = @import("stream_multistream.zig");

const wire_framing = @import("../req_resp/wire_framing.zig");
const snappy_wire = @import("../req_resp/snappy_wire.zig");

const gossipsub_msg = @import("../gossipsub/message.zig");
const gossipsub_rpc = @import("../gossipsub/rpc.zig");
const gossipsub_cfg = @import("../gossipsub/config.zig");
const gossipsub_wire_limits = @import("../gossipsub/wire_limits.zig");
const varint = @import("../varint.zig");

const relay_mod = @import("../relay/root.zig");
const dcutr_mod = @import("../dcutr/root.zig");
const identify_mod = @import("../identify.zig");
const ping_mod = @import("../ping.zig");
const libp2p_tls = @import("../security/libp2p_tls.zig");
const quic_relay_live = @import("quic_relay_live.zig");
const quic_dcutr_live = @import("quic_dcutr_live.zig");

const zquic = @import("zquic");
const ZIo = zquic.transport.io;

/// Canonical gossipsub multistream protocol id zeam uses for *outgoing* streams.
/// Inbound streams accept the wider `/meshsub/1.0.0`–`/meshsub/1.3.0` set so we can interop
/// with rust-libp2p peers (e.g. ethlambda) that offer the highest version they support first
/// and tear the stream down on `na` without trying lower versions.
const meshsub_protocol_id: []const u8 = "/meshsub/1.1.0";
const meshsub_protocol_id_v10: []const u8 = "/meshsub/1.0.0";
const meshsub_protocol_id_v12: []const u8 = "/meshsub/1.2.0";
const meshsub_protocol_id_v13: []const u8 = "/meshsub/1.3.0";
/// Protocol id offered on zeam-initiated `/meshsub` streams. Offer the highest
/// version first so rust-libp2p's responder can pick the newest it supports;
/// the ack may be any `/meshsub/*` (see [`initiatorHandshakeMeshsubReadPhase`]).
const meshsub_initiator_offer: []const u8 = meshsub_protocol_id_v13;

/// Per-stream inbound accumulator caps (#119).
const max_inbound_gossip_acc_bytes: usize =
    gossipsub_wire_limits.max_rpc_length_delimited_bytes + varint.max_encoding_bytes + 4096;
const max_inbound_req_acc_bytes: usize = (wire_framing.ExchangeLimits{}).max_accumulated;

const identify_protocol_id: []const u8 = std.mem.trimEnd(u8, identify_mod.protocol_line, "\n");
const identify_push_protocol_id: []const u8 = std.mem.trimEnd(u8, identify_mod.push_protocol_line, "\n");

const supported_protocols: [13][]const u8 = .{
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
    identify_protocol_id,
    ping_mod.multistream_protocol_id,
    identify_push_protocol_id,
};

/// Last index in `supported_protocols` that should be dispatched as the gossipsub
/// `/meshsub/*` path. Used by `normalizeProtocolIndex` to collapse the four versioned
/// entries onto `proto_meshsub`.
const proto_meshsub_last_index: usize = 3;
const proto_meshsub: usize = 0;
const proto_relay_hop: usize = 7;
const proto_relay_stop: usize = 8;
const proto_dcutr: usize = 9;
const proto_identify: usize = 10;
const proto_ping: usize = 11;
const proto_identify_push: usize = 12;

/// Map a `supported_protocols` index returned by the multistream responder onto the
/// canonical per-protocol dispatch index. Today this only collapses the four meshsub
/// variants onto `proto_meshsub`; non-meshsub indices are returned unchanged.
fn normalizeProtocolIndex(ix: usize) usize {
    if (ix <= proto_meshsub_last_index) return proto_meshsub;
    return ix;
}
const max_inbound_relay_acc_bytes: usize = relay_mod.wire.Limits.standard.max_frame_bytes + varint.max_encoding_bytes + 64;

const PemError = error{
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
const ResolvedTlsPem = union(enum) {
    paths: struct {
        cert_path: []const u8,
        key_path: []const u8,
    },
    bytes: struct {
        cert_pem: []const u8,
        key_pem: []const u8,
    },
};

fn resolveTlsPemSource(src: TlsPemSource) ResolvedTlsPem {
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
    /// Circuit relay v2 server/client (#91).
    relay: RelayRuntimeOptions = .{},
    /// DCUtR hole punching over relayed connections (#91).
    dcutr: DcutrRuntimeOptions = .{},
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

const PeerIdContext = struct {
    pub fn hash(_: PeerIdContext, key: identity.PeerId) u64 {
        var buf: [128]u8 = undefined;
        const b = key.toBytes(&buf) catch return 0;
        return std.hash.Wyhash.hash(0, b);
    }
    pub fn eql(_: PeerIdContext, a: identity.PeerId, b: identity.PeerId) bool {
        return a.eql(&b);
    }
};

const PeerIdMap = std.HashMap(identity.PeerId, *OutboundConn, PeerIdContext, std.hash_map.default_max_load_percentage);
const InboundPeerMap = std.HashMap(identity.PeerId, InboundConnRef, PeerIdContext, std.hash_map.default_max_load_percentage);
const PersistentGossipMap = std.HashMap(identity.PeerId, *PersistentGossipStream, PeerIdContext, std.hash_map.default_max_load_percentage);

const InboundConnRef = struct {
    slot: usize,
    conn: *ZIo.ConnState,
};

/// Tracked outbound connection: one QUIC connection per (remote peer).
const OutboundConn = struct {
    outbound: quic_endpoint.QuicOutbound,
    /// Whether [`host_mod.Host.onConnectionEstablished`] has fired for this slot.
    notified: bool = false,
    conn_id: connection_manager_mod.ConnectionId,
    peer_id: ?identity.PeerId = null,
    /// Last observed *effective* connection state, sampled at the end of every
    /// [`QuicRuntime.driveLoop`] iteration by [`detectOutboundConnectionClose`].
    /// `notified == true && prev_closed == false && current_closed == true` is how we
    /// detect that the remote QUIC peer sent `CONNECTION_CLOSE` (or that we hit a
    /// transport idle-timeout).
    ///
    /// `current_closed` is true when either `conn.phase == .closed` **or**
    /// `conn.draining` — zquic sets `draining = true` on every CONNECTION_CLOSE
    /// receipt and only later (after the 3×PTO draining deadline) reaps the
    /// connection; if we wait for `.closed` we miss the disconnect entirely on the
    /// client (outbound) side. Without this signal `outbound_by_peer` retains a
    /// dead entry, the host never sees `onConnectionClosed`, and
    /// `connection_manager` never schedules a redial. Mirrors the listener-side
    /// [`QuicListener.syncSeenFlags`] sweep.
    prev_closed: bool = false,
    /// Tracks which server-initiated bidi stream IDs on this outbound QUIC connection have
    /// already been surfaced as inbound streams. Server-initiated bidi streams (IDs 1, 5, 9…)
    /// are opened by the remote peer on the connection zeam dialled; without this tracking they
    /// would be silently ignored because only the listener's lifecycle callback detects new
    /// inbound streams. See [`QuicRuntime.dispatchOutboundPeerStreams`].
    peer_stream_reported: std.bit_set.StaticBitSet(quic_endpoint.max_tracked_peer_bidi_streams) =
        std.bit_set.StaticBitSet(quic_endpoint.max_tracked_peer_bidi_streams).initEmpty(),
};

/// Per-inbound-stream state: tracks where in the per-protocol read flow we are.
const InboundStream = struct {
    /// Listener connection slot index. Set to `inbound_slot_none` for streams that arrived on
    /// an outbound (client-side) QUIC connection: those connections are already fully
    /// established so the normal connection-notification path must be skipped.
    slot: usize,
    conn: *ZIo.ConnState,
    stream_id: u64,
    raw: quic_raw_stream_io.RawAppBidiServer,
    handshake_done: bool = false,
    protocol_index: ?usize = null,
    /// channel_id once we've called `host.registerInboundReqRespChannel`.
    channel_id: ?u64 = null,
    request_id_for_channel: u64 = 0,
    /// Set after the responder half-closes (FIN) following `finishResponseStream`.
    /// The zquic raw-app slot is released once this is true and the peer FINs.
    response_fin_sent: bool = false,
    sender_peer: ?identity.PeerId = null,
    /// Pre-verified peer identity for streams on outbound connections. When non-null the TLS
    /// verification step during multistream negotiation is skipped — the peer was already
    /// authenticated when the outbound connection was established.
    known_peer_id: ?identity.PeerId = null,
    /// Accumulated bytes for an in-progress unary request. Cleared once a
    /// complete request is parsed and the inbound channel registered.
    req_acc: std.ArrayList(u8) = .empty,
    /// Accumulated bytes for in-progress gossipsub frames on a `/meshsub/1.1.0`
    /// stream. Each frame is `uvarint(len) + RPC protobuf` and the stream MAY
    /// carry multiple frames. Bytes are consumed as full frames are decoded.
    gossip_acc: std.ArrayList(u8) = .empty,
    /// Accumulated bytes for one circuit-relay hop/stop length-prefixed frame.
    relay_acc: std.ArrayList(u8) = .empty,
    /// When true, hop/stop/dcutr control frame was handled; stream may bridge.
    relay_control_done: bool = false,
    /// Cumulative bytes pulled from the raw recv buffer for multistream-select;
    /// persisted across drive ticks so a partial negotiation (DialFailed) does
    /// not lose bytes the responder helper already consumed.
    ms_acc: std.ArrayList(u8) = .empty,
    /// Bytes left over after multistream-select succeeded (e.g. ping payload
    /// flushed in the same STREAM frame as the handshake ack).
    ms_tail: std.ArrayList(u8) = .empty,
};

const OutboundRequest = struct {
    /// The peer this request is destined for.
    peer: identity.PeerId,
    request_id: u64,
    proto: protocol_mod.LeanSupportedProtocol,
    stream_id: u64,
    raw: quic_raw_stream_io.RawAppBidiClient,
    handshake_sent: bool = false,
    handshake_done: bool = false,
    request_written: bool = false,
    finished: bool = false,
    /// SSZ payload to send (heap-owned).
    payload: []u8,
    /// Accumulated response bytes (for incremental decode).
    resp_acc: std.ArrayList(u8) = .empty,
};

/// Multistream I/O for a locally opened `/meshsub/1.1.0` publish stream.
const PublishBidiStream = union(enum) {
    outbound: quic_raw_stream_io.RawAppBidiClient,
    inbound: quic_raw_stream_io.RawAppBidiServer,

    fn reader(self: *PublishBidiStream) std.Io.Reader {
        return switch (self.*) {
            .outbound => |*c| c.reader(),
            .inbound => |*s| s.reader(),
        };
    }

    fn writer(self: *PublishBidiStream) std.Io.Writer {
        return switch (self.*) {
            .outbound => |*c| c.writer(),
            .inbound => |*s| s.writer(),
        };
    }

    fn unreadRecvLen(self: *const PublishBidiStream) usize {
        return switch (self.*) {
            .outbound => |*c| c.unreadRecvLen(),
            .inbound => |*s| s.unreadRecvLen(),
        };
    }

    fn finStream(self: *PublishBidiStream) void {
        switch (self.*) {
            .outbound => |*c| c.client.sendRawStreamData(c.stream_id, c.send_offset, &[_]u8{}, true),
            .inbound => |*s| {
                if (s.client) |c| {
                    c.sendRawStreamData(s.stream_id, s.send_offset, &[_]u8{}, true);
                } else {
                    s.server.sendRawStreamData(s.conn, s.stream_id, s.send_offset, &[_]u8{}, true);
                }
            },
        }
    }
};

/// In-flight gossipsub publish on a `/meshsub/1.1.0` stream. One per peer per
/// message (`per-message stream` pattern — open, multistream-select, write one
/// length-prefixed RPC frame, close).
const OutboundPublish = struct {
    peer: identity.PeerId,
    stream_id: u64,
    raw: PublishBidiStream,
    handshake_sent: bool = false,
    handshake_done: bool = false,
    frame_written: bool = false,
    finished: bool = false,
    /// `uvarint(len) + RPC protobuf` wire bytes (heap-owned).
    wire: []u8,
};

/// Persistent per-peer outbound `/meshsub/1.1.0` stream — exactly one stream
/// per peer for the connection's lifetime. All gossipsub RPCs (SUBSCRIBE,
/// GRAFT, PRUNE, IHAVE, IWANT, **publish**) multiplex onto this stream
/// back-to-back without FIN.
///
/// **Why only one stream:** rust-libp2p's gossipsub handler caps inbound
/// substreams per connection at `MAX_SUBSTREAM_ATTEMPTS = 1`
/// (`MaxInboundSubstreams` in `GossipsubHandlerError`). Opening a second
/// `/meshsub` stream — whether for a publish (per-message-stream pattern) or
/// to retry after a wedge — trips that limit, the rust handler is disabled,
/// and **all** gossip on that connection dies permanently.
///
/// Consequently this code never:
///   * opens a per-message publish stream (publishes ride this stream too);
///   * recreates the stream after a wedge (a wedge means the peer's gossip
///     handler is broken — opening a new stream cannot fix it).
///
/// On wedge: the stream is marked `broken`, outbox is dropped, and the
/// underlying QUIC connection is closed locally so `connection_manager`
/// redials and `ensurePersistentGossipStream` opens a fresh stream.
const PersistentGossipStream = struct {
    peer: identity.PeerId,
    stream_id: u64,
    raw: PublishBidiStream,
    handshake_sent: bool = false,
    handshake_done: bool = false,
    /// Set when the multistream-select handshake or a frame write fails.
    /// Once broken, the stream is never revived for the remainder of the
    /// underlying QUIC connection's lifetime; new outbox enqueues are dropped
    /// and the drain loop skips this entry.
    broken: bool = false,
    /// Queue of `uvarint(len) + RPC protobuf` frames waiting to be flushed
    /// once the multistream-select handshake completes. Bytes are heap-owned;
    /// drained in FIFO order. Capped at [`persistent_gossip_outbox_cap`] so a
    /// peer that never reads cannot make us hold unbounded memory before the
    /// QUIC keepalive notices and tears down the connection.
    outbox: std.ArrayList([]u8) = .empty,
    /// Wall-clock time of the most recent successful flush on this stream.
    /// Used by [`maybeSendPersistentGossipKeepalive`] to emit an empty-control
    /// RPC every [`persistent_gossip_keepalive_interval_ms`] when the stream
    /// is otherwise idle. Without this, rust-libp2p's gossipsub handler
    /// receives no application-layer traffic on stable-mesh topics and the
    /// connection is torn down with an error close once its idle timer
    /// fires — independent of QUIC-layer keepalive PINGs which only refresh
    /// the transport idle timer, not the libp2p handler's keep-alive.
    /// Seeded at handshake completion so the first keepalive fires one full
    /// interval later, not immediately on connect.
    last_write_ms: i64 = 0,
};

/// Hard cap on queued outbox frames per peer before the persistent gossip
/// stream is marked broken. Picked to accommodate ~30 seconds of gossip on a
/// healthy mainnet topic without unbounded growth on a wedged peer.
const persistent_gossip_outbox_cap: usize = 1024;

/// Interval at which an empty-control gossipsub RPC is pushed onto an
/// otherwise-idle persistent `/meshsub` stream. The frame is a no-op at the
/// gossipsub layer (one `ControlMessage` field with all sub-fields absent)
/// but generates real wire traffic, which is what rust-libp2p's connection
/// handler needs to keep the connection alive on a stable mesh topic.
///
/// 20s is comfortably under rust-libp2p's default `idle_timeout` for both
/// gossipsub (60s) and the underlying `libp2p-quic` (30s effective) so we
/// always refresh both timers with at least 10s of slack before they fire.
const persistent_gossip_keepalive_interval_ms: i64 = 20_000;

/// A queued command from the swarm hook to the drive thread.
const HookWork = union(enum) {
    dial: struct {
        addr: []u8,
        expected_peer: ?identity.PeerId,
    },
    send_request: struct {
        peer: identity.PeerId,
        proto: protocol_mod.LeanSupportedProtocol,
        request_id: u64,
        payload: []u8,
    },
    send_response_chunk: struct {
        peer: identity.PeerId,
        request_id: u64,
        chunk: []u8,
    },
    send_end_of_stream: struct {
        peer: identity.PeerId,
        request_id: u64,
    },
    send_error_response: struct {
        peer: identity.PeerId,
        request_id: u64,
    },
    publish: struct {
        topic: []u8,
        payload: []u8,
    },
    /// gossipsub SUBSCRIBE — broadcast to every connected peer on its
    /// persistent `/meshsub/1.1.0` stream (#183).
    subscribe: struct {
        topic: []u8,
    },
};

fn freeHookWork(a: std.mem.Allocator, w: HookWork) void {
    switch (w) {
        .dial => |d| a.free(d.addr),
        .send_request => |r| a.free(r.payload),
        .send_response_chunk => |r| a.free(r.chunk),
        .publish => |p| {
            a.free(p.topic);
            a.free(p.payload);
        },
        .subscribe => |s| a.free(s.topic),
        .send_end_of_stream, .send_error_response => {},
    }
}

pub const QuicRuntime = struct {
    allocator: std.mem.Allocator,
    host: *host_mod.Host,
    opts: QuicRuntimeOptions,
    tls_pem_resolved: ResolvedTlsPem,

    listener: *quic_endpoint.QuicListener,
    bound_port_v4: ?u16 = null,

    outbound_by_peer: PeerIdMap,
    /// Verified inbound QUIC connections keyed by remote peer id.
    inbound_by_peer: InboundPeerMap,
    /// Inbound streams keyed by an internal monotonic id; supports lookup by
    /// (slot, stream_id) for incoming-stream callbacks.
    inbound_streams: std.ArrayList(*InboundStream),
    /// Outbound request streams indexed by req/resp `request_id`.
    outbound_requests: std.AutoHashMap(u64, *OutboundRequest),
    /// Outbound gossipsub publish streams (one stream per publish per peer).
    /// Indexed by a monotonic id; entries are removed once the write completes
    /// and we've FIN'd the stream.
    outbound_publishes: std.AutoHashMap(u64, *OutboundPublish),
    next_publish_id: u64 = 1,

    /// Persistent per-peer `/meshsub/1.1.0` streams keyed by remote peer id
    /// (#183). Opened on connection establishment, alive until peer
    /// disconnect. All publish + control RPCs to that peer ride this stream.
    persistent_gossip: PersistentGossipMap,

    /// Topics we have subscribed to locally — used to (a) queue SUBSCRIBE
    /// frames into freshly-opened persistent streams so newly-connected
    /// peers see our subscription, (b) re-broadcast on subscribe.
    /// Keys are heap-owned `[]u8` topic strings.
    subscribed_topics: std.StringHashMap(void),
    /// Inbound channels: req/resp's `channel_id` -> the InboundStream that
    /// originated it. So when `.send_response_chunk` etc. arrive we can find
    /// the stream to write back on.
    channel_to_inbound: std.AutoHashMap(u64, *InboundStream),

    next_conn_id: connection_manager_mod.ConnectionId = 1,
    /// Per-slot conn id for inbound. Populated when an inbound stream first
    /// fires (lazy verify of remote peer id from TLS).
    inbound_conn_ids: [ZIo.MAX_CONNECTIONS]connection_manager_mod.ConnectionId = .{0} ** ZIo.MAX_CONNECTIONS,
    inbound_conn_notified: [ZIo.MAX_CONNECTIONS]bool = .{false} ** ZIo.MAX_CONNECTIONS,
    inbound_conn_peer: [ZIo.MAX_CONNECTIONS]?identity.PeerId = .{null} ** ZIo.MAX_CONNECTIONS,

    /// Cross-thread hook → drive-thread work queue. Hook runs on swarm
    /// thread; drive thread drains via [`drainHookWork`]. Synchronization
    /// uses [`std.Io.Mutex`] backed by the host swarm's `Io` instance so
    /// both producer (swarm thread) and consumer (drive thread) speak the
    /// same primitive.
    hook_mutex: std.Io.Mutex = .init,
    hook_queue: std.ArrayList(HookWork) = .empty,

    relay_live: quic_relay_live.LiveRelay,
    dcutr_live: quic_dcutr_live.LiveDcutr,
    relay_addrs_buf: ?[]u8 = null,
    auto_reserve_pending: bool = false,

    /// Drive thread control.
    drive_thread: ?std.Thread = null,
    shutdown_requested: std.atomic.Value(bool) = .init(false),
    started: bool = false,

    /// Cached raw Identify protobuf for inbound `/ipfs/id/1.0.0` replies.
    identify_reply_wire: ?[]u8 = null,

    /// CommandDispatchHook context — must be heap-stable so the swarm can
    /// hold a `*anyopaque` to it across runtime moves (it can't because we
    /// only allow `*QuicRuntime`).
    pub fn create(opts: QuicRuntimeOptions) anyerror!*QuicRuntime {
        const a = opts.allocator;

        const tls_pem_resolved = resolveTlsPemSource(opts.tls_pem);

        var listen_ma = try multiaddr.Multiaddr.fromString(a, opts.listen_multiaddr);
        defer listen_ma.deinit();

        // Build the listener TLS config: borrow paths for `.paths`, borrow
        // PEM bytes for `.bytes` (zquic v1.6.6 parses bytes in memory; no
        // temp file is written to disk).
        var listen_opts: quic_v1.Libp2pZquicServerOptions = .{};
        switch (tls_pem_resolved) {
            .paths => |p| {
                listen_opts.cert_path = p.cert_path;
                listen_opts.key_path = p.key_path;
            },
            .bytes => |b| {
                listen_opts.cert_pem = b.cert_pem;
                listen_opts.key_pem = b.key_pem;
            },
        }
        const listener = try quic_endpoint.QuicListener.listen(a, listen_ma, listen_opts);
        errdefer listener.deinit();

        const self = try a.create(QuicRuntime);
        errdefer a.destroy(self);

        const relay_hooks = quic_relay_live.RuntimeHooks{
            .ctx = self,
            .dial_plain = relayHookDialPlain,
            .outbound_client = relayHookOutboundClient,
            .next_bidi_stream = relayHookNextBidiStream,
            .on_relayed_connected = relayHookRelayedConnected,
            .on_relayed_dial_failed = relayHookRelayedDialFailed,
            .next_conn_id = relayHookNextConnId,
        };
        const dcutr_hooks = quic_dcutr_live.RuntimeHooks{
            .ctx = self,
            .now_ms = opts.now_ms_fn,
            .listener_port_v4 = dcutrHookListenerPort,
            .tls_pem_paths = dcutrHookTlsPaths,
            .tls_pem_bytes = dcutrHookTlsBytes,
            .use_pem_bytes = dcutrHookUsePemBytes,
            .on_direct_connected = dcutrHookDirectConnected,
            .close_relayed = dcutrHookCloseRelayed,
        };

        self.* = .{
            .allocator = a,
            .host = opts.host,
            .opts = opts,
            .tls_pem_resolved = tls_pem_resolved,
            .listener = listener,
            .outbound_by_peer = PeerIdMap.init(a),
            .inbound_by_peer = InboundPeerMap.init(a),
            .inbound_streams = .empty,
            .outbound_requests = std.AutoHashMap(u64, *OutboundRequest).init(a),
            .outbound_publishes = std.AutoHashMap(u64, *OutboundPublish).init(a),
            .channel_to_inbound = std.AutoHashMap(u64, *InboundStream).init(a),
            .relay_live = quic_relay_live.LiveRelay.init(a, opts.host.swarm.local_peer, .{
                .enable_server = opts.relay.enable_server,
                .enable_client = opts.relay.enable_client,
            }, relay_hooks),
            .dcutr_live = quic_dcutr_live.LiveDcutr.init(a, .{
                .enable = opts.dcutr.enable,
                .local_obs_addrs = opts.dcutr.local_obs_addrs,
            }, dcutr_hooks),
            .persistent_gossip = PersistentGossipMap.init(a),
            .subscribed_topics = std.StringHashMap(void).init(a),
        };

        const bound = listener.boundUdpPortIpv4() catch null;
        self.bound_port_v4 = bound;

        if (bound) |port| {
            const relay_addr = std.fmt.allocPrint(a, "/ip4/0.0.0.0/udp/{d}/quic-v1", .{port}) catch null;
            if (relay_addr) |ra| {
                self.relay_addrs_buf = ra;
                self.relay_live.setRelayAddrs(&.{ra}) catch {
                    a.free(ra);
                    self.relay_addrs_buf = null;
                };
            }
        }
        if (opts.relay.auto_reserve_relay != null) {
            self.auto_reserve_pending = true;
        }

        // Install the swarm CommandDispatchHook by patching it onto the
        // already-constructed swarm. host.zig owns the swarm but doesn't
        // expose a "set hook" mutator; we set the field directly. This is
        // safe because we run before `start` (no commands flowing yet).
        opts.host.swarm.command_dispatch = .{
            .ctx = self,
            .dispatch = swarmHookDispatch,
        };

        // Install QUIC lifecycle hooks for inbound stream readiness.
        listener.lifecycle = .{
            .ctx = self,
            .on_connection_established = onLifecycleConnected,
            .on_connection_closed = onLifecycleClosed,
            .on_inbound_stream_ready = onLifecycleInboundStream,
        };

        return self;
    }

    pub fn destroy(self: *QuicRuntime) void {
        self.stop();

        // Drain hook queue (drive thread already joined, but be defensive).
        for (self.hook_queue.items) |w| freeHookWork(self.allocator, w);
        self.hook_queue.deinit(self.allocator);

        self.relay_live.deinit();
        self.dcutr_live.deinit();
        if (self.relay_addrs_buf) |b| self.allocator.free(b);
        if (self.identify_reply_wire) |w| self.allocator.free(w);

        // Free outbound conns.
        var it = self.outbound_by_peer.valueIterator();
        while (it.next()) |v| {
            v.*.outbound.deinit();
            self.allocator.destroy(v.*);
        }
        self.outbound_by_peer.deinit();
        self.inbound_by_peer.deinit();

        // Free inbound streams.
        for (self.inbound_streams.items) |s| {
            s.req_acc.deinit(self.allocator);
            s.gossip_acc.deinit(self.allocator);
            s.relay_acc.deinit(self.allocator);
            s.ms_acc.deinit(self.allocator);
            s.ms_tail.deinit(self.allocator);
            self.allocator.destroy(s);
        }
        self.inbound_streams.deinit(self.allocator);

        // Free outbound requests.
        var rit = self.outbound_requests.valueIterator();
        while (rit.next()) |r| {
            self.allocator.free(r.*.payload);
            r.*.resp_acc.deinit(self.allocator);
            self.allocator.destroy(r.*);
        }
        self.outbound_requests.deinit();

        // Free outbound publishes.
        var pit = self.outbound_publishes.valueIterator();
        while (pit.next()) |p| {
            self.allocator.free(p.*.wire);
            self.allocator.destroy(p.*);
        }
        self.outbound_publishes.deinit();

        // Free persistent gossip streams + their outbox bytes.
        var git = self.persistent_gossip.valueIterator();
        while (git.next()) |g| {
            for (g.*.outbox.items) |w| self.allocator.free(w);
            g.*.outbox.deinit(self.allocator);
            self.allocator.destroy(g.*);
        }
        self.persistent_gossip.deinit();

        var st_it = self.subscribed_topics.keyIterator();
        while (st_it.next()) |k| self.allocator.free(k.*);
        self.subscribed_topics.deinit();

        self.channel_to_inbound.deinit();

        // Unlink the hook so swarm doesn't keep calling into freed memory.
        self.host.swarm.command_dispatch = null;
        self.listener.lifecycle = .{};

        self.listener.deinit();
        // `tls_pem_resolved` borrows the embedder's TlsPemSource slices —
        // nothing to free.
        self.allocator.destroy(self);
    }

    pub fn boundUdpPortIpv4(self: *const QuicRuntime) ?u16 {
        return self.bound_port_v4;
    }

    pub fn start(self: *QuicRuntime) anyerror!void {
        if (self.started) return;
        self.started = true;
        self.shutdown_requested.store(false, .release);
        self.drive_thread = try std.Thread.spawn(.{}, driveTrampoline, .{self});
    }

    pub fn stop(self: *QuicRuntime) void {
        if (!self.started) return;
        self.shutdown_requested.store(true, .release);
        if (self.drive_thread) |t| {
            t.join();
            self.drive_thread = null;
        }
        self.started = false;
    }

    pub fn registerKnownPeer(
        self: *QuicRuntime,
        ma: *const multiaddr.Multiaddr,
        peer_override: ?identity.PeerId,
    ) anyerror!void {
        try self.host.connection_manager.registerKnownPeer(ma, peer_override);
    }

    // ── CommandDispatchHook ────────────────────────────────────────────────

    fn swarmHookDispatch(ctx: ?*anyopaque, cmd: *const swarm_mod.OwnedCommand) swarm_mod.CommandDispatchHook.Disposition {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        return self.dispatchOwnedCommand(cmd);
    }

    fn dispatchOwnedCommand(self: *QuicRuntime, cmd: *const swarm_mod.OwnedCommand) swarm_mod.CommandDispatchHook.Disposition {
        const a = self.allocator;
        switch (cmd.*) {
            .dial => |d| {
                self.enqueueHookWork(.{ .dial = .{
                    .addr = d.addr,
                    .expected_peer = d.expected_peer,
                } });
                return .handled;
            },
            .send_request => |r| {
                self.enqueueHookWork(.{ .send_request = .{
                    .peer = r.peer,
                    .proto = r.protocol,
                    .request_id = r.request_id,
                    .payload = r.payload,
                } });
                return .handled;
            },
            .send_response_chunk => |r| {
                self.enqueueHookWork(.{ .send_response_chunk = .{
                    .peer = r.peer,
                    .request_id = r.request_id,
                    .chunk = r.chunk,
                } });
                return .handled;
            },
            .send_end_of_stream => |e| {
                self.enqueueHookWork(.{ .send_end_of_stream = .{
                    .peer = e.peer,
                    .request_id = e.request_id,
                } });
                return .handled;
            },
            .send_error_response => |e| {
                self.enqueueHookWork(.{ .send_error_response = .{
                    .peer = e.peer,
                    .request_id = e.request_id,
                } });
                return .handled;
            },
            .publish => |p| {
                self.enqueueHookWork(.{ .publish = .{
                    .topic = p.topic,
                    .payload = p.payload,
                } });
                return .handled;
            },
            .subscribe => |s| {
                self.enqueueHookWork(.{ .subscribe = .{ .topic = s.topic } });
                return .handled;
            },
            .shutdown => return .fallthrough,
        }
        _ = a;
    }

    fn enqueueHookWork(self: *QuicRuntime, w: HookWork) void {
        const io = self.host.swarm.io;
        self.hook_mutex.lockUncancelable(io);
        defer self.hook_mutex.unlock(io);
        self.hook_queue.append(self.allocator, w) catch |err| {
            log.err("quic_runtime: hook queue append failed: {s}", .{@errorName(err)});
            freeHookWork(self.allocator, w);
        };
    }

    fn drainHookWork(self: *QuicRuntime, into: *std.ArrayList(HookWork)) void {
        const io = self.host.swarm.io;
        self.hook_mutex.lockUncancelable(io);
        defer self.hook_mutex.unlock(io);
        if (self.hook_queue.items.len == 0) return;
        into.appendSlice(self.allocator, self.hook_queue.items) catch return;
        self.hook_queue.clearRetainingCapacity();
    }

    // ── QuicListener lifecycle ─────────────────────────────────────────────

    fn onLifecycleConnected(ctx: ?*anyopaque, slot: usize, _: *ZIo.ConnState) void {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        if (!self.inbound_conn_notified[slot]) {
            // We don't yet have the verified peer id (TLS handshake might be
            // freshly complete). Delay onConnectionEstablished until first
            // inbound stream when peer id is available.
            self.inbound_conn_ids[slot] = self.next_conn_id;
            self.next_conn_id += 1;
        }
    }

    fn onLifecycleClosed(ctx: ?*anyopaque, slot: usize) void {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        if (self.inbound_conn_notified[slot]) {
            const peer = self.inbound_conn_peer[slot] orelse identity.PeerId.random() catch return;
            const cid = self.inbound_conn_ids[slot];
            const now_ms = self.opts.now_ms_fn();
            self.host.onConnectionClosed(now_ms, cid, peer, .remote_close) catch |e| {
                log.warn("quic_runtime: onConnectionClosed failed: {s}", .{@errorName(e)});
            };
            _ = self.inbound_by_peer.remove(peer);
            self.destroyPersistentGossipStream(peer);
        }
        self.inbound_conn_notified[slot] = false;
        self.inbound_conn_peer[slot] = null;
        self.inbound_conn_ids[slot] = 0;
    }

    /// Detect outbound QUIC connections that the remote peer has closed
    /// (`CONNECTION_CLOSE` frame received, or transport idle-timeout fired locally)
    /// and surface them via `host.onConnectionClosed`. Without this poll, zeam keeps
    /// the dead entry in `outbound_by_peer` and `connection_manager` never schedules
    /// a redial — gossip stays silent forever even though the underlying transport
    /// has signalled the disconnect.
    ///
    /// Mirrors the listener-side [`QuicListener.syncSeenFlags`] which fires
    /// [`onLifecycleClosed`] for inbound connections.
    fn detectOutboundConnectionClose(self: *QuicRuntime) void {
        // Two-pass: collect peers to evict, then mutate the map. Avoids invalidating
        // the iterator on `fetchRemove` and keeps the close handling identical to
        // the inbound path (host callback then destroyPersistentGossipStream).
        var to_close: std.ArrayList(identity.PeerId) = .empty;
        defer to_close.deinit(self.allocator);

        var it = self.outbound_by_peer.iterator();
        while (it.next()) |entry| {
            const slot = entry.value_ptr.*;
            const conn = &slot.outbound.client.conn;
            // `draining` flips to true as soon as we send or receive a
            // CONNECTION_CLOSE frame (see zquic transport/io.zig). The
            // QUIC spec requires us to keep the connection state around for
            // 3*PTO afterwards, so `phase` does not move to `.closed` for
            // hundreds of ms (longer if the deadline math drags). For our
            // purposes — telling the connection_manager that the link is
            // dead and clearing publish state — draining is the moment of
            // truth.
            const cur_closed = (conn.phase == .closed) or conn.draining;
            if (slot.notified and !slot.prev_closed and cur_closed) {
                to_close.append(self.allocator, entry.key_ptr.*) catch {};
            }
            slot.prev_closed = cur_closed;
        }

        for (to_close.items) |peer| {
            const slot = self.outbound_by_peer.get(peer) orelse continue;
            const cid = slot.conn_id;
            const now_ms = self.opts.now_ms_fn();
            log.info(
                "quic_runtime: outbound QUIC connection closed by remote (cid={d}); notifying host",
                .{cid},
            );
            self.host.onConnectionClosed(now_ms, cid, peer, .remote_close) catch |e| {
                log.warn("quic_runtime: outbound onConnectionClosed failed: {s}", .{@errorName(e)});
            };
            self.destroyPersistentGossipStream(peer);
            if (self.outbound_by_peer.fetchRemove(peer)) |kv| {
                kv.value.outbound.deinit();
                self.allocator.destroy(kv.value);
            }
        }
    }

    fn onLifecycleInboundStream(
        ctx: ?*anyopaque,
        _: *quic_endpoint.QuicListener,
        slot: usize,
        conn: *ZIo.ConnState,
        stream_id: u64,
    ) void {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        self.startInboundStream(slot, conn, stream_id) catch |err| {
            log.warn("quic_runtime: startInboundStream failed: {s}", .{@errorName(err)});
        };
    }

    fn startInboundStream(self: *QuicRuntime, slot: usize, conn: *ZIo.ConnState, stream_id: u64) !void {
        const ist = try self.allocator.create(InboundStream);
        ist.* = .{
            .slot = slot,
            .conn = conn,
            .stream_id = stream_id,
            .raw = .{
                .server = self.listener.server,
                .conn = conn,
                .stream_id = stream_id,
            },
        };
        try self.inbound_streams.append(self.allocator, ist);
    }

    /// Sentinel slot value for [`InboundStream.slot`] when the stream arrived on an outbound
    /// (client-side) QUIC connection and has no corresponding listener slot.
    const inbound_slot_none: usize = std.math.maxInt(usize);

    /// Detect server-initiated bidi streams that the remote peer opened on one of zeam's
    /// outbound QUIC connections and surface them as inbound streams.
    ///
    /// Gossipsub in rust-libp2p (and go-libp2p) opens its own `/meshsub/1.1.0` stream
    /// on the connection that zeam dialled.  From zeam's perspective these are inbound
    /// streams on an *outbound* QUIC connection (QUIC stream IDs 1, 5, 9 … — server-
    /// initiated bidi).  The listener lifecycle callback fires only for connections that
    /// zeam accepted, so without this sweep those streams are never added to
    /// `inbound_streams` and ethlambda's gossipsub messages are silently lost.
    fn dispatchOutboundPeerStreams(self: *QuicRuntime, slot: *OutboundConn) void {
        const peer_id = slot.peer_id orelse return;
        const client = slot.outbound.client;
        while (true) {
            const scan = quic_endpoint.popNextUnreportedServerBidiStream(
                client,
                &slot.peer_stream_reported,
            );
            const sid = scan.stream_id orelse break;
            const ist = self.allocator.create(InboundStream) catch break;
            ist.* = .{
                .slot = inbound_slot_none,
                .conn = &client.conn,
                .stream_id = sid,
                .raw = .{
                    .server = self.listener.server, // placeholder; writes go through .client
                    .conn = &client.conn,
                    .stream_id = sid,
                    .client = client,
                },
                .known_peer_id = peer_id,
            };
            self.inbound_streams.append(self.allocator, ist) catch {
                self.allocator.destroy(ist);
                break;
            };
        }
    }

    // ── Drive thread ───────────────────────────────────────────────────────

    fn driveTrampoline(self: *QuicRuntime) void {
        self.driveLoop() catch |err| {
            log.err("quic_runtime: drive loop exited with {s}", .{@errorName(err)});
        };
    }

    fn driveLoop(self: *QuicRuntime) !void {
        var recv_buf: [65536]u8 = undefined;
        var work_scratch: std.ArrayList(HookWork) = .empty;
        defer work_scratch.deinit(self.allocator);

        var last_tick_ms = self.opts.now_ms_fn();
        while (!self.shutdown_requested.load(.acquire)) {
            const poll_to: u32 = 5; // short timeout so we can multiplex
            // Drive listener.
            self.listener.drive(&recv_buf, poll_to) catch |err| {
                log.warn("quic_runtime: listener.drive: {s}", .{@errorName(err)});
            };
            // pollAccept once per loop so the lifecycle callback fires.
            _ = self.listener.pollAccept();

            // Drive every active outbound, then surface any remote-initiated streams.
            {
                var it = self.outbound_by_peer.valueIterator();
                while (it.next()) |v| {
                    v.*.outbound.drive(&recv_buf, 0) catch |err| {
                        log.warn("quic_runtime: outbound.drive: {s}", .{@errorName(err)});
                    };
                    self.dispatchOutboundPeerStreams(v.*);
                }
            }

            // Detect outbound connections the remote closed (CONNECTION_CLOSE / idle
            // timeout) and surface to the host so connection_manager can redial.
            // Must run AFTER outbound.drive so zquic has processed any inbound packets
            // that triggered the phase transition this tick.
            self.detectOutboundConnectionClose();

            // Drain hook queue.
            self.drainHookWork(&work_scratch);
            for (work_scratch.items) |w| {
                self.handleHookWork(w) catch |err| {
                    log.warn("quic_runtime: hook handler error: {s}", .{@errorName(err)});
                    freeHookWork(self.allocator, w);
                };
            }
            work_scratch.clearRetainingCapacity();

            // Advance inbound streams (multistream + framing).
            self.advanceInboundStreams() catch |err| {
                log.warn("quic_runtime: advanceInboundStreams: {s}", .{@errorName(err)});
            };

            // Advance outbound request streams.
            self.advanceOutboundRequests() catch |err| {
                log.warn("quic_runtime: advanceOutboundRequests: {s}", .{@errorName(err)});
            };

            // Advance outbound gossipsub publish streams.
            self.advanceOutboundPublishes() catch |err| {
                log.warn("quic_runtime: advanceOutboundPublishes: {s}", .{@errorName(err)});
            };

            self.relay_live.advance();
            self.dcutr_live.advance();

            if (self.auto_reserve_pending) {
                if (self.opts.relay.auto_reserve_relay) |relay_ma| {
                    var ma = multiaddr.Multiaddr.fromString(self.allocator, relay_ma) catch null;
                    if (ma) |*m| {
                        defer m.deinit();
                        var iter = m.iterator();
                        var relay_peer: ?identity.PeerId = null;
                        while (iter.next() catch break) |proto| {
                            switch (proto) {
                                .P2P => |id| relay_peer = id,
                                else => {},
                            }
                        }
                        if (relay_peer) |rp| {
                            if (self.outbound_by_peer.contains(rp)) {
                                self.relay_live.reserveOnRelay(rp) catch |err| {
                                    log.warn("quic_runtime: auto reserve failed: {s}", .{@errorName(err)});
                                };
                                self.auto_reserve_pending = false;
                            }
                        }
                    }
                }
            }

            // Advance persistent per-peer /meshsub streams (#183).
            self.advancePersistentGossipStreams();

            // Periodic host ticks (~ every 100ms).
            const now_ms = self.opts.now_ms_fn();
            if (now_ms - last_tick_ms >= 100) {
                last_tick_ms = now_ms;
                self.host.runPeriodicTicks(now_ms) catch |err| {
                    log.warn("quic_runtime: host periodic ticks: {s}", .{@errorName(err)});
                };
                self.drainGossipsubOutbox();
            }
        }
    }

    fn handleHookWork(self: *QuicRuntime, w: HookWork) !void {
        switch (w) {
            .dial => |d| {
                defer self.allocator.free(d.addr);
                self.handleDial(d.addr, d.expected_peer);
            },
            .send_request => |r| {
                try self.startOutboundRequest(r.peer, r.proto, r.request_id, r.payload);
                // payload ownership moved into OutboundRequest; do NOT free here.
            },
            .send_response_chunk => |r| {
                defer self.allocator.free(r.chunk);
                self.handleSendResponseChunk(r.peer, r.request_id, r.chunk);
            },
            .send_end_of_stream => |e| {
                self.handleEndOfStream(e.peer, e.request_id);
            },
            .send_error_response => |e| {
                self.handleEndOfStream(e.peer, e.request_id);
            },
            .publish => |p| {
                defer self.allocator.free(p.topic);
                defer self.allocator.free(p.payload);
                self.onPublishCommand(p.topic, p.payload);
            },
            .subscribe => |s| {
                defer self.allocator.free(s.topic);
                self.onSubscribeCommand(s.topic);
            },
        }
    }

    /// Outbound gossipsub publish path.
    ///
    fn peerHasActiveConnection(self: *QuicRuntime, peer: identity.PeerId) bool {
        return self.host.connection_manager.hasActiveConnection(peer);
    }

    fn peerBase58(peer: identity.PeerId, buf: *[128]u8) []const u8 {
        return peer.toBase58(buf) catch "<peer-id-format-err>";
    }

    /// The swarm's `.publish` command carries raw `(topic, payload)` — the
    /// payload is the application data, not the gossipsub RPC frame.  We
    /// build the RPC protobuf here (`Message{topic, data}` wrapped in
    /// `RPC.publish[]`), length-prefix it with an unsigned varint per the
    /// libp2p gossipsub wire spec, and open a fresh `/meshsub/1.1.0` stream
    /// to every currently connected peer (outbound dials and inbound accepts).
    fn onPublishCommand(self: *QuicRuntime, topic: []const u8, payload: []const u8) void {
        const a = self.allocator;

        // Build the gossipsub `Message` and wrap as `RPC.publish[0]`.
        const inner = gossipsub_msg.encode(a, .{ .topic = topic, .data = payload }) catch |err| {
            log.warn("quic_runtime: gossipsub message encode failed: {s}", .{@errorName(err)});
            return;
        };
        defer a.free(inner);
        if (inner.len > gossipsub_cfg.max_transmit_size_bytes) {
            log.warn("quic_runtime: gossipsub publish dropped: payload {d} bytes exceeds max_transmit_size {d}", .{
                inner.len,
                gossipsub_cfg.max_transmit_size_bytes,
            });
            return;
        }
        if (inner.len > gossipsub_wire_limits.max_rpc_length_delimited_bytes) {
            log.warn("quic_runtime: gossipsub publish dropped: payload {d} bytes exceeds wire limit {d}", .{
                inner.len,
                gossipsub_wire_limits.max_rpc_length_delimited_bytes,
            });
            return;
        }
        const rpc_frame = gossipsub_rpc.encodePublish(a, inner) catch |err| {
            log.warn("quic_runtime: gossipsub RPC encode failed: {s}", .{@errorName(err)});
            return;
        };
        defer a.free(rpc_frame);

        // Build `uvarint(len) + rpc_frame` once; clone per peer.
        var wire_buf: std.ArrayList(u8) = .empty;
        defer wire_buf.deinit(a);
        varint.append(&wire_buf, a, @intCast(rpc_frame.len)) catch return;
        wire_buf.appendSlice(a, rpc_frame) catch return;

        var peers: std.ArrayList(identity.PeerId) = .empty;
        defer peers.deinit(a);
        self.collectConnectedPeers(&peers) catch return;

        if (peers.items.len == 0) {
            log.debug("quic_runtime: gossipsub publish topic={s} inner_bytes={d} wire_bytes={d}: no connected peers", .{
                topic,
                inner.len,
                wire_buf.items.len,
            });
            return;
        }

        log.info("quic_runtime: gossipsub publish topic={s} inner_bytes={d} wire_bytes={d} peer_count={d}", .{
            topic,
            inner.len,
            wire_buf.items.len,
            peers.items.len,
        });

        for (peers.items) |peer| {
            const wire_dup = a.dupe(u8, wire_buf.items) catch continue;
            // Publishes ride the single per-peer persistent `/meshsub` stream
            // alongside SUBSCRIBE / GRAFT / PRUNE. See [`PersistentGossipStream`]
            // for why opening a per-message stream here would trip rust-libp2p's
            // `MaxInboundSubstreams` cap and kill all gossip on the connection.
            self.enqueueGossipFrame(peer, wire_dup);
        }
    }

    /// Handle the swarm `.subscribe(topic)` command (#183). Track the topic
    /// so we replay SUBSCRIBE on every future peer connection, then queue a
    /// SUBSCRIBE RPC into every currently-connected peer's persistent
    /// `/meshsub/1.1.0` stream.
    fn onSubscribeCommand(self: *QuicRuntime, topic: []const u8) void {
        const a = self.allocator;
        if (!self.subscribed_topics.contains(topic)) {
            const owned = a.dupe(u8, topic) catch return;
            self.subscribed_topics.put(owned, {}) catch {
                a.free(owned);
                return;
            };
        }

        var peers: std.ArrayList(identity.PeerId) = .empty;
        defer peers.deinit(a);
        self.collectConnectedPeers(&peers) catch return;
        for (peers.items) |peer| {
            const w = self.buildSubscribeWire(topic) orelse continue;
            self.enqueueGossipFrame(peer, w);
        }
    }

    fn collectConnectedPeers(self: *QuicRuntime, out: *std.ArrayList(identity.PeerId)) !void {
        const a = self.allocator;
        var it = self.outbound_by_peer.iterator();
        while (it.next()) |e| try out.append(a, e.key_ptr.*);
        var iit = self.inbound_by_peer.iterator();
        while (iit.next()) |e| {
            if (self.outbound_by_peer.contains(e.key_ptr.*)) continue;
            try out.append(a, e.key_ptr.*);
        }
    }

    fn buildSubscribeWire(self: *QuicRuntime, topic: []const u8) ?[]u8 {
        const a = self.allocator;
        const rpc_frame = gossipsub_rpc.encodeSubscribe(a, topic, true) catch return null;
        defer a.free(rpc_frame);
        return lengthPrefixGossipRpcFrame(a, rpc_frame);
    }

    /// Wrap a raw gossipsub `RPC` protobuf blob in the unsigned-varint length prefix
    /// required on every `/meshsub/1.1.0` stream frame (persistent or per-message).
    fn lengthPrefixGossipRpcFrame(allocator: std.mem.Allocator, rpc_frame: []const u8) ?[]u8 {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        varint.append(&buf, allocator, @intCast(rpc_frame.len)) catch return null;
        buf.appendSlice(allocator, rpc_frame) catch return null;
        return buf.toOwnedSlice(allocator) catch null;
    }

    /// Drain gossipsub control frames (GRAFT, PRUNE, IHAVE, IWANT, mesh forwards,
    /// SUBSCRIBE / UNSUBSCRIBE) queued by [`Gossipsub.heartbeat`],
    /// [`Gossipsub.handleInboundRpc`], and [`Gossipsub.subscribe`] /
    /// [`Gossipsub.unsubscribe`].
    ///
    /// Without this, zeam never ships the GRAFTs heartbeat generates and
    /// rust-libp2p (ethlambda) only publishes to mesh peers — so aggregation
    /// gossip from ethlambda never reaches zeam and justification stalls.
    ///
    /// Broadcast entries (`to == null`) are fanned out to every peer with an
    /// active persistent `/meshsub` stream. This is what [`Gossipsub.subscribe`]
    /// / [`Gossipsub.unsubscribe`] emit. The transport-side
    /// [`onSubscribeCommand`] still records the topic in `subscribed_topics`
    /// so it can be replayed to *future* connections; this fan-out covers
    /// already-connected peers in the same tick.
    fn drainGossipsubOutbox(self: *QuicRuntime) void {
        const a = self.allocator;
        const gs = self.host.gossipsub;
        while (gs.popOutboxDelivery()) |d| {
            defer a.free(d.wire);
            if (d.to) |peer| {
                if (!self.peerHasActiveConnection(peer)) continue;
                const framed = lengthPrefixGossipRpcFrame(a, d.wire) orelse continue;
                self.enqueueGossipFrame(peer, framed);
            } else {
                // Broadcast (SUBSCRIBE/UNSUBSCRIBE). Length-prefix once, clone per peer.
                // Targets every currently-connected peer (outbound and inbound)
                // so late `Gossipsub.subscribe` calls also reach existing peers,
                // not just future connections. New connections still get
                // SUBSCRIBE via `subscribed_topics` replay in
                // `onConnectionEstablished` / inbound-stream notify path.
                const framed = lengthPrefixGossipRpcFrame(a, d.wire) orelse continue;
                defer a.free(framed);
                var peers: std.ArrayList(identity.PeerId) = .empty;
                defer peers.deinit(a);
                self.collectConnectedPeers(&peers) catch continue;
                for (peers.items) |peer| {
                    const dup = a.dupe(u8, framed) catch continue;
                    self.enqueueGossipFrame(peer, dup);
                }
            }
        }
    }

    /// Open a persistent /meshsub/1.1.0 stream to `peer` if we don't already
    /// have one. On a fresh open, queue SUBSCRIBE for every topic we've
    /// joined so the peer learns of our subscriptions on its first read.
    ///
    /// **Outbound dial only:** gossip publishes must ride the QUIC connection
    /// zeam/libp2p initiated toward the peer. rust-libp2p attributes inbound
    /// gossipsub RPCs to the dialer leg; opening the persistent stream on a
    /// peer-initiated inbound connection delivers the first few frames then
    /// stalls once the outbound leg comes up.
    fn ensurePersistentGossipStream(self: *QuicRuntime, peer: identity.PeerId) ?*PersistentGossipStream {
        if (self.persistent_gossip.get(peer)) |existing| return existing;

        const slot = self.outbound_by_peer.get(peer) orelse return null;
        const a = self.allocator;

        var raw: PublishBidiStream = undefined;
        var stream_id: u64 = undefined;
        const sid = slot.outbound.nextLocalBidiStream() catch |err| {
            var peer_buf: [128]u8 = undefined;
            log.debug("quic_runtime: persistent gossip stream open failed peer={s} direction=outbound err={s}", .{
                peerBase58(peer, &peer_buf),
                @errorName(err),
            });
            return null;
        };
        stream_id = sid;
        raw = .{ .outbound = .{
            .client = slot.outbound.client,
            .stream_id = sid,
        } };

        const g = a.create(PersistentGossipStream) catch return null;
        g.* = .{
            .peer = peer,
            .stream_id = stream_id,
            .raw = raw,
        };
        self.persistent_gossip.put(peer, g) catch {
            a.destroy(g);
            return null;
        };
        var peer_buf: [128]u8 = undefined;
        log.debug("quic_runtime: opened persistent /meshsub stream peer={s} stream_id={d} leg=outbound", .{
            peerBase58(peer, &peer_buf),
            stream_id,
        });
        return g;
    }

    fn enqueueGossipFrame(self: *QuicRuntime, peer: identity.PeerId, wire: []u8) void {
        var peer_buf: [128]u8 = undefined;
        const peer_str = peerBase58(peer, &peer_buf);

        const g = self.ensurePersistentGossipStream(peer) orelse {
            log.info("quic_runtime: gossip frame dropped peer={s} wire_bytes={d}: no persistent stream", .{
                peer_str,
                wire.len,
            });
            self.allocator.free(wire);
            return;
        };
        if (g.broken) {
            log.info("quic_runtime: gossip frame dropped peer={s} wire_bytes={d}: persistent stream broken", .{
                peer_str,
                wire.len,
            });
            self.allocator.free(wire);
            return;
        }
        if (g.outbox.items.len >= persistent_gossip_outbox_cap) {
            log.warn(
                "quic_runtime: persistent gossip outbox cap ({d}) hit for peer={s}; marking stream broken",
                .{ persistent_gossip_outbox_cap, peer_str },
            );
            self.markPersistentGossipBroken(g, "outbox_cap");
            self.allocator.free(wire);
            return;
        }
        log.debug("quic_runtime: gossip frame queued peer={s} wire_bytes={d} outbox_depth={d}", .{
            peer_str,
            wire.len,
            g.outbox.items.len + 1,
        });
        g.outbox.append(self.allocator, wire) catch {
            log.info("quic_runtime: gossip frame dropped peer={s} wire_bytes={d}: outbox append failed", .{
                peer_str,
                wire.len,
            });
            self.allocator.free(wire);
        };
    }

    /// Mark the stream broken and drop all queued frames. The stream entry is
    /// kept in the map so subsequent enqueues short-circuit instead of opening
    /// a replacement (which would trip rust-libp2p's `MaxInboundSubstreams`).
    /// Also closes the QUIC connection so connection_manager can redial promptly.
    fn markPersistentGossipBroken(self: *QuicRuntime, g: *PersistentGossipStream, reason: []const u8) void {
        const peer = g.peer;
        var peer_buf: [128]u8 = undefined;
        log.info("quic_runtime: persistent gossip stream broken peer={s} reason={s} stream_id={d} queued_frames={d}", .{
            peerBase58(peer, &peer_buf),
            reason,
            g.stream_id,
            g.outbox.items.len,
        });
        g.broken = true;
        for (g.outbox.items) |w| self.allocator.free(w);
        g.outbox.clearRetainingCapacity();
        self.closePeerConnectionForGossipRecovery(peer);
    }

    /// Tear down the QUIC connection after a persistent `/meshsub` stream wedge.
    /// A broken stream cannot be recreated on the same connection (rust-libp2p
    /// `MaxInboundSubstreams`); closing the connection is the only recovery path.
    fn closePeerConnectionForGossipRecovery(self: *QuicRuntime, peer: identity.PeerId) void {
        var peer_buf: [128]u8 = undefined;
        const peer_str = peerBase58(peer, &peer_buf);
        if (self.outbound_by_peer.get(peer)) |slot| {
            if (slot.outbound.client.conn.phase != .closed) {
                log.info("quic_runtime: closing outbound QUIC connection for gossip recovery peer={s}", .{peer_str});
                slot.outbound.closeConnection();
            }
            return;
        }
        if (self.inbound_by_peer.get(peer)) |ic| {
            if (ic.conn.phase != .closed) {
                log.info("quic_runtime: closing inbound QUIC connection for gossip recovery peer={s}", .{peer_str});
                self.listener.server.closeConnection(ic.conn, 0, "gossip stream wedge");
            }
        }
    }

    fn destroyPersistentGossipStream(self: *QuicRuntime, peer: identity.PeerId) void {
        const g = self.persistent_gossip.fetchRemove(peer) orelse return;
        for (g.value.outbox.items) |w| self.allocator.free(w);
        g.value.outbox.deinit(self.allocator);
        self.allocator.destroy(g.value);
    }

    /// FIN the wire stream and drop the map entry. Used when migrating gossip
    /// publish from a peer-dialed inbound leg to our outbound dial leg.
    fn dropPersistentGossipStream(self: *QuicRuntime, peer: identity.PeerId) void {
        const g = self.persistent_gossip.get(peer) orelse return;
        if (g.handshake_sent and !g.broken) g.raw.finStream();
        self.destroyPersistentGossipStream(peer);
    }

    fn replaySubscribeToPeer(self: *QuicRuntime, peer: identity.PeerId) void {
        if (self.subscribed_topics.count() == 0) return;
        var t_it = self.subscribed_topics.keyIterator();
        while (t_it.next()) |topic_key| {
            const w = self.buildSubscribeWire(topic_key.*) orelse continue;
            self.enqueueGossipFrame(peer, w);
        }
    }

    /// Per-tick driver for the persistent /meshsub streams: complete the
    /// multistream-select handshake, then drain the outbox onto the wire.
    /// Never FINs.
    ///
    /// On handshake or write failure the stream is marked **broken** for the
    /// rest of the underlying QUIC connection — no retry, no replacement
    /// stream. See [`PersistentGossipStream`] for why opening a second
    /// `/meshsub` stream would kill all gossip to the peer instead of
    /// recovering anything.
    fn advancePersistentGossipStreams(self: *QuicRuntime) void {
        const a = self.allocator;

        var it = self.persistent_gossip.valueIterator();
        while (it.next()) |g_ptr| {
            const g = g_ptr.*;
            if (g.broken) continue;
            // Each of the three steps below (offer, ack, drain) is non-blocking
            // and falls through to the next when its precondition becomes
            // available in the same tick. The previous code returned `continue`
            // between steps, costing one reactor cycle (~100ms) per step — a
            // cold-start latency of ~200-400ms before the first SUBSCRIBE
            // could even leave the box. With small frames the responder's ack
            // is often already in `unreadRecvLen` by the time we finish
            // writing our offer, so coalescing here makes the common-case
            // mesh formation happen in one tick.
            if (!g.handshake_sent) {
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(a);
                // Delimited (length-prefixed) framing per go-multistream v0.5+
                // — same dialect rust-libp2p / go-libp2p use on QUIC. The
                // legacy newline framing would be misread by their
                // responders and the connection would be torn down (#183).
                stream_multistream.appendFirstStreamInitiatorHandshakeFramed(
                    &out,
                    a,
                    meshsub_initiator_offer,
                    .delimited,
                ) catch {
                    log.warn("quic_runtime: persistent gossip handshake build failed; marking stream broken", .{});
                    self.markPersistentGossipBroken(g, "handshake_build_failed");
                    continue;
                };
                var w = g.raw.writer();
                std.Io.Writer.writeAll(&w, out.items) catch {
                    log.warn("quic_runtime: persistent gossip handshake write failed; marking stream broken", .{});
                    self.markPersistentGossipBroken(g, "handshake_write_failed");
                    continue;
                };
                std.Io.Writer.flush(&w) catch {};
                g.handshake_sent = true;
                // Fall through: the responder ack may already be buffered.
            }
            if (!g.handshake_done) {
                if (g.raw.unreadRecvLen() == 0) continue;
                var r = g.raw.reader();
                var w = g.raw.writer();
                stream_multistream.initiatorHandshakeMeshsubReadPhase(&r, &w, a, null) catch |err| {
                    log.warn(
                        "quic_runtime: persistent gossip handshake failed: {s}; marking stream broken",
                        .{@errorName(err)},
                    );
                    self.markPersistentGossipBroken(g, "handshake_read_failed");
                    continue;
                };
                g.handshake_done = true;
                // Seed the keepalive baseline so the first empty-control RPC
                // fires `keepalive_interval` after handshake, not immediately.
                g.last_write_ms = self.opts.now_ms_fn();
                // Fall through: we may already have a SUBSCRIBE / GRAFT in
                // the outbox that can ship in this same tick.
            }
            // Only drain the outbox AFTER multistream-select completes —
            // otherwise the gossipsub RPC bytes would arrive before the
            // peer's responder negotiates `/meshsub/1.1.0` and rust-libp2p's
            // gossipsub codec would see them as a malformed initial frame.
            if (g.handshake_done and g.outbox.items.len > 0) {
                var w = g.raw.writer();
                var sent: usize = 0;
                var write_failed = false;
                for (g.outbox.items, 0..) |frame_wire, i| {
                    std.Io.Writer.writeAll(&w, frame_wire) catch {
                        write_failed = true;
                        sent = i;
                        break;
                    };
                    a.free(frame_wire);
                    sent = i + 1;
                }
                std.Io.Writer.flush(&w) catch {
                    write_failed = true;
                };
                if (write_failed) {
                    var peer_buf: [128]u8 = undefined;
                    log.warn(
                        "quic_runtime: persistent gossip write failed peer={s} after {d}/{d} frames; marking stream broken",
                        .{ peerBase58(g.peer, &peer_buf), sent, g.outbox.items.len },
                    );
                    // Free the unsent tail before marking broken (which clears).
                    if (sent < g.outbox.items.len) {
                        for (g.outbox.items[sent..]) |frame| a.free(frame);
                    }
                    g.outbox.clearRetainingCapacity();
                    self.markPersistentGossipBroken(g, "write_failed");
                    continue;
                }
                g.outbox.clearRetainingCapacity();
                g.last_write_ms = self.opts.now_ms_fn();
            }

            // App-layer keepalive: when the stream is healthy, handshaken,
            // and otherwise idle, emit an empty-control gossipsub RPC every
            // `persistent_gossip_keepalive_interval_ms`. See the field doc
            // on [`PersistentGossipStream.last_write_ms`] for rationale.
            if (g.handshake_done and !g.broken) {
                self.maybeSendPersistentGossipKeepalive(g);
            }
        }
    }

    /// If the persistent /meshsub stream `g` has been idle for at least
    /// [`persistent_gossip_keepalive_interval_ms`], synthesize and flush
    /// one length-prefixed empty-control gossipsub RPC to refresh the
    /// peer's application-layer connection handler.
    ///
    /// Wire shape (per go-libp2p-pubsub `rpc.proto`): a top-level `RPC`
    /// with field 3 (`ControlMessage control`) set to an empty submessage
    /// (2 bytes: tag 0x1a, length 0x00). Length-prefixed with the usual
    /// unsigned varint per the libp2p gossipsub framing. The receiver
    /// parses it as a valid RPC with no subscriptions, no publishes, and
    /// no control sub-messages — a true no-op at the gossipsub layer that
    /// still produces real bytes on the wire.
    fn maybeSendPersistentGossipKeepalive(self: *QuicRuntime, g: *PersistentGossipStream) void {
        const a = self.allocator;
        const now_ms = self.opts.now_ms_fn();
        if (g.last_write_ms == 0) g.last_write_ms = now_ms; // safety net
        if (now_ms - g.last_write_ms < persistent_gossip_keepalive_interval_ms) return;

        const rpc_frame = gossipsub_rpc.encodeEmptyControlRpc(a) catch {
            // OOM here is non-fatal: skip this tick, try again next cycle.
            return;
        };
        defer a.free(rpc_frame);
        const framed = lengthPrefixGossipRpcFrame(a, rpc_frame) orelse return;
        defer a.free(framed);

        var w = g.raw.writer();
        std.Io.Writer.writeAll(&w, framed) catch {
            var peer_buf: [128]u8 = undefined;
            log.warn(
                "quic_runtime: persistent gossip keepalive write failed peer={s}; marking stream broken",
                .{peerBase58(g.peer, &peer_buf)},
            );
            self.markPersistentGossipBroken(g, "keepalive_write_failed");
            return;
        };
        std.Io.Writer.flush(&w) catch {
            var peer_buf: [128]u8 = undefined;
            log.warn(
                "quic_runtime: persistent gossip keepalive flush failed peer={s}; marking stream broken",
                .{peerBase58(g.peer, &peer_buf)},
            );
            self.markPersistentGossipBroken(g, "keepalive_flush_failed");
            return;
        };
        g.last_write_ms = now_ms;
        var peer_buf: [128]u8 = undefined;
        log.debug(
            "quic_runtime: persistent gossip keepalive sent peer={s} wire_bytes={d}",
            .{ peerBase58(g.peer, &peer_buf), framed.len },
        );
    }

    fn startOutboundPublish(self: *QuicRuntime, peer: identity.PeerId, wire: []u8) !void {
        const slot = self.outbound_by_peer.get(peer) orelse return error.NotConnected;
        const sid = try slot.outbound.nextLocalBidiStream();
        const pub_id = self.next_publish_id;
        self.next_publish_id += 1;

        const op = try self.allocator.create(OutboundPublish);
        op.* = .{
            .peer = peer,
            .stream_id = sid,
            .raw = .{ .outbound = .{
                .client = slot.outbound.client,
                .stream_id = sid,
            } },
            .wire = wire,
        };
        try self.outbound_publishes.put(pub_id, op);
    }

    fn startInboundPublish(self: *QuicRuntime, peer: identity.PeerId, wire: []u8) !void {
        const ic = self.inbound_by_peer.get(peer) orelse return error.NotConnected;
        const sid = try ZIo.rawAllocateNextLocalBidiStream(ic.conn);
        const pub_id = self.next_publish_id;
        self.next_publish_id += 1;

        const op = try self.allocator.create(OutboundPublish);
        op.* = .{
            .peer = peer,
            .stream_id = sid,
            .raw = .{ .inbound = .{
                .server = self.listener.server,
                .conn = ic.conn,
                .stream_id = sid,
            } },
            .wire = wire,
        };
        try self.outbound_publishes.put(pub_id, op);
    }

    fn handleDial(self: *QuicRuntime, addr_str: []const u8, expected_peer: ?identity.PeerId) void {
        const a = self.allocator;

        if (quic_relay_live.LiveRelay.isCircuitDialAddr(addr_str)) {
            self.relay_live.enqueueCircuitDial(addr_str, expected_peer) catch |err| {
                log.warn("quic_runtime: circuit dial plan failed: {s}", .{@errorName(err)});
                self.failDial(expected_peer);
            };
            return;
        }

        if (expected_peer) |ep| {
            if (self.outbound_by_peer.contains(ep)) return;
            if (self.peerHasActiveConnection(ep)) return;
        }

        var ma = multiaddr.Multiaddr.fromString(a, addr_str) catch |err| {
            log.warn("quic_runtime: parse dial multiaddr failed: {s}", .{@errorName(err)});
            self.failDial(expected_peer);
            return;
        };
        defer ma.deinit();

        var dial_opts: quic.Libp2pZquicClientDialOptions = .{};
        switch (self.tls_pem_resolved) {
            .paths => |p| {
                dial_opts.client_cert_path = p.cert_path;
                dial_opts.client_key_path = p.key_path;
            },
            .bytes => |b| {
                dial_opts.client_cert_pem = b.cert_pem;
                dial_opts.client_key_pem = b.key_pem;
            },
        }
        var outbound = quic_endpoint.QuicOutbound.dial(a, ma, dial_opts) catch |err| {
            log.warn("quic_runtime: QuicOutbound.dial failed: {s}", .{@errorName(err)});
            self.failDial(expected_peer);
            return;
        };

        // Allocate slot, store, drive until connected or timeout.
        const slot = a.create(OutboundConn) catch {
            outbound.deinit();
            self.failDial(expected_peer);
            return;
        };
        slot.* = .{
            .outbound = outbound,
            .conn_id = self.next_conn_id,
        };
        self.next_conn_id += 1;

        // Drive until the QUIC handshake completes (bound deadline).
        var recv_buf: [65536]u8 = undefined;
        const deadline_ms = self.opts.now_ms_fn() + 20_000;
        var connected = false;
        while (self.opts.now_ms_fn() < deadline_ms) {
            slot.outbound.drive(&recv_buf, 5) catch {};
            // Also keep listener drained so its TLS handshake responses move.
            self.listener.drive(&recv_buf, 0) catch {};
            if (slot.outbound.client.conn.phase == .connected) {
                connected = true;
                break;
            }
            if (self.shutdown_requested.load(.acquire)) break;
        }

        if (!connected) {
            // No log here previously: the drive loop walked away silently and
            // upstream (`peer connection failed: result=error_`) had no idea
            // whether the conn even started or what phase it died at. Emit
            // one warn with the stalled phase so packet captures / zquic
            // logs aren't the only signal for cross-impl TLS gaps.
            var peer_buf: [128]u8 = undefined;
            const peer_str: []const u8 = if (expected_peer) |p|
                (p.toBase58(&peer_buf) catch "<peer-id-format-err>")
            else
                "<unknown>";
            log.warn(
                "quic_runtime: dial drive-loop timed out after 20s; peer={s} stalled_phase={s}",
                .{ peer_str, @tagName(slot.outbound.client.conn.phase) },
            );
            slot.outbound.deinit();
            a.destroy(slot);
            if (expected_peer) |ep| {
                if (self.peerHasActiveConnection(ep)) return;
            }
            self.failDial(expected_peer);
            return;
        }

        // Verify remote peer id from TLS leaf.
        const now_sec = @divTrunc(self.opts.now_ms_fn(), 1000);
        const verified = quic_peer_identity.verifiedPeerIdFromLibp2pQuicClient(
            slot.outbound.client,
            a,
            expected_peer,
            now_sec,
        ) catch |err| {
            log.warn("quic_runtime: verify remote peer id failed: {s}", .{@errorName(err)});
            slot.outbound.deinit();
            a.destroy(slot);
            self.failDial(expected_peer);
            return;
        };

        slot.peer_id = verified;
        self.outbound_by_peer.put(verified, slot) catch {
            slot.outbound.deinit();
            a.destroy(slot);
            self.failDial(expected_peer);
            return;
        };

        slot.notified = true;
        self.host.onConnectionEstablished(slot.conn_id, verified, .outbound) catch |err| {
            log.warn("quic_runtime: onConnectionEstablished failed: {s}", .{@errorName(err)});
        };

        // Tear down any stale gossip publish stream that was bound to a
        // peer-dialed inbound leg (pre-fix builds) before replaying SUBSCRIBE
        // on this outbound dial leg.
        if (self.persistent_gossip.get(verified)) |g| {
            if (g.raw == .inbound) {
                var peer_buf: [128]u8 = undefined;
                log.info(
                    "quic_runtime: migrating persistent gossip from inbound to outbound leg peer={s}",
                    .{peerBase58(verified, &peer_buf)},
                );
                self.dropPersistentGossipStream(verified);
            }
        }

        // SUBSCRIBE replay rides the outbound dial leg only (see
        // `ensurePersistentGossipStream`). Inbound notification may arrive
        // before our dial completes; defer gossip wire setup until then.
        self.replaySubscribeToPeer(verified);
    }

    fn failDial(self: *QuicRuntime, expected_peer: ?identity.PeerId) void {
        const now_ms = self.opts.now_ms_fn();
        const cid = self.next_conn_id;
        self.next_conn_id += 1;
        self.host.onDialFailure(now_ms, cid, expected_peer, .outbound, .{ .err = error.DialFailed }) catch |err| {
            log.warn("quic_runtime: onDialFailure failed: {s}", .{@errorName(err)});
        };
    }

    fn startOutboundRequest(
        self: *QuicRuntime,
        peer: identity.PeerId,
        proto: protocol_mod.LeanSupportedProtocol,
        request_id: u64,
        payload: []u8,
    ) !void {
        const slot = self.outbound_by_peer.get(peer) orelse {
            // No connection — surface a failure event and free payload.
            log.warn("quic_runtime: send_request to unknown peer (no outbound conn)", .{});
            self.allocator.free(payload);
            self.host.swarm.queueEvent(.{ .rpc_error_response = .{
                .peer = peer,
                .request_id = request_id,
                .kind = error.Disconnected,
            } }) catch {};
            return;
        };

        const sid = slot.outbound.nextLocalBidiStream() catch |err| {
            log.warn("quic_runtime: nextLocalBidiStream failed: {s}", .{@errorName(err)});
            self.allocator.free(payload);
            self.host.swarm.queueEvent(.{ .rpc_error_response = .{
                .peer = peer,
                .request_id = request_id,
                .kind = error.IoError,
            } }) catch {};
            return;
        };

        const req = try self.allocator.create(OutboundRequest);
        req.* = .{
            .peer = peer,
            .request_id = request_id,
            .proto = proto,
            .stream_id = sid,
            .raw = .{
                .client = slot.outbound.client,
                .stream_id = sid,
            },
            .payload = payload,
        };
        try self.outbound_requests.put(request_id, req);
    }

    fn handleSendResponseChunk(self: *QuicRuntime, peer: identity.PeerId, request_id: u64, chunk: []const u8) void {
        _ = peer;
        // Look up channel via request_id (`stream_request_id` == request_id
        // for inbound channels). Iterate channel_to_inbound to find a match.
        var found: ?*InboundStream = null;
        var it = self.channel_to_inbound.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.*.request_id_for_channel == request_id) {
                found = e.value_ptr.*;
                break;
            }
        }
        const ist = found orelse {
            log.warn("quic_runtime: send_response_chunk for unknown request_id {d}", .{request_id});
            return;
        };

        // Write response chunk wire-framed.
        const wire = snappy_wire.buildResponseWire(self.allocator, 0, chunk) catch |err| {
            log.warn("quic_runtime: buildResponseWire failed: {s}", .{@errorName(err)});
            return;
        };
        defer self.allocator.free(wire);

        var w = ist.raw.writer();
        std.Io.Writer.writeAll(&w, wire) catch |err| {
            log.warn("quic_runtime: write response chunk failed: {s}", .{@errorName(err)});
            return;
        };
        std.Io.Writer.flush(&w) catch {};
    }

    fn handleEndOfStream(self: *QuicRuntime, peer: identity.PeerId, request_id: u64) void {
        _ = peer;
        // Find the inbound stream and close it (send a fin via 0-byte STREAM frame).
        var found_key: ?u64 = null;
        var found_stream: ?*InboundStream = null;
        var it = self.channel_to_inbound.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.*.request_id_for_channel == request_id) {
                found_key = e.key_ptr.*;
                found_stream = e.value_ptr.*;
                break;
            }
        }
        const ist = found_stream orelse return;

        // Half-close the responder write side so rust-libp2p sees the response
        // stream end (empty chunk sequence is valid for blocks_by_root).
        ist.raw.writeAllFin(&.{});
        ist.response_fin_sent = true;

        // Drop from channel map; advanceInboundStreams releases the zquic
        // raw-app slot once the peer FINs (see ch4r10t33r/zquic#149).
        if (found_key) |k| _ = self.channel_to_inbound.remove(k);
    }

    fn appendInboundAccBounded(
        self: *QuicRuntime,
        list: *std.ArrayList(u8),
        new_bytes: []const u8,
        max_bytes: usize,
    ) (errors_mod.ReqRespError || std.mem.Allocator.Error)!void {
        const new_len = list.items.len + new_bytes.len;
        if (new_len > max_bytes) return error.PayloadTooLarge;
        try list.appendSlice(self.allocator, new_bytes);
    }

    fn removeInboundStreamAt(self: *QuicRuntime, index: usize) void {
        const ist = self.inbound_streams.items[index];
        // Release the zquic-side raw_app slot so the connection's 64-slot
        // table doesn't fill up.  Without this, the libp2p
        // per-message-stream gossipsub pattern (each publish opens a fresh
        // /meshsub/1.1.0 stream and FINs) exhausts all slots within ~30 s
        // of normal traffic and every subsequent inbound STREAM frame is
        // silently dropped by zquic.  See ch4r10t33r/zquic#149.
        _ = ist.raw.release(self.allocator);
        if (ist.channel_id) |cid| _ = self.channel_to_inbound.remove(cid);
        ist.req_acc.deinit(self.allocator);
        ist.gossip_acc.deinit(self.allocator);
        ist.relay_acc.deinit(self.allocator);
        ist.ms_acc.deinit(self.allocator);
        ist.ms_tail.deinit(self.allocator);
        self.allocator.destroy(ist);
        _ = self.inbound_streams.swapRemove(index);
    }

    fn tryTakeLengthPrefixedFrame(acc: []const u8, max_payload: usize) ?struct { frame: []const u8, total: usize } {
        const dec = varint.decode(acc) catch return null;
        const payload_len: usize = @intCast(dec.value);
        if (payload_len > max_payload) return null;
        const total = dec.len + payload_len;
        if (acc.len < total) return null;
        return .{ .frame = acc[dec.len..total], .total = total };
    }

    fn appendRelayAcc(self: *QuicRuntime, ist: *InboundStream) void {
        self.drainMsTailInto(ist, &ist.relay_acc, max_inbound_relay_acc_bytes);
        const recv_buf = ist.raw.recvBuffer() orelse return;
        if (recv_buf.len <= ist.raw.read_cursor) return;
        const new_bytes = recv_buf[ist.raw.read_cursor..];
        self.appendInboundAccBounded(&ist.relay_acc, new_bytes, max_inbound_relay_acc_bytes) catch {
            log.warn("quic_runtime: relay_acc cap exceeded", .{});
        };
        ist.raw.read_cursor = recv_buf.len;
    }

    /// Move any post-handshake bytes captured during multistream-select into
    /// the per-protocol accumulator before the dispatch loop reads from the
    /// raw recv buffer. rust-libp2p / go-libp2p routinely flush the protocol
    /// ack and the first application bytes (request payload, gossipsub frame,
    /// hop frame, …) in a single QUIC STREAM frame; without this the bytes
    /// stay in `ms_tail` and the protocol handler waits forever.
    fn drainMsTailInto(self: *QuicRuntime, ist: *InboundStream, acc: *std.ArrayList(u8), max_bytes: usize) void {
        if (ist.ms_tail.items.len == 0) return;
        self.appendInboundAccBounded(acc, ist.ms_tail.items, max_bytes) catch {
            log.warn("quic_runtime: dispatch acc cap exceeded while draining ms_tail", .{});
        };
        ist.ms_tail.clearAndFree(self.allocator);
    }

    // ── Relay / DCUtR runtime hooks ─────────────────────────────────────────

    fn relayHookDialPlain(ctx: ?*anyopaque, addr: []const u8, expected: ?identity.PeerId) bool {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        self.handleDial(addr, expected);
        if (expected) |ep| return self.outbound_by_peer.contains(ep);
        return true;
    }

    fn relayHookOutboundClient(ctx: ?*anyopaque, peer: identity.PeerId) ?*ZIo.Client {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        const slot = self.outbound_by_peer.get(peer) orelse return null;
        return slot.outbound.client;
    }

    fn relayHookNextBidiStream(ctx: ?*anyopaque, peer: identity.PeerId) ?u64 {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        const slot = self.outbound_by_peer.get(peer) orelse return null;
        return slot.outbound.nextLocalBidiStream() catch null;
    }

    fn relayHookRelayedConnected(ctx: ?*anyopaque, target: identity.PeerId, conn_id: connection_manager_mod.ConnectionId) void {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        self.host.onConnectionEstablished(conn_id, target, .outbound) catch |err| {
            log.warn("quic_runtime: relayed onConnectionEstablished failed: {s}", .{@errorName(err)});
        };
    }

    fn relayHookRelayedDialFailed(ctx: ?*anyopaque, target: ?identity.PeerId) void {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        self.failDial(target);
    }

    fn relayHookNextConnId(ctx: ?*anyopaque) connection_manager_mod.ConnectionId {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        const cid = self.next_conn_id;
        self.next_conn_id += 1;
        return cid;
    }

    fn dcutrHookListenerPort(ctx: ?*anyopaque) ?u16 {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        return self.bound_port_v4;
    }

    fn dcutrHookTlsPaths(ctx: ?*anyopaque) quic_dcutr_live.TlsPemRef {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        return switch (self.tls_pem_resolved) {
            .paths => |p| .{ .cert = p.cert_path, .key = p.key_path },
            .bytes => |b| .{ .cert = b.cert_pem, .key = b.key_pem },
        };
    }

    fn dcutrHookTlsBytes(ctx: ?*anyopaque) quic_dcutr_live.TlsPemRef {
        return dcutrHookTlsPaths(ctx);
    }

    fn dcutrHookUsePemBytes(ctx: ?*anyopaque) bool {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        return self.tls_pem_resolved == .bytes;
    }

    fn dcutrHookDirectConnected(ctx: ?*anyopaque, peer: identity.PeerId) void {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        log.info("quic_runtime: DCUtR direct connection to peer (relay upgrade)", .{});
        _ = peer;
        _ = self;
    }

    fn dcutrHookCloseRelayed(ctx: ?*anyopaque, peer: identity.PeerId) void {
        const self: *QuicRuntime = @ptrCast(@alignCast(ctx.?));
        if (self.relay_live.relay_virtual.fetchRemove(peer)) |kv| {
            self.allocator.destroy(kv.value);
        }
    }

    /// Extra listen addrs from an active relay reservation (for Identify).
    pub fn relayCircuitListenAddrs(self: *const QuicRuntime) []const []const u8 {
        return self.relay_live.extraListenAddrs();
    }

    // ── Per-stream pump ────────────────────────────────────────────────────

    fn readTlsCertPemFromPath(a: std.mem.Allocator, path: []const u8) ![]u8 {
        if (!builtin.link_libc) return error.UnsupportedPlatform;
        var path_buf: [1024]u8 = undefined;
        const z = try std.fmt.bufPrintZ(&path_buf, "{s}", .{path});
        const mode: std.c.mode_t = 0;
        const fd = std.c.open(z.ptr, .{ .ACCMODE = .RDONLY }, mode);
        if (fd < 0) return error.OpenFailed;
        defer _ = std.c.close(fd);
        var buf = std.ArrayList(u8).empty;
        errdefer buf.deinit(a);
        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = std.c.read(fd, &chunk, chunk.len);
            if (n < 0) return error.ReadFailed;
            if (n == 0) break;
            try buf.appendSlice(a, chunk[0..@intCast(n)]);
        }
        return try buf.toOwnedSlice(a);
    }

    fn pemFirstCertDer(a: std.mem.Allocator, pem: []const u8) ![]u8 {
        const begin = std.mem.indexOf(u8, pem, "-----BEGIN CERTIFICATE-----") orelse return error.PemNoBegin;
        const after_begin = begin + "-----BEGIN CERTIFICATE-----".len;
        const end_rel = std.mem.indexOf(u8, pem[after_begin..], "-----END CERTIFICATE-----") orelse return error.PemNoEnd;
        const b64_block = pem[after_begin .. after_begin + end_rel];
        const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
        const upper = decoder.calcSizeUpperBound(b64_block.len);
        const out = try a.alloc(u8, upper);
        errdefer a.free(out);
        const n = try decoder.decode(out, b64_block);
        return try a.realloc(out, n);
    }

    fn hostPublicKeyProtoFromCertPem(a: std.mem.Allocator, cert_pem: []const u8) ![]u8 {
        const der = try pemFirstCertDer(a, cert_pem);
        defer a.free(der);
        const ext = try libp2p_tls.findLibp2pExtensionExtValue(der);
        const sk = try libp2p_tls.parseSignedKey(ext);
        return try a.dupe(u8, sk.public_key_pb);
    }

    fn ensureIdentifyReplyWire(self: *QuicRuntime) ![]const u8 {
        if (self.identify_reply_wire) |w| return w;
        const a = self.allocator;
        var cert_pem_owned: ?[]u8 = null;
        defer if (cert_pem_owned) |p| a.free(p);
        const cert_pem = switch (self.tls_pem_resolved) {
            .paths => |paths| blk: {
                cert_pem_owned = try readTlsCertPemFromPath(a, paths.cert_path);
                break :blk cert_pem_owned.?;
            },
            .bytes => |b| b.cert_pem,
        };
        const host_pk = try hostPublicKeyProtoFromCertPem(a, cert_pem);
        defer a.free(host_pk);
        const msg = identify_mod.MessageView{
            .public_key = host_pk,
            .protocols = &supported_protocols,
        };
        self.identify_reply_wire = try identify_mod.encode(a, msg);
        return self.identify_reply_wire.?;
    }

    fn advanceInboundStreams(self: *QuicRuntime) !void {
        const a = self.allocator;
        var i: usize = 0;
        while (i < self.inbound_streams.items.len) {
            const ist = self.inbound_streams.items[i];

            // 1. Multistream handshake: responder side.
            //
            // Bytes pulled from the raw stream live in `ms_acc`, which we own
            // across drive ticks. Each tick we append any newly-arrived raw
            // bytes and run the responder helper against a `Reader.fixed`
            // view; on `error.DialFailed` (helper needs more bytes) we leave
            // `ms_acc` intact and try again next tick, instead of losing the
            // bytes the helper already consumed into its local accumulator.
            if (!ist.handshake_done) {
                const recv_buf = ist.raw.recvBuffer();
                if (recv_buf) |rb| {
                    if (rb.len > ist.raw.read_cursor) {
                        const new_bytes = rb[ist.raw.read_cursor..];
                        ist.ms_acc.appendSlice(a, new_bytes) catch {
                            log.warn("quic_runtime: ms_acc append failed", .{});
                            self.removeInboundStreamAt(i);
                            continue;
                        };
                        ist.raw.read_cursor = rb.len;
                    }
                }
                if (ist.ms_acc.items.len == 0) {
                    i += 1;
                    continue;
                }
                var fixed_r = std.Io.Reader.fixed(ist.ms_acc.items);
                var w = ist.raw.writer();
                const cands: []const []const u8 = &supported_protocols;
                var tail_local: std.ArrayList(u8) = .empty;
                defer tail_local.deinit(a);
                const ix = stream_multistream.responderHandshakeMultistreamAmong(&fixed_r, &w, cands, a, &tail_local) catch |err| switch (err) {
                    error.DialFailed => {
                        i += 1;
                        continue;
                    },
                    else => {
                        if (ist.ms_acc.items.len > 0) {
                            log.warn("quic_runtime: inbound responder handshake failed: {s} (accumulated {d} bytes)", .{
                                @errorName(err),
                                ist.ms_acc.items.len,
                            });
                        } else {
                            log.warn("quic_runtime: inbound responder handshake failed: {s}", .{@errorName(err)});
                        }
                        // FIN our write half on `na` instead of releasing the
                        // stream — releasing resets it on the wire, which
                        // rust-libp2p's connection handler interprets as a
                        // peer-induced stream error and tears the whole
                        // gossipsub stream pair down (#183). A clean half-close
                        // lets the initiator's protocol handler (e.g. ping)
                        // observe the `na`, give up on this stream, and keep
                        // the connection alive.
                        if (err == error.ProtocolNegotiationFailed) {
                            if (ist.raw.client) |c| {
                                c.sendRawStreamData(ist.stream_id, ist.raw.send_offset, &[_]u8{}, true);
                            } else {
                                ist.raw.server.sendRawStreamData(ist.conn, ist.stream_id, ist.raw.send_offset, &[_]u8{}, true);
                            }
                        }
                        self.removeInboundStreamAt(i);
                        continue;
                    },
                };

                // Negotiation consumed every byte of `ms_acc` we passed in
                // (the helper drains its reader at success time). Anything
                // the peer flushed past the protocol ack is in `tail_local`.
                ist.ms_acc.clearAndFree(a);
                ist.ms_tail = tail_local;
                tail_local = .empty;

                // For streams arriving on an outbound (client-side) connection, the peer was
                // already authenticated during the QUIC handshake that zeam initiated. Skip the
                // server-TLS identity extraction and the inbound-connection notification: the
                // host was already notified via `onConnectionEstablished(.outbound)` when the
                // dial succeeded.
                const sender: identity.PeerId = if (ist.known_peer_id) |kp| kp else blk: {
                    const now_sec = @divTrunc(self.opts.now_ms_fn(), 1000);
                    break :blk quic_peer_identity.verifiedPeerIdFromLibp2pQuicServerConn(
                        ist.conn,
                        a,
                        null,
                        now_sec,
                    ) catch |perr| {
                        log.warn("quic_runtime: verify inbound peer failed: {s}", .{@errorName(perr)});
                        self.removeInboundStreamAt(i);
                        continue;
                    };
                };
                ist.handshake_done = true;
                ist.protocol_index = normalizeProtocolIndex(ix);
                ist.sender_peer = sender;

                // Lazily notify host of new inbound connection (once per listener slot).
                // Streams on outbound connections have slot == inbound_slot_none so we skip this.
                if (ist.slot != inbound_slot_none and !self.inbound_conn_notified[ist.slot]) {
                    self.inbound_conn_notified[ist.slot] = true;
                    self.inbound_conn_peer[ist.slot] = sender;
                    self.inbound_by_peer.put(sender, .{ .slot = ist.slot, .conn = ist.conn }) catch {};
                    const cid = self.inbound_conn_ids[ist.slot];
                    self.host.onConnectionEstablished(cid, sender, .inbound) catch |err| {
                        log.warn("quic_runtime: onConnectionEstablished (inbound) failed: {s}", .{@errorName(err)});
                    };
                }
            }

            // 2. Dispatch protocol-specific payload reader (verified peer only).
            const sender_peer = ist.sender_peer orelse {
                i += 1;
                continue;
            };
            const pi = ist.protocol_index orelse {
                i += 1;
                continue;
            };
            switch (pi) {
                0 => {
                    // /meshsub/1.1.0 — read length-prefixed gossipsub RPC
                    // frames. The peer sends `uvarint(len) + RPC protobuf`
                    // and MAY emit multiple frames before FIN; decode every
                    // complete frame in the accumulator and hand each to
                    // `host.handleGossipRpc` for sender attribution.
                    self.drainMsTailInto(ist, &ist.gossip_acc, max_inbound_gossip_acc_bytes);
                    const recv_buf = ist.raw.recvBuffer() orelse {
                        i += 1;
                        continue;
                    };
                    if (recv_buf.len > ist.raw.read_cursor) {
                        const new_bytes = recv_buf[ist.raw.read_cursor..];
                        self.appendInboundAccBounded(&ist.gossip_acc, new_bytes, max_inbound_gossip_acc_bytes) catch {
                            log.warn("quic_runtime: gossip_acc cap exceeded, dropping inbound stream", .{});
                            self.removeInboundStreamAt(i);
                            continue;
                        };
                        ist.raw.read_cursor = recv_buf.len;
                    }
                    if (ist.gossip_acc.items.len == 0) {
                        // Nothing pending in the accumulator.  If the peer
                        // has already FIN'd, the stream is done — release
                        // the zquic raw-app slot now so the 64-slot table
                        // can absorb the next inbound per-message stream.
                        // Without this, finned-and-drained streams stay in
                        // inbound_streams forever and the slot table fills.
                        if (ist.raw.finReceived()) {
                            self.removeInboundStreamAt(i);
                            continue;
                        }
                        i += 1;
                        continue;
                    }

                    // Drain every complete frame from the accumulator.
                    // The buffer can contain a partial frame on the tail; if
                    // varint decode fails we leave the bytes alone and try again
                    // next loop. Oversized-but-under-absolute-max frames are
                    // skipped (consumed, not passed to handleGossipRpc) so one
                    // bad publish does not tear down the whole QUIC stream.
                    var consumed: usize = 0;
                    var drop_stream = false;
                    while (consumed < ist.gossip_acc.items.len) {
                        const tail = ist.gossip_acc.items[consumed..];
                        const dec = varint.decode(tail) catch break; // need more bytes
                        if (dec.value > gossipsub_wire_limits.max_gossip_frame_declared_absolute_bytes) {
                            log.warn("quic_runtime: gossipsub frame declared length abusive ({d}), dropping inbound stream", .{dec.value});
                            drop_stream = true;
                            break;
                        }
                        const frame_len: usize = @intCast(dec.value);
                        const frame_total = dec.len + frame_len;
                        if (tail.len < frame_total) break; // partial frame
                        if (dec.value > gossipsub_wire_limits.max_rpc_length_delimited_bytes) {
                            log.warn("quic_runtime: gossipsub frame length too large ({d}), skipping frame", .{dec.value});
                            consumed += frame_total;
                            continue;
                        }
                        const frame_bytes = tail[dec.len .. dec.len + frame_len];
                        self.host.handleGossipRpc(sender_peer, frame_bytes) catch |err| {
                            log.warn("quic_runtime: handleGossipRpc failed: {s}", .{@errorName(err)});
                        };
                        consumed += frame_total;
                    }
                    if (drop_stream) {
                        self.removeInboundStreamAt(i);
                        continue;
                    }
                    if (consumed > 0) {
                        // Compact remaining (partial) frame to the front.
                        const remaining = ist.gossip_acc.items.len - consumed;
                        if (remaining > 0) {
                            std.mem.copyForwards(u8, ist.gossip_acc.items[0..remaining], ist.gossip_acc.items[consumed..]);
                        }
                        ist.gossip_acc.shrinkRetainingCapacity(remaining);
                    }
                    // libp2p gossipsub publishes use the per-message-stream
                    // pattern: open stream → one length-prefixed RPC frame →
                    // FIN.  When zquic has seen the FIN and we've drained the
                    // accumulator down to nothing, the stream is done — drop
                    // it so the zquic 64-slot raw-app table can take the
                    // next inbound stream (see ch4r10t33r/zquic#149).
                    if (ist.gossip_acc.items.len == 0 and ist.raw.finReceived()) {
                        self.removeInboundStreamAt(i);
                        continue;
                    }
                },
                proto_relay_hop, proto_relay_stop => {
                    if (ist.relay_control_done) {
                        i += 1;
                        continue;
                    }
                    self.appendRelayAcc(ist);
                    if (ist.relay_acc.items.len == 0) {
                        i += 1;
                        continue;
                    }
                    const taken = tryTakeLengthPrefixedFrame(
                        ist.relay_acc.items,
                        relay_mod.wire.Limits.standard.max_frame_bytes,
                    ) orelse {
                        i += 1;
                        continue;
                    };
                    const hop_leg: quic_relay_live.StreamLeg = .{ .inbound = ist.raw };
                    if (pi == proto_relay_hop) {
                        const resp = self.relay_live.handleHopFrame(hop_leg, sender_peer, taken.frame, false) catch {
                            self.removeInboundStreamAt(i);
                            continue;
                        };
                        if (resp.len > 0) {
                            var w = ist.raw.writer();
                            std.Io.Writer.writeAll(&w, resp) catch {};
                            std.Io.Writer.flush(&w) catch {};
                        }
                    } else {
                        self.relay_live.handleStopFrame(hop_leg, self.host.swarm.local_peer, taken.frame) catch {
                            self.removeInboundStreamAt(i);
                            continue;
                        };
                    }
                    ist.relay_control_done = true;
                    if (ist.relay_acc.items.len > taken.total) {
                        const rem = ist.relay_acc.items.len - taken.total;
                        std.mem.copyForwards(u8, ist.relay_acc.items[0..rem], ist.relay_acc.items[taken.total..]);
                        ist.relay_acc.shrinkRetainingCapacity(rem);
                    } else {
                        ist.relay_acc.clearRetainingCapacity();
                    }
                    self.removeInboundStreamAt(i);
                    continue;
                },
                proto_dcutr => {
                    if (!ist.relay_control_done) {
                        self.dcutr_live.startResponderInbound(sender_peer, ist.raw) catch {
                            self.removeInboundStreamAt(i);
                            continue;
                        };
                        ist.relay_control_done = true;
                    }
                    i += 1;
                },
                proto_identify => {
                    const wire = self.ensureIdentifyReplyWire() catch |err| {
                        log.warn("quic_runtime: identify reply build failed: {s}", .{@errorName(err)});
                        self.removeInboundStreamAt(i);
                        continue;
                    };
                    ist.raw.writeAllFin(wire);
                    self.removeInboundStreamAt(i);
                    continue;
                },
                proto_ping => {
                    if (ist.ms_tail.items.len < ping_mod.payload_len and ist.raw.unreadRecvLen() == 0) {
                        i += 1;
                        continue;
                    }
                    var r = ist.raw.reader();
                    var w = ist.raw.writer();
                    ping_mod.handleInboundPrefixed(ist.ms_tail.items, &r, &w) catch |err| {
                        log.warn("quic_runtime: ping inbound failed: {s}", .{@errorName(err)});
                        self.removeInboundStreamAt(i);
                        continue;
                    };
                    ist.ms_tail.clearRetainingCapacity();
                    ist.raw.writeAllFin(&.{});
                    self.removeInboundStreamAt(i);
                    continue;
                },
                proto_identify_push => {
                    // rust-libp2p identify opens `/ipfs/id/push/1.0.0` after the
                    // initial exchange to push listen-addrs updates. Receive-only:
                    // drain any pushed protobuf and half-close cleanly.
                    self.drainMsTailInto(ist, &ist.req_acc, max_inbound_req_acc_bytes);
                    const recv_buf = ist.raw.recvBuffer();
                    if (recv_buf) |rb| {
                        if (rb.len > ist.raw.read_cursor) ist.raw.read_cursor = rb.len;
                    }
                    ist.req_acc.clearRetainingCapacity();
                    ist.raw.writeAllFin(&.{});
                    self.removeInboundStreamAt(i);
                    continue;
                },
                else => |idx| {
                    // SSZ req/resp path.
                    if (ist.response_fin_sent) {
                        if (ist.raw.finReceived()) {
                            self.removeInboundStreamAt(i);
                            continue;
                        }
                        i += 1;
                        continue;
                    }
                    if (ist.channel_id != null) {
                        // Request dispatched; waiting for handler finish().
                        i += 1;
                        continue;
                    }
                    const proto: protocol_mod.LeanSupportedProtocol = switch (idx) {
                        proto_meshsub_last_index + 1 => .blocks_by_root,
                        proto_meshsub_last_index + 2 => .blocks_by_range,
                        proto_meshsub_last_index + 3 => .status,
                        else => {
                            i += 1;
                            continue;
                        },
                    };
                    // Drain whatever new bytes have arrived into the per-stream
                    // accumulator. `wire_framing.readOneUnaryRequest` consumed
                    // bytes destructively on partial errors so we maintain our
                    // own accumulating buffer and decode straight from it.
                    self.drainMsTailInto(ist, &ist.req_acc, max_inbound_req_acc_bytes);
                    const recv_buf = ist.raw.recvBuffer() orelse {
                        i += 1;
                        continue;
                    };
                    if (recv_buf.len > ist.raw.read_cursor) {
                        const new_bytes = recv_buf[ist.raw.read_cursor..];
                        self.appendInboundAccBounded(&ist.req_acc, new_bytes, max_inbound_req_acc_bytes) catch {
                            log.warn("quic_runtime: req_acc cap exceeded, dropping inbound stream", .{});
                            self.removeInboundStreamAt(i);
                            continue;
                        };
                        ist.raw.read_cursor = recv_buf.len;
                    }
                    const peer_fin = ist.raw.finReceived();
                    if (ist.req_acc.items.len == 0) {
                        if (peer_fin) {
                            self.removeInboundStreamAt(i);
                            continue;
                        }
                        i += 1;
                        continue;
                    }

                    // Attempt to decode a full unary request from the acc.
                    const req_ssz = snappy_wire.decodeRequestSsz(a, ist.req_acc.items) catch |err| switch (err) {
                        error.IncompleteHeader, error.InvalidData => {
                            if (peer_fin) {
                                log.warn("quic_runtime: inbound req/resp decode failed after peer FIN ({d} bytes)", .{
                                    ist.req_acc.items.len,
                                });
                                ist.raw.writeAllFin(&.{});
                                self.removeInboundStreamAt(i);
                                continue;
                            }
                            i += 1;
                            continue;
                        },
                        else => |e| {
                            log.warn("quic_runtime: decodeRequestSsz failed: {s}", .{@errorName(e)});
                            self.removeInboundStreamAt(i);
                            continue;
                        },
                    };
                    defer a.free(req_ssz);

                    // Synthesize a stream_request_id; we use the QUIC stream
                    // id as the req/resp stream id correlator.
                    const stream_rid = ist.stream_id +% 1; // any nonzero u64 unique within this peer
                    const now_ms = self.opts.now_ms_fn();
                    const channel_id = self.host.registerInboundReqRespChannel(sender_peer, proto, stream_rid, now_ms) catch |err| {
                        log.warn("quic_runtime: registerInboundReqRespChannel failed: {s}", .{@errorName(err)});
                        i += 1;
                        continue;
                    };
                    ist.channel_id = channel_id;
                    ist.request_id_for_channel = stream_rid;
                    self.channel_to_inbound.put(channel_id, ist) catch {};

                    // Hand the request payload to the embedder via swarm.
                    const payload_dup = a.dupe(u8, req_ssz) catch {
                        i += 1;
                        continue;
                    };
                    self.host.swarm.queueEvent(.{ .rpc_request = .{
                        .peer = sender_peer,
                        .protocol = proto,
                        .request_id = stream_rid,
                        .channel_id = channel_id,
                        .payload = payload_dup,
                    } }) catch {
                        a.free(payload_dup);
                    };
                    // Reset acc for any subsequent unary on the same stream.
                    ist.req_acc.clearRetainingCapacity();
                },
            }
            i += 1;
        }
    }

    fn advanceOutboundRequests(self: *QuicRuntime) !void {
        const a = self.allocator;
        var it = self.outbound_requests.iterator();
        while (it.next()) |e| {
            const req = e.value_ptr.*;
            if (req.finished) continue;

            // 1. Send initiator multistream header + protocol id (one-shot).
            if (!req.handshake_sent) {
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(a);
                stream_multistream.appendFirstStreamInitiatorHandshakeFramed(
                    &out,
                    a,
                    req.proto.protocolId(),
                    .delimited,
                ) catch |err| {
                    log.warn("quic_runtime: append first init handshake failed: {s}", .{@errorName(err)});
                    continue;
                };
                var w = req.raw.writer();
                std.Io.Writer.writeAll(&w, out.items) catch |err| {
                    log.warn("quic_runtime: write init handshake failed: {s}", .{@errorName(err)});
                    continue;
                };
                std.Io.Writer.flush(&w) catch {};
                req.handshake_sent = true;
            }

            // 2. Read multistream ack (go-multistream delimited on QUIC).
            if (!req.handshake_done) {
                if (req.raw.unreadRecvLen() == 0) continue;
                var r = req.raw.reader();
                var w = req.raw.writer();
                stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, req.proto.protocolId(), a, null) catch |err| switch (err) {
                    error.ProtocolNegotiationFailed, error.DialFailed => continue,
                    else => {
                        log.warn("quic_runtime: read init ack failed: {s}", .{@errorName(err)});
                        continue;
                    },
                };
                req.handshake_done = true;
            }

            // 3. Write the SSZ request once.
            if (!req.request_written) {
                var w = req.raw.writer();
                wire_framing.writeUnaryRequestFlush(a, &w, req.payload) catch |err| {
                    log.warn("quic_runtime: writeUnaryRequestFlush failed: {s}", .{@errorName(err)});
                    continue;
                };
                req.request_written = true;
            }

            // 4. Drain new bytes into the per-request accumulator; decode
            //    from there to avoid losing bytes on partial reads.
            const recv_buf = req.raw.client.rawAppRecvBuffer(req.stream_id) orelse continue;
            if (recv_buf.len > req.raw.read_cursor) {
                try req.resp_acc.appendSlice(a, recv_buf[req.raw.read_cursor..]);
                req.raw.read_cursor = recv_buf.len;
            }
            if (req.resp_acc.items.len == 0) continue;

            const resp_decoded = snappy_wire.decodeResponseSsz(a, req.resp_acc.items) catch |derr| switch (derr) {
                error.IncompleteHeader, error.InvalidData => continue, // need more bytes
                else => |de| {
                    log.warn("quic_runtime: decodeResponseSsz failed: {s}", .{@errorName(de)});
                    continue;
                },
            };
            const resp = wire_framing.UnaryResponse{ .code = resp_decoded.code, .ssz = resp_decoded.ssz };
            req.resp_acc.clearRetainingCapacity();

            if (resp.code != 0) {
                a.free(resp.ssz);
                self.host.swarm.queueEvent(.{ .rpc_error_response = .{
                    .peer = req.peer,
                    .request_id = req.request_id,
                    .kind = error.InvalidData,
                } }) catch {};
                self.finishOutboundReq(req);
                continue;
            }

            // Hand the chunk to swarm; swarm.Event.deinit will free.
            self.host.swarm.queueEvent(.{ .rpc_response_chunk = .{
                .peer = req.peer,
                .request_id = req.request_id,
                .chunk = resp.ssz,
            } }) catch {
                a.free(resp.ssz);
                continue;
            };

            // Single-chunk simplification: emit response_end after one chunk.
            self.host.swarm.queueEvent(.{ .rpc_response_end = .{
                .peer = req.peer,
                .request_id = req.request_id,
            } }) catch {};
            self.finishOutboundReq(req);
        }
    }

    fn finishOutboundReq(self: *QuicRuntime, req: *OutboundRequest) void {
        req.finished = true;
        // NOTE: the FIN-on-finish that lived here regressed zeam↔zeam
        // protocol negotiation — sending an empty-data + FIN STREAM frame on
        // the bidi stream broke the responder's reading of the same stream,
        // so status RPC times out from the very first attempt and gossip
        // stops after slot 2.  Reverted while we diagnose the right place
        // to FIN.  Stream-credit accounting is still backed by the zquic-side
        // MAX_STREAMS replenishment from #130 + the cap from #133.

        // Remove from map and free.
        if (self.outbound_requests.fetchRemove(req.request_id)) |kv| {
            self.allocator.free(kv.value.payload);
            kv.value.resp_acc.deinit(self.allocator);
            self.allocator.destroy(kv.value);
        }
    }

    /// Drive every in-flight gossipsub publish stream: send the multistream
    /// initiator handshake, read the responder ack, write the length-prefixed
    /// RPC frame, FIN the stream, then drop the entry.
    fn advanceOutboundPublishes(self: *QuicRuntime) !void {
        const a = self.allocator;
        // Collect ids to remove after iteration so we don't mutate the map mid-walk.
        var to_remove: std.ArrayList(u64) = .empty;
        defer to_remove.deinit(a);

        var it = self.outbound_publishes.iterator();
        while (it.next()) |e| {
            const op = e.value_ptr.*;
            if (op.finished) {
                try to_remove.append(a, e.key_ptr.*);
                continue;
            }

            // 1. Send initiator multistream offer + protocol id.
            if (!op.handshake_sent) {
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(a);
                stream_multistream.appendFirstStreamInitiatorHandshakeFramed(
                    &out,
                    a,
                    meshsub_initiator_offer,
                    .delimited,
                ) catch |err| {
                    log.warn("quic_runtime: publish handshake build failed: {s}", .{@errorName(err)});
                    continue;
                };
                var w = op.raw.writer();
                std.Io.Writer.writeAll(&w, out.items) catch |err| {
                    log.warn("quic_runtime: publish handshake write failed: {s}", .{@errorName(err)});
                    continue;
                };
                std.Io.Writer.flush(&w) catch {};
                op.handshake_sent = true;
            }

            // 2. Read responder ack.
            if (!op.handshake_done) {
                if (op.raw.unreadRecvLen() == 0) continue;
                var r = op.raw.reader();
                var w = op.raw.writer();
                stream_multistream.initiatorHandshakeMeshsubReadPhase(&r, &w, a, null) catch |err| switch (err) {
                    error.ProtocolNegotiationFailed, error.DialFailed => continue,
                    else => {
                        log.warn("quic_runtime: publish read ack failed: {s}", .{@errorName(err)});
                        continue;
                    },
                };
                op.handshake_done = true;
            }

            // 3. Write the gossipsub frame (`uvarint(len) + RPC protobuf`).
            if (!op.frame_written) {
                var w = op.raw.writer();
                std.Io.Writer.writeAll(&w, op.wire) catch |err| {
                    log.warn("quic_runtime: publish frame write failed: {s}", .{@errorName(err)});
                    continue;
                };
                std.Io.Writer.flush(&w) catch {};
                op.frame_written = true;

                // FIN: per-message-stream pattern signals end of publish by
                // closing the stream. The peer's reader treats EOF after a
                // complete frame as a clean handoff.
                op.raw.finStream();
                op.finished = true;
                try to_remove.append(a, e.key_ptr.*);
            }
        }

        for (to_remove.items) |id| {
            if (self.outbound_publishes.fetchRemove(id)) |kv| {
                a.free(kv.value.wire);
                a.destroy(kv.value);
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

// Test cert bundle: an ECDSA-P-256 libp2p TLS cert + matching private key,
// written to /tmp as PEM files so zquic's vendored TLS parser can ingest them.
// All cert/key material is built through `libp2p_tls_cert.generate` + the
// matching `ecdsaP256SeedToPem` helper — see that module for the X.509 and
// SEC1 encoding logic. This file deliberately holds no DER/ASN.1 code.

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const peer_id_pkg = @import("peer_id");
const libp2p_tls_cert = @import("../security/libp2p_tls_cert.zig");

const TestCertBundle = struct {
    cert_pem: []u8,
    key_pem: []u8,
    peer: identity.PeerId,

    fn deinit(self: *TestCertBundle, a: std.mem.Allocator) void {
        a.free(self.cert_pem);
        a.free(self.key_pem);
    }
};

const TestEcdsaHostSigner = struct {
    kp: EcdsaP256.KeyPair,
    fn sign(ctx: ?*anyopaque, message: []const u8, out_sig: []u8, out_sig_len: *usize) anyerror!void {
        const self: *TestEcdsaHostSigner = @ptrCast(@alignCast(ctx.?));
        const sig = try self.kp.sign(message, null);
        var buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
        const der = sig.toDer(&buf);
        if (der.len > out_sig.len) return error.NoSpaceLeft;
        @memcpy(out_sig[0..der.len], der);
        out_sig_len.* = der.len;
    }
};

fn buildTestBundle(a: std.mem.Allocator, label: []const u8, seed: u8) !TestCertBundle {
    _ = label;
    const host_seed = [_]u8{seed} ** 32;
    const cert_seed = [_]u8{seed +% 1} ** 32;
    const now_sec = @divTrunc(wall_time.milliTimestamp(), 1000);

    // 1. Host identity: deterministic ECDSA-P-256 keypair (so the peer id is
    //    stable across runs, which the loopback test relies on for dialing).
    const host_kp = try EcdsaP256.KeyPair.generateDeterministic(host_seed);
    var signer = TestEcdsaHostSigner{ .kp = host_kp };
    const host_pub_sec1: [65]u8 = host_kp.public_key.toUncompressedSec1();

    // 2. Mint cert via the public generator.
    var gen = try libp2p_tls_cert.generate(a, .{
        .host_identity = .{
            .ecdsa_p256 = .{
                .public_key_sec1_uncompressed = host_pub_sec1,
                .sign = TestEcdsaHostSigner.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now_sec - 3600,
        .not_after_sec = now_sec + 365 * 24 * 3600,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    // 3. PEM encode cert + the matching SEC1 EC PRIVATE KEY.
    const cert_pem = try libp2p_tls_cert.certDerToPem(a, gen.cert_der);
    errdefer a.free(cert_pem);
    const key_pem = try libp2p_tls_cert.ecdsaP256SeedToPem(a, gen.cert_key_seed);
    errdefer a.free(key_pem);

    // 4. Derive PeerId from the ECDSA host pubkey. The protobuf encoder lives
    //    in libp2p_tls_cert so the PKIX SPKI shape (per the libp2p TLS spec's
    //    ECDSA arm) stays in one place.
    const host_pub_proto = try libp2p_tls_cert.encodeEcdsaPublicKeyProto(a, host_pub_sec1);
    defer a.free(host_pub_proto);
    const reader = try peer_id_pkg.PublicKeyReader.init(host_pub_proto);
    const spki_bytes = reader.getData();
    var host_pk = peer_id_pkg.PublicKey{ .type = .ECDSA, .data = spki_bytes };
    const peer = try peer_id_pkg.PeerId.fromPublicKey(a, &host_pk);

    return .{
        .cert_pem = cert_pem,
        .key_pem = key_pem,
        .peer = peer,
    };
}

test "QuicRuntime.create threads in-memory PEM bytes straight to zquic (no /tmp)" {
    // v0.1.4 wrote the PEM bytes to `/tmp/zlibp2p_runtime_*_{cert,key}.pem`
    // and handed those paths to zquic — that broke in containers without
    // `/tmp`. From v0.1.5 the runtime borrows the embedder's PEM bytes and
    // routes them through zquic v1.6.6's `cert_pem` / `key_pem` (#129).
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    var bundle = try buildTestBundle(a, "pem", 0xC3);
    defer bundle.deinit(a);

    var host = try host_mod.Host.create(.{
        .allocator = a,
        .local_peer = bundle.peer,
        .gossipsub = .{ .local_peer_id = bundle.peer },
    });
    defer host.destroy();
    try host.startBackground();
    try testing.expect(host.waitUntilReady(5_000));

    var rt = try QuicRuntime.create(.{
        .allocator = a,
        .host = host,
        .tls_pem = .{
            .pem_bytes = .{
                .cert_pem = bundle.cert_pem,
                .key_pem = bundle.key_pem,
            },
        },
        .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
    });
    defer rt.destroy();

    // The resolved state is the `.bytes` arm and borrows the caller's slices
    // (pointer + length equality, no copy).
    switch (rt.tls_pem_resolved) {
        .bytes => |b| {
            try testing.expectEqual(bundle.cert_pem.ptr, b.cert_pem.ptr);
            try testing.expectEqual(bundle.cert_pem.len, b.cert_pem.len);
            try testing.expectEqual(bundle.key_pem.ptr, b.key_pem.ptr);
            try testing.expectEqual(bundle.key_pem.len, b.key_pem.len);
        },
        .paths => return error.UnexpectedPathsArm,
    }

    // And the runtime still came up — bound an IPv4 UDP socket.
    try testing.expect(rt.boundUdpPortIpv4() != null);

    // Belt-and-braces: no `/tmp/zlibp2p_runtime_*` file should exist whose
    // contents match this runtime's PEM bytes. We can't enumerate `/tmp`
    // portably, but we can probe the well-known names v0.1.4 used (ids
    // start at 0 and increment monotonically); if any of them exist and
    // their bytes match our cert PEM verbatim, this PR regressed.
    if (builtin.os.tag != .windows) {
        var i: u64 = 0;
        while (i < 8) : (i += 1) {
            var buf: [128]u8 = undefined;
            const cert_p = std.fmt.bufPrintZ(&buf, "/tmp/zlibp2p_runtime_{d}_cert.pem", .{i}) catch break;
            var o: std.c.O = .{};
            o.ACCMODE = .RDONLY;
            const fd = std.c.open(cert_p.ptr, o, @as(std.c.mode_t, 0));
            if (fd < 0) continue;
            defer _ = std.c.close(fd);
            var rbuf: [4096]u8 = undefined;
            const n = std.c.read(fd, &rbuf, rbuf.len);
            if (n <= 0) continue;
            const got = rbuf[0..@intCast(n)];
            try testing.expect(!std.mem.startsWith(u8, bundle.cert_pem, got) or got.len < bundle.cert_pem.len);
        }
    }
}

test "QuicRuntime.create surfaces error for nonexistent .paths cert" {
    // Sanity for the path-based arm: a path that doesn't exist must
    // propagate as an error (proving the path loader is still in play
    // for `.paths`, while `.pem_bytes` skips it entirely).
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    var bundle = try buildTestBundle(a, "pathneg", 0xE7);
    defer bundle.deinit(a);

    var host = try host_mod.Host.create(.{
        .allocator = a,
        .local_peer = bundle.peer,
        .gossipsub = .{ .local_peer_id = bundle.peer },
    });
    defer host.destroy();
    try host.startBackground();
    try testing.expect(host.waitUntilReady(5_000));

    // Path that demonstrably does not exist — zquic's path loader should
    // fail and propagate up through `QuicRuntime.create`.
    const result = QuicRuntime.create(.{
        .allocator = a,
        .host = host,
        .tls_pem = .{
            .paths = .{
                .cert_path = "/this/does/not/exist/cert.pem",
                .key_path = "/this/does/not/exist/key.pem",
            },
        },
        .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
    });
    try testing.expect(std.meta.isError(result));
    if (result) |rt| rt.destroy() else |_| {}

    // And the same identity via `.pem_bytes` must succeed without any
    // disk access.
    var rt_ok = try QuicRuntime.create(.{
        .allocator = a,
        .host = host,
        .tls_pem = .{
            .pem_bytes = .{
                .cert_pem = bundle.cert_pem,
                .key_pem = bundle.key_pem,
            },
        },
        .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
    });
    defer rt_ok.destroy();
    try testing.expect(rt_ok.boundUdpPortIpv4() != null);
}

test "appendInboundAccBounded rejects growth past cap" {
    const a = std.testing.allocator;
    var rt: QuicRuntime = undefined;
    rt.allocator = a;

    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(a);
    const cap: usize = 64;
    try acc.appendSlice(a, &[_]u8{0} ** (cap - 1));
    try std.testing.expectError(error.PayloadTooLarge, rt.appendInboundAccBounded(&acc, &[_]u8{ 1, 2 }, cap));
    try std.testing.expectEqual(cap - 1, acc.items.len);
}

test "gossip inbound drain skips oversize frame without drop_stream" {
    const a = std.testing.allocator;
    const max_accept = gossipsub_wire_limits.max_rpc_length_delimited_bytes;
    const absolute_max = gossipsub_wire_limits.max_gossip_frame_declared_absolute_bytes;

    var acc_buf: std.ArrayList(u8) = .empty;
    defer acc_buf.deinit(a);

    const oversize_decl = max_accept + 1;
    try varint.append(&acc_buf, a, oversize_decl);
    try acc_buf.appendNTimes(a, 0, oversize_decl);

    const small_inner = [_]u8{0xAB};
    try varint.append(&acc_buf, a, small_inner.len);
    try acc_buf.appendSlice(a, &small_inner);

    var consumed: usize = 0;
    var drop_stream = false;
    var handled: usize = 0;
    while (consumed < acc_buf.items.len) {
        const tail = acc_buf.items[consumed..];
        const dec = varint.decode(tail) catch break;
        if (dec.value > absolute_max) {
            drop_stream = true;
            break;
        }
        const frame_len: usize = @intCast(dec.value);
        const frame_total = dec.len + frame_len;
        if (tail.len < frame_total) break;
        if (dec.value > max_accept) {
            consumed += frame_total;
            continue;
        }
        handled += 1;
        consumed += frame_total;
    }

    try std.testing.expect(!drop_stream);
    try std.testing.expectEqual(@as(usize, 1), handled);
    try std.testing.expectEqual(acc_buf.items.len, consumed);
}

test "QuicRuntime: two instances exchange a status req/resp over UDP loopback" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;

    var bundle_a = try buildTestBundle(a, "a", 0xA1);
    defer bundle_a.deinit(a);
    var bundle_b = try buildTestBundle(a, "b", 0xB2);
    defer bundle_b.deinit(a);

    var host_a = try host_mod.Host.create(.{
        .allocator = a,
        .local_peer = bundle_a.peer,
        .gossipsub = .{ .local_peer_id = bundle_a.peer },
    });
    defer host_a.destroy();
    try host_a.startBackground();
    try testing.expect(host_a.waitUntilReady(5_000));

    var rt_a = try QuicRuntime.create(.{
        .allocator = a,
        .host = host_a,
        .tls_pem = .{
            .pem_bytes = .{
                .cert_pem = bundle_a.cert_pem,
                .key_pem = bundle_a.key_pem,
            },
        },
        .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
    });
    defer rt_a.destroy();

    var host_b = try host_mod.Host.create(.{
        .allocator = a,
        .local_peer = bundle_b.peer,
        .gossipsub = .{ .local_peer_id = bundle_b.peer },
    });
    defer host_b.destroy();
    try host_b.startBackground();
    try testing.expect(host_b.waitUntilReady(5_000));

    var rt_b = try QuicRuntime.create(.{
        .allocator = a,
        .host = host_b,
        .tls_pem = .{
            .pem_bytes = .{
                .cert_pem = bundle_b.cert_pem,
                .key_pem = bundle_b.key_pem,
            },
        },
        .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
    });
    defer rt_b.destroy();

    try rt_a.start();
    try rt_b.start();

    const a_port = rt_a.boundUdpPortIpv4() orelse return error.NoBoundPort;

    // B dials A.
    var a_peer_b58_buf: [128]u8 = undefined;
    const a_peer_b58 = try bundle_a.peer.toBase58(&a_peer_b58_buf);
    const a_ma_str = try std.fmt.allocPrint(a, "/ip4/127.0.0.1/udp/{d}/quic-v1/p2p/{s}", .{ a_port, a_peer_b58 });
    defer a.free(a_ma_str);
    var a_ma = try multiaddr.Multiaddr.fromString(a, a_ma_str);
    defer a_ma.deinit();
    try rt_b.registerKnownPeer(&a_ma, bundle_a.peer);

    // Spin a small responder on Host A: when it sees an rpc_request, send
    // back a single response chunk + finishResponseStream.
    const ResponderTask = struct {
        fn run(h: *host_mod.Host, done: *std.atomic.Value(bool)) void {
            const deadline_ms = wall_time.milliTimestamp() + 25_000;
            while (wall_time.milliTimestamp() < deadline_ms) {
                if (done.load(.acquire)) return;
                var ev = h.nextEvent(200) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return,
                };
                defer ev.deinit(h.allocator);
                switch (ev) {
                    .rpc_request => |r| {
                        h.sendResponseChunk(r.channel_id, "STATUS-RESP-FIXTURE", wall_time.milliTimestamp()) catch {};
                        h.finishResponseStream(r.channel_id) catch {};
                    },
                    else => {},
                }
            }
        }
    };
    var a_done = std.atomic.Value(bool).init(false);
    var a_thread = try std.Thread.spawn(.{}, ResponderTask.run, .{ host_a, &a_done });
    defer {
        a_done.store(true, .release);
        a_thread.join();
    }

    // Give the dial+connect time to land.
    var connected = false;
    {
        const deadline_ms = wall_time.milliTimestamp() + 20_000;
        while (wall_time.milliTimestamp() < deadline_ms) {
            if (rt_b.outbound_by_peer.get(bundle_a.peer)) |_| {
                connected = true;
                break;
            }
            // 20ms passive wait; the drive thread does the real work. Uses
            // libc nanosleep (Zig 0.16 dropped `std.Thread.sleep`).
            var req = std.c.timespec{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
            var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
            _ = std.c.nanosleep(&req, &rem);
        }
    }
    try testing.expect(connected);

    // B sends a request.
    const status_req: []const u8 = "STATUS-REQ-FIXTURE";
    // host.sendRequest's last arg is a timeout_ms.
    _ = try host_b.sendRequest(bundle_a.peer, .status, status_req, 15_000);

    // B should see rpc_response_chunk then rpc_response_end.
    var saw_chunk = false;
    var saw_end = false;
    const deadline_ms = wall_time.milliTimestamp() + 20_000;
    while (wall_time.milliTimestamp() < deadline_ms and !(saw_chunk and saw_end)) {
        var ev = host_b.nextEvent(500) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        defer ev.deinit(a);
        switch (ev) {
            .rpc_response_chunk => |c| {
                try testing.expectEqualStrings("STATUS-RESP-FIXTURE", c.chunk);
                saw_chunk = true;
            },
            .rpc_response_end => saw_end = true,
            else => {},
        }
    }

    try testing.expect(saw_chunk);
    try testing.expect(saw_end);
}

/// Holds the bytes the gossipsub validator captured on host A. The QUIC drive
/// thread writes to it; the test thread reads it under the `len` atomic.
const GossipCapture = struct {
    buf: [256]u8 = undefined,
    len: std.atomic.Value(usize) = .init(0),

    fn record(self: *GossipCapture, data: []const u8) void {
        if (data.len > self.buf.len) return;
        @memcpy(self.buf[0..data.len], data);
        self.len.store(data.len, .release);
    }

    fn get(self: *const GossipCapture) ?[]const u8 {
        const n = self.len.load(.acquire);
        if (n == 0) return null;
        return self.buf[0..n];
    }
};

fn gossipRecordValidator(ctx: ?*anyopaque, topic: []const u8, data: []const u8) gossipsub_runtime_pkg.ValidationResult {
    _ = topic;
    const cap: *GossipCapture = @ptrCast(@alignCast(ctx.?));
    cap.record(data);
    return .accept;
}

const gossipsub_runtime_pkg = @import("../gossipsub/runtime.zig");

test "QuicRuntime: two instances exchange a gossipsub message over UDP loopback" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;

    var bundle_a = try buildTestBundle(a, "ga", 0xC3);
    defer bundle_a.deinit(a);
    var bundle_b = try buildTestBundle(a, "gb", 0xD4);
    defer bundle_b.deinit(a);

    // Capture slot the validator writes into. Heap-allocated so the
    // validator's `*anyopaque` stays valid across the test scope.
    const capture = try a.create(GossipCapture);
    defer a.destroy(capture);
    capture.* = .{};

    var host_a = try host_mod.Host.create(.{
        .allocator = a,
        .local_peer = bundle_a.peer,
        .gossipsub = .{
            .local_peer_id = bundle_a.peer,
            .topic_validator = gossipRecordValidator,
            .validator_ctx = capture,
        },
    });
    defer host_a.destroy();
    try host_a.startBackground();
    try testing.expect(host_a.waitUntilReady(5_000));

    var rt_a = try QuicRuntime.create(.{
        .allocator = a,
        .host = host_a,
        .tls_pem = .{
            .pem_bytes = .{
                .cert_pem = bundle_a.cert_pem,
                .key_pem = bundle_a.key_pem,
            },
        },
        .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
    });
    defer rt_a.destroy();

    var host_b = try host_mod.Host.create(.{
        .allocator = a,
        .local_peer = bundle_b.peer,
        .gossipsub = .{ .local_peer_id = bundle_b.peer },
    });
    defer host_b.destroy();
    try host_b.startBackground();
    try testing.expect(host_b.waitUntilReady(5_000));

    var rt_b = try QuicRuntime.create(.{
        .allocator = a,
        .host = host_b,
        .tls_pem = .{
            .pem_bytes = .{
                .cert_pem = bundle_b.cert_pem,
                .key_pem = bundle_b.key_pem,
            },
        },
        .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
    });
    defer rt_b.destroy();

    try rt_a.start();
    try rt_b.start();

    const a_port = rt_a.boundUdpPortIpv4() orelse return error.NoBoundPort;

    // B dials A.
    var a_peer_b58_buf: [128]u8 = undefined;
    const a_peer_b58 = try bundle_a.peer.toBase58(&a_peer_b58_buf);
    const a_ma_str = try std.fmt.allocPrint(a, "/ip4/127.0.0.1/udp/{d}/quic-v1/p2p/{s}", .{ a_port, a_peer_b58 });
    defer a.free(a_ma_str);
    var a_ma = try multiaddr.Multiaddr.fromString(a, a_ma_str);
    defer a_ma.deinit();
    try rt_b.registerKnownPeer(&a_ma, bundle_a.peer);

    // Drain events on both hosts so internal swarm rings don't back up while
    // the test waits for the publish to land. We don't care about the event
    // contents — only that the validator fires on A.
    const Drainer = struct {
        fn run(h: *host_mod.Host, done: *std.atomic.Value(bool)) void {
            const deadline_ms = wall_time.milliTimestamp() + 25_000;
            while (wall_time.milliTimestamp() < deadline_ms) {
                if (done.load(.acquire)) return;
                var ev = h.nextEvent(100) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return,
                };
                ev.deinit(h.allocator);
            }
        }
    };
    var drain_done = std.atomic.Value(bool).init(false);
    var a_drainer = try std.Thread.spawn(.{}, Drainer.run, .{ host_a, &drain_done });
    defer a_drainer.join();
    var b_drainer = try std.Thread.spawn(.{}, Drainer.run, .{ host_b, &drain_done });
    defer b_drainer.join();
    defer drain_done.store(true, .release);

    // Wait for B's outbound dial to land.
    var connected = false;
    {
        const deadline_ms = wall_time.milliTimestamp() + 20_000;
        while (wall_time.milliTimestamp() < deadline_ms) {
            if (rt_b.outbound_by_peer.get(bundle_a.peer)) |_| {
                connected = true;
                break;
            }
            var req = std.c.timespec{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
            var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
            _ = std.c.nanosleep(&req, &rem);
        }
    }
    try testing.expect(connected);

    // Subscribe both sides. This is required for the gossipsub layer on A to
    // expose the topic to the duplicate cache; the validator itself runs
    // regardless of local subscription state but it doesn't hurt to mirror
    // a real two-node bring-up.
    try host_a.subscribe("test/topic");
    try host_b.subscribe("test/topic");

    // Publish from B. host.publish enqueues a swarm `.publish` (eaten by the
    // QuicRuntime hook) which fans the RPC frame out to every connected
    // outbound peer — A in this test.
    try host_b.publish("test/topic", "GOSSIP-FIXTURE");

    // Poll the validator capture until it sees the bytes (or we time out).
    var saw_payload = false;
    const deadline_ms = wall_time.milliTimestamp() + 20_000;
    while (wall_time.milliTimestamp() < deadline_ms) {
        if (capture.get()) |bytes| {
            try testing.expectEqualStrings("GOSSIP-FIXTURE", bytes);
            saw_payload = true;
            break;
        }
        var req = std.c.timespec{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
        var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
        _ = std.c.nanosleep(&req, &rem);
    }
    try testing.expect(saw_payload);
}

/// Validator-context that just counts how many distinct payloads arrived,
/// so the 3-node test below can assert "B+C each received N publishes from
/// A" — i.e. the libp2p per-message-stream gossipsub pattern survives
/// sustained traffic, not just a one-off publish.
const GossipCounter = struct {
    received: std.atomic.Value(usize) = .init(0),

    fn record(self: *GossipCounter) void {
        _ = self.received.fetchAdd(1, .monotonic);
    }

    fn count(self: *const GossipCounter) usize {
        return self.received.load(.acquire);
    }
};

fn gossipCountValidator(ctx: ?*anyopaque, topic: []const u8, data: []const u8) gossipsub_runtime_pkg.ValidationResult {
    _ = topic;
    _ = data;
    const c: *GossipCounter = @ptrCast(@alignCast(ctx.?));
    c.record();
    return .accept;
}

test "QuicRuntime: 3-node gossipsub propagation under sustained publishes" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;

    // Three hosts: A, B, C.  Each gets a GossipCounter validator so we can
    // assert how many publishes each side delivered.  Counters are
    // heap-allocated so they outlive the test's stack scope while the QUIC
    // drive threads still hold pointers to them.
    var bundle_a = try buildTestBundle(a, "ga", 0xC3);
    defer bundle_a.deinit(a);
    var bundle_b = try buildTestBundle(a, "gb", 0xD4);
    defer bundle_b.deinit(a);
    var bundle_c = try buildTestBundle(a, "gc", 0xE5);
    defer bundle_c.deinit(a);

    const counter_a = try a.create(GossipCounter);
    defer a.destroy(counter_a);
    counter_a.* = .{};
    const counter_b = try a.create(GossipCounter);
    defer a.destroy(counter_b);
    counter_b.* = .{};
    const counter_c = try a.create(GossipCounter);
    defer a.destroy(counter_c);
    counter_c.* = .{};

    // Bring up host_a + rt_a.
    var host_a = try host_mod.Host.create(.{
        .allocator = a,
        .local_peer = bundle_a.peer,
        .gossipsub = .{
            .local_peer_id = bundle_a.peer,
            .topic_validator = gossipCountValidator,
            .validator_ctx = counter_a,
        },
    });
    defer host_a.destroy();
    try host_a.startBackground();
    try testing.expect(host_a.waitUntilReady(5_000));
    var rt_a = try QuicRuntime.create(.{
        .allocator = a,
        .host = host_a,
        .tls_pem = .{ .pem_bytes = .{ .cert_pem = bundle_a.cert_pem, .key_pem = bundle_a.key_pem } },
        .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
    });
    defer rt_a.destroy();

    var host_b = try host_mod.Host.create(.{
        .allocator = a,
        .local_peer = bundle_b.peer,
        .gossipsub = .{
            .local_peer_id = bundle_b.peer,
            .topic_validator = gossipCountValidator,
            .validator_ctx = counter_b,
        },
    });
    defer host_b.destroy();
    try host_b.startBackground();
    try testing.expect(host_b.waitUntilReady(5_000));
    var rt_b = try QuicRuntime.create(.{
        .allocator = a,
        .host = host_b,
        .tls_pem = .{ .pem_bytes = .{ .cert_pem = bundle_b.cert_pem, .key_pem = bundle_b.key_pem } },
        .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
    });
    defer rt_b.destroy();

    var host_c = try host_mod.Host.create(.{
        .allocator = a,
        .local_peer = bundle_c.peer,
        .gossipsub = .{
            .local_peer_id = bundle_c.peer,
            .topic_validator = gossipCountValidator,
            .validator_ctx = counter_c,
        },
    });
    defer host_c.destroy();
    try host_c.startBackground();
    try testing.expect(host_c.waitUntilReady(5_000));
    var rt_c = try QuicRuntime.create(.{
        .allocator = a,
        .host = host_c,
        .tls_pem = .{ .pem_bytes = .{ .cert_pem = bundle_c.cert_pem, .key_pem = bundle_c.key_pem } },
        .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
    });
    defer rt_c.destroy();

    try rt_a.start();
    try rt_b.start();
    try rt_c.start();

    // Each non-A host dials A; C also dials B so the mesh ends up full
    // (A↔B, A↔C, B↔C).  zeam's runtime config does similar wiring.
    const a_port = rt_a.boundUdpPortIpv4() orelse return error.NoBoundPort;
    const b_port = rt_b.boundUdpPortIpv4() orelse return error.NoBoundPort;

    const c_port = rt_c.boundUdpPortIpv4() orelse return error.NoBoundPort;

    var peer_b58: [128]u8 = undefined;
    // Build a multiaddr for each host and have every other host register it.
    // Models zeam where each node dials every configured bootnode (so each
    // peer ends up in everyone else's outbound_by_peer table).
    {
        const s = try bundle_a.peer.toBase58(&peer_b58);
        const ma_str = try std.fmt.allocPrint(a, "/ip4/127.0.0.1/udp/{d}/quic-v1/p2p/{s}", .{ a_port, s });
        defer a.free(ma_str);
        var ma = try multiaddr.Multiaddr.fromString(a, ma_str);
        defer ma.deinit();
        try rt_b.registerKnownPeer(&ma, bundle_a.peer);
        try rt_c.registerKnownPeer(&ma, bundle_a.peer);
    }
    {
        const s = try bundle_b.peer.toBase58(&peer_b58);
        const ma_str = try std.fmt.allocPrint(a, "/ip4/127.0.0.1/udp/{d}/quic-v1/p2p/{s}", .{ b_port, s });
        defer a.free(ma_str);
        var ma = try multiaddr.Multiaddr.fromString(a, ma_str);
        defer ma.deinit();
        try rt_a.registerKnownPeer(&ma, bundle_b.peer);
        try rt_c.registerKnownPeer(&ma, bundle_b.peer);
    }
    {
        const s = try bundle_c.peer.toBase58(&peer_b58);
        const ma_str = try std.fmt.allocPrint(a, "/ip4/127.0.0.1/udp/{d}/quic-v1/p2p/{s}", .{ c_port, s });
        defer a.free(ma_str);
        var ma = try multiaddr.Multiaddr.fromString(a, ma_str);
        defer ma.deinit();
        try rt_a.registerKnownPeer(&ma, bundle_c.peer);
        try rt_b.registerKnownPeer(&ma, bundle_c.peer);
    }

    // Drain events on all hosts so internal rings don't back up.
    const Drainer = struct {
        fn run(h: *host_mod.Host, done: *std.atomic.Value(bool)) void {
            const dl = wall_time.milliTimestamp() + 60_000;
            while (wall_time.milliTimestamp() < dl) {
                if (done.load(.acquire)) return;
                var ev = h.nextEvent(100) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return,
                };
                ev.deinit(h.allocator);
            }
        }
    };
    var drain_done = std.atomic.Value(bool).init(false);
    var da = try std.Thread.spawn(.{}, Drainer.run, .{ host_a, &drain_done });
    defer da.join();
    var db = try std.Thread.spawn(.{}, Drainer.run, .{ host_b, &drain_done });
    defer db.join();
    var dc = try std.Thread.spawn(.{}, Drainer.run, .{ host_c, &drain_done });
    defer dc.join();
    defer drain_done.store(true, .release);

    // Wait for the full 6-edge outbound mesh: each node has dialed the
    // other two.  Models zeam where every node has every other node in its
    // outbound_by_peer table.
    {
        const dl = wall_time.milliTimestamp() + 20_000;
        while (wall_time.milliTimestamp() < dl) {
            const ab = rt_a.outbound_by_peer.get(bundle_b.peer) != null;
            const ac = rt_a.outbound_by_peer.get(bundle_c.peer) != null;
            const ba = rt_b.outbound_by_peer.get(bundle_a.peer) != null;
            const bc = rt_b.outbound_by_peer.get(bundle_c.peer) != null;
            const ca = rt_c.outbound_by_peer.get(bundle_a.peer) != null;
            const cb = rt_c.outbound_by_peer.get(bundle_b.peer) != null;
            if (ab and ac and ba and bc and ca and cb) break;
            var req = std.c.timespec{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
            var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
            _ = std.c.nanosleep(&req, &rem);
        }
        try testing.expect(rt_a.outbound_by_peer.get(bundle_b.peer) != null);
        try testing.expect(rt_a.outbound_by_peer.get(bundle_c.peer) != null);
        try testing.expect(rt_b.outbound_by_peer.get(bundle_a.peer) != null);
        try testing.expect(rt_b.outbound_by_peer.get(bundle_c.peer) != null);
        try testing.expect(rt_c.outbound_by_peer.get(bundle_a.peer) != null);
        try testing.expect(rt_c.outbound_by_peer.get(bundle_b.peer) != null);
    }

    // All subscribe so the gossipsub mesh forms on the common topic.
    try host_a.subscribe("test/topic");
    try host_b.subscribe("test/topic");
    try host_c.subscribe("test/topic");

    // Publish a stream of messages from A.  Each publish opens a fresh
    // /meshsub/1.1.0 stream — this is the per-message pattern that exhausts
    // the 64-slot raw_app_streams table on the receiver in production.  We
    // pace publishes lightly so the receiver's drive loop has cycles to
    // release slots.
    const total_publishes: usize = 30;
    for (0..total_publishes) |i| {
        var payload_buf: [32]u8 = undefined;
        const payload = try std.fmt.bufPrint(&payload_buf, "msg-{d}", .{i});
        try host_a.publish("test/topic", payload);
        // 50ms between publishes — sustained but not bursty.
        var req = std.c.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
        var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
        _ = std.c.nanosleep(&req, &rem);
    }

    // Poll until each receiver's counter reaches `total_publishes` (or time
    // out).  gossipsub dedups so each peer sees each message once.
    const expected: usize = total_publishes;
    const deadline = wall_time.milliTimestamp() + 20_000;
    while (wall_time.milliTimestamp() < deadline) {
        if (counter_b.count() >= expected and counter_c.count() >= expected) break;
        var req = std.c.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
        var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
        _ = std.c.nanosleep(&req, &rem);
    }

    // Diagnostic on failure: print received counts so we can see how far
    // delivery got.  Use std.debug.print so this lands in test output.
    if (counter_b.count() < expected or counter_c.count() < expected) {
        std.debug.print(
            "\n3-node gossipsub: B={d}/{d} C={d}/{d}\n",
            .{ counter_b.count(), expected, counter_c.count(), expected },
        );
    }
    try testing.expect(counter_b.count() >= expected);
    try testing.expect(counter_c.count() >= expected);
}

// ============================================================================
// Interop test suite — extends the 3-node baseline with mesh-scale + workload-
// shape coverage that matches zeam's deployment pattern.  Each test builds a
// small all-to-all QuicRuntime mesh, runs a focused traffic shape, and asserts
// the outcome.  Helpers (`buildTestBundle`, `Drainer`, `GossipCounter`) are
// reused from the tests above.
// ============================================================================

/// Minimal cluster scaffold: bring up `n` Hosts + QuicRuntimes, wire them in a
/// full all-to-all outbound mesh, return the slices.  Caller drives, polls,
/// and tears down.  Hard-coded for n ≤ 8 because each host needs its own
/// deterministic test bundle seed.
const ClusterCfg = struct {
    n: usize,
    /// Per-host topic_validator.  Same fn for all hosts.  Null = no validator.
    topic_validator: ?*const fn (?*anyopaque, []const u8, []const u8) gossipsub_runtime_pkg.ValidationResult = null,
    /// Per-host validator contexts.  Slice length must equal `n`.  Each entry
    /// is passed verbatim to that host's gossipsub config.
    validator_ctxs: ?[]const ?*anyopaque = null,
};

const ClusterHost = struct {
    bundle: TestCertBundle,
    host: *host_mod.Host,
    rt: *QuicRuntime,
};

fn buildCluster(a: std.mem.Allocator, cfg: ClusterCfg) ![]ClusterHost {
    const seeds = [_]u8{ 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87 };
    if (cfg.n > seeds.len) return error.ClusterTooLarge;
    if (cfg.validator_ctxs) |c| if (c.len != cfg.n) return error.CtxLenMismatch;

    var out = try a.alloc(ClusterHost, cfg.n);
    errdefer a.free(out);
    var built: usize = 0;
    errdefer for (out[0..built]) |*h| {
        h.rt.destroy();
        h.host.destroy();
        h.bundle.deinit(a);
    };

    for (0..cfg.n) |i| {
        out[i].bundle = try buildTestBundle(a, "cluster", seeds[i]);
        const validator_ctx = if (cfg.validator_ctxs) |c| c[i] else null;
        out[i].host = try host_mod.Host.create(.{
            .allocator = a,
            .local_peer = out[i].bundle.peer,
            .gossipsub = .{
                .local_peer_id = out[i].bundle.peer,
                .topic_validator = cfg.topic_validator,
                .validator_ctx = validator_ctx,
            },
        });
        try out[i].host.startBackground();
        if (!out[i].host.waitUntilReady(5_000)) return error.HostNotReady;
        out[i].rt = try QuicRuntime.create(.{
            .allocator = a,
            .host = out[i].host,
            .tls_pem = .{ .pem_bytes = .{ .cert_pem = out[i].bundle.cert_pem, .key_pem = out[i].bundle.key_pem } },
            .listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1",
        });
        try out[i].rt.start();
        built += 1;
    }

    // Wire the all-to-all outbound mesh.  Each host registers every other
    // host's multiaddr as a known peer, which the connection_manager
    // background dials.
    for (out) |*hi| {
        for (out) |*hj| {
            if (hi.bundle.peer.eql(&hj.bundle.peer)) continue;
            const port = hj.rt.boundUdpPortIpv4() orelse return error.NoBoundPort;
            var b58: [128]u8 = undefined;
            const s = try hj.bundle.peer.toBase58(&b58);
            const ma_str = try std.fmt.allocPrint(a, "/ip4/127.0.0.1/udp/{d}/quic-v1/p2p/{s}", .{ port, s });
            defer a.free(ma_str);
            var ma = try multiaddr.Multiaddr.fromString(a, ma_str);
            defer ma.deinit();
            try hi.rt.registerKnownPeer(&ma, hj.bundle.peer);
        }
    }
    return out;
}

fn destroyCluster(a: std.mem.Allocator, cluster: []ClusterHost) void {
    for (cluster) |*h| {
        h.rt.destroy();
        h.host.destroy();
        h.bundle.deinit(a);
    }
    a.free(cluster);
}

/// Block until every host in the cluster has every other host in its
/// `outbound_by_peer` map, or the deadline elapses.
fn waitMeshConverged(cluster: []ClusterHost, deadline_ms: i64) bool {
    while (wall_time.milliTimestamp() < deadline_ms) {
        var all_ok = true;
        for (cluster) |*hi| {
            for (cluster) |*hj| {
                if (hi.bundle.peer.eql(&hj.bundle.peer)) continue;
                if (hi.rt.outbound_by_peer.get(hj.bundle.peer) == null) {
                    all_ok = false;
                    break;
                }
            }
            if (!all_ok) break;
        }
        if (all_ok) return true;
        var req = std.c.timespec{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
        var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
        _ = std.c.nanosleep(&req, &rem);
    }
    return false;
}

const ClusterDrainer = struct {
    fn run(h: *host_mod.Host, done: *std.atomic.Value(bool)) void {
        const dl = wall_time.milliTimestamp() + 120_000;
        while (wall_time.milliTimestamp() < dl) {
            if (done.load(.acquire)) return;
            var ev = h.nextEvent(100) catch |err| switch (err) {
                error.Timeout => continue,
                else => return,
            };
            ev.deinit(h.allocator);
        }
    }
};

test "QuicRuntime: 5-node gossipsub mesh under sustained publishes" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const n: usize = 5;

    // Per-host validator counters so we can assert delivery per receiver.
    var counters: [n]*GossipCounter = undefined;
    for (0..n) |i| {
        counters[i] = try a.create(GossipCounter);
        counters[i].* = .{};
    }
    defer for (counters) |c| a.destroy(c);

    var ctx_storage: [n]?*anyopaque = undefined;
    for (0..n) |i| ctx_storage[i] = @as(*anyopaque, @ptrCast(counters[i]));

    const cluster = try buildCluster(a, .{
        .n = n,
        .topic_validator = gossipCountValidator,
        .validator_ctxs = ctx_storage[0..],
    });
    defer destroyCluster(a, cluster);

    // Drainers for all hosts.
    var drain_done = std.atomic.Value(bool).init(false);
    var threads = std.ArrayList(std.Thread).empty;
    defer threads.deinit(a);
    defer {
        drain_done.store(true, .release);
        for (threads.items) |th| th.join();
    }
    for (cluster) |*ch| {
        const th = try std.Thread.spawn(.{}, ClusterDrainer.run, .{ ch.host, &drain_done });
        try threads.append(a, th);
    }

    try testing.expect(waitMeshConverged(cluster, wall_time.milliTimestamp() + 20_000));

    for (cluster) |*ch| try ch.host.subscribe("interop/topic");

    // Publish 20 messages from each of the first 3 hosts.  Gossipsub does
    // NOT fire the local validator on the publisher's own publishes (the
    // sender already has the message), so receiver counts differ between
    // publishers and pure listeners:
    //   - hosts 0..n_publishers (each is also a publisher) see
    //     (n_publishers - 1) × pubs_per_host messages from the *other*
    //     publishers
    //   - hosts n_publishers..n see all n_publishers × pubs_per_host
    const pubs_per_host: usize = 20;
    const n_publishers: usize = 3;
    for (cluster[0..n_publishers], 0..) |*ch, p| {
        for (0..pubs_per_host) |i| {
            var buf: [32]u8 = undefined;
            const payload = try std.fmt.bufPrint(&buf, "h{d}-m{d}", .{ p, i });
            try ch.host.publish("interop/topic", payload);
            var req = std.c.timespec{ .sec = 0, .nsec = 25 * std.time.ns_per_ms };
            var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
            _ = std.c.nanosleep(&req, &rem);
        }
    }

    const expected_pub: usize = (n_publishers - 1) * pubs_per_host;
    const expected_listener: usize = n_publishers * pubs_per_host;
    const dl = wall_time.milliTimestamp() + 30_000;
    while (wall_time.milliTimestamp() < dl) {
        var all = true;
        for (counters, 0..) |c, i| {
            const exp = if (i < n_publishers) expected_pub else expected_listener;
            if (c.count() < exp) {
                all = false;
                break;
            }
        }
        if (all) break;
        var req = std.c.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
        var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
        _ = std.c.nanosleep(&req, &rem);
    }

    for (counters, 0..) |c, i| {
        const exp = if (i < n_publishers) expected_pub else expected_listener;
        if (c.count() < exp) {
            std.debug.print("5-node mesh: host[{d}] got {d}/{d}\n", .{ i, c.count(), exp });
        }
        try testing.expect(c.count() >= exp);
    }
}

test "QuicRuntime: req-resp burst — multiple inflight requests per peer" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;

    const cluster = try buildCluster(a, .{ .n = 2 });
    defer destroyCluster(a, cluster);

    var drain_done = std.atomic.Value(bool).init(false);
    // B is the requester — only drain A (responder); we manually loop B's
    // events in the test thread to observe response chunks.
    var a_drainer = try std.Thread.spawn(.{}, struct {
        fn run(h: *host_mod.Host, done: *std.atomic.Value(bool)) void {
            const dl = wall_time.milliTimestamp() + 60_000;
            while (wall_time.milliTimestamp() < dl) {
                if (done.load(.acquire)) return;
                var ev = h.nextEvent(100) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return,
                };
                defer ev.deinit(h.allocator);
                switch (ev) {
                    .rpc_request => |r| {
                        h.sendResponseChunk(r.channel_id, "OK", wall_time.milliTimestamp()) catch {};
                        h.finishResponseStream(r.channel_id) catch {};
                    },
                    else => {},
                }
            }
        }
    }.run, .{ cluster[0].host, &drain_done });
    defer {
        drain_done.store(true, .release);
        a_drainer.join();
    }

    try testing.expect(waitMeshConverged(cluster, wall_time.milliTimestamp() + 20_000));

    // Fire 16 status requests back-to-back from B → A without waiting for
    // each response.  Exercises req-resp's multi-inflight bookkeeping.
    const n_req: usize = 16;
    for (0..n_req) |_| {
        _ = try cluster[1].host.sendRequest(cluster[0].bundle.peer, .status, "REQ", 15_000);
    }

    var ends: usize = 0;
    var chunks: usize = 0;
    const dl = wall_time.milliTimestamp() + 30_000;
    while (wall_time.milliTimestamp() < dl and ends < n_req) {
        var ev = cluster[1].host.nextEvent(500) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        defer ev.deinit(a);
        switch (ev) {
            .rpc_response_chunk => chunks += 1,
            .rpc_response_end => ends += 1,
            else => {},
        }
    }

    try testing.expectEqual(@as(usize, n_req), ends);
    try testing.expect(chunks >= n_req); // at least one chunk per request
}

test "QuicRuntime: mixed gossipsub pub + req-resp on same hosts" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const n: usize = 3;

    var counters: [n]*GossipCounter = undefined;
    for (0..n) |i| {
        counters[i] = try a.create(GossipCounter);
        counters[i].* = .{};
    }
    defer for (counters) |c| a.destroy(c);
    var ctx: [n]?*anyopaque = undefined;
    for (0..n) |i| ctx[i] = @as(*anyopaque, @ptrCast(counters[i]));

    const cluster = try buildCluster(a, .{
        .n = n,
        .topic_validator = gossipCountValidator,
        .validator_ctxs = ctx[0..],
    });
    defer destroyCluster(a, cluster);

    // All hosts respond to incoming req-resp + drain events.
    var drain_done = std.atomic.Value(bool).init(false);
    const Responder = struct {
        fn run(h: *host_mod.Host, done: *std.atomic.Value(bool)) void {
            const dl = wall_time.milliTimestamp() + 60_000;
            while (wall_time.milliTimestamp() < dl) {
                if (done.load(.acquire)) return;
                var ev = h.nextEvent(100) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return,
                };
                defer ev.deinit(h.allocator);
                switch (ev) {
                    .rpc_request => |r| {
                        h.sendResponseChunk(r.channel_id, "RR-OK", wall_time.milliTimestamp()) catch {};
                        h.finishResponseStream(r.channel_id) catch {};
                    },
                    else => {},
                }
            }
        }
    };
    var threads = std.ArrayList(std.Thread).empty;
    defer threads.deinit(a);
    defer {
        drain_done.store(true, .release);
        for (threads.items) |th| th.join();
    }
    for (cluster) |*ch| {
        const th = try std.Thread.spawn(.{}, Responder.run, .{ ch.host, &drain_done });
        try threads.append(a, th);
    }

    try testing.expect(waitMeshConverged(cluster, wall_time.milliTimestamp() + 20_000));
    for (cluster) |*ch| try ch.host.subscribe("mixed/topic");

    // Interleave 10 publishes from host 0 with 10 status requests from host 0
    // to host 1.  Exercises both paths running concurrently on shared
    // connection state.
    const n_iter: usize = 10;
    for (0..n_iter) |i| {
        var buf: [32]u8 = undefined;
        const payload = try std.fmt.bufPrint(&buf, "mix-{d}", .{i});
        try cluster[0].host.publish("mixed/topic", payload);
        _ = try cluster[0].host.sendRequest(cluster[1].bundle.peer, .status, "REQ", 15_000);
        var req = std.c.timespec{ .sec = 0, .nsec = 30 * std.time.ns_per_ms };
        var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
        _ = std.c.nanosleep(&req, &rem);
    }

    // Publisher (host 0) does NOT fire its own validator on its publishes,
    // so only hosts 1..n should have the full count.
    const dl = wall_time.milliTimestamp() + 20_000;
    while (wall_time.milliTimestamp() < dl) {
        var ok = true;
        for (counters[1..]) |c| if (c.count() < n_iter) {
            ok = false;
            break;
        };
        if (ok) break;
        var req = std.c.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
        var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
        _ = std.c.nanosleep(&req, &rem);
    }

    for (counters[1..], 1..) |c, i| {
        if (c.count() < n_iter) {
            std.debug.print("mixed: host[{d}] got {d}/{d}\n", .{ i, c.count(), n_iter });
        }
        try testing.expect(c.count() >= n_iter);
    }
}

test "QuicRuntime: long-running sustained gossipsub (60s)" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;
    // Long-running soak: skipped by default to keep `zig build test` fast.
    // Flip `enable` to true locally or in a dedicated CI job to run.
    const enable: bool = false;
    if (!enable) return error.SkipZigTest;

    const a = testing.allocator;
    const n: usize = 3;

    var counters: [n]*GossipCounter = undefined;
    for (0..n) |i| {
        counters[i] = try a.create(GossipCounter);
        counters[i].* = .{};
    }
    defer for (counters) |c| a.destroy(c);
    var ctx: [n]?*anyopaque = undefined;
    for (0..n) |i| ctx[i] = @as(*anyopaque, @ptrCast(counters[i]));

    const cluster = try buildCluster(a, .{
        .n = n,
        .topic_validator = gossipCountValidator,
        .validator_ctxs = ctx[0..],
    });
    defer destroyCluster(a, cluster);

    var drain_done = std.atomic.Value(bool).init(false);
    var threads = std.ArrayList(std.Thread).empty;
    defer threads.deinit(a);
    defer {
        drain_done.store(true, .release);
        for (threads.items) |th| th.join();
    }
    for (cluster) |*ch| {
        const th = try std.Thread.spawn(.{}, ClusterDrainer.run, .{ ch.host, &drain_done });
        try threads.append(a, th);
    }

    try testing.expect(waitMeshConverged(cluster, wall_time.milliTimestamp() + 20_000));
    for (cluster) |*ch| try ch.host.subscribe("soak/topic");

    // 60-second window, one publish from host 0 every 200 ms ≈ 300 publishes.
    // Asserts no slow-leak / state drift over time.
    const soak_ms: i64 = 60_000;
    const interval_ms: i64 = 200;
    const start = wall_time.milliTimestamp();
    var sent: usize = 0;
    var next_at = start;
    while (wall_time.milliTimestamp() - start < soak_ms) {
        const now = wall_time.milliTimestamp();
        if (now >= next_at) {
            var buf: [32]u8 = undefined;
            const payload = try std.fmt.bufPrint(&buf, "soak-{d}", .{sent});
            try cluster[0].host.publish("soak/topic", payload);
            sent += 1;
            next_at = now + interval_ms;
        }
        var req = std.c.timespec{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
        var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
        _ = std.c.nanosleep(&req, &rem);
    }

    // After a short settle window every receiver should have all `sent`
    // payloads.  Tolerate slack of up to 5 missing under heavy timing
    // jitter — the failure surface we care about is total stall, not single
    // dropped msgs.
    const settle_dl = wall_time.milliTimestamp() + 10_000;
    while (wall_time.milliTimestamp() < settle_dl) {
        var ok = true;
        for (counters) |c| if (c.count() + 5 < sent) {
            ok = false;
            break;
        };
        if (ok) break;
        var req = std.c.timespec{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
        var rem = std.c.timespec{ .sec = 0, .nsec = 0 };
        _ = std.c.nanosleep(&req, &rem);
    }

    for (counters, 0..) |c, i| {
        if (c.count() + 5 < sent) {
            std.debug.print("soak: host[{d}] got {d}/{d}\n", .{ i, c.count(), sent });
        }
        try testing.expect(c.count() + 5 >= sent);
    }
}
