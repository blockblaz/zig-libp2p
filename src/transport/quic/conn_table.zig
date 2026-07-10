//! Per-connection QUIC runtime tables and stream state.

const std = @import("std");

const identity = @import("../../primitives/identity.zig");
const protocol_mod = @import("../../primitives/protocol.zig");
const connection_manager_mod = @import("../../core/connection_manager.zig");
const quic_endpoint = @import("endpoint.zig");
const quic_raw_stream_io = @import("raw_stream_io.zig");
const zquic = @import("zquic");
const ZIo = zquic.transport.io;

pub const PeerIdContext = struct {
    pub fn hash(_: PeerIdContext, key: identity.PeerId) u64 {
        var buf: [128]u8 = undefined;
        const b = key.toBytes(&buf) catch return 0;
        return std.hash.Wyhash.hash(0, b);
    }
    pub fn eql(_: PeerIdContext, a: identity.PeerId, b: identity.PeerId) bool {
        return a.eql(&b);
    }
};

pub const PeerIdMap = std.HashMap(identity.PeerId, *OutboundConn, PeerIdContext, std.hash_map.default_max_load_percentage);
pub const InboundPeerMap = std.HashMap(identity.PeerId, InboundConnRef, PeerIdContext, std.hash_map.default_max_load_percentage);
pub const PersistentGossipMap = std.HashMap(identity.PeerId, *PersistentGossipStream, PeerIdContext, std.hash_map.default_max_load_percentage);
pub const RelayedConnIdMap = std.HashMap(identity.PeerId, connection_manager_mod.ConnectionId, PeerIdContext, std.hash_map.default_max_load_percentage);
/// peer id -> owning drive-shard index (Phase 4 authoritative work router).
pub const PeerShardMap = std.HashMap(identity.PeerId, u8, PeerIdContext, std.hash_map.default_max_load_percentage);

pub const InboundConnRef = struct {
    slot: usize,
    conn: *ZIo.ConnState,
};

/// Tracked outbound connection: one QUIC connection per (remote peer).
pub const OutboundConn = struct {
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
    peer_stream_reported: quic_endpoint.SurfacedStreamSet = .{},
};

/// Per-inbound-stream state: tracks where in the per-protocol read flow we are.
pub const InboundStream = struct {
    /// Listener connection slot index. Set to `inbound_slot_none` for streams that arrived on
    /// an outbound (client-side) QUIC connection: those connections are already fully
    /// established so the normal connection-notification path must be skipped.
    slot: usize,
    conn: *ZIo.ConnState,
    stream_id: u64,
    raw: quic_raw_stream_io.RawAppBidiServer,
    handshake_done: bool = false,
    /// Wall-clock ms the stream was accepted; drives the inbound reap
    /// ([`inbound_request_reap_ms`]). 0 = unset (never reaped on age).
    created_ms: i64 = 0,
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
    /// Queued, wire-framed response chunks awaiting a BUDGETED per-drive-lap drain
    /// (`drainResponseOutbox`). The responder enqueues here instead of `writeAll`-ing
    /// synchronously: a multi-MB BlocksByRange response shoved into zquic in one lap
    /// fills the 32 MB per-stream pending queue, makes the lap 0.3-1.3s, starves the
    /// inbound socket drain → packet loss → CC collapse. Drained at
    /// `response_drain_budget_bytes`/tick like the gossip bulk lane.
    response_outbox: std.ArrayList([]u8) = .empty,
    /// Send offset into `response_outbox.items[0]` (a chunk may span several laps).
    response_outbox_offset: usize = 0,
    /// FIN requested by handleEndOfStream but deferred until response_outbox drains,
    /// so the 0-byte FIN never races ahead of queued response bytes.
    response_fin_pending: bool = false,
};

/// Hard upper bound on how long an in-flight outbound request may hold its
/// zquic raw-app slot before the drive loop reaps it. The embedder applies its
/// own (shorter) request timeout and stops waiting for the response, but it
/// never tells the runtime to drop the request — so without this reaper an
/// orphaned request (response lost, peer never replied) holds one of the conn's
/// 64 raw_app slots forever. On a long-lived inbound-leg connection a handful
/// of such orphans per peer exhaust the table and every later request fails with
/// RawAppStreamSlotsFull. Set well above any real RPC round-trip.
pub const outbound_request_reap_ms: i64 = 15_000;

/// Deadline after which the drive loop reaps an INBOUND req/resp stream that has
/// not finished its response. Catches a peer that opens a stream and stalls
/// mid-request (never sends the body / never FINs), which otherwise leaks the
/// InboundStream + its raw-app slot forever (→ RawAppStreamSlotsFull → the node
/// silently stops serving sync). Generous (2× the outbound reaper) so a slow but
/// legitimate response is never falsely reaped.
pub const inbound_request_reap_ms: i64 = 30_000;

/// Grace window before an inbound `/status` stream with NO request body yet is
/// dispatched to the responder with an EMPTY payload. rust-libp2p (lantern) and
/// other clients open `/status`, complete multistream-select, then send ZERO
/// request-body bytes and never FIN — treating an empty request as valid (our
/// own status responder ignores the body). Without answering, we reap after
/// `inbound_request_reap_ms` → the peer times out → conn flap. But a NORMAL peer
/// that DOES send a body may have it still in flight on the first drive tick, so
/// dispatching an empty payload immediately would race ahead of the body. This
/// grace lets a real body land + decode first; only a genuinely empty request
/// (body never arrives) trips the empty-`/status` dispatch. Well under the reap.
///
/// 500ms was FAR longer than an in-flight request body ever needs (a body lands
/// within ~1 RTT + a drive lap — single-digit ms on loopback, low ms on the
/// devnet). The live zeam<->lantern flap proved lantern's own reqresp deadline
/// is shorter than 500ms: lantern opens a server-initiated `/status` on the leg
/// zeam dialed, sends 0 body bytes, and gives up (-1004) + graceful-closes the
/// leg before the 500ms grace elapses, so zeam never answers → redial churn.
/// 20ms keeps a real body's decode-first behavior (bodies land far faster than
/// this) while answering the empty (lantern) shape well within its deadline.
/// `/status` is body-independent (the responder returns chain.getStatus()), so
/// even a rare raced body-sender still gets the correct response.
pub const inbound_status_empty_grace_ms: i64 = 20;

pub const OutboundRequest = struct {
    /// The peer this request is destined for.
    peer: identity.PeerId,
    request_id: u64,
    proto: protocol_mod.LeanSupportedProtocol,
    stream_id: u64,
    /// Wall-clock ms after which the drive loop reaps this request even if no
    /// response/FIN arrived, releasing its raw-app slot. See
    /// [`outbound_request_reap_ms`].
    deadline_ms: i64 = 0,
    /// Outbound (client) leg when we dialed the peer; inbound (server-initiated)
    /// leg when the peer dialed us and we have no outbound conn. libp2p req/resp
    /// rides whichever single connection exists — see `startOutboundRequest`.
    raw: PublishBidiStream,
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
pub const PublishBidiStream = union(enum) {
    outbound: quic_raw_stream_io.RawAppBidiClient,
    inbound: quic_raw_stream_io.RawAppBidiServer,

    pub fn reader(self: *PublishBidiStream) std.Io.Reader {
        return switch (self.*) {
            .outbound => |*c| c.reader(),
            .inbound => |*s| s.reader(),
        };
    }

    pub fn writer(self: *PublishBidiStream) std.Io.Writer {
        return switch (self.*) {
            .outbound => |*c| c.writer(),
            .inbound => |*s| s.writer(),
        };
    }

    pub fn unreadRecvLen(self: *const PublishBidiStream) usize {
        return switch (self.*) {
            .outbound => |*c| c.unreadRecvLen(),
            .inbound => |*s| s.unreadRecvLen(),
        };
    }

    /// Mark the underlying zquic stream PRIORITY so its pending-send bytes
    /// reserve headroom in the per-connection budget. The persistent /meshsub
    /// gossip stream uses this so a large req/resp response (e.g. a multi-MB
    /// `blocks_by_range`) can never monopolize the budget and starve gossip.
    pub fn markPriority(self: *PublishBidiStream) void {
        switch (self.*) {
            .outbound => |*c| c.markPriority(),
            .inbound => |*s| s.markPriority(),
        }
    }

    /// Pending receive buffer for this stream (null until the peer sends data).
    /// Lets a response reader work over either an outbound (client) leg or an
    /// inbound (server-initiated) leg — the req/resp-over-inbound fallback,
    /// symmetric with the gossip-publish fallback this union already serves.
    pub fn recvBuffer(self: *const PublishBidiStream) ?[]const u8 {
        return switch (self.*) {
            .outbound => |*c| c.client.rawAppRecvBuffer(c.stream_id),
            .inbound => |*s| s.recvBuffer(),
        };
    }

    /// FIN seen AND all bytes up to the final size contiguously reassembled.
    pub fn fullyReceived(self: *const PublishBidiStream) bool {
        return switch (self.*) {
            .outbound => |*c| c.client.rawAppStreamFullyReceived(c.stream_id),
            .inbound => |*s| s.fullyReceived(),
        };
    }

    pub fn readCursor(self: *const PublishBidiStream) usize {
        return switch (self.*) {
            .outbound => |*c| c.read_cursor,
            .inbound => |*s| s.read_cursor,
        };
    }

    pub fn setReadCursor(self: *PublishBidiStream, v: usize) void {
        switch (self.*) {
            .outbound => |*c| c.read_cursor = v,
            .inbound => |*s| s.read_cursor = v,
        }
    }

    /// Release the underlying zquic raw-app slot for this stream. For the
    /// `.inbound` (server-initiated) leg this frees the listener-side
    /// `raw_app_streams` slot on `conn`; for the `.outbound` leg it frees the
    /// client-side `raw_app_recv` slot. Without this an inbound-leg req/resp
    /// permanently burns one of the conn's 64 slots — after ~64 cumulative
    /// inbound-leg requests `openRawAppStream` returns `RawAppStreamSlotsFull`
    /// and every later request fails forever (the live status-RPC ~94% timeout).
    pub fn release(self: *PublishBidiStream, allocator: std.mem.Allocator) bool {
        return switch (self.*) {
            .outbound => |*c| c.release(allocator),
            .inbound => |*s| s.release(allocator),
        };
    }

    pub fn finStream(self: *PublishBidiStream) void {
        switch (self.*) {
            .outbound => |*c| _ = c.client.sendRawStreamData(c.stream_id, c.send_offset, &[_]u8{}, true),
            .inbound => |*s| {
                if (s.client) |c| {
                    _ = c.sendRawStreamData(s.stream_id, s.send_offset, &[_]u8{}, true);
                } else {
                    _ = s.server.sendRawStreamData(s.conn, s.stream_id, s.send_offset, &[_]u8{}, true);
                }
            },
        }
    }

    /// Single-shot raw-stream send that returns the number of bytes zquic
    /// accepted (queued for transmission).  A return value of `0` means
    /// **transient backpressure** — the zquic per-stream pending queue is at
    /// its cap and the caller must hold the unsent bytes and retry on a
    /// later tick.  This is the equivalent of `Poll::Pending` from quinn's
    /// `SendStream::poll_write` (rust-libp2p treats it the same way and
    /// suspends the writer task without dropping the stream).
    ///
    /// `send_offset` is advanced by the accepted byte count so the next call
    /// continues at the right STREAM frame offset; partial sends never
    /// re-emit accepted bytes.
    pub fn sendChunk(self: *PublishBidiStream, chunk: []const u8, fin: bool) usize {
        return switch (self.*) {
            .outbound => |*c| blk: {
                const accepted = c.client.sendRawStreamData(c.stream_id, c.send_offset, chunk, fin);
                c.send_offset += @intCast(accepted);
                break :blk accepted;
            },
            .inbound => |*s| blk: {
                if (s.client) |c| {
                    const accepted = c.sendRawStreamData(s.stream_id, s.send_offset, chunk, fin);
                    s.send_offset += @intCast(accepted);
                    break :blk accepted;
                }
                const accepted = s.server.sendRawStreamData(s.conn, s.stream_id, s.send_offset, chunk, fin);
                s.send_offset += @intCast(accepted);
                break :blk accepted;
            },
        };
    }
};

/// In-flight gossipsub publish on a `/meshsub/1.1.0` stream. One per peer per
/// message (`per-message stream` pattern — open, multistream-select, write one
/// length-prefixed RPC frame, close).
pub const OutboundPublish = struct {
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

/// One-shot outbound `/ipfs/id/push/1.0.0` stream (#202 QUIC wiring).
pub const OutboundIdentifyPush = struct {
    peer: identity.PeerId,
    stream_id: u64,
    raw: PublishBidiStream,
    handshake_sent: bool = false,
    handshake_done: bool = false,
    wire_written: bool = false,
    finished: bool = false,
    wire: []u8,
};

/// One-shot outbound `/libp2p/autonat/1.0.0` probe stream (#206).
pub const OutboundAutonatProbe = struct {
    peer: identity.PeerId,
    stream_id: u64,
    raw: PublishBidiStream,
    handshake_sent: bool = false,
    handshake_done: bool = false,
    probe_written: bool = false,
    response_done: bool = false,
    finished: bool = false,
    probe_wire: []u8,
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
///
/// Wedge is declared by any of:
///   * `markPersistentGossipBroken` on a handshake or keepalive write/flush
///     failure (synchronous error from the writer).
///   * `outbox_stuck_since_ms` in [`advancePersistentGossipStreams`] exceeding
///     [`persistent_gossip_outbox_stuck_timeout_ms`] (proactive trigger fires
///     before zquic's 60 s no-ACK conn-lost timer so libp2p drives recovery
///     on its own clock rather than waiting for the transport to give up —
///     a single 20 s wedge per peer used to drop 30+ slots of gossip,
///     starving the FFG supermajority and stalling finalization).
pub const PersistentGossipStream = struct {
    peer: identity.PeerId,
    stream_id: u64,
    raw: PublishBidiStream,
    handshake_sent: bool = false,
    handshake_done: bool = false,
    /// True once the peer's `/multistream/1.0.0` header has been consumed by
    /// [`stream_multistream.initiatorMeshsubFallbackStep`]. The header is read
    /// once; subsequent ticks read only protocol-ack tokens.
    ms_header_done: bool = false,
    /// Index into [`meshsub_offer_fallbacks`] of the `/meshsub` version we are
    /// currently offering. Advances each time the responder answers `na`, so a
    /// peer that doesn't support the newest version negotiates down instead of
    /// tearing the connection down (lantern / go-libp2p interop).
    offer_idx: usize = 0,
    /// Set when the multistream-select handshake or a frame write fails.
    /// Once broken, the stream is never revived for the remainder of the
    /// underlying QUIC connection's lifetime; new outbox enqueues are dropped
    /// and the drain loop skips this entry.
    broken: bool = false,
    /// PRIORITY lane: queue of `uvarint(len) + RPC protobuf` frames waiting to
    /// be flushed once the multistream-select handshake completes. Bytes are
    /// heap-owned; drained in FIFO order. Capped at
    /// [`persistent_gossip_outbox_cap`] so a peer that never reads cannot make
    /// us hold unbounded memory before the QUIC keepalive notices and tears
    /// down the connection.
    ///
    /// This lane carries small, time-sensitive frames (subnet attestations,
    /// aggregations, control: SUBSCRIBE/GRAFT/PRUNE/IHAVE/IWANT, keepalives) —
    /// any frame `<= persistent_gossip_priority_max_bytes`. The drain always
    /// empties this lane FIRST so a multi-MB block sitting in [`outbox_bulk`]
    /// can never head-of-line-block a tiny attestation that must reach the mesh
    /// inside its aggregation window. Named `outbox` (not `outbox_priority`) to
    /// minimize churn to the proven drain loop, which keeps operating on it.
    outbox: std.ArrayList([]u8) = .empty,
    /// BULK lane: queue of large frames (blocks — any frame
    /// `> persistent_gossip_priority_max_bytes`). Heap-owned, FIFO, capped at
    /// [`persistent_gossip_bulk_outbox_cap`] (small — blocks are big and few,
    /// so drop-oldest sheds stale blocks). Drained AFTER the priority lane is
    /// empty, but each FRAME is written ATOMICALLY: once any byte of a bulk
    /// frame has hit the wire the lane is locked (see [`outbox_bulk_partial`])
    /// until that frame completes, and only THEN can the priority lane
    /// preempt. This mirrors rust-libp2p's gossipsub `Framed` sink:
    /// `poll_ready=Pending` while a partial frame is in flight, no interleave
    /// possible. HOL bound shrinks from "whole queued backlog" (6-8 slots,
    /// observed) to "one block's transmit" (~1 slot), at zero corruption risk.
    outbox_bulk: std.ArrayList([]u8) = .empty,
    /// True iff `outbox.items[0]` is a partial suffix from a backpressured
    /// `sendChunk` — the frame on the wire is in mid-flight and MUST complete
    /// before any other frame (incl. a fresh bulk frame) is written, else the
    /// receiver reads inter-frame bytes as the next length prefix and the
    /// `/meshsub` byte stream desyncs. Mirrors rust-libp2p's `Framed` sink
    /// semantics: `poll_ready` returns `Pending` while a partial frame is in
    /// flight; the next message is not started until the current one drains.
    /// Set when `drainGossipLane` leaves a suffix; cleared when the lane's head
    /// frame is fully consumed.
    outbox_partial: bool = false,
    /// Same invariant for the BULK lane. At most one of `outbox_partial` /
    /// `outbox_bulk_partial` may be true; the orchestration in
    /// `advancePersistentGossipStreams` enforces "if a lane is partial, only
    /// that lane drains this tick", so an attestation cannot slip between two
    /// bytes of a block (or vice versa).
    outbox_bulk_partial: bool = false,
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
    /// Wall-clock time of the first drain tick where `sendChunk` returned 0
    /// (transient backpressure from zquic's full per-stream pending queue)
    /// without having accepted any bytes in the current tick. Cleared back
    /// to `null` on any drain tick that accepts > 0 bytes.
    ///
    /// When this stays non-null for at least
    /// [`persistent_gossip_outbox_stuck_timeout_ms`], the stream is marked
    /// broken (see [`markPersistentGossipBroken`]), which tears down the
    /// underlying QUIC connection and lets `connection_manager` redial. The
    /// alternative — waiting for zquic's 60 s no-ACK conn-lost timeout — left
    /// gossip silent for a full minute per wedge, dropped every block from
    /// the affected peer during that window, and was the direct cause of
    /// asymmetric attestation aggregation (zeam aggregator seeing only 2/3
    /// instead of 3/3 of validators, blocking FFG supermajority and stalling
    /// finalization).
    outbox_stuck_since_ms: ?i64 = null,
    /// Rate-limit for the "outbox full, dropping oldest gossip frame" warn so a
    /// sustained-congestion peer doesn't flood the log.
    outbox_drop_warn_ms: i64 = 0,
};

/// Hard cap on queued outbox frames per peer before the persistent gossip
/// stream is marked broken. Picked to accommodate ~30 seconds of gossip on a
/// healthy mainnet topic without unbounded growth on a wedged peer.
pub const persistent_gossip_outbox_cap: usize = 1024;

/// Size threshold for the two-lane priority outbox: frames whose wire length is
/// `<=` this go to the PRIORITY lane ([`PersistentGossipStream.outbox`]), larger
/// frames go to the BULK lane ([`PersistentGossipStream.outbox_bulk`]). 16 KiB
/// comfortably holds attestations, aggregations, and gossipsub control frames
/// (typically 100 B – a few KiB) while routing block frames (multi-MB) to the
/// bulk lane so they cannot HOL-block time-sensitive attestations.
pub const persistent_gossip_priority_max_bytes: usize = 16 * 1024;

/// Hard cap on queued BULK-lane frames per peer. Small because blocks are big
/// and few; dropping the OLDEST queued block on overflow sheds stale blocks
/// (the consensus layer re-syncs missed blocks by root) while keeping the
/// connection and the priority lane alive.
pub const persistent_gossip_bulk_outbox_cap: usize = 64;

/// Scratch size for coalescing consecutive queued gossip frames into one
/// MTU-chunked stream write. gossipsub RPC frames are self-delimiting (uvarint
/// length prefix), so packing many small frames (e.g. forwarded subnet
/// attestations) into a single contiguous write lets zquic fill 1-RTT packets
/// (~a dozen 100-300 B frames each) instead of emitting one mostly-empty packet
/// per frame — the packet-rate reduction that keeps the loss detector's
/// in-flight table and the single drive loop from saturating once every
/// per-subnet attestation mesh is live.
pub const persistent_gossip_coalesce_bytes: usize = 16 * 1024;

/// Interval at which an empty-control gossipsub RPC is pushed onto an
/// otherwise-idle persistent `/meshsub` stream. The frame is a no-op at the
/// gossipsub layer (one `ControlMessage` field with all sub-fields absent)
/// but generates real wire traffic, which is what rust-libp2p's connection
/// handler needs to keep the connection alive on a stable mesh topic.
///
/// 20s is comfortably under rust-libp2p's default `idle_timeout` for both
/// gossipsub (60s) and the underlying `libp2p-quic` (30s effective) so we
/// always refresh both timers with at least 10s of slack before they fire.
pub const persistent_gossip_keepalive_interval_ms: i64 = 20_000;

/// Maximum time the persistent gossip outbox is allowed to be fully stuck
/// (every drain tick returns 0 accepted bytes from zquic) before we declare
/// the stream wedged and trigger recovery via [`markPersistentGossipBroken`].
///
/// Picked to fire strictly *before* zquic's 60 s no-ACK conn-lost timeout so
/// libp2p drives recovery on its own clock instead of waiting for the
/// transport to give up. 20 s is also long enough to ride out brief cwnd
/// collapses without bouncing healthy connections — a 20 s outbox stall in
/// steady state implies the peer has stopped reading the stream, which is
/// terminal for a `/meshsub/1.1.0` stream that rust-libp2p caps at one
/// substream per connection (see [`PersistentGossipStream`] doc).
pub const persistent_gossip_outbox_stuck_timeout_ms: i64 = 5_000;

/// A queued command from the swarm hook to the drive thread.
pub const HookWork = union(enum) {
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

pub fn freeHookWork(a: std.mem.Allocator, w: HookWork) void {
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

/// Minimal atomic spin lock for the cross-thread inbound-gossip work queue.
/// Producer (drive thread) and consumer (gossip worker thread) are raw OS
/// threads, so this guards the queue independently of any `Io` instance.
pub const SpinLock = struct {
    locked: std.atomic.Value(bool) = .init(false),
    pub fn lock(self: *SpinLock) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }
    pub fn unlock(self: *SpinLock) void {
        self.locked.store(false, .release);
    }
};

/// One reassembled inbound gossipsub RPC frame, handed from the drive thread to
/// the gossip worker for off-thread validation + forwarding.  `frame` is heap
/// owned (a copy of the stream accumulator slice) and freed by the worker.
pub const InboundGossipWork = struct {
    sender: identity.PeerId,
    frame: []u8,
};

/// Caps on the inbound gossip work backlog.  If the embedder's validator can't
/// keep up, drop the oldest work rather than grow unbounded — the network stays
/// live (the point of offloading) even if validation lags.
pub const inbound_gossip_work_cap_entries: usize = 1024;
pub const inbound_gossip_work_cap_bytes: usize = 64 * 1024 * 1024;

/// Size proxy that separates consensus-critical blocks (large) from redundant
/// attestations (small) in the inbound gossip backlog. On a full queue,
/// `enqueueInboundGossip` evicts small frames first and never drops a block for
/// an attestation. gossipsub/transport are topic-agnostic (opaque frame bytes),
/// so size is the only cheap classifier — same proxy the outbound priority/bulk
/// outbox uses.
pub const inbound_gossip_block_size_bytes: usize = 16 * 1024;

/// Max inbound gossip frames the worker drains per loop iteration before
/// running command/heartbeat processing. Batch-draining amortizes the
/// per-iteration overhead so the single validation thread keeps up with the
/// full-mesh inbound rate instead of letting the backlog hit its cap.
pub const inbound_gossip_drain_batch: usize = 64;

/// Fairness bound: max gossip frames drained from one inbound stream's
/// accumulator per drive iteration. Draining a large post-stall `gossip_acc`
/// backlog (varint-decode + dupe + enqueue per frame) in one call monopolized
/// the drive thread for seconds (live: inbound_streams=3400ms) — starving every
/// peer's ACKs. The remainder stays compacted in the accumulator for the next
/// iteration. Well above the steady-state per-stream frame rate.
pub const max_inbound_gossip_frames_per_call: usize = 512;
