//! Bundled libp2p QUIC transport runtime: composes [`QuicListener`],
//! [`QuicOutbound`], multistream-select, wire framing, the swarm command
//! dispatch hook, and the libp2p TLS cert generator into a single drop-in
//! that an embedder can start, hand a [`host_mod.Host`], and use without
//! writing the accept loop, dial flow, or per-stream protocol dispatch.
//!
//! Status: minimum-viable. Only the req/resp send/receive path is implemented
//! end-to-end (this is what the loopback test gates on). Gossipsub publish is
//! a `log.warn` TODO — see [`onPublishCommand`]. Inbound gossipsub frames are
//! delivered to [`host_mod.Host.handleGossipRpc`] after multistream-select.

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

const zquic = @import("zquic");
const ZIo = zquic.transport.io;

const meshsub_protocol_id: []const u8 = "/meshsub/1.1.0";

const supported_protocols: [4][]const u8 = .{
    meshsub_protocol_id,
    protocol_mod.blocks_by_root_v1,
    protocol_mod.blocks_by_range_v1,
    protocol_mod.status_v1,
};

pub const QuicRuntimeOptions = struct {
    allocator: std.mem.Allocator,
    /// Wired-up [`host_mod.Host`]. The runtime calls into
    /// `host.handleGossipRpc`, `host.registerInboundReqRespChannel`,
    /// `host.onConnectionEstablished`, `host.onDialFailure`, etc.
    host: *host_mod.Host,
    /// PEM cert path passed to [`quic_v1.libp2pZquicServerConfig`] /
    /// [`quic.Libp2pZquicClientDialOptions`]. Must exist before [`start`].
    cert_path: []const u8,
    /// PEM key path; same constraints as `cert_path`.
    key_path: []const u8,
    /// Listen multiaddr (e.g. `/ip4/0.0.0.0/udp/0/quic-v1`).
    listen_multiaddr: []const u8,
    /// Wall-clock millisecond getter; defaults to [`wall_time.milliTimestamp`].
    now_ms_fn: *const fn () i64 = wall_time.milliTimestamp,
    /// Per-iteration poll timeout for the drive loop.
    poll_timeout_ms: u32 = 50,
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

/// Tracked outbound connection: one QUIC connection per (remote peer).
const OutboundConn = struct {
    outbound: quic_endpoint.QuicOutbound,
    /// Whether [`host_mod.Host.onConnectionEstablished`] has fired for this slot.
    notified: bool = false,
    conn_id: connection_manager_mod.ConnectionId,
    peer_id: ?identity.PeerId = null,
};

/// Per-inbound-stream state: tracks where in the per-protocol read flow we are.
const InboundStream = struct {
    slot: usize,
    conn: *ZIo.ConnState,
    stream_id: u64,
    raw: quic_raw_stream_io.RawAppBidiServer,
    handshake_done: bool = false,
    protocol_index: ?usize = null,
    /// channel_id once we've called `host.registerInboundReqRespChannel`.
    channel_id: ?u64 = null,
    request_id_for_channel: u64 = 0,
    sender_peer: ?identity.PeerId = null,
    /// Accumulated bytes for an in-progress unary request. Cleared once a
    /// complete request is parsed and the inbound channel registered.
    req_acc: std.ArrayList(u8) = .empty,
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
        .send_end_of_stream, .send_error_response => {},
    }
}

pub const QuicRuntime = struct {
    allocator: std.mem.Allocator,
    host: *host_mod.Host,
    opts: QuicRuntimeOptions,

    listener: *quic_endpoint.QuicListener,
    bound_port_v4: ?u16 = null,

    outbound_by_peer: PeerIdMap,
    /// Inbound streams keyed by an internal monotonic id; supports lookup by
    /// (slot, stream_id) for incoming-stream callbacks.
    inbound_streams: std.ArrayList(*InboundStream),
    /// Outbound request streams indexed by req/resp `request_id`.
    outbound_requests: std.AutoHashMap(u64, *OutboundRequest),
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

    /// Drive thread control.
    drive_thread: ?std.Thread = null,
    shutdown_requested: std.atomic.Value(bool) = .init(false),
    started: bool = false,

    /// CommandDispatchHook context — must be heap-stable so the swarm can
    /// hold a `*anyopaque` to it across runtime moves (it can't because we
    /// only allow `*QuicRuntime`).
    pub fn create(opts: QuicRuntimeOptions) anyerror!*QuicRuntime {
        const a = opts.allocator;

        var listen_ma = try multiaddr.Multiaddr.fromString(a, opts.listen_multiaddr);
        defer listen_ma.deinit();

        const listener = try quic_endpoint.QuicListener.listen(a, listen_ma, .{
            .cert_path = opts.cert_path,
            .key_path = opts.key_path,
        });
        errdefer listener.deinit();

        const self = try a.create(QuicRuntime);
        errdefer a.destroy(self);

        self.* = .{
            .allocator = a,
            .host = opts.host,
            .opts = opts,
            .listener = listener,
            .outbound_by_peer = PeerIdMap.init(a),
            .inbound_streams = .empty,
            .outbound_requests = std.AutoHashMap(u64, *OutboundRequest).init(a),
            .channel_to_inbound = std.AutoHashMap(u64, *InboundStream).init(a),
        };

        const bound = listener.boundUdpPortIpv4() catch null;
        self.bound_port_v4 = bound;

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

        // Free outbound conns.
        var it = self.outbound_by_peer.valueIterator();
        while (it.next()) |v| {
            v.*.outbound.deinit();
            self.allocator.destroy(v.*);
        }
        self.outbound_by_peer.deinit();

        // Free inbound streams.
        for (self.inbound_streams.items) |s| {
            s.req_acc.deinit(self.allocator);
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

        self.channel_to_inbound.deinit();

        // Unlink the hook so swarm doesn't keep calling into freed memory.
        self.host.swarm.command_dispatch = null;
        self.listener.lifecycle = .{};

        self.listener.deinit();
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
            .subscribe, .shutdown => return .fallthrough,
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
        }
        self.inbound_conn_notified[slot] = false;
        self.inbound_conn_peer[slot] = null;
        self.inbound_conn_ids[slot] = 0;
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

            // Drive every active outbound.
            {
                var it = self.outbound_by_peer.valueIterator();
                while (it.next()) |v| {
                    v.*.outbound.drive(&recv_buf, 0) catch |err| {
                        log.warn("quic_runtime: outbound.drive: {s}", .{@errorName(err)});
                    };
                }
            }

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

            // Periodic host ticks (~ every 100ms).
            const now_ms = self.opts.now_ms_fn();
            if (now_ms - last_tick_ms >= 100) {
                last_tick_ms = now_ms;
                self.host.runPeriodicTicks(now_ms) catch |err| {
                    log.warn("quic_runtime: host periodic ticks: {s}", .{@errorName(err)});
                };
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
                _ = e;
                // Simplified: just end-of-stream without an error code over the wire.
                // (Bytes-on-the-wire error semantics are out of scope for this PR.)
            },
            .publish => |p| {
                defer self.allocator.free(p.topic);
                defer self.allocator.free(p.payload);
                self.onPublishCommand();
            },
        }
    }

    fn onPublishCommand(_: *QuicRuntime) void {
        // TODO(quic_runtime gossipsub): for each gossipsub mesh peer, open a
        // new stream, run multistream-select with `/meshsub/1.1.0`, write the
        // snappy-framed RPC, close the stream. See
        // [`gossipsub_runtime.Gossipsub.queryMeshPeers`].
        log.warn("quic_runtime: .publish hook is a TODO (gossipsub publish path not yet wired); message dropped", .{});
    }

    fn handleDial(self: *QuicRuntime, addr_str: []const u8, expected_peer: ?identity.PeerId) void {
        const a = self.allocator;

        var ma = multiaddr.Multiaddr.fromString(a, addr_str) catch |err| {
            log.warn("quic_runtime: parse dial multiaddr failed: {s}", .{@errorName(err)});
            self.failDial(expected_peer);
            return;
        };
        defer ma.deinit();

        var outbound = quic_endpoint.QuicOutbound.dial(a, ma, .{
            .client_cert_path = self.opts.cert_path,
            .client_key_path = self.opts.key_path,
        }) catch |err| {
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
            slot.outbound.deinit();
            a.destroy(slot);
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

        // Send a FIN on the QUIC stream.
        self.listener.server.sendRawStreamData(
            ist.conn,
            ist.stream_id,
            ist.raw.send_offset,
            &[_]u8{},
            true,
        );

        // Drop from channel map (stream itself stays alive until peer FINs).
        if (found_key) |k| _ = self.channel_to_inbound.remove(k);
    }

    // ── Per-stream pump ────────────────────────────────────────────────────

    fn advanceInboundStreams(self: *QuicRuntime) !void {
        const a = self.allocator;
        var i: usize = 0;
        while (i < self.inbound_streams.items.len) : (i += 1) {
            const ist = self.inbound_streams.items[i];

            // 1. Multistream handshake: responder side, among 4 protocols.
            if (!ist.handshake_done) {
                // Buffer the full multistream offer (two newline-terminated
                // lines) before running the handshake; the responder helper
                // is byte-at-a-time and `error.ProtocolNegotiationFailed`
                // is unrecoverable mid-stream once it consumes any bytes.
                const have = ist.raw.unreadRecvLen();
                if (have < 2) continue;
                const buf = ZIo.rawAppRecvBuffer(ist.conn, ist.stream_id) orelse continue;
                const tail = buf[ist.raw.read_cursor..];
                // need at least two '\n' bytes in the buffered region.
                var newlines: u32 = 0;
                for (tail) |b| {
                    if (b == '\n') newlines += 1;
                    if (newlines >= 2) break;
                }
                if (newlines < 2) continue;

                var r = ist.raw.reader();
                var w = ist.raw.writer();
                const cands: []const []const u8 = &supported_protocols;
                const ix = stream_multistream.responderHandshakeMultistreamAmong(&r, &w, cands, a) catch |err| {
                    log.warn("quic_runtime: inbound responder handshake failed: {s}", .{@errorName(err)});
                    continue;
                };
                ist.handshake_done = true;
                ist.protocol_index = ix;

                // Resolve sender peer id from server TLS leaf.
                const now_sec = @divTrunc(self.opts.now_ms_fn(), 1000);
                const sender = quic_peer_identity.verifiedPeerIdFromLibp2pQuicServerConn(
                    ist.conn,
                    a,
                    null,
                    now_sec,
                ) catch |perr| {
                    log.warn("quic_runtime: verify inbound peer failed: {s}", .{@errorName(perr)});
                    continue;
                };
                ist.sender_peer = sender;

                // Lazily notify host of new inbound connection (once per slot).
                if (!self.inbound_conn_notified[ist.slot]) {
                    self.inbound_conn_notified[ist.slot] = true;
                    self.inbound_conn_peer[ist.slot] = sender;
                    const cid = self.inbound_conn_ids[ist.slot];
                    self.host.onConnectionEstablished(cid, sender, .inbound) catch |err| {
                        log.warn("quic_runtime: onConnectionEstablished (inbound) failed: {s}", .{@errorName(err)});
                    };
                }
            }

            // 2. Dispatch protocol-specific payload reader.
            const pi = ist.protocol_index orelse continue;
            switch (pi) {
                0 => {
                    // /meshsub/1.1.0 — TODO: snappy-framed gossipsub RPC.
                    // For now, log and skip.
                    log.warn("quic_runtime: inbound /meshsub/1.1.0 stream — TODO (frame reader)", .{});
                    ist.protocol_index = null; // don't loop forever
                },
                else => |idx| {
                    // SSZ req/resp path.
                    if (ist.channel_id != null) continue;
                    const proto: protocol_mod.LeanSupportedProtocol = switch (idx) {
                        1 => .blocks_by_root,
                        2 => .blocks_by_range,
                        3 => .status,
                        else => continue,
                    };
                    // Drain whatever new bytes have arrived into the per-stream
                    // accumulator. `wire_framing.readOneUnaryRequest` consumed
                    // bytes destructively on partial errors so we maintain our
                    // own accumulating buffer and decode straight from it.
                    const recv_buf = ZIo.rawAppRecvBuffer(ist.conn, ist.stream_id) orelse continue;
                    if (recv_buf.len > ist.raw.read_cursor) {
                        const new_bytes = recv_buf[ist.raw.read_cursor..];
                        try ist.req_acc.appendSlice(a, new_bytes);
                        ist.raw.read_cursor = recv_buf.len;
                    }
                    if (ist.req_acc.items.len == 0) continue;

                    // Attempt to decode a full unary request from the acc.
                    const req_ssz = snappy_wire.decodeRequestSsz(a, ist.req_acc.items) catch |err| switch (err) {
                        error.IncompleteHeader, error.InvalidData => continue, // need more bytes
                        else => |e| {
                            log.warn("quic_runtime: decodeRequestSsz failed: {s}", .{@errorName(e)});
                            continue;
                        },
                    };
                    defer a.free(req_ssz);

                    // Synthesize a stream_request_id; we use the QUIC stream
                    // id as the req/resp stream id correlator.
                    const stream_rid = ist.stream_id +% 1; // any nonzero u64 unique within this peer
                    const now_ms = self.opts.now_ms_fn();
                    const sender_peer = ist.sender_peer orelse continue;
                    const channel_id = self.host.registerInboundReqRespChannel(sender_peer, proto, stream_rid, now_ms) catch |err| {
                        log.warn("quic_runtime: registerInboundReqRespChannel failed: {s}", .{@errorName(err)});
                        continue;
                    };
                    ist.channel_id = channel_id;
                    ist.request_id_for_channel = stream_rid;
                    self.channel_to_inbound.put(channel_id, ist) catch {};

                    // Hand the request payload to the embedder via swarm.
                    const payload_dup = a.dupe(u8, req_ssz) catch continue;
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
                stream_multistream.appendFirstStreamInitiatorHandshake(&out, a, req.proto.protocolId()) catch |err| {
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

            // 2. Read multistream ack.
            if (!req.handshake_done) {
                const need = stream_multistream.responderSuccessReplyWireLen(req.proto.protocolId()) catch continue;
                if (req.raw.unreadRecvLen() < need) continue;
                var r = req.raw.reader();
                var w = req.raw.writer();
                stream_multistream.initiatorHandshakeMultistreamReadPhase(&r, &w, req.proto.protocolId(), a) catch |err| {
                    log.warn("quic_runtime: read init ack failed: {s}", .{@errorName(err)});
                    continue;
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
        // Remove from map and free.
        if (self.outbound_requests.fetchRemove(req.request_id)) |kv| {
            self.allocator.free(kv.value.payload);
            kv.value.resp_acc.deinit(self.allocator);
            self.allocator.destroy(kv.value);
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
    cert_path: [:0]u8,
    key_path: [:0]u8,
    peer: identity.PeerId,

    fn deinit(self: *TestCertBundle, a: std.mem.Allocator) void {
        _ = std.c.unlink(self.cert_path.ptr);
        _ = std.c.unlink(self.key_path.ptr);
        a.free(self.cert_pem);
        a.free(self.key_pem);
        a.free(self.cert_path);
        a.free(self.key_path);
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

fn writeFileSync(path: [:0]const u8, data: []const u8) !void {
    // Uses libc directly (`unit_tests.linkLibC()` in `build.zig` makes this
    // cross-platform). Routing through `std.Io.Dir` would require plumbing an
    // `Io` instance through the test, which the surrounding bring-up doesn't
    // otherwise need.
    var o: std.c.O = .{};
    o.ACCMODE = .WRONLY;
    o.CREAT = true;
    o.TRUNC = true;
    const fd = std.c.open(path.ptr, o, @as(std.c.mode_t, 0o600));
    if (fd < 0) return error.OpenFailed;
    defer _ = std.c.close(fd);
    var off: usize = 0;
    while (off < data.len) {
        const n = std.c.write(fd, data[off..].ptr, data.len - off);
        if (n <= 0) return error.WriteShort;
        off += @intCast(n);
    }
}

fn buildTestBundle(a: std.mem.Allocator, label: []const u8, seed: u8) !TestCertBundle {
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

    const cert_path = try std.fmt.allocPrintSentinel(a, "/tmp/zlibp2p_quic_runtime_{s}_cert.pem", .{label}, 0);
    errdefer a.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(a, "/tmp/zlibp2p_quic_runtime_{s}_key.pem", .{label}, 0);
    errdefer a.free(key_path);

    try writeFileSync(cert_path, cert_pem);
    try writeFileSync(key_path, key_pem);

    return .{
        .cert_pem = cert_pem,
        .key_pem = key_pem,
        .cert_path = cert_path,
        .key_path = key_path,
        .peer = peer,
    };
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
        .cert_path = bundle_a.cert_path,
        .key_path = bundle_a.key_path,
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
        .cert_path = bundle_b.cert_path,
        .key_path = bundle_b.key_path,
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
