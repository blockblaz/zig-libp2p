//! Swarm command queue + typed event channel for a dedicated runtime thread (#34).
//!
//! ## Threading model (pick one)
//!
//! 1. **Owned thread** — call [`startBackground`] (or [`run`] on the swarm thread). Producers call
//!    [`submit`] from any thread; the consumer calls [`nextEvent`] from one thread.
//! 2. **Embedder-driven** — do **not** start [`run`]. On a single thread, interleave [`submit`],
//!    [`tick`], and [`nextEvent`] so commands are drained without a background worker.
//!
//! Do not mix (1) and (2): running [`run`] concurrently with [`tick`] on another thread races on
//! the command buffer.
//!
//! * Command channel: bounded MPSC, capacity [`command_capacity`], at most [`commands_per_tick`]
//!   are processed per [`run`] loop iteration (or per [`tick`] call, up to its `budget`).
//! * Event channel: bounded SPSC (one [`nextEvent`] consumer), same capacity as commands by default.
//! * Synchronization uses `std.Io` primitives backed by [`Io.Threaded`] (futex + condvar).
//!
//! Real transport, gossip, and req/resp I/O are intentionally stubbed: commands still produce
//! deterministic typed [`Event`]s so embedders can wire behaviour incrementally.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const errors = @import("errors.zig");
const metrics = @import("metrics.zig");
const peer_events = @import("peer_events.zig");
const protocol = @import("protocol.zig");
const identity = @import("identity.zig");
const autonat_mod = @import("autonat/root.zig");

pub const command_capacity: usize = 8192;
pub const commands_per_tick: u32 = 256;
pub const default_event_capacity: usize = command_capacity;

pub const LogLevel = enum(u8) {
    debug,
    info,
    warn,
    err,
};

pub const GossipMessage = struct {
    topic: []const u8,
    from: identity.PeerId,
    data: []const u8,
};

pub const RpcRequest = struct {
    peer: identity.PeerId,
    protocol: protocol.LeanSupportedProtocol,
    /// Correlates [`SwarmCommand.send_response_chunk`] / [`Event.rpc_response_chunk`] with this RPC.
    request_id: u64,
    /// Inbound only: handle from [`req_resp.runtime.ReqResp.registerInboundChannel`] (#40). Zero when unset.
    channel_id: u64 = 0,
    payload: []const u8,
};

pub const RpcResponseChunk = struct {
    peer: identity.PeerId,
    request_id: u64,
    chunk: []const u8,
};

pub const RpcError = struct {
    peer: identity.PeerId,
    request_id: u64,
    kind: errors.ReqRespError,
};

pub const RpcResponseEnd = struct {
    peer: identity.PeerId,
    request_id: u64,
};

/// Application → swarm control plane. Slices are copied by [`Swarm.submit`].
pub const SwarmCommand = union(enum) {
    publish: struct {
        topic: []const u8,
        payload: []const u8,
    },
    subscribe: struct {
        topic: []const u8,
    },
    send_request: RpcRequest,
    send_response_chunk: RpcResponseChunk,
    send_end_of_stream: RpcResponseEnd,
    send_error_response: RpcError,
    dial: struct {
        addr: []const u8,
        /// Hint for embedder correlation when the dial stub reports failure (no heap copy).
        expected_peer: ?identity.PeerId = null,
    },
    shutdown,
};

/// Embedder hook letting a real transport intercept [`SwarmCommand`]s before
/// the loopback stubs in [`dispatchCommand`] fire. Returning `.handled` tells
/// the swarm "I have taken ownership of the OwnedCommand bytes — do nothing
/// else with them, and call [`destroyCommand`] yourself when you're done."
/// Returning `.fallthrough` is a no-op assertion that the embedder will let
/// the default stub run (matching pre-hook behaviour).
///
/// Typical use: a QUIC transport hook intercepts `.dial`, `.send_request`,
/// `.publish` and the corresponding response-side commands so they reach
/// the wire instead of being echoed back as events. Subscribe / shutdown
/// flow through as before.
pub const CommandDispatchHook = struct {
    /// Opaque context handed back to `dispatch`. Lifetime is the embedder's;
    /// the swarm only stores the pointer.
    ctx: ?*anyopaque = null,
    /// Called once per dispatched command. The pointed-to OwnedCommand carries
    /// heap slices the embedder must free (via [`destroyCommand`]) IFF it
    /// returns `.handled`. The swarm retains ownership when `.fallthrough`
    /// is returned.
    dispatch: *const fn (ctx: ?*anyopaque, cmd: *const OwnedCommand) Disposition,

    pub const Disposition = enum { handled, fallthrough };
};

/// Reason for an embedder-actionable connection trim recommendation (#90).
pub const TrimReason = enum {
    /// Total connection count exceeded `high_watermark` and is being trimmed back to `low_watermark`.
    over_global_watermark,
    /// Connection count to one peer exceeded `max_per_peer`.
    over_per_peer_cap,
};

pub const RelayReservationKind = enum {
    acquired,
    refreshed,
    lost,
};

pub const DcutrFailReason = enum {
    exchange_failed,
    punch_failed,
    max_attempts_exceeded,
};

/// Swarm → embedder events. Owned memory is released with [`Event.deinit`].
pub const Event = union(enum) {
    gossip_message: GossipMessage,
    rpc_request: RpcRequest,
    rpc_response_chunk: RpcResponseChunk,
    rpc_response_end: RpcResponseEnd,
    rpc_error_response: RpcError,
    peer_connected: peer_events.PeerConnectedPayload,
    peer_disconnected: peer_events.PeerDisconnectedPayload,
    peer_connection_failed: peer_events.PeerConnectionFailedPayload,
    /// Connection manager has decided to trim a connection (#90). The embedder
    /// owns the actual transport close; this is purely a recommendation.
    connection_trim_recommended: struct {
        peer: identity.PeerId,
        conn_id: u64,
        reason: TrimReason,
    },
    /// Open `/ipfs/id/push/1.0.0` to `peer` with [`host.Host.identifyReplyParams`] (#202).
    identify_push_peer: identity.PeerId,
    /// Circuit relay v2 reservation lifecycle (#204).
    relay_reservation: struct {
        relay: identity.PeerId,
        kind: RelayReservationKind,
        expire_unix: ?u64 = null,
    },
    /// Direct connection upgrade succeeded (#205).
    dcutr_succeeded: struct {
        peer: identity.PeerId,
        relayed_conn_id: u64,
        direct_conn_id: u64,
    },
    /// Direct connection upgrade failed (#205).
    dcutr_failed: struct {
        peer: identity.PeerId,
        relayed_conn_id: u64,
        reason: DcutrFailReason,
    },
    /// Per-address reachability from AutoNAT (#206).
    reachability_changed: struct {
        addr: []const u8,
        status: autonat_mod.NatStatus,
    },
    /// Open `/libp2p/autonat/1.0.0` to `peer` for an active probe (#206).
    autonat_probe_peer: identity.PeerId,
    /// LAN peer discovered via mDNS (#207).
    peer_discovered: peer_events.PeerDiscoveredPayload,
    log: struct {
        level: LogLevel,
        message: []const u8,
    },
    swarm_closed,

    pub fn deinit(e: *Event, a: std.mem.Allocator) void {
        switch (e.*) {
            .gossip_message => |*m| {
                a.free(m.topic);
                a.free(m.data);
            },
            .rpc_request => |*r| {
                a.free(r.payload);
            },
            .rpc_response_chunk => |*r| {
                a.free(r.chunk);
            },
            .log => |*l| {
                a.free(l.message);
            },
            .reachability_changed => |r| {
                a.free(r.addr);
            },
            .peer_discovered => |*pd| {
                for (pd.addrs) |addr| a.free(addr);
                a.free(pd.addrs);
            },
            .rpc_response_end,
            .rpc_error_response,
            .peer_connected,
            .peer_disconnected,
            .peer_connection_failed,
            .connection_trim_recommended,
            .identify_push_peer,
            .relay_reservation,
            .dcutr_succeeded,
            .dcutr_failed,
            .autonat_probe_peer,
            .swarm_closed,
            => {},
        }
        e.* = undefined;
    }
};

pub const SubmitError = error{ QueueFull, QueueClosed } || std.mem.Allocator.Error;
pub const NextEventError = error{ Timeout, QueueClosed };

pub const InitError = std.mem.Allocator.Error ||
    @typeInfo(@TypeOf(identity.PeerId.random())).error_union.error_set;

pub const OwnedCommand = union(enum) {
    publish: struct { topic: []u8, payload: []u8 },
    subscribe: struct { topic: []u8 },
    send_request: struct {
        peer: identity.PeerId,
        protocol: protocol.LeanSupportedProtocol,
        request_id: u64,
        channel_id: u64,
        payload: []u8,
    },
    send_response_chunk: struct {
        peer: identity.PeerId,
        request_id: u64,
        chunk: []u8,
    },
    send_end_of_stream: RpcResponseEnd,
    send_error_response: RpcError,
    dial: struct { addr: []u8, expected_peer: ?identity.PeerId },
    shutdown,
};

const OwnedEvent = Event;

pub fn destroyCommand(a: std.mem.Allocator, c: OwnedCommand) void {
    switch (c) {
        .publish => |x| {
            a.free(x.topic);
            a.free(x.payload);
        },
        .subscribe => |x| a.free(x.topic),
        .send_request => |x| a.free(x.payload),
        .send_response_chunk => |x| a.free(x.chunk),
        .dial => |x| a.free(x.addr),
        .send_end_of_stream,
        .send_error_response,
        .shutdown,
        => {},
    }
}

fn cloneCommand(a: std.mem.Allocator, cmd: SwarmCommand) SubmitError!OwnedCommand {
    return switch (cmd) {
        .publish => |p| OwnedCommand{
            .publish = .{
                .topic = try a.dupe(u8, p.topic),
                .payload = try a.dupe(u8, p.payload),
            },
        },
        .subscribe => |s| OwnedCommand{
            .subscribe = .{ .topic = try a.dupe(u8, s.topic) },
        },
        .send_request => |r| OwnedCommand{
            .send_request = .{
                .peer = r.peer,
                .protocol = r.protocol,
                .request_id = r.request_id,
                .channel_id = r.channel_id,
                .payload = try a.dupe(u8, r.payload),
            },
        },
        .send_response_chunk => |r| OwnedCommand{
            .send_response_chunk = .{
                .peer = r.peer,
                .request_id = r.request_id,
                .chunk = try a.dupe(u8, r.chunk),
            },
        },
        .send_end_of_stream => |e| OwnedCommand{ .send_end_of_stream = e },
        .send_error_response => |e| OwnedCommand{ .send_error_response = e },
        .dial => |d| OwnedCommand{
            .dial = .{
                .addr = try a.dupe(u8, d.addr),
                .expected_peer = d.expected_peer,
            },
        },
        .shutdown => .shutdown,
    };
}

pub const Swarm = struct {
    gpa: std.mem.Allocator,
    threaded: Io.Threaded,
    io: Io,

    local_peer: identity.PeerId,

    cmd_mutex: Io.Mutex = .init,
    cmd_notify: Io.Event = .unset,
    cmd_head: usize = 0,
    cmd_len: usize = 0,
    cmd_buf: []OwnedCommand,

    evt_mutex: Io.Mutex = .init,
    evt_notify: Io.Event = .unset,
    evt_space: Io.Condition = .init,
    evt_head: usize = 0,
    evt_len: usize = 0,
    evt_buf: []OwnedEvent,
    evt_cap: usize,

    shutdown_requested: std.atomic.Value(bool) = .init(false),
    cmd_closed: std.atomic.Value(bool) = .init(false),

    /// Fires once the background worker enters [`run`] (or the embedder calls
    /// [`tick`] for the first time in single-threaded mode). Mirrors the
    /// `wait_for_network_ready` FFI zeam's Rust glue exports so a host thread
    /// can park until it is safe to submit commands. One-shot: once set, stays
    /// set for the lifetime of the swarm.
    ready_event: Io.Event = .unset,

    /// When non-null, failed [`submit`] calls record [`metrics.SwarmDropReason`] on this registry.
    metrics: ?*metrics.Metrics = null,

    runner: ?std.Thread = null,

    /// Embedder hook for real-transport interception of commands. When `null`,
    /// every command runs through the default loopback stubs in
    /// [`dispatchCommand`]. See [`CommandDispatchHook`].
    command_dispatch: ?CommandDispatchHook = null,

    pub const SwarmConfig = struct {
        event_capacity: usize = default_event_capacity,
        /// When `null`, a random [`identity.PeerId`] is generated at init.
        local_peer: ?identity.PeerId = null,
        /// Overrides [`command_capacity`] for the command ring. `0` means use the default capacity.
        command_ring_capacity: usize = 0,
        /// Same pointer stored on [`Swarm.metrics`].
        metrics: ?*metrics.Metrics = null,
        /// Optional real-transport interception hook. See [`CommandDispatchHook`].
        command_dispatch: ?CommandDispatchHook = null,
    };

    pub fn init(gpa: std.mem.Allocator, event_capacity: usize) InitError!Swarm {
        return initWithConfig(gpa, .{ .event_capacity = event_capacity });
    }

    pub fn initWithConfig(gpa: std.mem.Allocator, config: SwarmConfig) InitError!Swarm {
        var threaded = Io.Threaded.init(gpa, .{
            .async_limit = .nothing,
            .concurrent_limit = .nothing,
        });
        const io = threaded.io();

        const cmd_ring_cap = if (config.command_ring_capacity == 0) command_capacity else config.command_ring_capacity;
        const cmd_buf = try gpa.alloc(OwnedCommand, cmd_ring_cap);
        errdefer gpa.free(cmd_buf);
        @memset(std.mem.sliceAsBytes(cmd_buf), 0);

        const evt_buf = try gpa.alloc(OwnedEvent, config.event_capacity);
        errdefer gpa.free(evt_buf);
        @memset(std.mem.sliceAsBytes(evt_buf), 0);

        const lp = config.local_peer orelse try identity.PeerId.random();

        return .{
            .gpa = gpa,
            .threaded = threaded,
            .io = io,
            .local_peer = lp,
            .metrics = config.metrics,
            .cmd_buf = cmd_buf,
            .evt_buf = evt_buf,
            .evt_cap = config.event_capacity,
            .command_dispatch = config.command_dispatch,
        };
    }

    pub fn deinit(self: *Swarm) void {
        self.shutdown();
        if (self.runner) |t| {
            t.join();
            self.runner = null;
        }
        self.cmd_mutex.lockUncancelable(self.io);
        for (0..self.cmd_len) |i| {
            const idx = (self.cmd_head + i) % self.cmd_buf.len;
            destroyCommand(self.gpa, self.cmd_buf[idx]);
        }
        self.cmd_mutex.unlock(self.io);

        self.evt_mutex.lockUncancelable(self.io);
        for (0..self.evt_len) |i| {
            const idx = (self.evt_head + i) % self.evt_buf.len;
            var ev = self.evt_buf[idx];
            ev.deinit(self.gpa);
        }
        self.evt_mutex.unlock(self.io);

        self.gpa.free(self.cmd_buf);
        self.gpa.free(self.evt_buf);
        self.threaded.deinit();
        self.* = undefined;
    }

    pub fn metricsRegistry(self: *const Swarm) ?*const metrics.Metrics {
        return self.metrics;
    }

    /// Starts [`run`] on a new OS thread. Idempotent if already started.
    pub fn startBackground(self: *Swarm) std.Thread.SpawnError!void {
        if (self.runner != null) return;
        self.runner = try std.Thread.spawn(.{}, runWorkerTrampoline, .{self});
    }

    fn runWorkerTrampoline(ctx: *Swarm) void {
        ctx.run();
    }

    /// Drains up to `budget` queued commands without blocking when the queue is empty.
    ///
    /// For use on the **same** thread as [`nextEvent`] when [`run`] / [`startBackground`] are not
    /// used (#34). Does nothing useful if a background [`run`] loop is active.
    pub fn tick(self: *Swarm, budget: u32) void {
        // Self-bootstrap [`ready_event`] so [`waitUntilReady`] also works under
        // tick-mode embedders (single-threaded).
        self.ready_event.set(self.io);
        var processed: u32 = 0;
        while (processed < budget) : (processed += 1) {
            const cmd = self.popCommand() orelse return;
            if (cmd == .shutdown) {
                destroyCommand(self.gpa, cmd);
                self.finishShutdown();
                return;
            }
            self.dispatchCommand(cmd);
        }
    }

    /// Blocks the calling thread until the background worker has entered its
    /// main loop (or, under [`tick`]-mode embedders, the first tick has run).
    /// Returns `true` once ready, `false` on timeout. Idempotent and safe to
    /// call from any thread — once the swarm is ready, subsequent calls return
    /// `true` immediately.
    ///
    /// Mirrors the `wait_for_network_ready(network_id, timeout_ms) -> bool` FFI
    /// zeam's Rust libp2p-glue exports today, so a host thread can park until
    /// it is safe to submit subscribe / publish / dial commands.
    pub fn waitUntilReady(self: *Swarm, timeout_ms: u32) bool {
        const io = self.io;
        const timeout: Io.Timeout = if (timeout_ms == 0) blk: {
            break :blk .{ .duration = .{ .raw = Io.Duration.zero, .clock = .awake } };
        } else blk: {
            const dur: Io.Clock.Duration = .{
                .raw = Io.Duration.fromMilliseconds(@intCast(timeout_ms)),
                .clock = .awake,
            };
            break :blk .{ .deadline = Io.Clock.Timestamp.fromNow(io, dur) };
        };
        self.ready_event.waitTimeout(io, timeout) catch return false;
        return true;
    }

    /// Convenience: non-blocking poll. Returns `true` if the worker has entered
    /// its loop (or [`tick`] has been called at least once), `false` otherwise.
    pub fn isReady(self: *Swarm) bool {
        return self.waitUntilReady(0);
    }

    /// Blocks the calling thread until [`shutdown`] completes processing.
    pub fn run(self: *Swarm) void {
        const io = self.io;
        // Signal readiness as the very first thing so producers can park on
        // [`waitUntilReady`] until the worker is genuinely spinning. Set under
        // the embedder's `io` instance for the same back-end the worker uses.
        self.ready_event.set(io);
        while (true) {
            var processed: u32 = 0;
            while (processed < commands_per_tick) : (processed += 1) {
                const cmd = self.popCommand() orelse break;
                if (cmd == .shutdown) {
                    destroyCommand(self.gpa, cmd);
                    self.finishShutdown();
                    return;
                }
                self.dispatchCommand(cmd);
            }

            self.cmd_mutex.lockUncancelable(io);
            if (self.cmd_len == 0) {
                if (self.shutdown_requested.load(.acquire)) {
                    self.cmd_mutex.unlock(io);
                    self.finishShutdown();
                    return;
                }
                self.cmd_notify.reset();
                self.cmd_mutex.unlock(io);
                self.cmd_notify.waitUncancelable(io);
                continue;
            }
            self.cmd_mutex.unlock(io);
        }
    }

    fn popCommand(self: *Swarm) ?OwnedCommand {
        const io = self.io;
        self.cmd_mutex.lockUncancelable(io);
        defer self.cmd_mutex.unlock(io);
        if (self.cmd_len == 0) return null;
        const slot = self.cmd_head % self.cmd_buf.len;
        const cmd = self.cmd_buf[slot];
        self.cmd_head = (self.cmd_head + 1) % self.cmd_buf.len;
        self.cmd_len -= 1;
        return cmd;
    }

    fn dispatchCommand(self: *Swarm, cmd: OwnedCommand) void {
        if (self.command_dispatch) |hook| {
            switch (hook.dispatch(hook.ctx, &cmd)) {
                .handled => return, // embedder took ownership of cmd's heap bytes
                .fallthrough => {},
            }
        }
        switch (cmd) {
            .publish => |p| {
                self.pushEvent(.{ .gossip_message = .{
                    .topic = p.topic,
                    .from = self.local_peer,
                    .data = p.payload,
                } }) catch {
                    destroyCommand(self.gpa, .{ .publish = p });
                    return;
                };
            },
            .subscribe => |s| {
                self.pushEvent(.{ .log = .{
                    .level = .debug,
                    .message = s.topic,
                } }) catch {
                    destroyCommand(self.gpa, .{ .subscribe = s });
                    return;
                };
            },
            .send_request => |r| {
                self.pushEvent(.{ .rpc_request = .{
                    .peer = r.peer,
                    .protocol = r.protocol,
                    .request_id = r.request_id,
                    .channel_id = r.channel_id,
                    .payload = r.payload,
                } }) catch {
                    destroyCommand(self.gpa, .{ .send_request = r });
                    return;
                };
            },
            .send_response_chunk => |r| {
                self.pushEvent(.{ .rpc_response_chunk = .{
                    .peer = r.peer,
                    .request_id = r.request_id,
                    .chunk = r.chunk,
                } }) catch {
                    destroyCommand(self.gpa, .{ .send_response_chunk = r });
                    return;
                };
            },
            .send_end_of_stream => |e| {
                self.pushEvent(.{ .rpc_response_end = e }) catch {};
            },
            .send_error_response => |e| {
                self.pushEvent(.{ .rpc_error_response = e }) catch {};
            },
            .dial => |d| {
                self.pushEvent(.{ .peer_connection_failed = .{
                    .peer = d.expected_peer,
                    .direction = .outbound,
                    .result = .{ .err = error.DialFailed },
                } }) catch {
                    destroyCommand(self.gpa, .{ .dial = d });
                    return;
                };
                destroyCommand(self.gpa, .{ .dial = d });
            },
            .shutdown => unreachable,
        }
    }

    /// Enqueue a swarm event from the embedder (for example the connection manager). Same capacity
    /// and lifetime rules as events produced inside [`run`].
    pub fn queueEvent(self: *Swarm, ev: Event) std.mem.Allocator.Error!void {
        return self.pushEvent(ev);
    }

    fn pushEvent(self: *Swarm, ev: OwnedEvent) std.mem.Allocator.Error!void {
        const io = self.io;
        self.evt_mutex.lockUncancelable(io);
        while (self.evt_len == self.evt_cap) {
            self.evt_space.waitUncancelable(io, &self.evt_mutex);
        }
        const slot = (self.evt_head + self.evt_len) % self.evt_buf.len;
        self.evt_buf[slot] = ev;
        self.evt_len += 1;
        self.evt_notify.set(io);
        self.evt_mutex.unlock(io);
    }

    fn finishShutdown(self: *Swarm) void {
        self.cmd_closed.store(true, .release);
        _ = self.pushEventCatchOom(.swarm_closed);
        self.evt_notify.set(self.io);
        self.cmd_notify.set(self.io);
    }

    fn pushEventCatchOom(self: *Swarm, ev: OwnedEvent) bool {
        self.pushEvent(ev) catch return false;
        return true;
    }

    /// Thread-safe. After the first call, [`submit`] begins returning `error.QueueClosed`.
    pub fn shutdown(self: *Swarm) void {
        if (self.shutdown_requested.swap(true, .acq_rel)) return;
        self.cmd_notify.set(self.io);
        self.submit(.shutdown) catch {};
    }

    pub fn submit(self: *Swarm, cmd: SwarmCommand) SubmitError!void {
        if (self.cmd_closed.load(.acquire)) {
            if (self.metrics) |m| m.recordSwarmCommandDropped(.closed);
            return error.QueueClosed;
        }
        const owned = try cloneCommand(self.gpa, cmd);
        errdefer destroyCommand(self.gpa, owned);

        const io = self.io;
        self.cmd_mutex.lockUncancelable(io);
        defer self.cmd_mutex.unlock(io);
        if (self.cmd_closed.load(.acquire)) {
            if (self.metrics) |m| m.recordSwarmCommandDropped(.closed);
            return error.QueueClosed;
        }
        if (self.cmd_len == self.cmd_buf.len) {
            if (self.metrics) |m| m.recordSwarmCommandDropped(.full);
            return error.QueueFull;
        }

        const slot = (self.cmd_head + self.cmd_len) % self.cmd_buf.len;
        self.cmd_buf[slot] = owned;
        self.cmd_len += 1;
        self.cmd_notify.set(io);
    }

    /// `timeout_ms == 0` uses a zero-length [`Io.Timeout`] (non-blocking wait attempt).
    pub fn nextEvent(self: *Swarm, timeout_ms: u32) NextEventError!Event {
        const io = self.io;
        const timeout: Io.Timeout = if (timeout_ms == 0) blk: {
            break :blk .{ .duration = .{
                .raw = Io.Duration.zero,
                .clock = .awake,
            } };
        } else blk: {
            const dur: Io.Clock.Duration = .{
                .raw = Io.Duration.fromMilliseconds(@intCast(timeout_ms)),
                .clock = .awake,
            };
            break :blk .{ .deadline = Io.Clock.Timestamp.fromNow(io, dur) };
        };

        while (true) {
            self.evt_mutex.lockUncancelable(io);
            if (self.evt_len > 0) {
                const slot = self.evt_head % self.evt_buf.len;
                const ev = self.evt_buf[slot];
                self.evt_head = (self.evt_head + 1) % self.evt_buf.len;
                self.evt_len -= 1;
                self.evt_space.signal(io);
                self.evt_mutex.unlock(io);
                return ev;
            }
            if (self.cmd_closed.load(.acquire)) {
                self.evt_mutex.unlock(io);
                return error.QueueClosed;
            }

            self.evt_notify.reset();
            self.evt_mutex.unlock(io);

            self.evt_notify.waitTimeout(io, timeout) catch |err| switch (err) {
                error.Timeout => return error.Timeout,
                error.Canceled => return error.Timeout,
            };
        }
    }
};

test "swarm publish produces gossip_message" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try Swarm.init(a, default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    try swarm.submit(.{ .publish = .{ .topic = "/t/1", .payload = "hi" } });
    var ev = try swarm.nextEvent(5000);
    defer ev.deinit(a);
    try std.testing.expectEqual(@as(std.meta.Tag(Event), .gossip_message), std.meta.activeTag(ev));
    try std.testing.expectEqualStrings("/t/1", ev.gossip_message.topic);
    try std.testing.expectEqualStrings("hi", ev.gossip_message.data);

    swarm.shutdown();
    var closed = try swarm.nextEvent(5000);
    defer closed.deinit(a);
    try std.testing.expectEqual(@as(std.meta.Tag(Event), .swarm_closed), std.meta.activeTag(closed));
}

test "swarm tick processes submit without background thread" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try Swarm.init(a, default_event_capacity);
    defer swarm.deinit();

    try swarm.submit(.{ .publish = .{ .topic = "/tick", .payload = "ok" } });
    swarm.tick(commands_per_tick);

    var ev = try swarm.nextEvent(1000);
    defer ev.deinit(a);
    try std.testing.expectEqual(.gossip_message, std.meta.activeTag(ev));
    try std.testing.expectEqualStrings("/tick", ev.gossip_message.topic);

    swarm.shutdown();
    swarm.tick(commands_per_tick);
    var closed = try swarm.nextEvent(1000);
    defer closed.deinit(a);
    try std.testing.expectEqual(.swarm_closed, std.meta.activeTag(closed));
}

test "swarm CommandDispatchHook .handled suppresses default stub" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    // Real-transport hook: intercept `.publish` so the default loopback
    // stub (which would emit a `gossip_message` event) is suppressed.
    // Asserts the embedder can fully take ownership of intercepted
    // commands before the swarm's stub fires.
    const a = std.testing.allocator;

    const Hook = struct {
        gpa: std.mem.Allocator,
        seen_publish: u32 = 0,

        fn dispatch(ctx: ?*anyopaque, cmd: *const OwnedCommand) CommandDispatchHook.Disposition {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            switch (cmd.*) {
                .publish => {
                    self.seen_publish += 1;
                    // We took ownership; free the heap bytes ourselves.
                    destroyCommand(self.gpa, cmd.*);
                    return .handled;
                },
                else => return .fallthrough,
            }
        }
    };
    var hook_state = Hook{ .gpa = a };

    var swarm = try Swarm.initWithConfig(a, .{
        .command_dispatch = .{
            .ctx = &hook_state,
            .dispatch = Hook.dispatch,
        },
    });
    defer swarm.deinit();

    try swarm.submit(.{ .publish = .{ .topic = "/t/intercept", .payload = "blob" } });
    // Also submit a `.subscribe` so the fallthrough path stays alive (it
    // produces a `log` event via the default stub).
    try swarm.submit(.{ .subscribe = .{ .topic = "/t/sub" } });
    swarm.tick(commands_per_tick);

    try std.testing.expectEqual(@as(u32, 1), hook_state.seen_publish);

    // .subscribe fell through → emitted a `log` event. .publish did NOT
    // produce a `gossip_message` because the hook suppressed the stub.
    var ev = try swarm.nextEvent(1000);
    defer ev.deinit(a);
    try std.testing.expectEqual(@as(std.meta.Tag(Event), .log), std.meta.activeTag(ev));
    try std.testing.expectEqualStrings("/t/sub", ev.log.message);

    // No further events are queued — the publish was eaten.
    try std.testing.expectError(error.Timeout, swarm.nextEvent(50));

    swarm.shutdown();
    swarm.tick(commands_per_tick);
    var closed = try swarm.nextEvent(1000);
    defer closed.deinit(a);
    try std.testing.expectEqual(.swarm_closed, std.meta.activeTag(closed));
}

test "swarm CommandDispatchHook .fallthrough preserves default stub" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    // Hook returns `.fallthrough` for every command → behaviour is
    // byte-identical to the no-hook case. Guards against the hook silently
    // breaking the existing event-emission contract.
    const a = std.testing.allocator;

    const Hook = struct {
        seen: u32 = 0,
        fn dispatch(ctx: ?*anyopaque, _: *const OwnedCommand) CommandDispatchHook.Disposition {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.seen += 1;
            return .fallthrough;
        }
    };
    var hook_state = Hook{};

    var swarm = try Swarm.initWithConfig(a, .{
        .command_dispatch = .{
            .ctx = &hook_state,
            .dispatch = Hook.dispatch,
        },
    });
    defer swarm.deinit();

    try swarm.submit(.{ .publish = .{ .topic = "/t/pass", .payload = "x" } });
    swarm.tick(commands_per_tick);

    try std.testing.expectEqual(@as(u32, 1), hook_state.seen);

    var ev = try swarm.nextEvent(1000);
    defer ev.deinit(a);
    try std.testing.expectEqual(.gossip_message, std.meta.activeTag(ev));
    try std.testing.expectEqualStrings("/t/pass", ev.gossip_message.topic);

    swarm.shutdown();
    swarm.tick(commands_per_tick);
    var closed = try swarm.nextEvent(1000);
    defer closed.deinit(a);
    try std.testing.expectEqual(.swarm_closed, std.meta.activeTag(closed));
}

test "swarm initWithConfig fixes local_peer for gossip_message" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    const fixed = try identity.PeerId.random();
    var swarm = try Swarm.initWithConfig(a, .{ .event_capacity = 32, .local_peer = fixed });
    defer swarm.deinit();
    try swarm.startBackground();

    try swarm.submit(.{ .publish = .{ .topic = "t", .payload = "p" } });
    var ev = try swarm.nextEvent(2000);
    defer ev.deinit(a);
    try std.testing.expect(ev.gossip_message.from.eql(&fixed));

    swarm.shutdown();
    while (true) {
        var e = swarm.nextEvent(2000) catch break;
        defer e.deinit(a);
        if (std.meta.activeTag(e) == .swarm_closed) break;
    }
}

test "swarm dial stub forwards expected_peer" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try Swarm.init(a, default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    const hint = try identity.PeerId.random();
    try swarm.submit(.{ .dial = .{ .addr = "/ip4/127.0.0.1/tcp/0", .expected_peer = hint } });

    var ev = try swarm.nextEvent(2000);
    defer ev.deinit(a);
    try std.testing.expectEqual(.peer_connection_failed, std.meta.activeTag(ev));
    try std.testing.expect(ev.peer_connection_failed.peer != null);
    try std.testing.expect(ev.peer_connection_failed.peer.?.eql(&hint));

    swarm.shutdown();
    while (true) {
        var e = swarm.nextEvent(2000) catch break;
        defer e.deinit(a);
        if (std.meta.activeTag(e) == .swarm_closed) break;
    }
}

test "swarm submit returns QueueClosed after shutdown" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var reg = metrics.Metrics{};
    var swarm = try Swarm.initWithConfig(a, .{ .metrics = &reg });
    defer swarm.deinit();
    try swarm.startBackground();

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
    try std.testing.expectError(error.QueueClosed, swarm.submit(.{ .subscribe = .{ .topic = "x" } }));
    try std.testing.expectEqual(@as(u64, 1), reg.swarmCommandDropped(.closed));
}

test "swarm submit QueueFull increments metrics" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var reg = metrics.Metrics{};
    var swarm = try Swarm.initWithConfig(a, .{
        .event_capacity = 32,
        .command_ring_capacity = 1,
        .metrics = &reg,
    });
    defer swarm.deinit();

    try swarm.submit(.{ .publish = .{ .topic = "/t", .payload = "one" } });
    try std.testing.expectError(error.QueueFull, swarm.submit(.{ .publish = .{ .topic = "/t", .payload = "two" } }));
    try std.testing.expectEqual(@as(u64, 1), reg.swarmCommandDropped(.full));

    swarm.tick(commands_per_tick);
    var ev = try swarm.nextEvent(1000);
    defer ev.deinit(a);
    try std.testing.expectEqual(.gossip_message, std.meta.activeTag(ev));

    swarm.shutdown();
    swarm.tick(commands_per_tick);
    var closed = try swarm.nextEvent(1000);
    defer closed.deinit(a);
    try std.testing.expectEqual(.swarm_closed, std.meta.activeTag(closed));
}

// ---------------------------------------------------------------------------
// Ready signal (zeam parity: wait_for_network_ready FFI semantic)
// ---------------------------------------------------------------------------

test "waitUntilReady returns true after startBackground" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try Swarm.init(a, default_event_capacity);
    defer swarm.deinit();

    // Before the worker has started the event has not been set yet.
    try std.testing.expect(!swarm.isReady());

    try swarm.startBackground();
    // Generous timeout: the OS scheduler should give us the worker thread
    // within seconds, but CI under load can be slow.
    try std.testing.expect(swarm.waitUntilReady(5_000));
    // Idempotent: a second call returns immediately, still true.
    try std.testing.expect(swarm.isReady());

    swarm.shutdown();
    var closed = try swarm.nextEvent(1_000);
    defer closed.deinit(a);
    try std.testing.expectEqual(.swarm_closed, std.meta.activeTag(closed));
}

test "waitUntilReady times out before startBackground" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try Swarm.init(a, default_event_capacity);
    defer swarm.deinit();

    // Short timeout — the worker never starts, so this MUST return false
    // and MUST NOT hang the test.
    try std.testing.expect(!swarm.waitUntilReady(25));
    try std.testing.expect(!swarm.isReady());
}

test "waitUntilReady self-bootstraps under tick-mode embedders" {
    const a = std.testing.allocator;
    var swarm = try Swarm.init(a, default_event_capacity);
    defer swarm.deinit();

    // Single-threaded embedders never call `startBackground`; their first
    // `tick()` should self-set the ready event so library code that gates on
    // `waitUntilReady` still works.
    try std.testing.expect(!swarm.isReady());
    swarm.tick(0); // budget=0 → no commands dispatched but ready still fires
    try std.testing.expect(swarm.isReady());
}

test "isReady stays true across shutdown (one-shot semantics)" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try Swarm.init(a, default_event_capacity);
    defer swarm.deinit();

    try swarm.startBackground();
    try std.testing.expect(swarm.waitUntilReady(5_000));
    swarm.shutdown();

    // Drain the swarm_closed event so deinit doesn't trip the leak detector.
    var closed = try swarm.nextEvent(1_000);
    defer closed.deinit(a);
    try std.testing.expectEqual(.swarm_closed, std.meta.activeTag(closed));

    // The ready event is one-shot: once set, calling `isReady` after shutdown
    // still returns true. Embedders should pair `waitUntilReady` with their
    // own shutdown observation, not re-poll it.
    try std.testing.expect(swarm.isReady());
}
