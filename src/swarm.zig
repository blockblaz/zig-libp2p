//! Swarm command queue + typed event channel for a dedicated runtime thread (#34).
//!
//! * Command channel: bounded MPSC, capacity [`command_capacity`], at most [`commands_per_tick`]
//!   are processed per [`run`] loop iteration.
//! * Event channel: bounded SPSC (one [`nextEvent`] consumer), same capacity as commands by default.
//! * Synchronization uses `std.Io` primitives backed by [`Io.Threaded`] (futex + condvar).
//!
//! Real transport, gossip, and req/resp I/O are intentionally stubbed: commands still produce
//! deterministic typed [`Event`]s so embedders can wire behaviour incrementally.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const errors = @import("errors.zig");
const layer_events = @import("layer_events.zig");
const protocol = @import("protocol.zig");
const identity = @import("identity.zig");

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
    request_id: u64,
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

pub const PeerIdPayload = struct {
    peer: identity.PeerId,
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
    send_end_of_stream: struct {
        peer: identity.PeerId,
        request_id: u64,
    },
    send_error_response: RpcError,
    dial: struct {
        addr: []const u8,
    },
    shutdown,
};

/// Swarm → embedder events. Owned memory is released with [`Event.deinit`].
pub const Event = union(enum) {
    gossip_message: GossipMessage,
    rpc_request: RpcRequest,
    rpc_response_chunk: RpcResponseChunk,
    rpc_response_end: struct {
        peer: identity.PeerId,
        request_id: u64,
    },
    rpc_error_response: RpcError,
    peer_connected: PeerIdPayload,
    peer_disconnected: PeerIdPayload,
    peer_connection_failed: layer_events.TransportFailure,
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
            .rpc_response_end,
            .rpc_error_response,
            .peer_connected,
            .peer_disconnected,
            .peer_connection_failed,
            .swarm_closed,
            => {},
        }
        e.* = undefined;
    }
};

pub const SubmitError = error{ QueueFull, QueueClosed } || std.mem.Allocator.Error;
pub const NextEventError = error{ Timeout, QueueClosed };

const OwnedCommand = union(enum) {
    publish: struct { topic: []u8, payload: []u8 },
    subscribe: struct { topic: []u8 },
    send_request: struct {
        peer: identity.PeerId,
        protocol: protocol.LeanSupportedProtocol,
        request_id: u64,
        payload: []u8,
    },
    send_response_chunk: struct {
        peer: identity.PeerId,
        request_id: u64,
        chunk: []u8,
    },
    send_end_of_stream: struct { peer: identity.PeerId, request_id: u64 },
    send_error_response: RpcError,
    dial: struct { addr: []u8 },
    shutdown,
};

const OwnedEvent = Event;

fn destroyCommand(a: std.mem.Allocator, c: OwnedCommand) void {
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
            .dial = .{ .addr = try a.dupe(u8, d.addr) },
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

    runner: ?std.Thread = null,

    pub fn init(gpa: std.mem.Allocator, event_capacity: usize) std.mem.Allocator.Error!Swarm {
        var threaded = Io.Threaded.init(gpa, .{
            .async_limit = .nothing,
            .concurrent_limit = .nothing,
        });
        const io = threaded.io();

        const cmd_buf = try gpa.alloc(OwnedCommand, command_capacity);
        errdefer gpa.free(cmd_buf);
        @memset(std.mem.sliceAsBytes(cmd_buf), 0);

        const evt_buf = try gpa.alloc(OwnedEvent, event_capacity);
        errdefer gpa.free(evt_buf);
        @memset(std.mem.sliceAsBytes(evt_buf), 0);

        return .{
            .gpa = gpa,
            .threaded = threaded,
            .io = io,
            .local_peer = try identity.PeerId.random(),
            .cmd_buf = cmd_buf,
            .evt_buf = evt_buf,
            .evt_cap = event_capacity,
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

    /// Starts [`run`] on a new OS thread. Idempotent if already started.
    pub fn startBackground(self: *Swarm) std.Thread.SpawnError!void {
        if (self.runner != null) return;
        self.runner = try std.Thread.spawn(.{}, runWorkerTrampoline, .{self});
    }

    fn runWorkerTrampoline(ctx: *Swarm) void {
        ctx.run();
    }

    /// Blocks the calling thread until [`shutdown`] completes processing.
    pub fn run(self: *Swarm) void {
        const io = self.io;
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
                self.pushEvent(.{ .peer_connection_failed = .{ .kind = error.DialFailed } }) catch {
                    destroyCommand(self.gpa, .{ .dial = d });
                    return;
                };
                destroyCommand(self.gpa, .{ .dial = d });
            },
            .shutdown => unreachable,
        }
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
        if (self.cmd_closed.load(.acquire)) return error.QueueClosed;
        const owned = try cloneCommand(self.gpa, cmd);
        errdefer destroyCommand(self.gpa, owned);

        const io = self.io;
        self.cmd_mutex.lockUncancelable(io);
        defer self.cmd_mutex.unlock(io);
        if (self.cmd_closed.load(.acquire)) return error.QueueClosed;
        if (self.cmd_len == self.cmd_buf.len) return error.QueueFull;

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
                else => return error.Timeout,
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

test "swarm submit returns QueueClosed after shutdown" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const a = std.testing.allocator;
    var swarm = try Swarm.init(a, default_event_capacity);
    defer swarm.deinit();
    try swarm.startBackground();

    swarm.shutdown();
    while (true) {
        var ev = swarm.nextEvent(5000) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .swarm_closed) break;
    }
    try std.testing.expectError(error.QueueClosed, swarm.submit(.{ .subscribe = .{ .topic = "x" } }));
}
