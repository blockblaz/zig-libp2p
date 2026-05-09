//! Embedder-driven swarm: [`swarm.Swarm.tick`] + [`swarm.Swarm.nextEvent`] without a background worker (#34).

const std = @import("std");
const zl = @import("zig_libp2p");

pub fn main() !void {
    if (@import("builtin").single_threaded) return;
    if (@import("builtin").os.tag == .wasi) return;

    const gpa = std.heap.page_allocator;
    var swarm = try zl.swarm.Swarm.init(gpa, zl.swarm.default_event_capacity);
    defer swarm.deinit();

    try swarm.submit(.{ .subscribe = .{ .topic = "/demo" } });
    swarm.tick(zl.swarm.commands_per_tick);

    var ev = try swarm.nextEvent(2000);
    defer ev.deinit(gpa);
    switch (ev) {
        .log => |l| {
            std.debug.print("swarm tick: log topic {s}\n", .{l.message});
        },
        else => return error.UnexpectedSwarmEvent,
    }

    swarm.shutdown();
    swarm.tick(zl.swarm.commands_per_tick);
    var closed = try swarm.nextEvent(2000);
    defer closed.deinit(gpa);
    if (std.meta.activeTag(closed) != .swarm_closed) return error.UnexpectedSwarmEvent;
}
