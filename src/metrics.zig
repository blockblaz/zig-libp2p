//! Prometheus-style metrics for embedders (#43): atomic counters/gauges, lock-free reads.
//!
//! Metric names align with zeam / libp2p-glue expectations:
//! `lean_gossip_mesh_peers{network_id}`, `swarm_command_dropped_total{network_id,reason}`.

const std = @import("std");

pub const SwarmDropReason = enum {
    full,
    closed,
    uninitialized,
};

fn reasonLabel(reason: SwarmDropReason) []const u8 {
    return switch (reason) {
        .full => "full",
        .closed => "closed",
        .uninitialized => "uninitialized",
    };
}

fn writeEscapedLabelValue(w: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '"' => try w.writeAll("\\\""),
            else => try w.writeByte(c),
        }
    }
}

/// Lock-free registry: one mesh gauge, three swarm drop counters.
pub const Metrics = struct {
    mesh_peers: std.atomic.Value(u64) = .init(0),
    drop_full: std.atomic.Value(u64) = .init(0),
    drop_closed: std.atomic.Value(u64) = .init(0),
    drop_uninitialized: std.atomic.Value(u64) = .init(0),
    /// `network_id` label for [`writePrometheusText`]; must outlive this struct (static embedder string).
    network_id: []const u8 = "",

    pub fn meshPeers(self: *const Metrics) u64 {
        return self.mesh_peers.load(.monotonic);
    }

    pub fn swarmCommandDropped(self: *const Metrics, reason: SwarmDropReason) u64 {
        return switch (reason) {
            .full => self.drop_full.load(.monotonic),
            .closed => self.drop_closed.load(.monotonic),
            .uninitialized => self.drop_uninitialized.load(.monotonic),
        };
    }

    pub fn setMeshPeers(self: *Metrics, n: u64) void {
        self.mesh_peers.store(n, .monotonic);
    }

    pub fn recordSwarmCommandDropped(self: *Metrics, reason: SwarmDropReason) void {
        _ = switch (reason) {
            .full => self.drop_full.fetchAdd(1, .monotonic),
            .closed => self.drop_closed.fetchAdd(1, .monotonic),
            .uninitialized => self.drop_uninitialized.fetchAdd(1, .monotonic),
        };
    }

    /// Alias for [`writePrometheusText`] (issue #43 `snapshot` / exporter iteration).
    pub fn snapshot(self: *const Metrics, w: anytype) !void {
        return self.writePrometheusText(w);
    }

    /// OpenMetrics-style text (subset). `w` is typically [`std.Io.Writer`] or [`std.ArrayList`]'s writer.
    pub fn writePrometheusText(self: *const Metrics, w: anytype) !void {
        try w.writeAll("# TYPE lean_gossip_mesh_peers gauge\n");
        try w.writeAll("lean_gossip_mesh_peers");
        if (self.network_id.len > 0) {
            try w.writeAll("{network_id=\"");
            try writeEscapedLabelValue(w, self.network_id);
            try w.writeAll("\"} ");
        } else {
            try w.writeAll("{network_id=\"\"} ");
        }
        try std.fmt.format(w, "{d}\n", .{self.meshPeers()});

        try w.writeAll("# TYPE swarm_command_dropped_total counter\n");
        inline for (std.enums.values(SwarmDropReason)) |r| {
            try w.writeAll("swarm_command_dropped_total{network_id=\"");
            try writeEscapedLabelValue(w, self.network_id);
            try w.writeAll("\",reason=\"");
            try w.writeAll(reasonLabel(r));
            try w.writeAll("\"} ");
            try std.fmt.format(w, "{d}\n", .{self.swarmCommandDropped(r)});
        }
    }
};

test "metrics prometheus text shape" {
    var m = Metrics{ .network_id = "devnet0" };
    m.setMeshPeers(7);
    m.recordSwarmCommandDropped(.full);
    m.recordSwarmCommandDropped(.full);
    m.recordSwarmCommandDropped(.closed);

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(std.testing.allocator);
    try m.writePrometheusText(&buf.writer(std.testing.allocator));

    const s = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, s, "lean_gossip_mesh_peers") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "network_id=\"devnet0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, " 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "network_id=\"devnet0\",reason=\"full\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "network_id=\"devnet0\",reason=\"closed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "network_id=\"devnet0\",reason=\"uninitialized\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "reason=\"full\"} 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "reason=\"closed\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "reason=\"uninitialized\"} 0") != null);

    var buf2 = std.ArrayList(u8).empty;
    defer buf2.deinit(std.testing.allocator);
    try m.snapshot(&buf2.writer(std.testing.allocator));
    try std.testing.expectEqualStrings(s, buf2.items);
}

test "metrics empty network_id on swarm counters" {
    var m = Metrics{};
    m.recordSwarmCommandDropped(.full);
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(std.testing.allocator);
    try m.writePrometheusText(&buf.writer(std.testing.allocator));
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "network_id=\"\",reason=\"full\"") != null);
}

test "metrics label escaping" {
    var m = Metrics{ .network_id = "a\"b\\c" };
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(std.testing.allocator);
    try m.writePrometheusText(&buf.writer(std.testing.allocator));
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "a\\\"b\\\\c") != null);
}
