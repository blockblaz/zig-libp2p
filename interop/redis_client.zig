//! Minimal Redis RESP client for unified-testing coordination (BLPOP / RPUSH / DEL).

const std = @import("std");
const Io = std.Io;
const net = Io.net;

pub const Error = error{
    ConnectFailed,
    ProtocolError,
    UnexpectedResponse,
    Timeout,
} || std.mem.Allocator.Error;

pub const Client = struct {
    stream: net.Stream,
    io: Io,
    allocator: std.mem.Allocator,
    scratch_r: [65536]u8 = undefined,
    scratch_w: [65536]u8 = undefined,
    recv_acc: std.ArrayList(u8) = .empty,

    pub fn connect(allocator: std.mem.Allocator, io: Io, host: []const u8, port: u16) Error!Client {
        const addr = net.IpAddress.resolve(io, host, port) catch return error.ConnectFailed;
        const stream = net.IpAddress.connect(&addr, io, .{ .mode = .stream, .protocol = .tcp }) catch return error.ConnectFailed;
        return .{ .stream = stream, .io = io, .allocator = allocator };
    }

    pub fn deinit(self: *Client) void {
        self.recv_acc.deinit(self.allocator);
        self.stream.close(self.io);
    }

    pub fn del(self: *Client, key: []const u8) Error!void {
        _ = try self.command(&.{ "DEL", key });
    }

    pub fn rpush(self: *Client, key: []const u8, value: []const u8) Error!void {
        const resp = try self.command(&.{ "RPUSH", key, value });
        switch (resp) {
            .integer => {},
            else => return error.UnexpectedResponse,
        }
    }

    /// Blocking left-pop. `timeout_secs == 0` waits indefinitely.
    pub fn blpop(self: *Client, allocator: std.mem.Allocator, key: []const u8, timeout_secs: u64) Error![]u8 {
        const timeout_str = try std.fmt.allocPrint(allocator, "{d}", .{timeout_secs});
        defer allocator.free(timeout_str);
        const resp = try self.command(&.{ "BLPOP", key, timeout_str });
        return switch (resp) {
            .null => error.Timeout,
            .array => |arr| blk: {
                if (arr.len < 2) return error.ProtocolError;
                switch (arr[1]) {
                    .bulk => |v| break :blk try allocator.dupe(u8, v),
                    else => return error.ProtocolError,
                }
            },
            else => error.UnexpectedResponse,
        };
    }

    const Value = union(enum) {
        null,
        integer: i64,
        bulk: []const u8,
        array: []const Value,
    };

    fn command(self: *Client, parts: []const []const u8) Error!Value {
        var cmd = std.ArrayList(u8).empty;
        defer cmd.deinit(self.allocator);
        try appendFmt(&cmd, self.allocator, "*{d}\r\n", .{parts.len});
        for (parts) |p| {
            try appendFmt(&cmd, self.allocator, "${d}\r\n", .{p.len});
            try cmd.appendSlice(self.allocator, p);
            try cmd.appendSlice(self.allocator, "\r\n");
        }
        var w = net.Stream.writer(self.stream, self.io, &self.scratch_w);
        Io.Writer.writeAll(&w.interface, cmd.items) catch return error.ConnectFailed;
        Io.Writer.flush(&w.interface) catch return error.ConnectFailed;
        return try self.readValue();
    }

    fn readValue(self: *Client) Error!Value {
        const line = try self.readLineAlloc();
        defer self.allocator.free(line);
        if (line.len == 0) return error.ProtocolError;
        switch (line[0]) {
            '$' => {
                const n = std.fmt.parseInt(usize, line[1..], 10) catch return error.ProtocolError;
                if (n == 0) return .{ .bulk = "" };
                const buf = try self.allocator.alloc(u8, n);
                try self.readExact(buf);
                _ = try self.readLineAlloc();
                return .{ .bulk = buf };
            },
            '+' => return .{ .bulk = try self.allocator.dupe(u8, line[1..]) },
            '-' => return error.ProtocolError,
            ':' => {
                const v = std.fmt.parseInt(i64, line[1..], 10) catch return error.ProtocolError;
                return .{ .integer = v };
            },
            '*' => {
                const count = std.fmt.parseInt(isize, line[1..], 10) catch return error.ProtocolError;
                if (count < 0) return .null;
                const n: usize = @intCast(count);
                const items = try self.allocator.alloc(Value, n);
                errdefer self.allocator.free(items);
                for (items) |*slot| slot.* = try self.readValue();
                return .{ .array = items };
            },
            else => return error.ProtocolError,
        }
    }

    fn readLineAlloc(self: *Client) Error![]u8 {
        while (true) {
            if (self.recv_acc.items.len > 0) {
                if (std.mem.indexOfScalar(u8, self.recv_acc.items, '\n')) |nl| {
                    const raw = self.recv_acc.items[0..nl];
                    const trim = if (raw.len > 0 and raw[raw.len - 1] == '\r') raw[0 .. raw.len - 1] else raw;
                    const line = try self.allocator.dupe(u8, trim);
                    const drop = nl + 1;
                    std.mem.copyForwards(u8, self.recv_acc.items[0 .. self.recv_acc.items.len - drop], self.recv_acc.items[drop..]);
                    self.recv_acc.shrinkRetainingCapacity(self.recv_acc.items.len - drop);
                    return line;
                }
            }
            var r = net.Stream.reader(self.stream, self.io, &self.scratch_r);
            var chunk: [4096]u8 = undefined;
            const n = Io.Reader.readSliceShort(&r.interface, &chunk) catch return error.ConnectFailed;
            if (n == 0) return error.ProtocolError;
            try self.recv_acc.appendSlice(self.allocator, chunk[0..n]);
        }
    }

    fn readExact(self: *Client, buf: []u8) Error!void {
        var off: usize = 0;
        while (off < buf.len) {
            if (self.recv_acc.items.len > 0) {
                const n = @min(buf.len - off, self.recv_acc.items.len);
                @memcpy(buf[off..][0..n], self.recv_acc.items[0..n]);
                std.mem.copyForwards(u8, self.recv_acc.items[0 .. self.recv_acc.items.len - n], self.recv_acc.items[n..]);
                self.recv_acc.shrinkRetainingCapacity(self.recv_acc.items.len - n);
                off += n;
                continue;
            }
            var r = net.Stream.reader(self.stream, self.io, &self.scratch_r);
            const n = Io.Reader.readSliceShort(&r.interface, buf[off..]) catch return error.ConnectFailed;
            if (n == 0) return error.ProtocolError;
            off += n;
        }
    }
};

fn appendFmt(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) Error!void {
    var buf: [64]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return error.ProtocolError;
    try list.appendSlice(allocator, s);
}
