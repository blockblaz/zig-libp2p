//! Minimal Redis RESP client for unified-testing coordination (BLPOP / RPUSH / DEL).
//! Uses blocking POSIX TCP — coordination must not share the libp2p Io runtime.

const builtin = @import("builtin");
const std = @import("std");
const posix = std.posix;
const c = std.c;
const system = posix.system;

inline fn checkRc(rc: anytype) posix.E {
    return posix.errno(rc);
}

pub const Error = error{
    ConnectFailed,
    ProtocolError,
    UnexpectedResponse,
    Timeout,
} || std.mem.Allocator.Error;

pub const Client = struct {
    fd: posix.socket_t,
    allocator: std.mem.Allocator,
    recv_acc: std.ArrayList(u8) = .empty,

    pub fn connect(allocator: std.mem.Allocator, host: []const u8, port: u16) Error!Client {
        const fd = try openTcp(host, port);
        return .{ .fd = fd, .allocator = allocator };
    }

    pub fn deinit(self: *Client) void {
        self.recv_acc.deinit(self.allocator);
        _ = system.close(self.fd);
    }

    pub fn localIpv4(self: *const Client) ![4]u8 {
        if (builtin.os.tag == .windows) return error.ConnectFailed;
        var sa: posix.sockaddr.in = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        const rc = system.getsockname(self.fd, @ptrCast(&sa), &len);
        switch (checkRc(rc)) {
            .SUCCESS => {},
            else => return error.ConnectFailed,
        }
        if (sa.family != 2) return error.ConnectFailed;
        var bytes: [4]u8 = undefined;
        @memcpy(&bytes, std.mem.asBytes(&sa.addr)[0..4]);
        return bytes;
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
        try writeAll(self.fd, cmd.items);
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
            var chunk: [4096]u8 = undefined;
            const n = posix.read(self.fd, &chunk) catch return error.ConnectFailed;
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
            const n = posix.read(self.fd, buf[off..]) catch return error.ConnectFailed;
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

fn writeAll(fd: posix.socket_t, bytes: []const u8) Error!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = system.write(fd, bytes.ptr + off, bytes.len - off);
        if (@as(isize, @bitCast(rc)) < 0) return error.ConnectFailed;
        off += @intCast(rc);
    }
}

fn openTcp(host: []const u8, port: u16) Error!posix.socket_t {
    if (builtin.os.tag == .windows) return error.ConnectFailed;

    const host_z = try std.heap.page_allocator.dupeZ(u8, host);
    defer std.heap.page_allocator.free(host_z);
    const port_str = try std.fmt.allocPrint(std.heap.page_allocator, "{d}", .{port});
    defer std.heap.page_allocator.free(port_str);
    const port_z = try std.heap.page_allocator.dupeZ(u8, port_str);
    defer std.heap.page_allocator.free(port_z);

    var hints: c.addrinfo = std.mem.zeroes(c.addrinfo);
    hints.family = 2;
    hints.socktype = 1;
    hints.protocol = 6;

    var res: ?*c.addrinfo = null;
    const gai_rc = c.getaddrinfo(host_z.ptr, port_z.ptr, &hints, &res);
    if (@intFromEnum(gai_rc) != 0 or res == null) return error.ConnectFailed;
    const list = res.?;
    defer c.freeaddrinfo(list);

    var entry: ?*c.addrinfo = list;
    while (entry) |ai| : (entry = ai.next) {
        if (ai.addr == null or ai.family != 2) continue;
        const fd = try openStreamSocket();
        errdefer _ = system.close(fd);
        const sa: *posix.sockaddr.in = @ptrCast(@alignCast(ai.addr));
        const rc = system.connect(fd, @ptrCast(sa), @sizeOf(posix.sockaddr.in));
        if (checkRc(rc) == .SUCCESS) return fd;
        _ = system.close(fd);
    }
    return error.ConnectFailed;
}

fn openStreamSocket() Error!posix.socket_t {
    const rc = system.socket(2, 1, 6);
    switch (checkRc(rc)) {
        .SUCCESS => return @intCast(rc),
        else => return error.ConnectFailed,
    }
}
