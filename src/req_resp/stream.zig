//! Incremental req/resp parsing over a byte stream.
//!
//! `scanComplete*` treats the varint as the **wire length** of the body
//! (length-delimited messages). For Ethereum-style `ssz_snappy` unary
//! messages where the buffer holds one full RPC blob, use `peekRpcUnary*`.
//!
//! Slices from `scanComplete*` alias the input until you call `consumePrefix`.

const std = @import("std");
const frame = @import("frame.zig");

pub const FrameError = frame.FrameError;

pub const BufferCapExceeded = error{BufferCapExceeded};

pub const PoppedRequest = struct {
    total_len: usize,
    declared_len: usize,
    body: []const u8,
};

pub const PoppedResponse = struct {
    total_len: usize,
    code: u8,
    declared_len: usize,
    body: []const u8,
};

/// One unary RPC request buffer: varint is **uncompressed** SSZ length;
/// `framed_payload` is the entire snappy-framed suffix (wire length may differ).
pub const RpcUnaryRequest = struct {
    total_len: usize,
    declared_uncompressed_len: usize,
    framed_payload: []const u8,
};

/// One unary RPC response buffer (same length semantics as `RpcUnaryRequest`).
pub const RpcUnaryResponse = struct {
    total_len: usize,
    code: u8,
    declared_uncompressed_len: usize,
    framed_payload: []const u8,
};

/// Returns `null` when the varint header is incomplete (`Truncated`).
pub fn peekRpcUnaryRequest(buf: []const u8) FrameError!?RpcUnaryRequest {
    if (buf.len == 0) return null;
    const h = frame.parseRequestHeader(buf) catch |err| switch (err) {
        error.Truncated => return null,
        else => |e| return e,
    };
    return .{
        .total_len = buf.len,
        .declared_uncompressed_len = h.declared_len,
        .framed_payload = h.payload,
    };
}

/// Returns `null` when the header (code + varint) is incomplete.
pub fn peekRpcUnaryResponse(buf: []const u8) FrameError!?RpcUnaryResponse {
    if (buf.len == 0) return null;
    const h = frame.parseResponseHeader(buf) catch |err| switch (err) {
        error.Truncated => return null,
        error.Incomplete => return null,
        else => |e| return e,
    };
    return .{
        .total_len = buf.len,
        .code = h.code,
        .declared_uncompressed_len = h.declared_len,
        .framed_payload = h.payload,
    };
}

/// Returns `null` if fewer than one full frame is present.
pub fn scanCompleteRequest(buf: []const u8) FrameError!?PoppedRequest {
    if (buf.len == 0) return null;
    const h = try frame.parseRequestHeader(buf);
    const header_len = buf.len - h.payload.len;
    if (h.payload.len < h.declared_len) return null;
    return .{
        .total_len = header_len + h.declared_len,
        .declared_len = h.declared_len,
        .body = h.payload[0..h.declared_len],
    };
}

/// Returns `null` if fewer than one full frame is present.
pub fn scanCompleteResponse(buf: []const u8) FrameError!?PoppedResponse {
    if (buf.len == 0) return null;
    const h = try frame.parseResponseHeader(buf);
    const header_len = buf.len - h.payload.len;
    if (h.payload.len < h.declared_len) return null;
    return .{
        .total_len = header_len + h.declared_len,
        .code = h.code,
        .declared_len = h.declared_len,
        .body = h.payload[0..h.declared_len],
    };
}

/// Removes the first `n` bytes from the front of `list`.
pub fn consumePrefix(list: *std.ArrayList(u8), n: usize) !void {
    try list.replaceRange(0, n, &.{});
}

/// Default cap for buffered inbound bytes (several max-sized frames plus slack).
pub const default_max_capacity: usize = 2 * frame.max_rpc_message_size + 4096;

pub const InboundBuffer = struct {
    raw: std.ArrayList(u8),
    max_capacity: usize,

    pub fn init(max_capacity: usize) InboundBuffer {
        return .{ .raw = std.ArrayList(u8).empty, .max_capacity = max_capacity };
    }

    pub fn initDefault() InboundBuffer {
        return init(default_max_capacity);
    }

    pub fn deinit(self: *InboundBuffer, allocator: std.mem.Allocator) void {
        self.raw.deinit(allocator);
    }

    pub fn feed(self: *InboundBuffer, allocator: std.mem.Allocator, chunk: []const u8) (BufferCapExceeded || std.mem.Allocator.Error)!void {
        const new_len = self.raw.items.len + chunk.len;
        if (new_len > self.max_capacity) return error.BufferCapExceeded;
        try self.raw.appendSlice(allocator, chunk);
    }

    pub fn scanRequest(self: *const InboundBuffer) FrameError!?PoppedRequest {
        return scanCompleteRequest(self.raw.items);
    }

    pub fn scanResponse(self: *const InboundBuffer) FrameError!?PoppedResponse {
        return scanCompleteResponse(self.raw.items);
    }

    pub fn peekRpcUnaryRequestFromBuffer(self: *const InboundBuffer) FrameError!?RpcUnaryRequest {
        return peekRpcUnaryRequest(self.raw.items);
    }

    pub fn peekRpcUnaryResponseFromBuffer(self: *const InboundBuffer) FrameError!?RpcUnaryResponse {
        return peekRpcUnaryResponse(self.raw.items);
    }

    pub fn consume(self: *InboundBuffer, n: usize) !void {
        try consumePrefix(&self.raw, n);
    }
};

test "scanCompleteRequest two frames back to back" {
    const a = std.testing.allocator;
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(a);
    try frame.appendRequestPrefix(&buf, a, 1);
    try buf.appendSlice(a, "a");
    try frame.appendRequestPrefix(&buf, a, 1);
    try buf.appendSlice(a, "b");

    const f1 = (try scanCompleteRequest(buf.items)).?;
    try std.testing.expectEqual(@as(usize, 1), f1.declared_len);
    try std.testing.expectEqualStrings("a", f1.body);
    try consumePrefix(&buf, f1.total_len);

    const f2 = (try scanCompleteRequest(buf.items)).?;
    try std.testing.expectEqualStrings("b", f2.body);
    try consumePrefix(&buf, f2.total_len);
    try std.testing.expectEqual(@as(usize, 0), buf.items.len);
}

test "scanCompleteRequest incremental feed" {
    const a = std.testing.allocator;
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    try frame.appendRequestPrefix(&wire, a, 3);
    try wire.appendSlice(a, "xyz");

    var inbound = InboundBuffer.initDefault();
    defer inbound.deinit(a);

    for (wire.items, 0..) |_, i| {
        try inbound.feed(a, wire.items[i .. i + 1]);
        if (i + 1 < wire.items.len) {
            try std.testing.expect((try inbound.scanRequest()) == null);
        }
    }
    const got = (try inbound.scanRequest()).?;
    try std.testing.expectEqualStrings("xyz", got.body);
    try inbound.consume(got.total_len);
    try std.testing.expectEqual(@as(usize, 0), inbound.raw.items.len);
}

test "scanCompleteResponse with code" {
    const a = std.testing.allocator;
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(a);
    try frame.appendResponsePrefix(&buf, a, 0, 2);
    try buf.appendSlice(a, "ok");
    const r = (try scanCompleteResponse(buf.items)).?;
    try std.testing.expectEqual(@as(u8, 0), r.code);
    try std.testing.expectEqualStrings("ok", r.body);
}

test "InboundBuffer feed rejects over cap" {
    const a = std.testing.allocator;
    var inbound = InboundBuffer.init(4);
    defer inbound.deinit(a);
    try std.testing.expectError(error.BufferCapExceeded, inbound.feed(a, "hello"));
}

test "peekRpcUnaryRequest incomplete varint" {
    const buf = [_]u8{0x80};
    try std.testing.expect((try peekRpcUnaryRequest(&buf)) == null);
}

test "peekRpcUnaryRequest treats suffix as framed blob" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).empty;
    defer list.deinit(a);
    try frame.appendRequestPrefix(&list, a, 5);
    try list.appendSlice(a, "payload-longer-than-five");
    const r = (try peekRpcUnaryRequest(list.items)).?;
    try std.testing.expectEqual(@as(usize, 5), r.declared_uncompressed_len);
    try std.testing.expectEqualStrings("payload-longer-than-five", r.framed_payload);
    try std.testing.expectEqual(list.items.len, r.total_len);
}
