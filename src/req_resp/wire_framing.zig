//! Shared Lean req/resp **ssz_snappy** byte framing on `std.Io.Reader` / `Writer` (#40).
//! Used by `wire_tcp` and `wire_quic` after multistream-select on the stream.

const std = @import("std");
const Io = std.Io;

const errors = @import("../errors.zig");
const frame = @import("frame.zig");
const snappy_wire = @import("snappy_wire.zig");

pub const ExchangeLimits = struct {
    max_accumulated: usize = 16 * 1024 * 1024,
    read_chunk: usize = 4096,
};

pub const FramingError = errors.ReqRespError;

/// One unary RPC response after decompression (`code` is the RPC status byte).
pub const UnaryResponse = struct {
    code: u8,
    ssz: []u8,
};

fn firstUnaryResponseWireLen(allocator: std.mem.Allocator, wire: []const u8) (FramingError || std.mem.Allocator.Error)!usize {
    const h = try frame.parseResponseHeader(wire);
    const hdr_len = wire.len - h.payload.len;
    if (h.payload.len == 0) return error.IncompleteStream;

    var i: usize = 1;
    while (i <= h.payload.len) : (i += 1) {
        const plain = snappy_wire.decompressFramed(allocator, h.payload[0..i]) catch continue;
        defer allocator.free(plain);
        if (plain.len == h.declared_len) {
            return hdr_len + i;
        }
    }
    return error.IncompleteStream;
}

fn readMoreInto(
    acc: *std.ArrayList(u8),
    r: *Io.Reader,
    allocator: std.mem.Allocator,
    scratch: []u8,
    limits: ExchangeLimits,
) (FramingError || std.mem.Allocator.Error)!void {
    const chunk = scratch[0..@min(scratch.len, limits.read_chunk)];
    const n = r.readSliceShort(chunk) catch return error.IoError;
    if (n == 0) return error.Disconnected;
    const new_len = acc.items.len + n;
    if (new_len > limits.max_accumulated) return error.PayloadTooLarge;
    try acc.appendSlice(allocator, chunk[0..n]);
}

pub fn readOneUnaryRequest(
    allocator: std.mem.Allocator,
    r: *Io.Reader,
    scratch: []u8,
    limits: ExchangeLimits,
) (FramingError || std.mem.Allocator.Error)![]u8 {
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);
    while (true) {
        try readMoreInto(&acc, r, allocator, scratch, limits);
        if (snappy_wire.decodeRequestSsz(allocator, acc.items)) |ssz| {
            return ssz;
        } else |err| switch (err) {
            error.IncompleteHeader => continue,
            error.InvalidData => continue,
            else => |e| return e,
        }
    }
}

pub fn readOneUnaryResponse(
    allocator: std.mem.Allocator,
    r: *Io.Reader,
    scratch: []u8,
    limits: ExchangeLimits,
) (FramingError || std.mem.Allocator.Error)!UnaryResponse {
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);
    while (true) {
        try readMoreInto(&acc, r, allocator, scratch, limits);
        const frame_len = firstUnaryResponseWireLen(allocator, acc.items) catch |err| switch (err) {
            error.IncompleteStream => continue,
            else => |e| return e,
        };
        const decoded = try snappy_wire.decodeResponseSsz(allocator, acc.items[0..frame_len]);
        return UnaryResponse{ .code = decoded.code, .ssz = decoded.ssz };
    }
}

pub fn writeUnaryRequestFlush(
    allocator: std.mem.Allocator,
    w: *Io.Writer,
    uncompressed_request: []const u8,
) (FramingError || std.mem.Allocator.Error)!void {
    const wire_req = try snappy_wire.buildRequestWire(allocator, uncompressed_request);
    defer allocator.free(wire_req);
    Io.Writer.writeAll(w, wire_req) catch return error.IoError;
    Io.Writer.flush(w) catch return error.IoError;
}

/// After multistream handshake on `r`/`w`, send one unary request and read one unary response.
pub fn initiatorUnaryAfterHandshake(
    allocator: std.mem.Allocator,
    r: *Io.Reader,
    w: *Io.Writer,
    scratch_r: []u8,
    uncompressed_request: []const u8,
    limits: ExchangeLimits,
) (FramingError || std.mem.Allocator.Error)!UnaryResponse {
    try writeUnaryRequestFlush(allocator, w, uncompressed_request);
    return try readOneUnaryResponse(allocator, r, scratch_r, limits);
}

pub fn initiatorReadResponsesAfterHandshake(
    allocator: std.mem.Allocator,
    r: *Io.Reader,
    w: *Io.Writer,
    scratch_r: []u8,
    uncompressed_request: []const u8,
    limits: ExchangeLimits,
    count: usize,
) (FramingError || std.mem.Allocator.Error)![][]u8 {
    try writeUnaryRequestFlush(allocator, w, uncompressed_request);
    var i: usize = 0;
    const out = try allocator.alloc([]u8, count);
    errdefer {
        for (out[0..i]) |s| allocator.free(s);
        allocator.free(out);
    }
    while (i < count) : (i += 1) {
        const got = try readOneUnaryResponse(allocator, r, scratch_r, limits);
        if (got.code != 0) {
            allocator.free(got.ssz);
            for (out[0..i]) |s| allocator.free(s);
            allocator.free(out);
            return error.InvalidData;
        }
        out[i] = got.ssz;
    }
    return out;
}

/// After multistream handshake, read one unary request and write `response_bodies` (code 0 each).
pub fn responderUnarySequenceAfterHandshake(
    allocator: std.mem.Allocator,
    r: *Io.Reader,
    w: *Io.Writer,
    scratch_r: []u8,
    limits: ExchangeLimits,
    response_bodies: []const []const u8,
) (FramingError || std.mem.Allocator.Error)![]u8 {
    const req_ssz = try readOneUnaryRequest(allocator, r, scratch_r, limits);
    errdefer allocator.free(req_ssz);

    for (response_bodies) |body| {
        const wire = try snappy_wire.buildResponseWire(allocator, 0, body);
        defer allocator.free(wire);
        Io.Writer.writeAll(w, wire) catch return error.IoError;
    }
    Io.Writer.flush(w) catch return error.IoError;
    return req_ssz;
}
