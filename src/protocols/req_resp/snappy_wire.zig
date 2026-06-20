//! Snappy block codec and Snappy **framing** for Lean `ssz_snappy` req/resp.
//!
//! Uses the same `zig_snappy` / `snappyframesz` revisions as Zeam for wire compatibility.

const std = @import("std");
const frame = @import("frame.zig");
const errors = @import("../../primitives/errors.zig");
const snappyz = @import("snappyz");
const snappyframesz = @import("snappyframesz");
const stream = @import("stream.zig");

pub const FrameError = frame.FrameError;
pub const ReqRespError = errors.ReqRespError;

/// Back-compat: length/header issues are [`ReqRespError`] values.
pub const WireError = ReqRespError;

const max_framed_chunk_payload: usize = (1 << 24) - 1;
const stream_identifier = "\xff\x06\x00\x00sNaPpY";
const identifier_payload = "sNaPpY";
const masked_crc_constant: u32 = 0xa282ead8;

pub fn compressBlock(allocator: std.mem.Allocator, plain: []const u8) (ReqRespError || std.mem.Allocator.Error)![]u8 {
    return snappyz.encode(allocator, plain) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidData,
    };
}

pub fn decompressBlock(allocator: std.mem.Allocator, compressed: []const u8) (ReqRespError || std.mem.Allocator.Error)![]u8 {
    return snappyz.decode(allocator, compressed) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidData,
    };
}

pub fn compressFramed(allocator: std.mem.Allocator, plain: []const u8) (ReqRespError || std.mem.Allocator.Error)![]u8 {
    return snappyframesz.encode(allocator, plain) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidData,
    };
}

pub fn decompressFramed(allocator: std.mem.Allocator, data: []const u8) (ReqRespError || std.mem.Allocator.Error)![]u8 {
    return snappyframesz.decode(allocator, data) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidData,
    };
}

const BoundedDecompressError = error{
    OutputBudgetExceeded,
};

/// Decompress snappy-framed (or raw block) data, stopping once `max_output` bytes
/// are produced (#121). Rejects declared lengths that exceed `frame.max_rpc_message_size`
/// before allocating decompressed output.
/// Decompressed payload plus the number of input bytes it consumed from `data`
/// (so a multi-chunk reqresp stream can advance to the next chunk).
pub const DecompressResult = struct { plain: []u8, consumed: usize };

pub fn decompressFramedMax(
    allocator: std.mem.Allocator,
    data: []const u8,
    max_output: usize,
) (ReqRespError || BoundedDecompressError || std.mem.Allocator.Error)!DecompressResult {
    if (max_output > frame.max_rpc_message_size) return error.PayloadTooLarge;
    if (data.len == 0) return error.InvalidData;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var consumed: usize = data.len;
    if (data.len >= stream_identifier.len and std.mem.eql(u8, data[0..stream_identifier.len], stream_identifier)) {
        consumed = try decodeFramedInto(&out, allocator, data, max_output);
    } else {
        const block = snappyz.decode(allocator, data) catch return error.InvalidData;
        defer allocator.free(block);
        if (block.len > max_output) return error.OutputBudgetExceeded;
        try out.appendSlice(allocator, block);
    }
    return .{ .plain = try out.toOwnedSlice(allocator), .consumed = consumed };
}

/// Returns the number of input bytes consumed from `data` to produce exactly
/// `max_output` bytes. In a multi-chunk reqresp response the bytes after that
/// belong to the NEXT response chunk, so decoding stops at `max_output` rather
/// than running to the end of `data`.
fn decodeFramedInto(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    data: []const u8,
    max_output: usize,
) (ReqRespError || BoundedDecompressError || std.mem.Allocator.Error)!usize {
    var cursor: usize = 0;
    var saw_data_chunk = false;

    while (cursor < data.len) {
        if (data.len - cursor < 4) return error.InvalidData;
        const chunk_type_byte = data[cursor];
        const length = readChunkLength(data[cursor + 1 .. cursor + 4]);
        cursor += 4;
        if (length > max_framed_chunk_payload) return error.InvalidData;
        if (cursor + length > data.len) return error.InvalidData;

        const chunk_data = data[cursor .. cursor + length];
        cursor += length;

        switch (chunk_type_byte) {
            0xff => {
                if (chunk_data.len != identifier_payload.len or
                    !std.mem.eql(u8, chunk_data, identifier_payload))
                {
                    return error.InvalidData;
                }
            },
            0x00 => {
                if (chunk_data.len < 4) return error.InvalidData;
                const raw = snappyz.decode(allocator, chunk_data[4..]) catch return error.InvalidData;
                defer allocator.free(raw);
                try appendChecked(out, allocator, raw, max_output);
                saw_data_chunk = true;
            },
            0x01 => {
                if (chunk_data.len < 4) return error.InvalidData;
                try appendChecked(out, allocator, chunk_data[4..], max_output);
                saw_data_chunk = true;
            },
            0x80...0xfd => continue,
            else => return error.InvalidData,
        }
        // Stop once the declared payload is fully produced — remaining bytes
        // are the next response chunk's header + payload.
        if (out.items.len >= max_output) break;
    }
    if (!saw_data_chunk) return error.InvalidData;
    return cursor;
}

fn appendChecked(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    slice: []const u8,
    max_output: usize,
) (BoundedDecompressError || std.mem.Allocator.Error)!void {
    const new_len = out.items.len + slice.len;
    if (new_len > max_output) return error.OutputBudgetExceeded;
    try out.appendSlice(allocator, slice);
}

fn readChunkLength(bytes: []const u8) usize {
    return @as(usize, bytes[0]) |
        (@as(usize, bytes[1]) << 8) |
        (@as(usize, bytes[2]) << 16);
}

/// Parse one unary request buffer and decompress SSZ; checks uncompressed length.
pub fn decodeRequestSsz(allocator: std.mem.Allocator, wire: []const u8) (ReqRespError || std.mem.Allocator.Error)![]u8 {
    const msg = (try stream.peekRpcUnaryRequest(wire)) orelse return error.IncompleteHeader;
    const dec = decompressFramedMax(allocator, msg.framed_payload, msg.declared_uncompressed_len) catch |err| switch (err) {
        error.OutputBudgetExceeded => return error.InvalidData,
        else => |e| return e,
    };
    if (dec.plain.len != msg.declared_uncompressed_len) {
        allocator.free(dec.plain);
        return error.LengthMismatch;
    }
    return dec.plain;
}

/// Parse one unary response chunk and decompress SSZ; checks uncompressed
/// length. `consumed` is the total wire length of this chunk (header + framed
/// payload), so a multi-chunk response stream can advance to the next chunk.
pub fn decodeResponseSsz(allocator: std.mem.Allocator, wire: []const u8) (ReqRespError || std.mem.Allocator.Error)!struct { code: u8, ssz: []u8, consumed: usize } {
    const msg = (try stream.peekRpcUnaryResponse(wire)) orelse return error.IncompleteHeader;
    const dec = decompressFramedMax(allocator, msg.framed_payload, msg.declared_uncompressed_len) catch |err| switch (err) {
        error.OutputBudgetExceeded => return error.InvalidData,
        else => |e| return e,
    };
    if (dec.plain.len != msg.declared_uncompressed_len) {
        allocator.free(dec.plain);
        return error.LengthMismatch;
    }
    // Header bytes preceding the framed payload (code + varint length) +
    // framed bytes consumed for this chunk's payload.
    const header_len = @intFromPtr(msg.framed_payload.ptr) - @intFromPtr(wire.ptr);
    return .{ .code = msg.code, .ssz = dec.plain, .consumed = header_len + dec.consumed };
}

/// Varint (uncompressed length) + snappy-framed SSZ payload.
pub fn buildRequestWire(allocator: std.mem.Allocator, uncompressed_ssz: []const u8) (ReqRespError || std.mem.Allocator.Error)![]u8 {
    const framed = try compressFramed(allocator, uncompressed_ssz);
    defer allocator.free(framed);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try frame.appendRequestPrefix(&out, allocator, uncompressed_ssz.len);
    try out.appendSlice(allocator, framed);
    return try out.toOwnedSlice(allocator);
}

/// Response code + varint (uncompressed length) + snappy-framed SSZ payload.
pub fn buildResponseWire(allocator: std.mem.Allocator, code: u8, uncompressed_ssz: []const u8) (ReqRespError || std.mem.Allocator.Error)![]u8 {
    const framed = try compressFramed(allocator, uncompressed_ssz);
    defer allocator.free(framed);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try frame.appendResponsePrefix(&out, allocator, code, uncompressed_ssz.len);
    try out.appendSlice(allocator, framed);
    return try out.toOwnedSlice(allocator);
}

test "framed snappy round trip" {
    const a = std.testing.allocator;
    const plain = "repeat-me-" ** 32;
    const enc = try compressFramed(a, plain);
    defer a.free(enc);
    const dec = try decompressFramed(a, enc);
    defer a.free(dec);
    try std.testing.expectEqualStrings(plain, dec);
}

test "request wire round trip" {
    const a = std.testing.allocator;
    const plain = "hello-ssz-payload-" ** 8;
    const wire = try buildRequestWire(a, plain);
    defer a.free(wire);
    const out = try decodeRequestSsz(a, wire);
    defer a.free(out);
    try std.testing.expectEqualStrings(plain, out);
}

test "response wire round trip" {
    const a = std.testing.allocator;
    const plain = "status-body-" ** 12;
    const wire = try buildResponseWire(a, 0, plain);
    defer a.free(wire);
    const got = try decodeResponseSsz(a, wire);
    defer a.free(got.ssz);
    try std.testing.expectEqual(@as(u8, 0), got.code);
    try std.testing.expectEqualStrings(plain, got.ssz);
    // `consumed` must cover exactly this one chunk's wire bytes.
    try std.testing.expectEqual(wire.len, got.consumed);
}

test "decodeResponseSsz walks a multi-chunk response (blocks_by_range shape)" {
    const a = std.testing.allocator;
    const bodies = [_][]const u8{ "block-AAAA" ** 700, "block-B" ** 9000, "tiny" };

    // Concatenate N response chunks on the wire, as a multi-block responder does.
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(a);
    for (bodies) |b| {
        const w = try buildResponseWire(a, 0, b);
        defer a.free(w);
        try buf.appendSlice(a, w);
    }

    // Walk every chunk, advancing by `consumed` each time.
    var rest: []const u8 = buf.items;
    for (bodies) |expected| {
        const got = try decodeResponseSsz(a, rest);
        defer a.free(got.ssz);
        try std.testing.expectEqual(@as(u8, 0), got.code);
        try std.testing.expectEqualStrings(expected, got.ssz);
        try std.testing.expect(got.consumed > 0 and got.consumed <= rest.len);
        rest = rest[got.consumed..];
    }
    try std.testing.expectEqual(@as(usize, 0), rest.len); // exactly drained
}

test "decodeResponseSsz round-trips a large incompressible multi-frame payload" {
    const a = std.testing.allocator;
    const big = try a.alloc(u8, 300 * 1024);
    defer a.free(big);
    for (big, 0..) |*b, i| b.* = @truncate((i *% 0x9E3779B1) ^ (i >> 7) ^ (i << 3));

    const wire = try buildResponseWire(a, 0, big);
    defer a.free(wire);
    const got = try decodeResponseSsz(a, wire);
    defer a.free(got.ssz);
    try std.testing.expectEqual(@as(u8, 0), got.code);
    try std.testing.expectEqual(wire.len, got.consumed);
    try std.testing.expectEqualSlices(u8, big, got.ssz);
}

test "decodeRequestSsz rejects declared length mismatch" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).empty;
    defer list.deinit(a);
    try frame.appendRequestPrefix(&list, a, 9999);
    const enc = try compressFramed(a, "short");
    defer a.free(enc);
    try list.appendSlice(a, enc);
    try std.testing.expectError(error.LengthMismatch, decodeRequestSsz(a, list.items));
}

test "decompressFramedMax rejects output larger than budget" {
    const a = std.testing.allocator;
    const plain = "x" ** 64;
    const enc = try compressFramed(a, plain);
    defer a.free(enc);
    try std.testing.expectError(error.OutputBudgetExceeded, decompressFramedMax(a, enc, 8));
}
