//! Snappy block codec and Snappy **framing** for Lean `ssz_snappy` req/resp.
//!
//! Uses the same `zig_snappy` / `snappyframesz` revisions as Zeam for wire compatibility.

const std = @import("std");
const frame = @import("frame.zig");
const snappyz = @import("snappyz");
const snappyframesz = @import("snappyframesz");
const stream = @import("stream.zig");

pub const FrameError = frame.FrameError;

pub const WireError = error{
    LengthMismatch,
    IncompleteHeader,
};

pub fn compressBlock(allocator: std.mem.Allocator, plain: []const u8) ![]u8 {
    return snappyz.encode(allocator, plain);
}

pub fn decompressBlock(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    return snappyz.decode(allocator, compressed);
}

pub fn compressFramed(allocator: std.mem.Allocator, plain: []const u8) ![]u8 {
    return snappyframesz.encode(allocator, plain);
}

pub fn decompressFramed(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    return snappyframesz.decode(allocator, data);
}

/// Varint (uncompressed length) + snappy-framed SSZ payload.
pub fn buildRequestWire(allocator: std.mem.Allocator, uncompressed_ssz: []const u8) ![]u8 {
    const framed = try compressFramed(allocator, uncompressed_ssz);
    defer allocator.free(framed);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try frame.appendRequestPrefix(&out, allocator, uncompressed_ssz.len);
    try out.appendSlice(allocator, framed);
    return try out.toOwnedSlice(allocator);
}

/// Response code + varint (uncompressed length) + snappy-framed SSZ payload.
pub fn buildResponseWire(allocator: std.mem.Allocator, code: u8, uncompressed_ssz: []const u8) ![]u8 {
    const framed = try compressFramed(allocator, uncompressed_ssz);
    defer allocator.free(framed);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try frame.appendResponsePrefix(&out, allocator, code, uncompressed_ssz.len);
    try out.appendSlice(allocator, framed);
    return try out.toOwnedSlice(allocator);
}

/// Parse one unary request buffer and decompress SSZ; checks uncompressed length.
pub fn decodeRequestSsz(allocator: std.mem.Allocator, wire: []const u8) ![]u8 {
    const msg = (try stream.peekRpcUnaryRequest(wire)) orelse return error.IncompleteHeader;
    const plain = try decompressFramed(allocator, msg.framed_payload);
    errdefer allocator.free(plain);
    if (plain.len != msg.declared_uncompressed_len) return error.LengthMismatch;
    return plain;
}

/// Parse one unary response buffer and decompress SSZ; checks uncompressed length.
pub fn decodeResponseSsz(allocator: std.mem.Allocator, wire: []const u8) !struct { code: u8, ssz: []u8 } {
    const msg = (try stream.peekRpcUnaryResponse(wire)) orelse return error.IncompleteHeader;
    const plain = try decompressFramed(allocator, msg.framed_payload);
    errdefer allocator.free(plain);
    if (plain.len != msg.declared_uncompressed_len) return error.LengthMismatch;
    return .{ .code = msg.code, .ssz = plain };
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
