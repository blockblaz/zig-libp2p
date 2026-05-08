//! Length-prefixed req/resp framing: varint-declared payload on requests,
//! single-byte response code then the same length prefix on responses.
//! Compression (for example snappy) is applied outside this layer.

const std = @import("std");
const varint = @import("../varint.zig");

pub const max_rpc_message_size: usize = 4 * 1024 * 1024;

pub const FrameError = error{
    EmptyFrame,
    PayloadTooLarge,
    Incomplete,
} || varint.DecodeError;

pub fn parseRequestHeader(bytes: []const u8) FrameError!struct { declared_len: usize, payload: []const u8 } {
    if (bytes.len == 0) return error.EmptyFrame;
    const dec = try varint.decode(bytes);
    if (dec.value > max_rpc_message_size) return error.PayloadTooLarge;
    return .{
        .declared_len = dec.value,
        .payload = bytes[dec.len..],
    };
}

pub fn parseResponseHeader(bytes: []const u8) FrameError!struct { code: u8, declared_len: usize, payload: []const u8 } {
    if (bytes.len == 0) return error.EmptyFrame;
    if (bytes.len == 1) return error.Incomplete;
    const code = bytes[0];
    const dec = try varint.decode(bytes[1..]);
    if (dec.value > max_rpc_message_size) return error.PayloadTooLarge;
    return .{
        .code = code,
        .declared_len = dec.value,
        .payload = bytes[1 + dec.len ..],
    };
}

pub fn appendRequestPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator, uncompressed_len: usize) !void {
    if (uncompressed_len > max_rpc_message_size) return error.PayloadTooLarge;
    var scratch: [varint.max_encoding_bytes]u8 = undefined;
    const enc = varint.encodeToScratch(&scratch, uncompressed_len);
    try list.appendSlice(allocator, enc);
}

pub fn appendResponsePrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator, code: u8, uncompressed_len: usize) !void {
    if (uncompressed_len > max_rpc_message_size) return error.PayloadTooLarge;
    try list.append(allocator, code);
    var scratch: [varint.max_encoding_bytes]u8 = undefined;
    const enc = varint.encodeToScratch(&scratch, uncompressed_len);
    try list.appendSlice(allocator, enc);
}

test "request header round trip prefix" {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(std.testing.allocator);
    try appendRequestPrefix(&buf, std.testing.allocator, 42);
    try buf.appendSlice(std.testing.allocator, "payload-here");
    const h = try parseRequestHeader(buf.items);
    try std.testing.expectEqual(@as(usize, 42), h.declared_len);
    try std.testing.expectEqualStrings("payload-here", h.payload);
}

test "response header with code" {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(std.testing.allocator);
    try appendResponsePrefix(&buf, std.testing.allocator, 0, 5);
    try buf.appendSlice(std.testing.allocator, "hello");
    const h = try parseResponseHeader(buf.items);
    try std.testing.expectEqual(@as(u8, 0), h.code);
    try std.testing.expectEqual(@as(usize, 5), h.declared_len);
    try std.testing.expectEqualStrings("hello", h.payload);
}
