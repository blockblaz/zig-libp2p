//! Length-prefixed req/resp framing: varint length field on requests,
//! single-byte response code then the same length field on responses.
//!
//! On Lean consensus libp2p streams (`…/ssz_snappy`), the varint is the
//! **uncompressed SSZ size**; the bytes after the header are snappy-framed
//! payload whose wire length may differ. For fixed-size raw bodies, see
//! `req_resp.stream.scanCompleteRequest`.

const std = @import("std");
const varint = @import("../varint.zig");
const errors = @import("../errors.zig");

pub const max_rpc_message_size: usize = 4 * 1024 * 1024;

/// Back-compat alias; use [`errors.ReqRespError`] in new code.
pub const FrameError = errors.ReqRespError;

pub fn parseRequestHeader(bytes: []const u8) FrameError!struct { declared_len: usize, payload: []const u8 } {
    if (bytes.len == 0) return error.EmptyFrame;
    const dec = varint.decode(bytes) catch |err| switch (err) {
        error.Truncated => return error.IncompleteStream,
        error.Overflow, error.TooLong, error.NonMinimal => return error.VarintOverflow,
    };
    if (dec.value > max_rpc_message_size) return error.PayloadTooLarge;
    return .{
        .declared_len = dec.value,
        .payload = bytes[dec.len..],
    };
}

pub fn parseResponseHeader(bytes: []const u8) FrameError!struct { code: u8, declared_len: usize, payload: []const u8 } {
    if (bytes.len == 0) return error.EmptyFrame;
    if (bytes.len == 1) return error.IncompleteStream;
    const code = bytes[0];
    const dec = varint.decode(bytes[1..]) catch |err| switch (err) {
        error.Truncated => return error.IncompleteStream,
        error.Overflow, error.TooLong, error.NonMinimal => return error.VarintOverflow,
    };
    if (dec.value > max_rpc_message_size) return error.PayloadTooLarge;
    return .{
        .code = code,
        .declared_len = dec.value,
        .payload = bytes[1 + dec.len ..],
    };
}

pub fn appendRequestPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator, uncompressed_len: usize) (FrameError || std.mem.Allocator.Error)!void {
    if (uncompressed_len > max_rpc_message_size) return error.PayloadTooLarge;
    var scratch: [varint.max_encoding_bytes]u8 = undefined;
    const enc = varint.encodeToScratch(&scratch, uncompressed_len);
    try list.appendSlice(allocator, enc);
}

pub fn appendResponsePrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator, code: u8, uncompressed_len: usize) (FrameError || std.mem.Allocator.Error)!void {
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

test "request header accepts declared len at max_rpc_message_size" {
    var scratch: [varint.max_encoding_bytes]u8 = undefined;
    const enc = varint.encodeToScratch(&scratch, max_rpc_message_size);
    const h = try parseRequestHeader(enc);
    try std.testing.expectEqual(max_rpc_message_size, h.declared_len);
    try std.testing.expectEqual(@as(usize, 0), h.payload.len);
}

test "request header rejects declared len one over max" {
    var scratch: [varint.max_encoding_bytes]u8 = undefined;
    const enc = varint.encodeToScratch(&scratch, max_rpc_message_size + 1);
    try std.testing.expectError(error.PayloadTooLarge, parseRequestHeader(enc));
}

test "response header rejects declared len one over max" {
    var scratch: [varint.max_encoding_bytes]u8 = undefined;
    const enc = varint.encodeToScratch(&scratch, max_rpc_message_size + 1);
    var buf: [1 + varint.max_encoding_bytes]u8 = undefined;
    buf[0] = 0;
    @memcpy(buf[1..][0..enc.len], enc);
    try std.testing.expectError(error.PayloadTooLarge, parseResponseHeader(buf[0 .. 1 + enc.len]));
}
