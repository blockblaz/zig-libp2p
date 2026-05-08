//! libp2p multistream-select 1.0.0 line framing (`\n` delimiters on the wire).

const std = @import("std");

/// Multistream protocol id including the mandatory newline terminator.
pub const multistream_1_0_0: []const u8 = "/multistream/1.0.0\n";

/// Default maximum length of the protocol id **body** (bytes before `\n`) for `writeProtocolLine`.
/// Matches `transport.multistream_negotiate.default_max_body_len` and typical libp2p stacks.
pub const max_protocol_id_body_bytes: usize = 1024;

pub const ProtocolLineError = error{ProtocolIdTooLong};

/// Writes `protocol_id` and `\n`, rejecting ids longer than `max_body_len` (DoS-safe for untrusted strings).
pub fn writeProtocolLineWithMax(
    protocol_id: []const u8,
    max_body_len: usize,
    writer: anytype,
) (ProtocolLineError || @TypeOf(writer).Error)!void {
    if (protocol_id.len > max_body_len) return error.ProtocolIdTooLong;
    try writer.writeAll(protocol_id);
    try writer.writeByte('\n');
}

/// Writes a protocol id followed by `\n` using `max_protocol_id_body_bytes`.
pub fn writeProtocolLine(protocol_id: []const u8, writer: anytype) (ProtocolLineError || @TypeOf(writer).Error)!void {
    return writeProtocolLineWithMax(protocol_id, max_protocol_id_body_bytes, writer);
}

/// Strips ASCII whitespace and CR around a received negotiation line.
pub fn trimNegotiationLine(line: []const u8) []const u8 {
    return std.mem.trim(u8, line, " \t\r\n");
}

test "multistream_1_0_0 ends with newline" {
    try std.testing.expect(std.mem.endsWith(u8, multistream_1_0_0, "\n"));
    try std.testing.expectEqualStrings("/multistream/1.0.0", multistream_1_0_0[0 .. multistream_1_0_0.len - 1]);
}

test "writeProtocolLine and trim" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);
    try writeProtocolLine("/foo/bar", list.writer(std.testing.allocator));
    try std.testing.expectEqualStrings("/foo/bar\n", list.items);
    try std.testing.expectEqualStrings("/foo/bar", trimNegotiationLine(list.items));
}

test "writeProtocolLine rejects oversized protocol id" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);
    const big = try std.testing.allocator.alloc(u8, max_protocol_id_body_bytes + 1);
    defer std.testing.allocator.free(big);
    @memset(big, 'a');
    try std.testing.expectError(
        error.ProtocolIdTooLong,
        writeProtocolLine(big, list.writer(std.testing.allocator)),
    );
}

test "writeProtocolLineWithMax allows custom cap" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);
    const s = try std.testing.allocator.alloc(u8, 8);
    defer std.testing.allocator.free(s);
    @memset(s, 'b');
    try writeProtocolLineWithMax(s, 8, list.writer(std.testing.allocator));
    try std.testing.expectEqual(@as(usize, 9), list.items.len);
}
