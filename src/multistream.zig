//! libp2p multistream-select 1.0.0 line framing (`\n` delimiters on the wire).

const std = @import("std");

/// Multistream protocol id including the mandatory newline terminator.
pub const multistream_1_0_0: []const u8 = "/multistream/1.0.0\n";

/// Writes a protocol id followed by `\n` (multistream-select negotiation line).
pub fn writeProtocolLine(protocol_id: []const u8, writer: anytype) @TypeOf(writer).Error!void {
    try writer.writeAll(protocol_id);
    try writer.writeByte('\n');
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
