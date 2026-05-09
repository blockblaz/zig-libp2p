//! Encode and decode unsigned varints (protobuf / req/resp length style).

const std = @import("std");
const zl = @import("zig_libp2p");

pub fn main() !void {
    var scratch: [zl.varint.max_encoding_bytes]u8 = undefined;
    const value: usize = 300;
    const enc = zl.varint.encodeToScratch(&scratch, value);
    const dec = try zl.varint.decode(enc);
    std.debug.print("{d} encodes to {d} bytes, decodes back to {d}\n", .{ value, enc.len, dec.value });
}
