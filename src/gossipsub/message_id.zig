//! Gossipsub message ID used on the wire (#39). Must match zeam / rust-libp2p.

const std = @import("std");

/// Writes the 20-byte message id for `(topic, data)`.
///
/// `snappy_decompressed_ok` is `true` when the payload was successfully Snappy-decompressed
/// before hashing (domain `0x01000000`); otherwise domain `0x00000000`.
pub fn writeMessageId(topic: []const u8, data: []const u8, snappy_decompressed_ok: bool, out: *[20]u8) void {
    const domain: u32 = if (snappy_decompressed_ok) 0x01000000 else 0;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var be: [4]u8 = undefined;
    std.mem.writeInt(u32, &be, domain, .big);
    h.update(&be);
    std.mem.writeInt(u32, &be, @intCast(topic.len), .big);
    h.update(&be);
    h.update(topic);
    h.update(data);
    var full: [32]u8 = undefined;
    h.final(&full);
    @memcpy(out, full[0..20]);
}

test "message id matches zeam formula (golden vectors)" {
    var id: [20]u8 = undefined;

    writeMessageId("t", "d", true, &id);
    const exp_td_ok = [_]u8{
        0x14, 0xf8, 0xd4, 0x5b, 0x50, 0x52, 0x0f, 0x22, 0xda, 0x21,
        0x6c, 0x0e, 0xd4, 0x5a, 0x85, 0x1e, 0x38, 0xf5, 0xed, 0xc8,
    };
    try std.testing.expectEqualSlices(u8, &exp_td_ok, &id);

    writeMessageId("t", "d", false, &id);
    const exp_td_bad = [_]u8{
        0x01, 0xef, 0xa8, 0x37, 0xac, 0xa9, 0xe2, 0xbb, 0x18, 0xd5,
        0xc6, 0x3f, 0x60, 0x92, 0x4f, 0x95, 0x4a, 0x6f, 0xb6, 0x3c,
    };
    try std.testing.expectEqualSlices(u8, &exp_td_bad, &id);

    writeMessageId("", "", true, &id);
    const exp_empty = [_]u8{
        0x7c, 0x9f, 0xa1, 0x36, 0xd4, 0x41, 0x3f, 0xa6, 0x17, 0x36,
        0x37, 0xe8, 0x83, 0xb6, 0x99, 0x8d, 0x32, 0xe1, 0xd6, 0x75,
    };
    try std.testing.expectEqualSlices(u8, &exp_empty, &id);
}
