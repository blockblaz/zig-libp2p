//! Peer identity types from the bundled [`peer-id`](https://github.com/blockblaz/peer-id) package
//! (same revision as `multiaddr-zig`). Re-exported at `zig_libp2p.peer_id` as well.

const std = @import("std");
const pid = @import("peer_id");

pub const PeerId = pid.PeerId;
pub const ParseError = pid.id.ParseError;

test "PeerId random bytes round trip" {
    const id = try PeerId.random();
    var buf: [128]u8 = undefined;
    const wire = try id.toBytes(&buf);
    const id2 = try PeerId.fromBytes(wire);
    try std.testing.expect(id.eql(&id2));
}

test "PeerId fromString spec vector (base58)" {
    const a = std.testing.allocator;
    const s = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";
    const id = try PeerId.fromString(a, s);
    var b58_buf: [128]u8 = undefined;
    const out = try id.toBase58(&b58_buf);
    try std.testing.expectEqualStrings(s, out);
}
