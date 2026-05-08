//! libp2p ping 1.0.0 (`/ipfs/ping/1.0.0`) used for RTT and keepalive on streams.

const std = @import("std");

/// Multistream negotiation line including newline.
pub const protocol_line: []const u8 = "/ipfs/ping/1.0.0\n";

/// Payload size for each ping or pong datagram on the stream.
pub const payload_len: usize = 32;

test "protocol_line ends with newline" {
    try std.testing.expect(std.mem.endsWith(u8, protocol_line, "\n"));
}
