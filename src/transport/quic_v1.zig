//! Libp2p QUIC transport labels used with multistream and TLS.

const std = @import("std");

/// Multistream protocol id for the QUIC v1 transport.
pub const multistream_protocol_id: []const u8 = "/quic-v1";

/// TLS ALPN identifier for libp2p over QUIC after the QUIC handshake.
pub const tls_alpn: []const u8 = "libp2p";

test "quic-v1 identifiers" {
    try std.testing.expect(std.mem.startsWith(u8, multistream_protocol_id, "/"));
    try std.testing.expect(multistream_protocol_id.len > 1);
    try std.testing.expect(tls_alpn.len > 0);
}
