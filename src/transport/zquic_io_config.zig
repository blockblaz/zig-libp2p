//! Opinionated [zquic](https://github.com/ch4r10t33r/zquic) `ServerConfig` / `ClientConfig` presets for libp2p-over-QUIC.
//!
//! Sets TLS ALPN to `transport.quic_v1.tls_alpn` and enables `raw_application_streams` so STREAM
//! data is surfaced for multistream-select (see `transport.multistream_negotiate`).

const std = @import("std");
const zquic = @import("zquic");
const io = zquic.transport.io;
const quic_v1 = @import("quic_v1.zig");

/// Server preset: PEM cert/key, libp2p ALPN, raw app streams (no HTTP/0.9 or HTTP/3).
pub fn serverConfigLibp2p(args: struct {
    port: u16,
    cert_path: []const u8,
    key_path: []const u8,
    max_udp_payload: ?u16 = null,
}) io.ServerConfig {
    return .{
        .port = args.port,
        .cert_path = args.cert_path,
        .key_path = args.key_path,
        .alpn = quic_v1.tls_alpn,
        .raw_application_streams = true,
        .http09 = false,
        .http3 = false,
        .max_udp_payload = args.max_udp_payload,
    };
}

/// Client preset: `host` is used for SNI and UDP connect; must be non-empty for typical TLS stacks.
pub fn clientConfigLibp2p(args: struct {
    host: []const u8,
    port: u16,
    max_udp_payload: ?u16 = null,
}) io.ClientConfig {
    return .{
        .host = args.host,
        .port = args.port,
        .alpn = quic_v1.tls_alpn,
        .raw_application_streams = true,
        .http09 = false,
        .http3 = false,
        .max_udp_payload = args.max_udp_payload,
    };
}

test "libp2p server config uses libp2p alpn and raw streams" {
    const c = serverConfigLibp2p(.{ .port = 4001, .cert_path = "/tmp/cert.pem", .key_path = "/tmp/key.pem" });
    try std.testing.expectEqualStrings(quic_v1.tls_alpn, c.alpn.?);
    try std.testing.expect(c.raw_application_streams);
    try std.testing.expect(!c.http09);
    try std.testing.expect(!c.http3);
}

test "libp2p client config uses libp2p alpn and raw streams" {
    const c = clientConfigLibp2p(.{ .host = "127.0.0.1", .port = 4001 });
    try std.testing.expectEqualStrings(quic_v1.tls_alpn, c.alpn.?);
    try std.testing.expect(c.raw_application_streams);
    try std.testing.expect(!c.http09);
    try std.testing.expect(!c.http3);
}
