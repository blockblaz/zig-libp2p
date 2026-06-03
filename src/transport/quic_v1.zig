//! Libp2p QUIC v1 transport labels and **zquic** integration helpers.
//!
//! Multiaddr listen/dial helpers live in [`transport.quic`]. This module centralizes ALPN,
//! raw-stream presets, and multistream byte helpers. On zquic QUIC clients, the server leaf DER
//! is available from [`zquic.transport.io.Client.peerLeafCertificateDer`]; use
//! [`transport.quic_peer_identity.verifiedPeerIdFromLibp2pQuicClient`] or [`transport.quic_endpoint.dialExtended`]
//! (default verify) with [`security.libp2p_tls`].

const std = @import("std");
const zquic = @import("zquic");
const libp2p_tls = @import("../security/libp2p_tls.zig");
const neg = @import("multistream_negotiate.zig");
const sm = @import("stream_multistream.zig");

const Io = zquic.transport.io;

/// Multistream protocol id for the QUIC v1 transport.
pub const multistream_protocol_id: []const u8 = "/quic-v1";

/// TLS ALPN identifier for libp2p over QUIC after the QUIC handshake (see `security.libp2p_tls`).
pub const tls_alpn: []const u8 = libp2p_tls.quic_application_layer_protocol;

/// Options for [`libp2pZquicServerConfig`].
///
/// Supply either on-disk PEM (`cert_path` / `key_path`) or in-memory PEM
/// (`cert_pem` / `key_pem`); if both are set on a side, zquic prefers the
/// PEM bytes and skips the path-based loader (see zquic v1.6.6).
pub const Libp2pZquicServerOptions = struct {
    port: u16 = 4433,
    cert_path: []const u8 = "",
    key_path: []const u8 = "",
    /// In-memory PEM-encoded server certificate (chain). When non-null zquic
    /// parses these bytes and never reads `cert_path` from disk. Borrowed
    /// until the resulting `Io.Server` finishes loading its TLS material.
    cert_pem: ?[]const u8 = null,
    /// In-memory PEM-encoded server private key. Same precedence/lifetime
    /// rules as `cert_pem`.
    key_pem: ?[]const u8 = null,
    keylog_path: ?[]const u8 = null,
    qlog_dir: ?[]const u8 = null,
    cubic: bool = false,
    v2: bool = false,
};

/// [`Io.ServerConfig`] preset: TLS ALPN `libp2p`, raw application streams (no HTTP parsing).
/// Enables TLS `CertificateRequest` so dialers can present a client cert; zquic exposes the leaf via [`Io.serverConnPeerLeafCertificateDer`].
/// Use with `zquic.transport.io.Server.init` (or `initFromSocket`) for libp2p-over-QUIC listeners.
pub fn libp2pZquicServerConfig(options: Libp2pZquicServerOptions) Io.ServerConfig {
    return .{
        .port = options.port,
        .cert_path = options.cert_path,
        .key_path = options.key_path,
        .cert_pem = options.cert_pem,
        .key_pem = options.key_pem,
        .keylog_path = options.keylog_path,
        .qlog_dir = options.qlog_dir,
        .cubic = options.cubic,
        .v2 = options.v2,
        .http09 = false,
        .http3 = false,
        .alpn = tls_alpn,
        .raw_application_streams = true,
        .request_client_certificate = true,
    };
}

/// Options for [`libp2pZquicClientConfig`].
pub const Libp2pZquicClientOptions = struct {
    host: []const u8,
    port: u16 = 4433,
    keylog_path: ?[]const u8 = null,
    qlog_dir: ?[]const u8 = null,
    cubic: bool = false,
    v2: bool = false,
    /// Non-empty with [`client_key_path`]: send a client `Certificate` when the server requests one (#16).
    client_cert_path: []const u8 = "",
    client_key_path: []const u8 = "",
    /// In-memory PEM-encoded client certificate. When non-null zquic parses
    /// these bytes and never reads `client_cert_path` from disk (zquic
    /// v1.6.6).
    client_cert_pem: ?[]const u8 = null,
    /// In-memory PEM-encoded client private key. Same precedence/lifetime
    /// rules as `client_cert_pem`.
    client_key_pem: ?[]const u8 = null,
};

/// [`Io.ClientConfig`] preset matching [`libp2pZquicServerConfig`].
pub fn libp2pZquicClientConfig(options: Libp2pZquicClientOptions) Io.ClientConfig {
    return .{
        .host = options.host,
        .port = options.port,
        .keylog_path = options.keylog_path,
        .qlog_dir = options.qlog_dir,
        .cubic = options.cubic,
        .v2 = options.v2,
        .http09 = false,
        .http3 = false,
        .alpn = tls_alpn,
        .raw_application_streams = true,
        .client_cert_path = options.client_cert_path,
        .client_key_path = options.client_key_path,
        .client_cert_pem = options.client_cert_pem,
        .client_key_pem = options.client_key_pem,
    };
}

/// Append initiator multistream-select preamble for the first app bidi stream:
/// `/multistream/1.0.0\n` then `protocol_id\n` (e.g. `/meshsub/1.1.0` or [`multistream_protocol_id`]).
pub fn appendFirstBidiStreamInitiatorHandshake(
    write: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol_id: []const u8,
) (neg.NegotiateError || std.mem.Allocator.Error)!void {
    return sm.appendFirstStreamInitiatorHandshake(write, allocator, protocol_id);
}

test "quic-v1 identifiers" {
    try std.testing.expect(std.mem.startsWith(u8, multistream_protocol_id, "/"));
    try std.testing.expect(multistream_protocol_id.len > 1);
    try std.testing.expect(tls_alpn.len > 0);
}

test "libp2p zquic server config uses libp2p ALPN and raw streams" {
    const cfg = libp2pZquicServerConfig(.{
        .port = 4001,
        .cert_path = "/tmp/cert.pem",
        .key_path = "/tmp/key.pem",
    });
    try std.testing.expectEqualStrings(tls_alpn, cfg.alpn.?);
    try std.testing.expect(cfg.raw_application_streams);
    try std.testing.expect(cfg.request_client_certificate);
    try std.testing.expect(!cfg.http3);
    try std.testing.expect(!cfg.http09);
    try std.testing.expectEqual(@as(u16, 4001), cfg.port);
    try std.testing.expectEqualStrings("/tmp/cert.pem", cfg.cert_path);
    try std.testing.expectEqualStrings("libp2p", Io.serverTlsAlpn(&cfg).?);
}

test "libp2p zquic client config uses libp2p ALPN and raw streams" {
    const cfg = libp2pZquicClientConfig(.{ .host = "127.0.0.1", .port = 4001 });
    try std.testing.expectEqualStrings(tls_alpn, cfg.alpn.?);
    try std.testing.expect(cfg.raw_application_streams);
    try std.testing.expectEqualStrings("libp2p", Io.clientTlsAlpn(&cfg).?);
}

test "first bidi stream initiator handshake round trip with responder" {
    const a = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(a);
    try appendFirstBidiStreamInitiatorHandshake(&out, a, "/meshsub/1.1.0");

    var rem: []const u8 = out.items;
    try neg.responderReadMultistreamOffer(&rem, neg.default_max_body_len);
    const offered = try neg.responderReadProtocolOffer(&rem, neg.default_max_body_len);
    try std.testing.expectEqualStrings("/meshsub/1.1.0", offered);

    var reply = std.ArrayList(u8).empty;
    defer reply.deinit(a);
    // Real multistream-select responder sends the version header first, then the
    // acknowledged protocol line; previously the test omitted the header which
    // tripped `InvalidMultistreamVersion` once the test became reachable under
    // discovery (#chore/zig-0.16-drift-cleanup).
    try neg.responderSendMultistreamHeader(&reply, a);
    try neg.responderReplyProtocol(&reply, a, offered, "/meshsub/1.1.0");

    var ack: []const u8 = reply.items;
    try neg.initiatorReadPeerMultistream(&ack, neg.default_max_body_len);
    try neg.initiatorReadProtocolAck(&ack, "/meshsub/1.1.0", neg.default_max_body_len);
    try std.testing.expectEqual(@as(usize, 0), ack.len);
}
