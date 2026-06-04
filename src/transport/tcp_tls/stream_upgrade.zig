//! Multistream-select for [`libp2p_tls.multistream_protocol_id`] then TLS 1.3 (ALPN `libp2p`).
//!
//! Uses zquic's vendored stream TLS stack via the `zquic_tls` module (#86).

const std = @import("std");
const builtin = @import("builtin");
const pid = @import("peer_id");
const errors = @import("../../errors.zig");
const libp2p_tls = @import("../../security/libp2p_tls.zig");
const sm = @import("../stream_multistream.zig");
const zquic_tls = @import("zquic_tls");

const Io = std.Io;
const net = Io.net;
const Cipher = zquic_tls.Cipher;
const Record = zquic_tls.record.Record;
const tls_config = zquic_tls.config;
const CertKeyPair = tls_config.CertKeyPair;
const PrivateKey = tls_config.PrivateKey;
const Certificate = std.crypto.Certificate;

pub const input_buffer_len = zquic_tls.input_buffer_len;
pub const output_buffer_len = zquic_tls.output_buffer_len;

pub const UpgradeError = sm.StreamHandshakeError || libp2p_tls.QuicPeerIdentityError || error{
    TlsHandshakeFailed,
    TlsRecordOverflow,
    TlsIllegalParameter,
    TlsUnexpectedMessage,
    TlsDecryptError,
    TlsBadVersion,
    TlsBadSignatureScheme,
    TlsUnknownSignatureScheme,
    InvalidEncoding,
    MissingEndMarker,
    EndOfStream,
    ReadFailed,
    WriteFailed,
    InputBufferUndersize,
    FrameTooLarge,
};

/// Lossy map for embedders that only surface [`errors.TransportError`].
pub fn toTransportError(err: UpgradeError) (errors.TransportError || std.mem.Allocator.Error) {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.DialFailed => error.DialFailed,
        error.Unreachable => error.Unreachable,
        error.ProtocolNegotiationFailed => error.ProtocolNegotiationFailed,
        error.SecurityUpgradeFailed, error.TlsHandshakeFailed => error.SecurityUpgradeFailed,
        error.ReadFailed, error.WriteFailed => error.DialFailed,
        error.EndOfStream => error.DialFailed,
        else => error.SecurityUpgradeFailed,
    };
}

/// Heap-owned server/client authentication material for [`negotiateResponder`].
pub const OwnedCertKeyPair = struct {
    pair: CertKeyPair,

    pub fn deinit(self: *OwnedCertKeyPair, allocator: std.mem.Allocator) void {
        self.pair.deinit(allocator);
        self.* = undefined;
    }
};

/// Build a [`CertKeyPair`] from PEM blobs (libp2p self-signed leaf + EC PRIVATE KEY).
pub fn certKeyPairFromPem(
    allocator: std.mem.Allocator,
    cert_pem: []const u8,
    key_pem: []const u8,
    now_sec: i64,
) UpgradeError!OwnedCertKeyPair {
    const cert_der = try decodeFirstCertificateDerPem(allocator, cert_pem);
    defer allocator.free(cert_der);
    const key = PrivateKey.parsePem(key_pem) catch return error.TlsHandshakeFailed;
    var bundle: Certificate.Bundle = .empty;
    const start: u32 = @intCast(bundle.bytes.items.len);
    try bundle.bytes.appendSlice(allocator, cert_der);
    try bundle.parseCert(allocator, start, now_sec);
    return .{ .pair = .{ .bundle = bundle, .key = key } };
}

fn decodeFirstCertificateDerPem(allocator: std.mem.Allocator, pem: []const u8) UpgradeError![]u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end_m = "-----END CERTIFICATE-----";
    const bi = std.mem.indexOf(u8, pem, begin) orelse return error.TlsHandshakeFailed;
    const after = bi + begin.len;
    const ei = std.mem.indexOf(u8, pem[after..], end_m) orelse return error.TlsHandshakeFailed;
    const raw = pem[after .. after + ei];
    var b64 = std.ArrayList(u8).empty;
    defer b64.deinit(allocator);
    for (raw) |c| {
        if (c != '\n' and c != '\r' and c != ' ') try b64.append(allocator, c);
    }
    const decoder = std.base64.standard.Decoder;
    const der_len = decoder.calcSizeForSlice(b64.items) catch return error.TlsHandshakeFailed;
    const der = try allocator.alloc(u8, der_len);
    decoder.decode(der, b64.items) catch {
        allocator.free(der);
        return error.TlsHandshakeFailed;
    };
    return der;
}

fn driveNonblockHandshake(
    nb: anytype,
    r: *Io.Reader,
    w: *Io.Writer,
    allocator: std.mem.Allocator,
    send_buf: []u8,
) UpgradeError!void {
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(allocator);

    while (!nb.done()) {
        const res = nb.run(acc.items, send_buf) catch return error.TlsHandshakeFailed;
        if (res.recv_pos > 0) {
            try acc.replaceRange(allocator, 0, res.recv_pos, &.{});
        }
        if (res.send.len > 0) {
            try w.writeAll(res.send);
            try w.flush();
        }
        if (!nb.done() and res.recv_pos == 0) {
            var chunk: [4096]u8 = undefined;
            const n = r.readSliceShort(&chunk) catch return error.ReadFailed;
            if (n == 0) return error.EndOfStream;
            try acc.appendSlice(allocator, chunk[0..n]);
        }
    }
}

/// TLS 1.3 application data over an established [`Cipher`].
pub const SecureChannel = struct {
    cipher: Cipher,
    recv_acc: std.ArrayList(u8),

    pub fn deinit(self: *SecureChannel, allocator: std.mem.Allocator) void {
        self.recv_acc.deinit(allocator);
        self.* = undefined;
    }

    pub fn write(self: *SecureChannel, w: *Io.Writer, plaintext: []const u8, scratch: []u8) UpgradeError!void {
        if (plaintext.len > scratch.len - 256) return error.FrameTooLarge;
        const ct = self.cipher.encrypt(scratch, .application_data, plaintext) catch return error.TlsHandshakeFailed;
        var hdr: [5]u8 = undefined;
        hdr[0] = @intFromEnum(zquic_tls.protocol.ContentType.application_data);
        std.mem.writeInt(u16, hdr[1..3], 0x0303, .big);
        std.mem.writeInt(u16, hdr[3..5], @intCast(ct.len), .big);
        try w.writeAll(&hdr);
        try w.writeAll(ct);
        try w.flush();
    }

    pub fn read(
        self: *SecureChannel,
        r: *Io.Reader,
        allocator: std.mem.Allocator,
        ciphertext_buf: []u8,
        plaintext_buf: []u8,
    ) UpgradeError![]const u8 {
        while (true) {
            var fr = Io.Reader.fixed(self.recv_acc.items);
            const rec = Record.read(&fr) catch |e| switch (e) {
                error.InputBufferUndersize, error.EndOfStream => {
                    var chunk: [4096]u8 = undefined;
                    const n = r.readSliceShort(&chunk) catch return error.ReadFailed;
                    if (n == 0) return error.EndOfStream;
                    try self.recv_acc.appendSlice(allocator, chunk[0..n]);
                    continue;
                },
                else => return e,
            };
            const consumed = fr.seek;
            try self.recv_acc.replaceRange(allocator, 0, consumed, &.{});

            const content_type, const cleartext = self.cipher.decrypt(plaintext_buf, rec) catch return error.TlsDecryptError;
            if (content_type != .application_data) continue;
            if (cleartext.len > ciphertext_buf.len) return error.FrameTooLarge;
            return cleartext;
        }
    }
};

pub const HandshakeResult = struct {
    channel: SecureChannel,
    /// Set on the TLS client after libp2p cert verification; optional on the server when the peer sends no client cert.
    remote_peer_id: ?pid.PeerId = null,
};

/// Initiator: multistream `/tls/1.0.0`, TLS 1.3 + libp2p cert verification.
pub fn negotiateInitiator(
    allocator: std.mem.Allocator,
    r: *Io.Reader,
    w: *Io.Writer,
    now_sec: i64,
    expected_remote: ?pid.PeerId,
) UpgradeError!HandshakeResult {
    try sm.initiatorHandshakeMultistream(r, w, libp2p_tls.multistream_protocol_id, allocator);

    var send_buf: [output_buffer_len]u8 = undefined;
    var nb = zquic_tls.nonblock.Client.init(.{
        .host = "libp2p",
        .root_ca = Certificate.Bundle.empty,
        .insecure_skip_verify = true,
        .alpn = libp2p_tls.quic_application_layer_protocol,
        .cipher_suites = &[_]tls_config.CipherSuite{.CHACHA20_POLY1305_SHA256},
        .named_groups = &[_]zquic_tls.protocol.NamedGroup{.x25519},
    });
    try driveNonblockHandshake(&nb, r, w, allocator, &send_buf);

    const cipher = nb.cipher() orelse return error.TlsHandshakeFailed;
    const leaf = nb.peerLeafCertificateDer();
    if (leaf.len == 0) return error.TlsHandshakeFailed;
    const remote = try libp2p_tls.verifiedPeerIdFromQuicLeafCertificate(allocator, leaf, expected_remote, now_sec);

    return .{
        .channel = .{
            .cipher = cipher,
            .recv_acc = std.ArrayList(u8).empty,
        },
        .remote_peer_id = remote,
    };
}

/// Responder: multistream `/tls/1.0.0`, TLS 1.3 with libp2p server cert.
pub fn negotiateResponder(
    allocator: std.mem.Allocator,
    r: *Io.Reader,
    w: *Io.Writer,
    auth: *CertKeyPair,
    now_sec: i64,
    expected_remote: ?pid.PeerId,
) UpgradeError!HandshakeResult {
    try sm.responderHandshakeMultistream(r, w, libp2p_tls.multistream_protocol_id, allocator);

    var send_buf: [output_buffer_len]u8 = undefined;
    var nb = zquic_tls.nonblock.Server.init(.{
        .auth = auth,
        .alpn = libp2p_tls.quic_application_layer_protocol,
    });
    try driveNonblockHandshake(&nb, r, w, allocator, &send_buf);

    const cipher = nb.cipher() orelse return error.TlsHandshakeFailed;

    _ = expected_remote;
    _ = now_sec;
    return .{
        .channel = .{
            .cipher = cipher,
            .recv_acc = std.ArrayList(u8).empty,
        },
        .remote_peer_id = null,
    };
}

test "/tls/1.0.0 protocol id valid for multistream-select" {
    const neg = @import("../multistream_negotiate.zig");
    try std.testing.expectEqualStrings("/tls/1.0.0", libp2p_tls.multistream_protocol_id);
    try neg.validateProtocolId(libp2p_tls.multistream_protocol_id);
}

fn skipDarwinTcpLoopbackTls() bool {
    return switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos => true,
        else => false,
    };
}

test "TLS 1.3 + multistream over TCP loopback" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;
    if (skipDarwinTcpLoopbackTls()) return error.SkipZigTest;
    // GH Actions sets CI=1; Linux runners hang on Io.Threaded + parallel accept/dial.
    if (std.process.hasEnvVar("CI")) return error.SkipZigTest;

    const a = std.testing.allocator;
    var io_impl = Io.Threaded.init(a, .{ .async_limit = Io.Limit.limited(8) });
    defer io_impl.deinit();
    const io = io_impl.io();

    const libp2p_tls_cert = @import("../../security/libp2p_tls_cert.zig");
    const peer_id_pkg = @import("peer_id");
    const tcp = @import("../tcp.zig");
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    const TestEcdsaHostSigner = struct {
        kp: EcdsaP256.KeyPair,
        fn sign(ctx: ?*anyopaque, message: []const u8, out_sig: []u8, out_sig_len: *usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            const sig = try self.kp.sign(message, null);
            var buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
            const der = sig.toDer(&buf);
            if (der.len > out_sig.len) return error.NoSpaceLeft;
            @memcpy(out_sig[0..der.len], der);
            out_sig_len.* = der.len;
        }
    };

    const host_seed = [_]u8{0x5a} ** 32;
    const cert_seed = [_]u8{0x5b} ** 32;
    const host_kp = try EcdsaP256.KeyPair.generateDeterministic(host_seed);
    var signer = TestEcdsaHostSigner{ .kp = host_kp };
    const host_pub_sec1: [65]u8 = host_kp.public_key.toUncompressedSec1();
    const wall_time = @import("../../wall_time.zig");
    const now_sec = @divTrunc(wall_time.milliTimestamp(), 1000);

    var gen = try libp2p_tls_cert.generate(a, .{
        .host_identity = .{
            .ecdsa_p256 = .{
                .public_key_sec1_uncompressed = host_pub_sec1,
                .sign = TestEcdsaHostSigner.sign,
                .sign_ctx = &signer,
            },
        },
        .not_before_sec = now_sec - 3600,
        .not_after_sec = now_sec + 365 * 24 * 3600,
        .cert_key_seed = cert_seed,
    });
    defer gen.deinit(a);

    const cert_pem = try libp2p_tls_cert.certDerToPem(a, gen.cert_der);
    defer a.free(cert_pem);
    const key_pem = try libp2p_tls_cert.ecdsaP256SeedToPem(a, gen.cert_key_seed);
    defer a.free(key_pem);

    var owned = try certKeyPairFromPem(a, cert_pem, key_pem, now_sec);
    defer owned.deinit(a);

    const host_pub_proto = try libp2p_tls_cert.encodeEcdsaPublicKeyProto(a, host_pub_sec1);
    defer a.free(host_pub_proto);
    const reader = try peer_id_pkg.PublicKeyReader.init(host_pub_proto);
    var host_pk = peer_id_pkg.PublicKey{ .type = .ECDSA, .data = reader.getData() };
    const expected_remote = try peer_id_pkg.PeerId.fromPublicKey(a, &host_pk);

    var bind_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    var server = try tcp.listen(&bind_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const Server = struct {
        fn run(
            srv: *net.Server,
            io_inner: Io,
            auth: *CertKeyPair,
            now: i64,
        ) void {
            const st = tcp.acceptTuned(srv, io_inner, .{}) catch return;
            defer st.close(io_inner);
            var scratch_r: [65536]u8 = undefined;
            var scratch_w: [65536]u8 = undefined;
            var r = net.Stream.reader(st, io_inner, &scratch_r);
            var w = net.Stream.writer(st, io_inner, &scratch_w);
            var hs = negotiateResponder(a, &r.interface, &w.interface, auth, now, null) catch return;
            defer hs.channel.deinit(a);
            var ct_buf: [input_buffer_len]u8 = undefined;
            var pt_buf: [4096]u8 = undefined;
            const plain = hs.channel.read(&r.interface, a, &ct_buf, &pt_buf) catch return;
            if (!std.mem.eql(u8, plain, "tls-payload")) return;
        }
    };

    const thr = try std.Thread.spawn(.{}, Server.run, .{ &server, io, &owned.pair, now_sec });
    defer thr.join();

    const connect_addr: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    var client = try tcp.dial(&connect_addr, io, .{});
    defer client.close(io);

    var scratch_r: [65536]u8 = undefined;
    var scratch_w: [65536]u8 = undefined;
    var r = net.Stream.reader(client, io, &scratch_r);
    var w = net.Stream.writer(client, io, &scratch_w);

    var hs = try negotiateInitiator(a, &r.interface, &w.interface, now_sec, expected_remote);
    defer hs.channel.deinit(a);
    const remote = hs.remote_peer_id orelse return error.TestExpectedEqual;
    try std.testing.expect(remote.eql(&expected_remote));

    var wscratch: [output_buffer_len]u8 = undefined;
    try hs.channel.write(&w.interface, "tls-payload", &wscratch);
}
