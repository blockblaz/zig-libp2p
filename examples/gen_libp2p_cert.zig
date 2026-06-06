//! Generate a libp2p-compatible TLS cert + key for the QUIC interop endpoint.
//!
//! Mints an ECDSA-P-256 host identity, builds a self-signed X.509 cert
//! carrying the libp2p TLS extension (RFC 0001) over a matching P-256
//! cert keypair, writes both as PEM to the paths in CERT_PATH / KEY_PATH.
//!
//! Replaces the openssl-generated vanilla self-signed cert that Phase B1
//! shipped — go-libp2p verifies the libp2p extension on the wire, so
//! cross-impl interop requires this.
//!
//! Environment:
//!   CERT_PATH      — output cert PEM path (default /certs/cert.pem)
//!   KEY_PATH       — output key PEM path  (default /certs/key.pem)
//!   SEED_HEX       — optional 32-byte hex; deterministic identity when set.
//!                    Default = OS random.
//!   PEER_ID_PATH   — optional path: when set, host peer-id (base58btc) is
//!                    written here for the matrix runner to share with the
//!                    dialing side (REMOTE_PEER_ID).
//!
//! Stdout: always prints `gen_libp2p_cert: peer_id=<base58btc>` for ad-hoc
//! capture in shell scripts (`PEER_ID=$(./gen-libp2p-cert | awk -F= …)`).

const std = @import("std");
const zl = @import("zig_libp2p");

const libp2p_tls_cert = zl.security.libp2p_tls_cert;
const peer_id_mod = zl.peer_id;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

fn getEnv(key: []const u8) ?[]const u8 {
    var buf: [256]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{key}) catch return null;
    const c_ptr = std.c.getenv(z.ptr) orelse return null;
    return std.mem.span(c_ptr);
}

fn envOr(key: []const u8, fallback: []const u8) []const u8 {
    return getEnv(key) orelse fallback;
}

fn fillRandom(out: []u8) !void {
    const builtin = @import("builtin");
    switch (builtin.os.tag) {
        .linux => {
            var off: usize = 0;
            while (off < out.len) {
                const rc = std.os.linux.getrandom(out.ptr + off, out.len - off, 0);
                if (@as(isize, @bitCast(rc)) < 0) return error.NoEntropy;
                off += @intCast(rc);
            }
        },
        else => {
            if (@TypeOf(std.c.arc4random_buf) == void) return error.NoEntropy;
            std.c.arc4random_buf(out.ptr, out.len);
        },
    }
}

fn parseSeed(hex_str: []const u8, out: *[32]u8) !void {
    if (hex_str.len != 64) return error.BadSeedLen;
    _ = try std.fmt.hexToBytes(out, hex_str);
}

pub fn main() !u8 {
    const a = std.heap.page_allocator;

    const cert_path = envOr("CERT_PATH", "/certs/cert.pem");
    const key_path = envOr("KEY_PATH", "/certs/key.pem");

    var host_seed: [32]u8 = undefined;
    if (getEnv("SEED_HEX")) |s| {
        try parseSeed(s, &host_seed);
    } else {
        try fillRandom(&host_seed);
    }
    var cert_seed: [32]u8 = undefined;
    try fillRandom(&cert_seed);

    // ECDSA-P-256 host identity.  Same algorithm as the cert keypair so
    // libp2p_tls_cert.generate's `ecdsa_p256` arm fires.
    const host_kp = try EcdsaP256.KeyPair.generateDeterministic(host_seed);
    const host_pub: [65]u8 = host_kp.public_key.toUncompressedSec1();

    const HostSigner = struct {
        kp: EcdsaP256.KeyPair,
        fn sign(ctx: ?*anyopaque, message: []const u8, out_sig: []u8, out_sig_len: *usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            const sig = try self.kp.sign(message, null);
            const Sig = @TypeOf(sig);
            var der_buf: [Sig.der_encoded_length_max]u8 = undefined;
            const der = sig.toDer(&der_buf);
            if (der.len > out_sig.len) return error.SignBufferTooSmall;
            @memcpy(out_sig[0..der.len], der);
            out_sig_len.* = der.len;
        }
    };
    var signer = HostSigner{ .kp = host_kp };

    const now_sec = @divTrunc(zl.wall_time.milliTimestamp(), 1000);
    var gen = try libp2p_tls_cert.generate(a, .{
        .host_identity = .{
            .ecdsa_p256 = .{
                .public_key_sec1_uncompressed = host_pub,
                .sign = HostSigner.sign,
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

    // Make parent dirs and write.
    try ensureParentDir(cert_path);
    try ensureParentDir(key_path);
    try writeFile(cert_path, cert_pem);
    try writeFile(key_path, key_pem);

    // Derive PeerId from the ECDSA-P-256 host pubkey via the protobuf
    // PublicKey { type=ECDSA, data=PKIX-SPKI } encoding (RFC 0001 spec).
    const pk_proto = try libp2p_tls_cert.encodeEcdsaPublicKeyProto(a, host_pub);
    defer a.free(pk_proto);
    const reader = try peer_id_mod.PublicKeyReader.init(pk_proto);
    const data_copy = try a.dupe(u8, reader.getData());
    defer a.free(data_copy);
    var pk = peer_id_mod.PublicKey{ .type = .ECDSA, .data = data_copy };
    const pid = try peer_id_mod.PeerId.fromPublicKey(a, &pk);
    var pid_buf: [128]u8 = undefined;
    const pid_b58 = try pid.toBase58(&pid_buf);

    if (getEnv("PEER_ID_PATH")) |p| {
        try ensureParentDir(p);
        try writeFile(p, pid_b58);
    }
    // Stdout line is the contract with shell runners — keep stable.
    std.debug.print("gen_libp2p_cert: peer_id={s}\n", .{pid_b58});
    std.debug.print("gen_libp2p_cert: wrote cert={s} key={s}\n", .{ cert_path, key_path });
    return 0;
}

// std 0.16 moved fs.cwd().createFile / makePath under an `Io` interface
// (see TODO in transport/quic_endpoint.zig). This binary is single-purpose
// (cert minting at container start) — use libc syscalls directly to avoid
// plumbing an Io.Threaded just for two writes.

fn ensureParentDir(path: []const u8) !void {
    const i = std.mem.lastIndexOfScalar(u8, path, '/') orelse return;
    const dir = path[0..i];
    if (dir.len == 0) return;
    // Walk path components, mkdir each (ignore EEXIST).
    var buf: [1024]u8 = undefined;
    var off: usize = 0;
    while (off < dir.len) {
        const slash = std.mem.indexOfScalarPos(u8, dir, off + 1, '/') orelse dir.len;
        const partial = dir[0..slash];
        if (partial.len + 1 > buf.len) return error.PathTooLong;
        @memcpy(buf[0..partial.len], partial);
        buf[partial.len] = 0;
        const z: [*:0]const u8 = @ptrCast(&buf[0]);
        const rc = std.c.mkdir(z, 0o755);
        if (rc != 0) {
            const errno = std.posix.errno(rc);
            if (errno != .EXIST) return error.MkdirFailed;
        }
        off = slash;
    }
}

fn writeFile(path: []const u8, bytes: []const u8) !void {
    var pbuf: [1024]u8 = undefined;
    const z = try std.fmt.bufPrintZ(&pbuf, "{s}", .{path});
    // O_WRONLY | O_CREAT | O_TRUNC
    const flags: std.c.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
    };
    const mode: std.c.mode_t = 0o644;
    const fd = std.c.open(z.ptr, flags, mode);
    if (fd < 0) return error.OpenFailed;
    defer _ = std.c.close(fd);
    var off: usize = 0;
    while (off < bytes.len) {
        const n = std.c.write(fd, bytes.ptr + off, bytes.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
}
