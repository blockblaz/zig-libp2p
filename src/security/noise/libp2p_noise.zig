//! libp2p Noise XX on a byte stream: 16-bit big-endian length frames, identity payloads, transport encryption.

const std = @import("std");
const pid = @import("peer_id");
const keypair = @import("../../keypair.zig");
const protocol = @import("protocol.zig");
const identity = @import("identity.zig");

pub const multistream_protocol_id: []const u8 = "/noise";

pub const Error = protocol.Error || identity.Error || error{FrameTooLarge} || std.Io.Reader.Error || std.Io.Writer.Error;

/// Read one Noise frame: 2-byte big-endian length, then body into `buf` (rejects `len > buf.len`).
pub fn readNoiseFrame(r: *std.Io.Reader, buf: []u8) Error![]const u8 {
    var hdr: [2]u8 = undefined;
    try r.readSliceAll(&hdr);
    const n = std.mem.readInt(u16, &hdr, .big);
    if (n > buf.len) return error.FrameTooLarge;
    try r.readSliceAll(buf[0..n]);
    return buf[0..n];
}

pub fn writeNoiseFrame(w: *std.Io.Writer, body: []const u8) Error!void {
    if (body.len > std.math.maxInt(u16)) return error.FrameTooLarge;
    var hdr: [2]u8 = undefined;
    std.mem.writeInt(u16, &hdr, @intCast(body.len), .big);
    try w.writeAll(&hdr);
    try w.writeAll(body);
}

pub const SecureChannel = struct {
    tx: protocol.CipherState,
    rx: protocol.CipherState,

    /// Encrypt `plaintext` (max `scratch.len - 16` bytes) and write one length-prefixed frame.
    pub fn writeTransport(self: *SecureChannel, w: *std.Io.Writer, plaintext: []const u8, scratch: []u8) Error!void {
        if (plaintext.len + 16 > scratch.len) return error.HandshakeBufferTooSmall;
        const ct = try self.tx.encryptTransport(plaintext, scratch);
        try writeNoiseFrame(w, ct);
        try w.flush();
    }

    /// Read one frame and decrypt into `plaintext_buf`.
    pub fn readTransport(self: *SecureChannel, r: *std.Io.Reader, ciphertext_buf: []u8, plaintext_buf: []u8) Error![]const u8 {
        const ct = try readNoiseFrame(r, ciphertext_buf);
        return self.rx.decryptTransport(ct, plaintext_buf);
    }
};

pub const HandshakeResult = struct {
    channel: SecureChannel,
    remote_peer_id: pid.PeerId,
};

/// Initiator: send m1, receive m2 (verify identity), send m3. Uses `scratch` for length-prefixed handshake read bodies (≤ capacity).
pub fn handshakeInitiator(
    allocator: std.mem.Allocator,
    io: std.Io,
    prologue: []const u8,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    host: keypair.KeyPair,
    noise_static: std.crypto.dh.X25519.KeyPair,
    stream_muxers: []const []const u8,
    expected_remote: ?pid.PeerId,
    scratch: []u8,
    payload_scratch: []u8,
    mux_list: *std.ArrayList([]const u8),
) Error!HandshakeResult {
    var hs = protocol.HandshakeXX.init(true, prologue, noise_static);
    var msg_buf: [8192]u8 = undefined;

    const m1 = try hs.writeMessage1(io, &[_]u8{}, &msg_buf);
    try writeNoiseFrame(w, m1);
    try w.flush();

    const m2 = try readNoiseFrame(r, scratch);
    const pl2 = try hs.readMessage2(m2, payload_scratch);
    const rs = hs.rs orelse return error.HandshakeOutOfOrder;
    const remote_id = try identity.verifySignedPayload(allocator, pl2, rs, expected_remote, 16 * 1024, mux_list);

    const pl3 = try identity.encodeSignedPayload(allocator, host, hs.s.public_key, stream_muxers);
    defer allocator.free(pl3);
    const m3 = try hs.writeMessage3(pl3, &msg_buf);
    try writeNoiseFrame(w, m3);
    try w.flush();

    const sp = try hs.splitInitiator();
    return .{
        .channel = .{ .tx = sp.tx, .rx = sp.rx },
        .remote_peer_id = remote_id,
    };
}

/// Responder: receive m1, send m2, receive m3 (verify identity).
pub fn handshakeResponder(
    allocator: std.mem.Allocator,
    io: std.Io,
    prologue: []const u8,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    host: keypair.KeyPair,
    noise_static: std.crypto.dh.X25519.KeyPair,
    stream_muxers: []const []const u8,
    expected_remote: ?pid.PeerId,
    scratch: []u8,
    payload_scratch: []u8,
    mux_list: *std.ArrayList([]const u8),
) Error!HandshakeResult {
    var hs = protocol.HandshakeXX.init(false, prologue, noise_static);
    var msg_buf: [8192]u8 = undefined;

    const m1 = try readNoiseFrame(r, scratch);
    _ = try hs.readMessage1(m1, payload_scratch);

    const pl2 = try identity.encodeSignedPayload(allocator, host, hs.s.public_key, stream_muxers);
    defer allocator.free(pl2);
    const m2 = try hs.writeMessage2(io, pl2, &msg_buf);
    try writeNoiseFrame(w, m2);
    try w.flush();

    const m3 = try readNoiseFrame(r, scratch);
    const pl3 = try hs.readMessage3(m3, payload_scratch);
    const rs = hs.rs orelse return error.HandshakeOutOfOrder;
    const remote_id = try identity.verifySignedPayload(allocator, pl3, rs, expected_remote, 16 * 1024, mux_list);

    const sp = try hs.splitResponder();
    return .{
        .channel = .{ .tx = sp.tx, .rx = sp.rx },
        .remote_peer_id = remote_id,
    };
}

test "noise length-prefixed frame round trip" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).empty;
    defer list.deinit(a);
    {
        var aw = std.Io.Writer.Allocating.fromArrayList(a, &list);
        defer list = aw.toArrayList();
        try writeNoiseFrame(&aw.writer, "hello-noise-frame");
    }
    var r = std.Io.Reader.fixed(list.items);
    var buf: [64]u8 = undefined;
    const got = try readNoiseFrame(&r, &buf);
    try std.testing.expectEqualStrings("hello-noise-frame", got);
}
