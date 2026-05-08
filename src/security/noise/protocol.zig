//! Noise `Noise_XX_25519_ChaChaPoly_SHA256` — symmetric primitives + XX handshake (Noise spec rev34).

const std = @import("std");
const crypto = std.crypto;
const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.hmac.sha2.HmacSha256;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = crypto.dh.X25519;

pub const protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
pub const hash_len: usize = Sha256.digest_length;
pub const dh_len: usize = X25519.public_length;

pub const Error = error{
    HandshakeOutOfOrder,
    HandshakeBufferTooSmall,
    HandshakeSizeMismatch,
    NonceExhausted,
    DhFailed,
    DecryptFailed,
    SplitAlreadyDone,
};

fn hmacSha256(key: []const u8, msg: []const u8, out: *[hash_len]u8) void {
    HmacSha256.create(out, msg, key);
}

/// Noise HKDF with `num_outputs == 2` (new chaining key + cipher material).
fn hkdf2(ck: [hash_len]u8, ikm: []const u8, out1: *[hash_len]u8, out2: *[hash_len]u8) void {
    var temp_key: [hash_len]u8 = undefined;
    hmacSha256(&ck, ikm, &temp_key);
    hmacSha256(&temp_key, &[_]u8{0x01}, out1);
    var buf: [hash_len + 1]u8 = undefined;
    @memcpy(buf[0..hash_len], out1);
    buf[hash_len] = 0x02;
    hmacSha256(&temp_key, buf[0 .. hash_len + 1], out2);
}

/// Noise HKDF with `num_outputs == 3` (used by `Split`).
fn hkdf2empty(ck: [hash_len]u8, out1: *[hash_len]u8, out2: *[hash_len]u8) void {
    hkdf2(ck, &[_]u8{}, out1, out2);
}

fn hashMix(h: *[hash_len]u8, data: []const u8) void {
    var st = Sha256.init(.{});
    st.update(h);
    st.update(data);
    st.final(h);
}

fn noiseNonce(n: u64) [12]u8 {
    var out: [12]u8 = [_]u8{0} ** 4;
    std.mem.writeInt(u64, out[4..][0..8], n, .little);
    return out;
}

pub const CipherState = struct {
    k: ?[32]u8 = null,
    n: u64 = 0,

    fn hasKey(self: *const CipherState) bool {
        return self.k != null;
    }

    fn initializeKey(self: *CipherState, key: [32]u8) void {
        self.k = key;
        self.n = 0;
    }

    fn encryptWithAd(
        self: *CipherState,
        ad: []const u8,
        plaintext: []const u8,
        buf: []u8,
    ) Error![]const u8 {
        if (self.k) |k| {
            if (self.n == std.math.maxInt(u64)) return error.NonceExhausted;
            const n = self.n;
            self.n += 1;
            if (buf.len < plaintext.len + 16) return error.HandshakeBufferTooSmall;
            const nonce = noiseNonce(n);
            ChaCha20Poly1305.encrypt(buf[0..plaintext.len], buf[plaintext.len..][0..16], plaintext, ad, nonce, k);
            return buf[0 .. plaintext.len + 16];
        }
        if (buf.len < plaintext.len) return error.HandshakeBufferTooSmall;
        @memcpy(buf[0..plaintext.len], plaintext);
        return buf[0..plaintext.len];
    }

    fn decryptWithAd(
        self: *CipherState,
        ad: []const u8,
        ciphertext: []const u8,
        buf: []u8,
    ) Error![]const u8 {
        if (self.k) |k| {
            if (self.n == std.math.maxInt(u64)) return error.NonceExhausted;
            if (ciphertext.len < 16) return error.DecryptFailed;
            const plen = ciphertext.len - 16;
            if (buf.len < plen) return error.HandshakeBufferTooSmall;
            const n = self.n;
            const nonce = noiseNonce(n);
            ChaCha20Poly1305.decrypt(buf[0..plen], ciphertext[0..plen], ciphertext[plen..].*, ad, nonce, k) catch {
                return error.DecryptFailed;
            };
            self.n += 1;
            return buf[0..plen];
        }
        if (buf.len < ciphertext.len) return error.HandshakeBufferTooSmall;
        @memcpy(buf[0..ciphertext.len], ciphertext);
        return buf[0..ciphertext.len];
    }

    /// Transport: encrypt with zero AD (libp2p wire message body).
    pub fn encryptTransport(self: *CipherState, plaintext: []const u8, buf: []u8) Error![]const u8 {
        return self.encryptWithAd(&[_]u8{}, plaintext, buf);
    }

    pub fn decryptTransport(self: *CipherState, ciphertext: []const u8, buf: []u8) Error![]const u8 {
        return self.decryptWithAd(&[_]u8{}, ciphertext, buf);
    }
};

pub const SymmetricState = struct {
    ck: [hash_len]u8,
    h: [hash_len]u8,
    cipher: CipherState,

    fn init(protocol: []const u8) SymmetricState {
        var h: [hash_len]u8 = undefined;
        if (protocol.len <= hash_len) {
            @memcpy(h[0..protocol.len], protocol);
            @memset(h[protocol.len..], 0);
        } else {
            Sha256.hash(protocol, &h, .{});
        }
        return .{
            .ck = h,
            .h = h,
            .cipher = .{},
        };
    }

    fn mixHash(self: *SymmetricState, data: []const u8) void {
        hashMix(&self.h, data);
    }

    fn mixKey(self: *SymmetricState, ikm: [dh_len]u8) void {
        var new_ck: [hash_len]u8 = undefined;
        var temp_k: [hash_len]u8 = undefined;
        hkdf2(self.ck, &ikm, &new_ck, &temp_k);
        self.ck = new_ck;
        self.cipher.initializeKey(temp_k);
    }

    fn encryptAndHash(self: *SymmetricState, plaintext: []const u8, buf: []u8) Error![]const u8 {
        const ct = try self.cipher.encryptWithAd(&self.h, plaintext, buf);
        hashMix(&self.h, ct);
        return ct;
    }

    fn decryptAndHash(self: *SymmetricState, ciphertext: []const u8, buf: []u8) Error![]const u8 {
        const pt = try self.cipher.decryptWithAd(&self.h, ciphertext, buf);
        hashMix(&self.h, ciphertext);
        return pt;
    }

    fn split(self: *SymmetricState) struct { c1: CipherState, c2: CipherState } {
        var k1: [hash_len]u8 = undefined;
        var k2: [hash_len]u8 = undefined;
        hkdf2empty(self.ck, &k1, &k2);
        var c1: CipherState = .{};
        c1.initializeKey(k1);
        var c2: CipherState = .{};
        c2.initializeKey(k2);
        return .{ .c1 = c1, .c2 = c2 };
    }
};

/// XX handshake (initiator/responder). After `finish*`, use `split` for transport keys.
pub const HandshakeXX = struct {
    sym: SymmetricState,
    initiator: bool,
    /// Local static Noise DH key.
    s: X25519.KeyPair,
    /// Local ephemeral (set after first local `e` token).
    e: ?X25519.KeyPair = null,
    /// Remote static (32-byte encoding).
    rs: ?[dh_len]u8 = null,
    /// Remote ephemeral.
    re: ?[dh_len]u8 = null,
    step: enum { start, after_msg1, after_msg2, done } = .start,

    pub fn init(initiator_side: bool, prologue: []const u8, static_keys: X25519.KeyPair) HandshakeXX {
        var sym = SymmetricState.init(protocol_name);
        sym.mixHash(prologue);
        return .{
            .sym = sym,
            .initiator = initiator_side,
            .s = static_keys,
        };
    }

    /// Initiator: build message `-> e` + payload. `buf` holds the full handshake message.
    pub fn writeMessage1(
        self: *HandshakeXX,
        io: std.Io,
        payload: []const u8,
        buf: []u8,
    ) Error![]const u8 {
        if (!self.initiator or self.step != .start) return error.HandshakeOutOfOrder;
        var w: usize = 0;
        const kp_e = X25519.KeyPair.generate(io);
        self.e = kp_e;
        @memcpy(buf[w..][0..dh_len], &kp_e.public_key);
        w += dh_len;
        self.sym.mixHash(&kp_e.public_key);
        const enc = try self.sym.encryptAndHash(payload, buf[w..]);
        w += enc.len;
        self.step = .after_msg1;
        return buf[0..w];
    }

    /// Responder: consume message 1.
    pub fn readMessage1(self: *HandshakeXX, message: []const u8, payload_buf: []u8) Error![]const u8 {
        if (self.initiator or self.step != .start) return error.HandshakeOutOfOrder;
        if (message.len < dh_len) return error.HandshakeSizeMismatch;
        const re_loc: [dh_len]u8 = message[0..dh_len].*;
        self.re = re_loc;
        self.sym.mixHash(message[0..dh_len]);
        const dec = try self.sym.decryptAndHash(message[dh_len..], payload_buf);
        self.step = .after_msg1;
        return dec;
    }

    /// Responder: build message `<- e, ee, s, es` + payload.
    pub fn writeMessage2(
        self: *HandshakeXX,
        io: std.Io,
        payload: []const u8,
        buf: []u8,
    ) Error![]const u8 {
        if (self.initiator or self.step != .after_msg1) return error.HandshakeOutOfOrder;
        var w: usize = 0;
        const kp_e = X25519.KeyPair.generate(io);
        self.e = kp_e;
        @memcpy(buf[w..][0..dh_len], &kp_e.public_key);
        w += dh_len;
        self.sym.mixHash(&kp_e.public_key);
        const re_k = self.re orelse return error.HandshakeOutOfOrder;
        const shared_ee = X25519.scalarmult(kp_e.secret_key, re_k) catch return error.DhFailed;
        self.sym.mixKey(shared_ee);
        const enc_s = try self.sym.encryptAndHash(&self.s.public_key, buf[w..]);
        w += enc_s.len;
        const rs_for_es = self.re orelse return error.HandshakeOutOfOrder;
        const shared_es = X25519.scalarmult(self.s.secret_key, rs_for_es) catch return error.DhFailed;
        self.sym.mixKey(shared_es);
        const enc_pl = try self.sym.encryptAndHash(payload, buf[w..]);
        w += enc_pl.len;
        self.step = .after_msg2;
        return buf[0..w];
    }

    /// Initiator: consume message 2.
    pub fn readMessage2(self: *HandshakeXX, message: []const u8, payload_buf: []u8) Error![]const u8 {
        if (!self.initiator or self.step != .after_msg1) return error.HandshakeOutOfOrder;
        if (message.len < dh_len) return error.HandshakeSizeMismatch;
        var off: usize = 0;
        var re_loc: [dh_len]u8 = message[off..][0..dh_len].*;
        self.re = re_loc;
        off += dh_len;
        self.sym.mixHash(&re_loc);
        const e_k = self.e orelse return error.HandshakeOutOfOrder;
        const shared_ee = X25519.scalarmult(e_k.secret_key, re_loc) catch return error.DhFailed;
        self.sym.mixKey(shared_ee);
        const need_s = if (self.sym.cipher.hasKey()) dh_len + 16 else dh_len;
        if (message.len < off + need_s) return error.HandshakeSizeMismatch;
        var rs_plain: [dh_len]u8 = undefined;
        const dec_s = try self.sym.decryptAndHash(message[off .. off + need_s], rs_plain[0..]);
        off += need_s;
        if (dec_s.len != dh_len) return error.DecryptFailed;
        self.rs = dec_s[0..dh_len].*;
        const rs_k = self.rs orelse return error.HandshakeOutOfOrder;
        const shared_es = X25519.scalarmult(e_k.secret_key, rs_k) catch return error.DhFailed;
        self.sym.mixKey(shared_es);
        const dec_payload = try self.sym.decryptAndHash(message[off..], payload_buf);
        self.step = .after_msg2;
        return dec_payload;
    }

    /// Initiator: build `-> s, se` + payload.
    pub fn writeMessage3(self: *HandshakeXX, payload: []const u8, buf: []u8) Error![]const u8 {
        if (!self.initiator or self.step != .after_msg2) return error.HandshakeOutOfOrder;
        var w: usize = 0;
        const enc_s = try self.sym.encryptAndHash(&self.s.public_key, buf[w..]);
        w += enc_s.len;
        const re_k = self.re orelse return error.HandshakeOutOfOrder;
        const shared_se = X25519.scalarmult(self.s.secret_key, re_k) catch return error.DhFailed;
        self.sym.mixKey(shared_se);
        const enc_pl = try self.sym.encryptAndHash(payload, buf[w..]);
        w += enc_pl.len;
        self.step = .done;
        return buf[0..w];
    }

    /// Responder: consume message 3.
    pub fn readMessage3(self: *HandshakeXX, message: []const u8, payload_buf: []u8) Error![]const u8 {
        if (self.initiator or self.step != .after_msg2) return error.HandshakeOutOfOrder;
        const need_s = if (self.sym.cipher.hasKey()) dh_len + 16 else dh_len;
        if (message.len < need_s) return error.HandshakeSizeMismatch;
        var off: usize = 0;
        var rs_plain: [dh_len]u8 = undefined;
        const dec_s = try self.sym.decryptAndHash(message[off..][0..need_s], rs_plain[0..]);
        off += need_s;
        if (dec_s.len != dh_len) return error.DecryptFailed;
        self.rs = dec_s[0..dh_len].*;
        const e_k = self.e orelse return error.HandshakeOutOfOrder;
        const rs_k = self.rs orelse return error.HandshakeOutOfOrder;
        const shared_se = X25519.scalarmult(e_k.secret_key, rs_k) catch return error.DhFailed;
        self.sym.mixKey(shared_se);
        const dec_payload = try self.sym.decryptAndHash(message[off..], payload_buf);
        self.step = .done;
        return dec_payload;
    }

    /// Initiator: `tx` encrypts to responder, `rx` decrypts from responder.
    pub fn splitInitiator(self: *HandshakeXX) Error!struct { tx: CipherState, rx: CipherState } {
        if (!self.initiator or self.step != .done) return error.HandshakeOutOfOrder;
        const sp = self.sym.split();
        return .{ .tx = sp.c1, .rx = sp.c2 };
    }

    /// Responder: `tx` encrypts to initiator, `rx` decrypts from initiator.
    pub fn splitResponder(self: *HandshakeXX) Error!struct { tx: CipherState, rx: CipherState } {
        if (self.initiator or self.step != .done) return error.HandshakeOutOfOrder;
        const sp = self.sym.split();
        return .{ .tx = sp.c2, .rx = sp.c1 };
    }
};

test "Noise XX handshake raw (empty payloads)" {
    var sk_l: [32]u8 = undefined;
    @memset(&sk_l, 0x11);
    var sk_r: [32]u8 = undefined;
    @memset(&sk_r, 0x22);
    const ls = try X25519.KeyPair.generateDeterministic(sk_l);
    const rs = try X25519.KeyPair.generateDeterministic(sk_r);

    var init: HandshakeXX = .init(true, &[_]u8{}, ls);
    var resp: HandshakeXX = .init(false, &[_]u8{}, rs);

    var b1: [512]u8 = undefined;
    var b2: [1024]u8 = undefined;
    var b3: [1024]u8 = undefined;
    var pbuf: [256]u8 = undefined;

    const m1 = try init.writeMessage1(std.testing.io, &[_]u8{}, &b1);
    _ = try resp.readMessage1(m1, &pbuf);

    const m2 = try resp.writeMessage2(std.testing.io, &[_]u8{}, &b2);
    _ = try init.readMessage2(m2, &pbuf);

    const m3 = try init.writeMessage3(&[_]u8{}, &b3);
    _ = try resp.readMessage3(m3, &pbuf);

    var itx = try init.splitInitiator();
    var rtx = try resp.splitResponder();

    var tbuf: [64]u8 = undefined;
    const ct = try itx.tx.encryptTransport("hello-noise", &tbuf);
    const pt = try rtx.rx.decryptTransport(ct, &pbuf);
    try std.testing.expectEqualStrings("hello-noise", pt);

    const ct2 = try rtx.tx.encryptTransport("reply", &tbuf);
    const pt2 = try itx.rx.decryptTransport(ct2, &pbuf);
    try std.testing.expectEqualStrings("reply", pt2);
}
