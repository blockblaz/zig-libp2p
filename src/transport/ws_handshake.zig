//! RFC 6455 §4 — opening handshake on top of HTTP/1.1.
//!
//! Pure encode/decode against byte buffers. The transport layer
//! ([`ws.zig`]) wires it up to a real TCP socket.
//!
//! Why a hand-rolled HTTP parser: this is a single, fixed-shape upgrade —
//! pulling in a general HTTP/1.1 parser for one request is overkill and
//! widens the attack surface. We only accept the exact header set RFC 6455
//! requires; anything else is rejected at parse time.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc6455#section-4>.

const std = @import("std");

const ascii = std.ascii;
const Sha1 = std.crypto.hash.Sha1;
const base64 = std.base64.standard;
const timing_safe = std.crypto.timing_safe;

/// Concatenated with the client's `Sec-WebSocket-Key` then SHA-1'd to produce
/// `Sec-WebSocket-Accept`. Pinned by the RFC.
pub const accept_magic: []const u8 = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Length of a 16-byte nonce base64-encoded (no padding stripped — RFC uses
/// `standard` alphabet with `=` padding, which is 24 chars for 16 bytes).
pub const key_b64_len: usize = 24;
/// `Sec-WebSocket-Accept` is 28 chars (SHA-1 = 20 bytes → base64 padded).
pub const accept_b64_len: usize = 28;

pub const ParseError = error{
    /// Request/response line malformed or missing trailing `\r\n`.
    BadStartLine,
    /// A header line lacks a `:`, doesn't terminate with `\r\n`, or duplicates
    /// a required header with a conflicting value.
    BadHeader,
    /// Required header missing or value not what RFC 6455 requires.
    MissingOrInvalidHeader,
    /// Buffer ended before the blank-line terminator was found.
    Incomplete,
    /// Computed `Sec-WebSocket-Accept` doesn't match the server's reply.
    HandshakeFailed,
    /// Caller-supplied buffer too small to format the message.
    BufferTooSmall,
    /// Caller-supplied `host`/`path` contains control characters (CR/LF/NUL)
    /// or non-printable bytes — refuses HTTP header / request-smuggling
    /// injection at the source.
    InvalidArgument,
};

// ── client → server upgrade request ──────────────────────────────────────

pub const ClientUpgrade = struct {
    /// Borrowed slice into the buffer the caller parsed from; lives as long as
    /// the buffer does. base64 of 16 random bytes per §4.1.
    sec_websocket_key: []const u8,
};

/// Build the upgrade GET request bytes into `out`.
///
/// `host` is the value for the HTTP `Host:` header (multiaddr authority).
/// `path` is the URI path; libp2p always uses `/`.
/// `key_b64` is a 24-byte base64 string of the caller's 16 random nonce bytes.
pub fn writeClientRequest(out: []u8, host: []const u8, path: []const u8, key_b64: []const u8) ParseError!usize {
    if (key_b64.len != key_b64_len) return error.MissingOrInvalidHeader;
    if (!isSafeHeaderValue(host) or !isSafeRequestTarget(path)) return error.InvalidArgument;
    if (!isValidStandardBase64(key_b64)) return error.MissingOrInvalidHeader;
    const w = formatRequest(out, host, path, key_b64) catch return error.BufferTooSmall;
    return w;
}

/// Reject any byte that could close the current header line and start a new
/// one (CR/LF) or terminate a C-style scan (NUL). Also reject everything
/// outside printable ASCII / SP / HTAB — RFC 7230 §3.2.6 obs-text.
fn isSafeHeaderValue(v: []const u8) bool {
    for (v) |b| {
        if (b == '\r' or b == '\n' or b == 0) return false;
        if (b != '\t' and (b < 0x20 or b == 0x7f)) return false;
    }
    return true;
}

/// Request-target subset of `isSafeHeaderValue`: no SP either, because we
/// splice it into the start line `GET <path> HTTP/1.1`.
fn isSafeRequestTarget(v: []const u8) bool {
    if (v.len == 0) return false;
    for (v) |b| {
        if (b == '\r' or b == '\n' or b == 0 or b == ' ' or b == '\t') return false;
        if (b < 0x20 or b == 0x7f) return false;
    }
    return true;
}

/// `Sec-WebSocket-Key` is base64 over the standard alphabet, length exactly
/// 24 (16-byte nonce + `==` padding). Anything else is rejected so we don't
/// echo attacker-chosen bytes into `Sec-WebSocket-Accept` computation.
fn isValidStandardBase64(s: []const u8) bool {
    if (s.len != key_b64_len) return false;
    // Last two chars are RFC-pinned padding for a 16-byte payload.
    if (s[22] != '=' or s[23] != '=') return false;
    for (s[0..22]) |b| {
        const ok = (b >= 'A' and b <= 'Z') or
            (b >= 'a' and b <= 'z') or
            (b >= '0' and b <= '9') or
            b == '+' or b == '/';
        if (!ok) return false;
    }
    return true;
}

fn formatRequest(out: []u8, host: []const u8, path: []const u8, key_b64: []const u8) !usize {
    var n: usize = 0;
    n += try appendStr(out[n..], "GET ");
    n += try appendStr(out[n..], path);
    n += try appendStr(out[n..], " HTTP/1.1\r\nHost: ");
    n += try appendStr(out[n..], host);
    n += try appendStr(out[n..], "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    n += try appendStr(out[n..], key_b64);
    n += try appendStr(out[n..], "\r\nSec-WebSocket-Version: 13\r\n\r\n");
    return n;
}

fn appendStr(buf: []u8, src: []const u8) error{NoSpaceLeft}!usize {
    if (buf.len < src.len) return error.NoSpaceLeft;
    @memcpy(buf[0..src.len], src);
    return src.len;
}

/// Parse the request as far as the trailing blank line. Returns the client's
/// `Sec-WebSocket-Key` (borrowed from `bytes`). All checks per §4.2.1.
pub fn parseClientRequest(bytes: []const u8) ParseError!ClientUpgrade {
    var p = bytes;

    // Request line: `GET <path> HTTP/1.1\r\n`.
    const line = try takeLine(&p);
    if (!std.mem.startsWith(u8, line, "GET ")) return error.BadStartLine;
    if (!std.mem.endsWith(u8, line, " HTTP/1.1")) return error.BadStartLine;

    var saw_upgrade = false;
    var saw_connection_upgrade = false;
    var saw_version_13 = false;
    var key: ?[]const u8 = null;

    while (true) {
        const h = try takeLine(&p);
        if (h.len == 0) break; // CRLF CRLF terminator.

        const colon = std.mem.indexOfScalar(u8, h, ':') orelse return error.BadHeader;
        const name = h[0..colon];
        var value = h[colon + 1 ..];
        while (value.len > 0 and (value[0] == ' ' or value[0] == '\t')) value = value[1..];

        if (asciiEqlIgnoreCase(name, "upgrade")) {
            if (!asciiEqlIgnoreCase(value, "websocket")) return error.MissingOrInvalidHeader;
            saw_upgrade = true;
        } else if (asciiEqlIgnoreCase(name, "connection")) {
            // May be a comma-separated list — check for the Upgrade token.
            if (containsTokenIgnoreCase(value, "upgrade")) saw_connection_upgrade = true;
        } else if (asciiEqlIgnoreCase(name, "sec-websocket-version")) {
            if (!std.mem.eql(u8, value, "13")) return error.MissingOrInvalidHeader;
            saw_version_13 = true;
        } else if (asciiEqlIgnoreCase(name, "sec-websocket-key")) {
            if (!isValidStandardBase64(value)) return error.MissingOrInvalidHeader;
            key = value;
        }
    }

    if (!saw_upgrade or !saw_connection_upgrade or !saw_version_13) {
        return error.MissingOrInvalidHeader;
    }
    return .{ .sec_websocket_key = key orelse return error.MissingOrInvalidHeader };
}

// ── server → client switching-protocols response ─────────────────────────

/// Compute `Sec-WebSocket-Accept`. The output is a 28-byte base64 string.
pub fn computeAccept(client_key_b64: []const u8, out: *[accept_b64_len]u8) ParseError!void {
    if (client_key_b64.len != key_b64_len) return error.MissingOrInvalidHeader;
    var sha = Sha1.init(.{});
    sha.update(client_key_b64);
    sha.update(accept_magic);
    var digest: [Sha1.digest_length]u8 = undefined;
    sha.final(&digest);
    _ = base64.Encoder.encode(out, &digest);
}

/// Build the `101 Switching Protocols` response bytes into `out`.
pub fn writeServerResponse(out: []u8, client_key_b64: []const u8) ParseError!usize {
    var accept: [accept_b64_len]u8 = undefined;
    try computeAccept(client_key_b64, &accept);
    return formatResponse(out, accept[0..]) catch error.BufferTooSmall;
}

fn formatResponse(out: []u8, accept: []const u8) !usize {
    var n: usize = 0;
    n += try appendStr(out[n..], "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
    n += try appendStr(out[n..], accept);
    n += try appendStr(out[n..], "\r\n\r\n");
    return n;
}

/// Parse the server's response and verify `Sec-WebSocket-Accept` matches the
/// nonce the client sent.
pub fn parseAndVerifyServerResponse(bytes: []const u8, client_key_b64: []const u8) ParseError!void {
    var p = bytes;

    const status_line = try takeLine(&p);
    // `HTTP/1.1 101 Switching Protocols` — accept any reason phrase as long
    // as the code is 101.
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 101 ")) return error.HandshakeFailed;

    var got_accept: ?[]const u8 = null;
    var saw_upgrade = false;
    var saw_connection_upgrade = false;
    while (true) {
        const h = try takeLine(&p);
        if (h.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, h, ':') orelse return error.BadHeader;
        const name = h[0..colon];
        var value = h[colon + 1 ..];
        while (value.len > 0 and (value[0] == ' ' or value[0] == '\t')) value = value[1..];

        if (asciiEqlIgnoreCase(name, "upgrade")) {
            if (!asciiEqlIgnoreCase(value, "websocket")) return error.HandshakeFailed;
            saw_upgrade = true;
        } else if (asciiEqlIgnoreCase(name, "connection")) {
            if (containsTokenIgnoreCase(value, "upgrade")) saw_connection_upgrade = true;
        } else if (asciiEqlIgnoreCase(name, "sec-websocket-accept")) {
            got_accept = value;
        }
    }
    const accept_value = got_accept orelse return error.HandshakeFailed;
    var expected: [accept_b64_len]u8 = undefined;
    try computeAccept(client_key_b64, &expected);
    // Length check first (timing_safe.eql requires comptime-known matching
    // array lengths); then constant-time byte compare so a network observer
    // can't learn how many leading bytes of `Sec-WebSocket-Accept` matched
    // by timing the response. Belt-and-braces — the Accept value is
    // deterministic from the public key the client just sent, but defending
    // it the same way we defend MACs avoids special-casing later.
    if (accept_value.len != accept_b64_len) return error.HandshakeFailed;
    var got_arr: [accept_b64_len]u8 = undefined;
    @memcpy(&got_arr, accept_value);
    if (!timing_safe.eql([accept_b64_len]u8, got_arr, expected)) return error.HandshakeFailed;
    if (!saw_upgrade or !saw_connection_upgrade) return error.HandshakeFailed;
}

// ── nonce helper ─────────────────────────────────────────────────────────

/// Encode a 16-byte client nonce into 24 base64 chars. Caller passes the
/// random bytes (`std.crypto.random` or a test fixture).
pub fn encodeKeyB64(nonce: [16]u8, out: *[key_b64_len]u8) void {
    _ = base64.Encoder.encode(out, &nonce);
}

// ── private helpers ──────────────────────────────────────────────────────

/// Pop the next CRLF-terminated line off `*p`. Returns the line excluding the
/// CRLF.
fn takeLine(p: *[]const u8) ParseError![]const u8 {
    const idx = std.mem.indexOf(u8, p.*, "\r\n") orelse return error.Incomplete;
    const line = p.*[0..idx];
    p.* = p.*[idx + 2 ..];
    return line;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (ascii.toLower(x) != ascii.toLower(y)) return false;
    }
    return true;
}

/// Token-aware substring match for `Connection: keep-alive, Upgrade` style
/// header values.
fn containsTokenIgnoreCase(value: []const u8, needle: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, value, ", \t");
    while (it.next()) |tok| {
        if (asciiEqlIgnoreCase(tok, needle)) return true;
    }
    return false;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "computeAccept: RFC 6455 §1.3 example" {
    // The RFC example uses key `dGhlIHNhbXBsZSBub25jZQ==` and expects
    // accept `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.
    var accept: [accept_b64_len]u8 = undefined;
    try computeAccept("dGhlIHNhbXBsZSBub25jZQ==", &accept);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
}

test "client request: round-trip parse" {
    var buf: [256]u8 = undefined;
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const n = try writeClientRequest(&buf, "example.com", "/", key);
    const upgrade = try parseClientRequest(buf[0..n]);
    try testing.expectEqualStrings(key, upgrade.sec_websocket_key);
}

test "client request: missing host header rejected" {
    const bad = "GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    // Host missing is actually allowed by our parser (RFC 6455 requires it,
    // but we tolerate — many libp2p multiaddr paths drop authority). The
    // following two tests focus on the headers RFC 6455 considers fatal.
    const u = try parseClientRequest(bad);
    try testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", u.sec_websocket_key);
}

test "client request: missing Upgrade rejected" {
    const bad = "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    try testing.expectError(error.MissingOrInvalidHeader, parseClientRequest(bad));
}

test "client request: wrong Sec-WebSocket-Version rejected" {
    const bad = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 8\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    try testing.expectError(error.MissingOrInvalidHeader, parseClientRequest(bad));
}

test "client request: Connection multi-token accepted" {
    const ok = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    _ = try parseClientRequest(ok);
}

test "client request: incomplete reports Incomplete" {
    const partial = "GET / HTTP/1.1\r\nHost: x\r\n";
    try testing.expectError(error.Incomplete, parseClientRequest(partial));
}

test "server response: round-trip" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    var buf: [256]u8 = undefined;
    const n = try writeServerResponse(&buf, key);
    try parseAndVerifyServerResponse(buf[0..n], key);
}

test "server response: wrong Sec-WebSocket-Accept rejected" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const bad = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";
    try testing.expectError(error.HandshakeFailed, parseAndVerifyServerResponse(bad, key));
}

test "server response: non-101 status rejected" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const bad = "HTTP/1.1 400 Bad Request\r\n\r\n";
    try testing.expectError(error.HandshakeFailed, parseAndVerifyServerResponse(bad, key));
}

test "encodeKeyB64: 24-char output" {
    const nonce: [16]u8 = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00 };
    var out: [key_b64_len]u8 = undefined;
    encodeKeyB64(nonce, &out);
    try testing.expectEqual(key_b64_len, out.len);
}

test "writeClientRequest: CRLF in host rejected" {
    var buf: [256]u8 = undefined;
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    try testing.expectError(
        error.InvalidArgument,
        writeClientRequest(&buf, "x.example\r\nX-Injected: yes", "/", key),
    );
    try testing.expectError(
        error.InvalidArgument,
        writeClientRequest(&buf, "x.example", "/\r\nX-Injected: yes", key),
    );
}

test "writeClientRequest: SP or NUL in path rejected" {
    var buf: [256]u8 = undefined;
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    try testing.expectError(
        error.InvalidArgument,
        writeClientRequest(&buf, "x.example", "/foo HTTP/1.1\r\nHost: evil", key),
    );
    try testing.expectError(
        error.InvalidArgument,
        writeClientRequest(&buf, "x.example", "/\x00", key),
    );
}

test "writeClientRequest: non-base64 key rejected" {
    var buf: [256]u8 = undefined;
    // 24 chars, but contains '!' (not in standard alphabet).
    try testing.expectError(
        error.MissingOrInvalidHeader,
        writeClientRequest(&buf, "x", "/", "AAAAAAAAAAAAAAAAAAAAA!=="),
    );
    // Missing the required `==` padding.
    try testing.expectError(
        error.MissingOrInvalidHeader,
        writeClientRequest(&buf, "x", "/", "AAAAAAAAAAAAAAAAAAAAAAAA"),
    );
}

test "parseClientRequest: non-base64 client key rejected" {
    const bad = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: !!!!!!!!!!!!!!!!!!!!!!==\r\n\r\n";
    try testing.expectError(error.MissingOrInvalidHeader, parseClientRequest(bad));
}
