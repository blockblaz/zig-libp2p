const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

pub const Cipher = @import("cipher.zig").Cipher;
pub const record = @import("record.zig");
pub const protocol = @import("protocol.zig");
pub const max_ciphertext_record_len = @import("cipher.zig").max_ciphertext_record_len;

/// Buffer of this size will fit any tls ciphertext record sent by other side.
/// To decrytp we need full record, smalled buffer will not work in general
/// case. Bigger can be used for performance reason.
pub const input_buffer_len = max_ciphertext_record_len; // 16645 bytes

/// Needed output buffer during handshake is the size of the tls hello message,
/// which is (when client authentication is not used) ~1600 bytes. After
/// handshake it limits how big tls record can be produced. This suggested value
/// can hold max ciphertext record produced with this implementation.
pub const output_buffer_len = @import("cipher.zig").max_encrypted_record_len; // 16469 bytes

// Stream-based TLS Connection API removed — connection.zig not vendored.
// This vendored copy is used only for PrivateKey loading and NonBlock handshake primitives.

pub const config = struct {
    const proto = @import("protocol.zig");
    const common = @import("handshake_common.zig");

    pub const CipherSuite = @import("cipher.zig").CipherSuite;
    pub const PrivateKey = @import("PrivateKey.zig");
    pub const NamedGroup = proto.NamedGroup;
    pub const Version = proto.Version;
    pub const cert = common.cert;
    pub const CertKeyPair = common.CertKeyPair;

    pub const cipher_suites = @import("cipher.zig").cipher_suites;
    pub const key_log = @import("key_log.zig");

    pub const Client = @import("handshake_client.zig").Options;
    pub const Server = @import("handshake_server.zig").Options;
};

/// Non-blocking client/server handshake. Handshake produces
/// cipher used to encrypt/decrypt data.
pub const nonblock = struct {
    pub const Client = @import("handshake_client.zig").NonBlock;
    pub const Server = @import("handshake_server.zig").NonBlock;
};

test {
    _ = @import("handshake_common.zig");
    _ = @import("handshake_server.zig");
    _ = @import("handshake_client.zig");

    _ = @import("cipher.zig");
    _ = @import("record.zig");
    _ = @import("transcript.zig");
    _ = @import("PrivateKey.zig");
}
