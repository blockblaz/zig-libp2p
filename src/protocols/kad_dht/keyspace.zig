//! Kademlia keyspace: sha256 keys and XOR distance (#93).
//!
//! Spec: https://github.com/libp2p/specs/tree/master/kad-dht

const std = @import("std");

pub const Key = [32]u8;
pub const key_bits: u16 = 256;

pub fn hashKey(raw: []const u8) Key {
    var out: Key = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &out, .{});
    return out;
}

pub fn xorDistance(a: Key, b: Key) Key {
    var out: Key = undefined;
    for (0..32) |i| out[i] = a[i] ^ b[i];
    return out;
}

/// Lexicographic compare of 256-bit keys (big-endian).
pub fn compareKeys(a: Key, b: Key) std.math.Order {
    for (0..32) |i| {
        if (a[i] < b[i]) return .lt;
        if (a[i] > b[i]) return .gt;
    }
    return .eq;
}

pub fn isCloser(a: Key, b: Key, target: Key) bool {
    const da = xorDistance(a, target);
    const db = xorDistance(b, target);
    return compareKeys(da, db) == .lt;
}

/// Common prefix length in bits between two keys (libp2p/go-libp2p-kbucket).
pub fn commonPrefixLength(a: Key, b: Key) u16 {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (a[i] == b[i]) continue;
        return @intCast(i * 8 + @clz(a[i] ^ b[i]));
    }
    return key_bits;
}

test "common prefix length" {
    var a: Key = undefined;
    @memset(&a, 0);
    var b: Key = undefined;
    @memset(&b, 0);
    try std.testing.expectEqual(@as(u16, 256), commonPrefixLength(a, b));
    b[0] = 0x80;
    try std.testing.expectEqual(@as(u16, 0), commonPrefixLength(a, b));
    b[0] = 0x01;
    try std.testing.expectEqual(@as(u16, 7), commonPrefixLength(a, b));
}

test "xor distance ordering" {
    const local = hashKey("local");
    const near = hashKey("near-peer");
    const far = hashKey("far-away-peer-on-other-side-of-keyspace");
    const target = hashKey("lookup-target");
    try std.testing.expect(isCloser(near, far, target) or isCloser(far, near, target));
    _ = local;
}
