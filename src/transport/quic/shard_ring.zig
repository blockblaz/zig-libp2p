//! Lock-free single-producer / single-consumer ring of inbound UDP datagrams.
//!
//! Part of the multi-shard drive-loop work (quinn model). A dedicated demux
//! thread reads the shared listen socket and `push`es raw datagrams here; the
//! owning shard's drive thread `peek`/`pop`s them and hands each to
//! `Server.feedPacket`. The demux thread never touches any `Server`/`ConnState`,
//! so all QUIC state mutation stays single-threaded on the drive thread — the
//! ring is the only cross-thread handoff and it is wait-free.
//!
//! SPSC discipline: the producer only ever advances `tail`, the consumer only
//! `head`. On overflow we drop the *incoming* datagram (drop-newest) rather than
//! reach across into the consumer's `head` — QUIC retransmits dropped packets,
//! and the kernel SO_RCVBUF already absorbs bursts ahead of this ring.

const std = @import("std");
const feed_addr = @import("../zquic_feed_addr.zig");

/// Per-slot datagram capacity. QUIC keeps datagrams at/under the path MTU
/// (~1452B); 2048 leaves margin without bloating the ring.
pub const max_datagram_bytes: usize = 2048;

pub const DatagramSlot = struct {
    addr: feed_addr.Address = undefined,
    len: u16 = 0,
    buf: [max_datagram_bytes]u8 = undefined,
};

/// Route an inbound datagram to the drive-loop shard that owns its connection.
///
/// Short-header (1-RTT) packets — the hot path — carry the DCID we issued as the
/// connection's `local_cid`, whose byte 0 encodes the shard (see
/// `ConnectionId.randomTagged`). The DCID immediately follows the 1-byte short
/// header, so the shard is `bytes[1] & mask`. O(1), no parse.
///
/// Long-header packets (Initial/Handshake) may carry a peer-chosen DCID that
/// isn't shard-tagged yet (the client's very first Initial), so we route them by
/// a hash of the source address instead — and the accepting shard tags the
/// `local_cid` it mints with its own index, so every subsequent 1-RTT packet for
/// that connection routes back here by byte 0. `src_hash` is a precomputed hash
/// of the datagram's source address.
///
/// `shard_mask` is `shard_count - 1` (power of two). With mask 0 (single shard)
/// this always returns 0 — the demux is a no-op.
pub fn shardForDatagram(bytes: []const u8, src_hash: u64, shard_mask: u8) u8 {
    if (shard_mask == 0 or bytes.len < 2) return 0;
    const long_header = (bytes[0] & 0x80) != 0;
    if (long_header) return @intCast(src_hash & shard_mask);
    return bytes[1] & shard_mask;
}

pub const InboundRing = struct {
    slots: []DatagramSlot,
    mask: usize, // capacity - 1; capacity is a power of two
    /// Consumer-owned read cursor.
    head: std.atomic.Value(usize) align(std.atomic.cache_line) = .{ .raw = 0 },
    /// Producer-owned write cursor.
    tail: std.atomic.Value(usize) align(std.atomic.cache_line) = .{ .raw = 0 },
    /// Datagrams dropped on overflow / oversize (diagnostic).
    drops: std.atomic.Value(u64) = .{ .raw = 0 },

    pub fn init(allocator: std.mem.Allocator, capacity_pow2: usize) !InboundRing {
        std.debug.assert(capacity_pow2 != 0 and (capacity_pow2 & (capacity_pow2 - 1)) == 0);
        const slots = try allocator.alloc(DatagramSlot, capacity_pow2);
        return .{ .slots = slots, .mask = capacity_pow2 - 1 };
    }

    pub fn deinit(self: *InboundRing, allocator: std.mem.Allocator) void {
        allocator.free(self.slots);
        self.slots = &.{};
    }

    /// Producer: copy a datagram into the ring. Returns false (counting a drop)
    /// when the ring is full or the datagram is oversize.
    pub fn push(self: *InboundRing, bytes: []const u8, addr: feed_addr.Address) bool {
        if (bytes.len > max_datagram_bytes) {
            _ = self.drops.fetchAdd(1, .monotonic);
            return false;
        }
        const tail = self.tail.load(.monotonic);
        const next = (tail + 1) & self.mask;
        if (next == self.head.load(.acquire)) {
            _ = self.drops.fetchAdd(1, .monotonic);
            return false;
        }
        const slot = &self.slots[tail];
        @memcpy(slot.buf[0..bytes.len], bytes);
        slot.len = @intCast(bytes.len);
        slot.addr = addr;
        self.tail.store(next, .release);
        return true;
    }

    /// Consumer: borrow the next datagram in place (no copy) or null if empty.
    /// The slot stays valid until the matching `pop`, so the consumer can pass
    /// `slot.buf[0..slot.len]` straight to `feedPacket` and only `pop` after it
    /// returns. The producer cannot overwrite this slot until `head` advances.
    pub fn peek(self: *InboundRing) ?*const DatagramSlot {
        const head = self.head.load(.monotonic);
        if (head == self.tail.load(.acquire)) return null;
        return &self.slots[head];
    }

    /// Consumer: release the slot returned by the preceding `peek`.
    pub fn pop(self: *InboundRing) void {
        const head = self.head.load(.monotonic);
        self.head.store((head + 1) & self.mask, .release);
    }

    pub fn dropCount(self: *const InboundRing) u64 {
        return self.drops.load(.monotonic);
    }
};

test "InboundRing: fifo push/peek/pop round-trips" {
    const testing = std.testing;
    var ring = try InboundRing.init(testing.allocator, 8);
    defer ring.deinit(testing.allocator);
    const addr: feed_addr.Address = undefined;

    try testing.expect(ring.peek() == null); // empty
    var i: u8 = 0;
    while (i < 5) : (i += 1) {
        try testing.expect(ring.push(&[_]u8{ i, i, i }, addr));
    }
    i = 0;
    while (i < 5) : (i += 1) {
        const slot = ring.peek() orelse return error.Unexpected;
        try testing.expectEqual(@as(u16, 3), slot.len);
        try testing.expectEqual(i, slot.buf[0]);
        ring.pop();
    }
    try testing.expect(ring.peek() == null);
}

test "InboundRing: drop-newest on overflow, counts drops" {
    const testing = std.testing;
    var ring = try InboundRing.init(testing.allocator, 4); // holds capacity-1 = 3
    defer ring.deinit(testing.allocator);
    const addr: feed_addr.Address = undefined;
    try testing.expect(ring.push("a", addr));
    try testing.expect(ring.push("b", addr));
    try testing.expect(ring.push("c", addr));
    try testing.expect(!ring.push("d", addr)); // full → drop newest
    try testing.expectEqual(@as(u64, 1), ring.dropCount());
    // Oldest still 'a'.
    const slot = ring.peek() orelse return error.Unexpected;
    try testing.expectEqual(@as(u8, 'a'), slot.buf[0]);
}

test "InboundRing: oversize datagram dropped" {
    const testing = std.testing;
    var ring = try InboundRing.init(testing.allocator, 4);
    defer ring.deinit(testing.allocator);
    const addr: feed_addr.Address = undefined;
    const big = [_]u8{0} ** (max_datagram_bytes + 1);
    try testing.expect(!ring.push(&big, addr));
    try testing.expectEqual(@as(u64, 1), ring.dropCount());
}

test "shardForDatagram: single shard (mask 0) is always 0" {
    const testing = std.testing;
    try testing.expectEqual(@as(u8, 0), shardForDatagram(&[_]u8{ 0x40, 0x07 }, 12345, 0));
    try testing.expectEqual(@as(u8, 0), shardForDatagram(&[_]u8{ 0xC0, 0x03 }, 9, 0));
}

test "shardForDatagram: short header routes by tagged DCID byte 0" {
    const testing = std.testing;
    const mask: u8 = 0b11; // 4 shards
    // Short header: bit 0x80 clear. byte[1] is the first DCID byte (shard tag).
    // 0x40 = short header form; DCID byte 0 low bits select the shard.
    try testing.expectEqual(@as(u8, 0), shardForDatagram(&[_]u8{ 0x40, 0b1000 }, 0, mask));
    try testing.expectEqual(@as(u8, 1), shardForDatagram(&[_]u8{ 0x40, 0b1001 }, 0, mask));
    try testing.expectEqual(@as(u8, 2), shardForDatagram(&[_]u8{ 0x40, 0b0110 }, 0, mask));
    try testing.expectEqual(@as(u8, 3), shardForDatagram(&[_]u8{ 0x40, 0b1111 }, 0, mask));
}

test "shardForDatagram: long header routes by source hash" {
    const testing = std.testing;
    const mask: u8 = 0b11;
    // Long header: bit 0x80 set. DCID may be peer-chosen → route by src hash.
    try testing.expectEqual(@as(u8, 1), shardForDatagram(&[_]u8{ 0xC0, 0xFF }, 5, mask)); // 5 & 3 = 1
    try testing.expectEqual(@as(u8, 2), shardForDatagram(&[_]u8{ 0xC0, 0x00 }, 6, mask)); // 6 & 3 = 2
}

test "shardForDatagram: runt datagram routes to shard 0" {
    const testing = std.testing;
    try testing.expectEqual(@as(u8, 0), shardForDatagram(&[_]u8{0x40}, 7, 0b11));
    try testing.expectEqual(@as(u8, 0), shardForDatagram(&[_]u8{}, 7, 0b11));
}
