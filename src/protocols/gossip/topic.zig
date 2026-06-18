//! Lean consensus gossip mesh topic strings (`/leanconsensus/...`).
//! Wire format matches Zeam `pkgs/network/src/interface.zig` (`LeanNetworkTopic`).

const std = @import("std");

pub const topic_prefix: []const u8 = "leanconsensus";

pub const GossipEncoding = enum {
    ssz_snappy,

    pub fn nameBytes(self: GossipEncoding) []const u8 {
        return @tagName(self);
    }

    pub fn decode(encoded: []const u8) DecodeError!GossipEncoding {
        return std.meta.stringToEnum(GossipEncoding, encoded) orelse error.InvalidEncoding;
    }
};

pub const DecodeError = error{
    InvalidTopic,
    MissingSubnetId,
    InvalidEncoding,
};

pub const GossipTopicKind = enum {
    block,
    attestation,
    aggregation,
};

pub const SubnetId = u32;

pub const GossipTopic = struct {
    kind: GossipTopicKind,
    subnet_id: ?SubnetId = null,

    pub fn encode(self: GossipTopic, allocator: std.mem.Allocator) (DecodeError || std.mem.Allocator.Error)![]u8 {
        if (self.kind == .attestation) {
            const sid = self.subnet_id orelse return error.MissingSubnetId;
            return std.fmt.allocPrint(allocator, "attestation_{d}", .{sid});
        }
        return allocator.dupe(u8, @tagName(self.kind));
    }

    pub fn decode(encoded: []const u8) DecodeError!GossipTopic {
        if (std.mem.startsWith(u8, encoded, "attestation_")) {
            const tail = encoded["attestation_".len..];
            const sid = std.fmt.parseInt(SubnetId, tail, 10) catch return error.InvalidEncoding;
            return .{ .kind = .attestation, .subnet_id = sid };
        }
        const kind = std.meta.stringToEnum(GossipTopicKind, encoded) orelse return error.InvalidEncoding;
        return .{ .kind = kind };
    }
};

pub const LeanNetworkTopic = struct {
    gossip_topic: GossipTopic,
    encoding: GossipEncoding,
    fork_digest: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, gossip_topic: GossipTopic, encoding: GossipEncoding, fork_digest: []const u8) std.mem.Allocator.Error!LeanNetworkTopic {
        return .{
            .allocator = allocator,
            .gossip_topic = gossip_topic,
            .encoding = encoding,
            .fork_digest = try allocator.dupe(u8, fork_digest),
        };
    }

    pub fn deinit(self: *LeanNetworkTopic) void {
        self.allocator.free(self.fork_digest);
    }

    pub const EncodeError = std.mem.Allocator.Error || error{
        InvalidEncoding,
        InvalidTopic,
        MissingSubnetId,
    };

    pub fn encode(self: *const LeanNetworkTopic) EncodeError![]u8 {
        const gossip_part = try self.gossip_topic.encode(self.allocator);
        defer self.allocator.free(gossip_part);
        return std.fmt.allocPrint(self.allocator, "/{s}/{s}/{s}/{s}", .{
            topic_prefix,
            self.fork_digest,
            gossip_part,
            self.encoding.nameBytes(),
        });
    }

    pub fn encodeZ(self: *const LeanNetworkTopic) EncodeError![:0]u8 {
        const gossip_part = try self.gossip_topic.encode(self.allocator);
        defer self.allocator.free(gossip_part);
        return std.fmt.allocPrintSentinel(self.allocator, "/{s}/{s}/{s}/{s}", .{
            topic_prefix,
            self.fork_digest,
            gossip_part,
            self.encoding.nameBytes(),
        }, 0);
    }

    /// Topic layout: `/leanconsensus/<fork_digest>/<gossip_name>/<encoding>` (no trailing slash).
    pub fn decode(allocator: std.mem.Allocator, topic: []const u8) (DecodeError || std.mem.Allocator.Error)!LeanNetworkTopic {
        var it = std.mem.splitSequence(u8, topic, "/");
        _ = it.next() orelse return error.InvalidTopic;
        const prefix = it.next() orelse return error.InvalidTopic;
        if (!std.mem.eql(u8, prefix, topic_prefix)) return error.InvalidTopic;
        const fork_digest_slice = it.next() orelse return error.InvalidTopic;
        const gossip_topic_slice = it.next() orelse return error.InvalidTopic;
        const encoding_slice = it.next() orelse return error.InvalidTopic;
        if (it.next() != null) return error.InvalidTopic;

        const gt = try GossipTopic.decode(gossip_topic_slice);
        const enc = try GossipEncoding.decode(encoding_slice);
        return try init(allocator, gt, enc, fork_digest_slice);
    }
};

test "LeanNetworkTopic block round trip" {
    const a = std.testing.allocator;
    var topic = try LeanNetworkTopic.init(a, .{ .kind = .block }, .ssz_snappy, "12345678");
    defer topic.deinit();
    const s = try topic.encode();
    defer a.free(s);
    try std.testing.expectEqualStrings("/leanconsensus/12345678/block/ssz_snappy", s);
    const z = try topic.encodeZ();
    defer a.free(z);
    try std.testing.expectEqualStrings("/leanconsensus/12345678/block/ssz_snappy", z);

    var decoded = try LeanNetworkTopic.decode(a, s);
    defer decoded.deinit();
    try std.testing.expectEqual(topic.gossip_topic.kind, decoded.gossip_topic.kind);
    try std.testing.expectEqual(@as(?SubnetId, null), decoded.gossip_topic.subnet_id);
    try std.testing.expectEqual(topic.encoding, decoded.encoding);
    try std.testing.expectEqualStrings(topic.fork_digest, decoded.fork_digest);
}

test "LeanNetworkTopic attestation subnet round trip" {
    const a = std.testing.allocator;
    var topic = try LeanNetworkTopic.init(a, .{ .kind = .attestation, .subnet_id = 7 }, .ssz_snappy, "abcdef01");
    defer topic.deinit();
    const s = try topic.encode();
    defer a.free(s);
    try std.testing.expectEqualStrings("/leanconsensus/abcdef01/attestation_7/ssz_snappy", s);
    var decoded = try LeanNetworkTopic.decode(a, s);
    defer decoded.deinit();
    try std.testing.expectEqual(GossipTopicKind.attestation, decoded.gossip_topic.kind);
    try std.testing.expectEqual(@as(SubnetId, 7), decoded.gossip_topic.subnet_id.?);
}

test "LeanNetworkTopic decode rejects trailing segment" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidTopic, LeanNetworkTopic.decode(a, "/leanconsensus/ab/block/ssz_snappy/extra"));
}

test "GossipTopic encode attestation without subnet fails" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.MissingSubnetId, (GossipTopic{ .kind = .attestation }).encode(a));
}
