//! Minimal DNS wire codec for libp2p mDNS (#207).
//!
//! Covers PTR / TXT questions and answers used by
//! [discovery/mdns](https://github.com/libp2p/specs/blob/master/discovery/mdns.md).

const std = @import("std");

pub const Error = error{
    Truncated,
    BadName,
    BadPointer,
    NameTooLong,
    RecordTooLarge,
    UnsupportedType,
} || std.mem.Allocator.Error;

pub const Type = enum(u16) {
    a = 1,
    ptr = 12,
    txt = 16,
    aaaa = 28,
    srv = 33,
};

pub const Class = enum(u16) {
    in = 1,
};

pub const Question = struct {
    qname: []const u8,
    qtype: Type,
    qclass: Class,
};

pub const ResourceRecord = struct {
    name: []const u8,
    rtype: Type,
    rclass: Class,
    ttl: u32,
    /// TXT: list of character-strings; PTR/SRV: domain name.
    rdata: []const u8,
    txt_strings: []const []const u8 = &.{},
};

pub const Message = struct {
    id: u16 = 0,
    is_response: bool = false,
    authoritative: bool = false,
    questions: []const Question = &.{},
    answers: []const ResourceRecord = &.{},
    additionals: []const ResourceRecord = &.{},
};

pub fn encodeName(out: *std.ArrayList(u8), allocator: std.mem.Allocator, fqdn: []const u8) Error!void {
    if (fqdn.len == 0 or fqdn[0] == '.') return error.BadName;
    var rest = fqdn;
    while (rest.len > 0) {
        if (rest[0] == '.') {
            rest = rest[1..];
            continue;
        }
        const dot = std.mem.indexOfScalar(u8, rest, '.') orelse rest.len;
        const label = rest[0..dot];
        if (label.len == 0 or label.len > 63) return error.BadName;
        try out.append(allocator, @intCast(label.len));
        try out.appendSlice(allocator, label);
        rest = rest[dot..];
    }
    try out.append(allocator, 0);
}

fn readNameAt(allocator: std.mem.Allocator, data: []const u8, offset: usize, scratch: *std.ArrayList(u8), visited: *std.AutoHashMapUnmanaged(usize, void)) Error!struct { name: []const u8, next: usize } {
    var pos = offset;
    var first = true;
    while (pos < data.len) {
        const len = data[pos];
        if (len == 0) {
            pos += 1;
            return .{ .name = scratch.items, .next = pos };
        }
        if (len & 0xC0 == 0xC0) {
            if (pos + 1 >= data.len) return error.Truncated;
            const ptr = (@as(usize, len & 0x3F) << 8) | data[pos + 1];
            if (visited.contains(ptr)) return error.BadPointer;
            try visited.put(allocator, ptr, {});
            _ = try readNameAt(allocator, data, ptr, scratch, visited);
            return .{ .name = scratch.items, .next = pos + 2 };
        }
        pos += 1;
        if (pos + len > data.len) return error.Truncated;
        if (!first and scratch.items.len > 0) try scratch.append(allocator, '.');
        try scratch.appendSlice(allocator, data[pos .. pos + len]);
        first = false;
        pos += len;
    }
    return error.Truncated;
}

pub fn readName(data: []const u8, offset: usize, allocator: std.mem.Allocator) Error!struct { name: []u8, next: usize } {
    var scratch: std.ArrayList(u8) = .empty;
    errdefer scratch.deinit(allocator);
    var visited: std.AutoHashMapUnmanaged(usize, void) = .empty;
    defer visited.deinit(allocator);
    const r = try readNameAt(allocator, data, offset, &scratch, &visited);
    defer scratch.deinit(allocator);
    const owned = try allocator.dupe(u8, r.name);
    return .{ .name = owned, .next = r.next };
}

fn parseRecords(
    allocator: std.mem.Allocator,
    data: []const u8,
    offset: usize,
    count: usize,
) Error!struct { records: []ResourceRecord, next: usize } {
    var records: std.ArrayList(ResourceRecord) = .empty;
    errdefer {
        for (records.items) |*rr| {
            allocator.free(rr.name);
            allocator.free(rr.rdata);
            for (rr.txt_strings) |s| allocator.free(s);
            allocator.free(rr.txt_strings);
        }
        records.deinit(allocator);
    }
    var pos = offset;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const name_r = try readName(data, pos, allocator);
        pos = name_r.next;
        if (pos + 10 > data.len) return error.Truncated;
        const rtype: Type = @enumFromInt(std.mem.readInt(u16, data[pos..][0..2], .big));
        pos += 2;
        const rclass_raw = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        const rclass: Class = @enumFromInt(rclass_raw & 0x7FFF);
        const ttl = std.mem.readInt(u32, data[pos..][0..4], .big);
        pos += 4;
        const rdlen = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        if (pos + rdlen > data.len) return error.Truncated;
        const rdata = try allocator.dupe(u8, data[pos .. pos + rdlen]);
        pos += rdlen;

        var txt_strings: []const []const u8 = &.{};
        if (rtype == .txt) {
            var strings: std.ArrayList([]const u8) = .empty;
            errdefer {
                for (strings.items) |s| allocator.free(s);
                strings.deinit(allocator);
            }
            var tpos: usize = 0;
            while (tpos < rdata.len) {
                const slen = rdata[tpos];
                tpos += 1;
                if (tpos + slen > rdata.len) return error.Truncated;
                try strings.append(allocator, try allocator.dupe(u8, rdata[tpos .. tpos + slen]));
                tpos += slen;
            }
            txt_strings = try strings.toOwnedSlice(allocator);
        }

        try records.append(allocator, .{
            .name = name_r.name,
            .rtype = rtype,
            .rclass = rclass,
            .ttl = ttl,
            .rdata = rdata,
            .txt_strings = txt_strings,
        });
    }
    return .{ .records = try records.toOwnedSlice(allocator), .next = pos };
}

pub fn decode(allocator: std.mem.Allocator, data: []const u8) Error!Message {
    if (data.len < 12) return error.Truncated;
    const id = std.mem.readInt(u16, data[0..2], .big);
    const flags = std.mem.readInt(u16, data[2..4], .big);
    const qdcount = std.mem.readInt(u16, data[4..6], .big);
    const ancount = std.mem.readInt(u16, data[6..8], .big);
    const nscount = std.mem.readInt(u16, data[8..10], .big);
    const arcount = std.mem.readInt(u16, data[10..12], .big);

    var pos: usize = 12;
    var questions: std.ArrayList(Question) = .empty;
    errdefer {
        for (questions.items) |q| allocator.free(q.qname);
        questions.deinit(allocator);
    }
    var qi: usize = 0;
    while (qi < qdcount) : (qi += 1) {
        const name_r = try readName(data, pos, allocator);
        pos = name_r.next;
        if (pos + 4 > data.len) return error.Truncated;
        const qtype: Type = @enumFromInt(std.mem.readInt(u16, data[pos..][0..2], .big));
        pos += 2;
        const qclass: Class = @enumFromInt(std.mem.readInt(u16, data[pos..][0..2], .big) & 0x7FFF);
        pos += 2;
        try questions.append(allocator, .{ .qname = name_r.name, .qtype = qtype, .qclass = qclass });
    }

    const ans = try parseRecords(allocator, data, pos, ancount);
    pos = ans.next;
    if (nscount > 0) {
        const ns = try parseRecords(allocator, data, pos, nscount);
        for (ns.records) |rr| freeRecord(allocator, rr);
        allocator.free(ns.records);
        pos = ns.next;
    }
    const add = try parseRecords(allocator, data, pos, arcount);

    return .{
        .id = id,
        .is_response = (flags & 0x8000) != 0,
        .authoritative = (flags & 0x0400) != 0,
        .questions = try questions.toOwnedSlice(allocator),
        .answers = ans.records,
        .additionals = add.records,
    };
}

pub fn freeMessage(allocator: std.mem.Allocator, msg: *Message) void {
    for (msg.questions) |q| allocator.free(q.qname);
    allocator.free(msg.questions);
    var ai: usize = 0;
    while (ai < msg.answers.len) : (ai += 1) freeRecord(allocator, msg.answers[ai]);
    allocator.free(msg.answers);
    var xi: usize = 0;
    while (xi < msg.additionals.len) : (xi += 1) freeRecord(allocator, msg.additionals[xi]);
    allocator.free(msg.additionals);
    msg.* = .{};
}

fn freeRecord(allocator: std.mem.Allocator, rr: ResourceRecord) void {
    allocator.free(rr.name);
    allocator.free(rr.rdata);
    if (rr.txt_strings.len > 0) {
        for (rr.txt_strings) |s| allocator.free(s);
        allocator.free(rr.txt_strings);
    }
}

pub fn encode(allocator: std.mem.Allocator, msg: Message) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendNTimes(allocator, 0, 2);
    var flags: u16 = 0;
    if (msg.is_response) flags |= 0x8000;
    if (msg.authoritative) flags |= 0x0400;
    try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, flags)));
    try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(msg.questions.len))));
    try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(msg.answers.len))));
    try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0)));
    try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(msg.additionals.len))));

    for (msg.questions) |q| {
        try encodeName(&out, allocator, q.qname);
        try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intFromEnum(q.qtype))));
        try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intFromEnum(q.qclass))));
    }

    inline for (.{ msg.answers, msg.additionals }) |section| {
        for (section) |rr| {
            try encodeName(&out, allocator, rr.name);
            try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intFromEnum(rr.rtype))));
            var rclass: u16 = @intFromEnum(rr.rclass);
            if (msg.is_response) rclass |= 0x8000;
            try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, rclass)));
            try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, rr.ttl)));
            try out.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(rr.rdata.len))));
            try out.appendSlice(allocator, rr.rdata);
        }
    }

    const id_bytes = std.mem.toBytes(std.mem.nativeToBig(u16, msg.id));
    out.items[0] = id_bytes[0];
    out.items[1] = id_bytes[1];
    return try out.toOwnedSlice(allocator);
}

pub fn encodeTxtRdata(allocator: std.mem.Allocator, value: []const u8) Error![]u8 {
    if (value.len > 255) return error.RecordTooLarge;
    var out: [256]u8 = undefined;
    out[0] = @intCast(value.len);
    @memcpy(out[1 .. 1 + value.len], value);
    return try allocator.dupe(u8, out[0 .. 1 + value.len]);
}

pub fn encodePtrRdata(allocator: std.mem.Allocator, target: []const u8) Error![]u8 {
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(allocator);
    try encodeName(&tmp, allocator, target);
    return try allocator.dupe(u8, tmp.items);
}

test "encode/decode PTR query round trip" {
    const a = std.testing.allocator;
    const qname = "_p2p._udp.local";
    const wire = try encode(a, .{
        .questions = &.{
            .{ .qname = qname, .qtype = .ptr, .qclass = .in },
        },
    });
    defer a.free(wire);
    var msg = try decode(a, wire);
    defer freeMessage(a, &msg);
    try std.testing.expectEqual(@as(usize, 1), msg.questions.len);
    try std.testing.expectEqualStrings(qname, msg.questions[0].qname);
    try std.testing.expect(msg.questions[0].qtype == .ptr);
}

test "encode/decode TXT response with dnsaddr" {
    const a = std.testing.allocator;
    const txt = "dnsaddr=/ip4/192.168.0.3/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";
    const peer_fqdn = "abc123._p2p._udp.local";
    const txt_rdata = try encodeTxtRdata(a, txt);
    defer a.free(txt_rdata);
    const ptr_rdata = try encodePtrRdata(a, peer_fqdn);
    defer a.free(ptr_rdata);
    const wire = try encode(a, .{
        .id = 42,
        .is_response = true,
        .authoritative = true,
        .answers = &.{
            .{
                .name = "_p2p._udp.local",
                .rtype = .ptr,
                .rclass = .in,
                .ttl = 120,
                .rdata = ptr_rdata,
            },
        },
        .additionals = &.{
            .{
                .name = peer_fqdn,
                .rtype = .txt,
                .rclass = .in,
                .ttl = 120,
                .rdata = txt_rdata,
            },
        },
    });
    defer a.free(wire);
    var msg = try decode(a, wire);
    defer freeMessage(a, &msg);
    try std.testing.expect(msg.is_response);
    try std.testing.expectEqual(@as(usize, 1), msg.additionals.len);
    try std.testing.expect(msg.additionals[0].rtype == .txt);
    try std.testing.expectEqual(@as(usize, 1), msg.additionals[0].txt_strings.len);
    try std.testing.expectEqualStrings(txt, msg.additionals[0].txt_strings[0]);
}
