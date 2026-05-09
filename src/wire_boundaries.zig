//! Deterministic wire smoke tests (#44): pseudo-random byte slices must not panic in core parsers.
//! Tests named `wire fuzz …` use [`std.testing.fuzz`] (corpus smoke in `zig build test`; long runs via `zig build fuzz` / Zig fuzzing).
//! rust-libp2p interop remains manual — see [`tests/interop/README.md`](../../tests/interop/README.md).

const std = @import("std");
const varint = @import("varint.zig");
const frame = @import("req_resp/frame.zig");
const rpc = @import("gossipsub/rpc.zig");
const pb = @import("protobuf/wire.zig");
const snappy_wire = @import("req_resp/snappy_wire.zig");
const gs_msg = @import("gossipsub/message.zig");

test "wire smoke varint decode" {
    var prng = std.Random.DefaultPrng.init(0xFACADE000044);
    const r = prng.random();
    var buf: [768]u8 = undefined;
    var i: u32 = 0;
    while (i < 8000) : (i += 1) {
        const n = r.intRangeLessThan(usize, 0, buf.len + 1);
        r.bytes(buf[0..n]);
        _ = varint.decode(buf[0..n]) catch {};
    }
}

test "wire smoke req/resp frame headers" {
    var prng = std.Random.DefaultPrng.init(0xBADC0DE000044);
    const r = prng.random();
    var buf: [256]u8 = undefined;
    var i: u32 = 0;
    while (i < 4000) : (i += 1) {
        const n = r.intRangeLessThan(usize, 0, buf.len + 1);
        r.bytes(buf[0..n]);
        _ = frame.parseRequestHeader(buf[0..n]) catch {};
        _ = frame.parseResponseHeader(buf[0..n]) catch {};
    }
}

test "wire smoke gossipsub rpc decode paths" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x600D00000044);
    const rand = prng.random();
    var buf: [2048]u8 = undefined;
    var i: u32 = 0;
    while (i < 3000) : (i += 1) {
        const n = rand.intRangeLessThan(usize, 0, buf.len + 1);
        rand.bytes(buf[0..n]);

        if (rpc.decodeFirstSubscribe(a, buf[0..n])) |opt| {
            if (opt) |sv| {
                var owned = sv;
                defer rpc.deinitSubscribeView(a, &owned);
            }
        } else |_| {}
        if (rpc.decodeSubscribes(a, buf[0..n])) |views| {
            defer rpc.freeSubscribeViews(a, views);
        } else |_| {}

        if (rpc.decodeControlPayload(a, buf[0..n])) |opt| {
            if (opt) |ctl| a.free(ctl);
        } else |_| {}

        if (rpc.decodePublishes(a, buf[0..n])) |blobs| {
            defer rpc.freePublishBlobs(a, blobs);
        } else |_| {}
    }
}

test "wire smoke protobuf varint and length-delimited" {
    var prng = std.Random.DefaultPrng.init(0x50520044);
    const rand = prng.random();
    var buf: [512]u8 = undefined;
    var i: u32 = 0;
    while (i < 2500) : (i += 1) {
        const n = rand.intRangeLessThan(usize, 0, buf.len + 1);
        rand.bytes(buf[0..n]);
        _ = pb.decodeVarUInt64(buf[0..n]) catch {};
        if (buf.len >= 2) {
            const key = (@as(u64, 1) << 3) | 2;
            var scratch: [256]u8 = undefined;
            var key_tmp: [varint.max_encoding_bytes]u8 = undefined;
            var len_tmp: [varint.max_encoding_bytes]u8 = undefined;
            const pay_len = @min(n, 200);
            const key_enc = varint.encodeToScratch(&key_tmp, @intCast(key));
            const len_enc = varint.encodeToScratch(&len_tmp, pay_len);
            const prefix_len = key_enc.len + len_enc.len;
            if (prefix_len + pay_len <= scratch.len) {
                @memcpy(scratch[0..key_enc.len], key_enc);
                @memcpy(scratch[key_enc.len..][0..len_enc.len], len_enc);
                @memcpy(scratch[prefix_len..][0..pay_len], buf[0..pay_len]);
                var walk = scratch[0 .. prefix_len + pay_len];
                if (pb.decodeVarUInt64(walk)) |fk| {
                    walk = walk[fk.len..];
                    const wt: pb.WireType = @enumFromInt(@as(u3, @truncate(fk.value & 7)));
                    _ = pb.nextFieldValueLimited(walk, wt, 256) catch {};
                } else |_| {}
            }
        }
    }
}

test "wire smoke snappy framed and gossipsub message" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x534E500044);
    const rand = prng.random();
    var buf: [4096]u8 = undefined;
    var i: u32 = 0;
    while (i < 1200) : (i += 1) {
        const n = rand.intRangeLessThan(usize, 0, buf.len + 1);
        rand.bytes(buf[0..n]);
        if (snappy_wire.decompressFramed(a, buf[0..n])) |out| {
            defer a.free(out);
        } else |_| {}
        if (gs_msg.decode(a, buf[0..n])) |got| {
            var m = got;
            defer m.deinit(a);
        } else |_| {}
    }
}

fn wireFuzzVarint(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytesWithHash(&buf, 0xA001);
    _ = varint.decode(&buf) catch {};
}

test "wire fuzz varint decode" {
    try std.testing.fuzz({}, wireFuzzVarint, .{});
}

fn wireFuzzFrameHeaders(_: void, smith: *std.testing.Smith) !void {
    var buf: [320]u8 = undefined;
    smith.bytesWithHash(&buf, 0xA002);
    _ = frame.parseRequestHeader(&buf) catch {};
    _ = frame.parseResponseHeader(&buf) catch {};
}

test "wire fuzz req/resp frame headers" {
    try std.testing.fuzz({}, wireFuzzFrameHeaders, .{});
}

fn wireFuzzGossipsubRpc(_: void, smith: *std.testing.Smith) !void {
    const a = std.testing.allocator;
    var buf: [2048]u8 = undefined;
    smith.bytesWithHash(&buf, 0xA003);
    if (rpc.decodeFirstSubscribe(a, &buf)) |opt| {
        if (opt) |sv| {
            var owned = sv;
            defer rpc.deinitSubscribeView(a, &owned);
        }
    } else |_| {}
    if (rpc.decodeControlPayload(a, &buf)) |opt| {
        if (opt) |ctl| a.free(ctl);
    } else |_| {}
}

test "wire fuzz gossipsub rpc decode" {
    try std.testing.fuzz({}, wireFuzzGossipsubRpc, .{});
}
