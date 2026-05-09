//! Deterministic wire smoke tests (#44): pseudo-random byte slices must not panic in core parsers.
//! LibFuzzer / long-run fuzzing and rust-libp2p interop are tracked in [#44](https://github.com/ch4r10t33r/zig-libp2p/issues/44).

const std = @import("std");
const varint = @import("varint.zig");
const frame = @import("req_resp/frame.zig");
const rpc = @import("gossipsub/rpc.zig");

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
