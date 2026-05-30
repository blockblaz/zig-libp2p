//! Microbenchmark harness for zig-libp2p hot paths (#19, follow-up to #103).
//!
//! Goal: pin per-iteration latency for parsers and the gossipsub dup cache so
//! a regression is caught by CI before it lands in production. The harness is
//! deliberately tiny — `zig build bench` runs a fixed iteration count, prints
//! ns/op via `std.debug.print` (which goes to stderr), and exits. No statistical
//! sampling, no warm-up beyond a few iterations.
//!
//! Output format is grep-friendly: `bench <name> <iters> <ns_per_op>` per line.

const std = @import("std");
const builtin = @import("builtin");
const zl = @import("zig_libp2p");

fn nowNs() i128 {
    if (comptime builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
    }
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

fn report(name: []const u8, iters: u64, ns_total: u64) void {
    const ns_per_op: u64 = if (iters == 0) 0 else ns_total / iters;
    std.debug.print("bench {s} {d} {d}\n", .{ name, iters, ns_per_op });
}

fn timeIt(ctx: anytype, comptime body: fn (@TypeOf(ctx)) anyerror!void, iters: u64) !u64 {
    // Warm-up: a few iterations to give the JIT-less binary a stable cache.
    var i: u64 = 0;
    while (i < @min(@as(u64, 8), iters)) : (i += 1) try body(ctx);
    const start = nowNs();
    i = 0;
    while (i < iters) : (i += 1) try body(ctx);
    const elapsed = nowNs() - start;
    return @intCast(@max(elapsed, 0));
}

// --- Varint ----------------------------------------------------------------

const VarintCtx = struct { buf: [10]u8 };

fn varintEncode(c: *VarintCtx) !void {
    var i: u64 = 0;
    while (i < 128) : (i += 1) {
        const enc = zl.varint.encodeToScratch(&c.buf, i);
        std.mem.doNotOptimizeAway(enc);
    }
}

fn varintDecode(c: *VarintCtx) !void {
    var i: u64 = 0;
    while (i < 128) : (i += 1) {
        const enc = zl.varint.encodeToScratch(&c.buf, i);
        const dec = zl.varint.decode(enc) catch unreachable;
        std.mem.doNotOptimizeAway(dec.value);
    }
}

// --- Gossipsub control: PRUNE round trip -----------------------------------

const PruneCtx = struct {
    a: std.mem.Allocator,
    topic: []const u8 = "/lean/blocks",
    backoff: u64 = 60,
};

fn pruneRoundTrip(c: *PruneCtx) !void {
    const wire = try zl.gossipsub.control.encodePrune(c.a, c.topic, c.backoff);
    defer c.a.free(wire);
    var view = (try zl.gossipsub.control.decodeFirstPrune(c.a, wire)).?;
    defer zl.gossipsub.control.deinitPruneView(c.a, &view);
    std.mem.doNotOptimizeAway(view.backoff_seconds);
}

// --- Gossipsub duplicate cache: hit + miss ---------------------------------

const DupCtx = struct {
    cache: *zl.gossipsub.duplicate_cache.DuplicateCache,
    id: [20]u8,
};

fn dupHit(c: *DupCtx) !void {
    const r = try c.cache.checkDuplicate("/t", c.id, 0);
    std.mem.doNotOptimizeAway(r);
}

fn dupMissThenHit(c: *DupCtx) !void {
    // Increment a byte so each iteration inserts a fresh id, then immediately re-hits.
    c.id[0] +%= 1;
    _ = try c.cache.checkDuplicate("/t", c.id, 0);
    const r = try c.cache.checkDuplicate("/t", c.id, 0);
    std.mem.doNotOptimizeAway(r);
}

// --- Yamux header parse ----------------------------------------------------

// `zl.transport.yamux` only re-exports a subset of types, not the `frame` module
// itself; reach the constant via the exported `Header` type's natural size of 12.
const YamuxHeaderLen: usize = 12;
const YamuxCtx = struct { buf: [YamuxHeaderLen]u8 };

fn yamuxHeaderParse(c: *YamuxCtx) !void {
    const h = zl.transport.yamux.Header{
        .kind = .data,
        .flags = .{ .syn = true },
        .stream_id = 1,
        .length = 42,
    };
    try h.encode(&c.buf);
    const r = try zl.transport.yamux.Header.parse(&c.buf, 64 * 1024);
    std.mem.doNotOptimizeAway(r);
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const iters_small: u64 = 10_000;
    const iters_mid: u64 = 5_000;
    const iters_large: u64 = 1_000;

    {
        var ctx = VarintCtx{ .buf = undefined };
        report("varint_encode_x128", iters_small, try timeIt(&ctx, varintEncode, iters_small));
        report("varint_decode_x128", iters_small, try timeIt(&ctx, varintDecode, iters_small));
    }

    {
        var ctx = PruneCtx{ .a = a };
        report("gossipsub_prune_roundtrip", iters_mid, try timeIt(&ctx, pruneRoundTrip, iters_mid));
    }

    {
        var cache = zl.gossipsub.duplicate_cache.DuplicateCache.init(a);
        defer cache.deinit();
        const seed: [20]u8 = [_]u8{0xcc} ** 20;
        _ = try cache.checkDuplicate("/t", seed, 0);
        var ctx = DupCtx{ .cache = &cache, .id = seed };
        report("dup_cache_hit", iters_small, try timeIt(&ctx, dupHit, iters_small));

        var ctx2 = DupCtx{ .cache = &cache, .id = [_]u8{0} ** 20 };
        report("dup_cache_miss_then_hit", iters_large, try timeIt(&ctx2, dupMissThenHit, iters_large));
    }

    {
        var ctx = YamuxCtx{ .buf = undefined };
        report("yamux_header_parse", iters_small, try timeIt(&ctx, yamuxHeaderParse, iters_small));
    }
}
