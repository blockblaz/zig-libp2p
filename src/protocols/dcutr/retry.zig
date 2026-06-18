//! DCUtR retry backoff (#205): 2s / 4s / 8s + ±25% jitter.

const std = @import("std");

pub const max_attempts: u32 = 3;

/// Base delays in milliseconds for attempts 0, 1, 2.
const base_ms: [max_attempts]i64 = .{ 2000, 4000, 8000 };

pub fn delayMs(attempt: u32, seed: u64) i64 {
    if (attempt >= max_attempts) return 0;
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    const base = base_ms[attempt];
    const jitter_span = @divTrunc(base, 4);
    const jitter = if (jitter_span == 0) @as(i64, 0) else rand.intRangeAtMost(i64, -jitter_span, jitter_span);
    return base + jitter;
}

test "delayMs grows with attempt" {
    const d0 = delayMs(0, 1);
    const d1 = delayMs(1, 1);
    const d2 = delayMs(2, 1);
    try std.testing.expect(d0 >= 1500 and d0 <= 2500);
    try std.testing.expect(d1 >= 3000 and d1 <= 5000);
    try std.testing.expect(d2 >= 6000 and d2 <= 10000);
}
