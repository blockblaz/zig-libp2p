//! Sliding-window rate detector for over-cap inbound streams (#105 / #75).
//!
//! Lives in its own module so the bookkeeping math is unit-testable without
//! pulling in the full QUIC stack (which transitively trips Zig 0.16 stdlib
//! drift bugs in adjacent transport modules that are queued for a separate
//! cleanup). [`quic_endpoint`] consumes [`step`] from here.

const std = @import("std");

/// Rate-based abuse detector knobs.
pub const Policy = struct {
    /// Skipped streams within `window_ms` that trigger the breach result. `0`
    /// disables the policy entirely.
    threshold: u32 = 0,
    /// Sliding-window length in milliseconds.
    window_ms: i64 = 30_000,
};

pub const State = struct {
    count: u32 = 0,
    window_start_ms: i64 = 0,
};

pub const Step = struct {
    state: State,
    breach: bool,
};

/// Pure helper for [`Policy`] bookkeeping.
///
/// Returns the post-step `State` and whether a breach fired *this call*. When
/// a breach fires we clear the counter and stamp the new window-start so the
/// embedder can react to subsequent breaches without a flood of consecutive
/// callbacks.
pub fn step(state: State, delta: u32, now_ms: i64, policy: Policy) Step {
    var next = state;
    if (policy.threshold == 0 or delta == 0) return .{ .state = next, .breach = false };
    if (now_ms - next.window_start_ms >= policy.window_ms) {
        next.window_start_ms = now_ms;
        next.count = 0;
    }
    next.count +|= delta;
    if (next.count >= policy.threshold) {
        return .{ .state = .{ .count = 0, .window_start_ms = now_ms }, .breach = true };
    }
    return .{ .state = next, .breach = false };
}

test "step is a no-op when policy is disabled" {
    const r = step(.{}, 100, 1_000, .{ .threshold = 0, .window_ms = 1_000 });
    try std.testing.expect(!r.breach);
    try std.testing.expectEqual(@as(u32, 0), r.state.count);
}

test "step is a no-op when delta is zero" {
    const r = step(.{ .count = 7, .window_start_ms = 0 }, 0, 1_000, .{ .threshold = 5, .window_ms = 1_000 });
    try std.testing.expect(!r.breach);
    try std.testing.expectEqual(@as(u32, 7), r.state.count);
}

test "step accumulates within the window without firing" {
    var st = State{};
    const policy = Policy{ .threshold = 5, .window_ms = 1_000 };
    var s = step(st, 2, 100, policy);
    st = s.state;
    try std.testing.expect(!s.breach);
    try std.testing.expectEqual(@as(u32, 2), st.count);

    s = step(st, 2, 200, policy);
    st = s.state;
    try std.testing.expect(!s.breach);
    try std.testing.expectEqual(@as(u32, 4), st.count);
}

test "step fires breach once threshold is reached" {
    const st = State{ .count = 4, .window_start_ms = 100 };
    const r = step(st, 2, 200, .{ .threshold = 5, .window_ms = 1_000 });
    try std.testing.expect(r.breach);
    try std.testing.expectEqual(@as(u32, 0), r.state.count);
    try std.testing.expectEqual(@as(i64, 200), r.state.window_start_ms);
}

test "step resets the count once the window has elapsed" {
    const st = State{ .count = 4, .window_start_ms = 100 };
    const r = step(st, 2, 100 + 2_000, .{ .threshold = 5, .window_ms = 1_000 });
    try std.testing.expect(!r.breach);
    try std.testing.expectEqual(@as(u32, 2), r.state.count);
    try std.testing.expectEqual(@as(i64, 100 + 2_000), r.state.window_start_ms);
}

test "step saturates the counter instead of overflowing" {
    const st = State{ .count = std.math.maxInt(u32) - 1, .window_start_ms = 100 };
    const r = step(st, 10, 100, .{ .threshold = 100, .window_ms = 1_000 });
    try std.testing.expect(r.breach);
}
