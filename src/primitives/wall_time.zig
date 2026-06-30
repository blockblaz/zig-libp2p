//! Wall-clock milliseconds (Zig 0.16 removed `std.time.milliTimestamp`).

const builtin = @import("builtin");
const std = @import("std");

pub fn milliTimestamp() i64 {
    // Prefer libc's clock_gettime whenever libc is linked. The Shadow simulator
    // virtualizes time through its libc shim, so the raw `std.os.linux` syscall
    // bypasses the shim and reads the real host clock — desynchronizing
    // simulated time (#291). Only no-libc Linux builds take the raw-syscall path.
    if (comptime builtin.os.tag == .linux and !builtin.link_libc) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        return @as(i64, ts.sec) * std.time.ms_per_s + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
    } else {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
        return @as(i64, ts.sec) * std.time.ms_per_s + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
    }
}

/// UTC unix time in whole seconds.
pub fn unixTimestamp() i64 {
    return @divTrunc(milliTimestamp(), std.time.ms_per_s);
}
