//! Zig 0.16 shims for the vendored stream TLS stack (no extra module imports).
const std = @import("std");
const builtin = @import("builtin");

const RandomSrc = struct {
    pub fn fill(_: *RandomSrc, buf: []u8) void {
        if (builtin.os.tag == .linux) {
            var off: usize = 0;
            while (off < buf.len) {
                const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
                if (@as(isize, @bitCast(rc)) < 0) @panic("getrandom failed");
                off += @intCast(rc);
            }
            return;
        }
        std.c.arc4random_buf(buf.ptr, buf.len);
    }
};

var random_src: RandomSrc = .{};
pub const random: std.Random = std.Random.init(&random_src, RandomSrc.fill);

pub fn nowSec() i64 {
    if (comptime builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        return ts.sec;
    }
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    return ts.sec;
}
