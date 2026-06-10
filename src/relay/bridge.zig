//! Bidirectional byte pump between two relay stream halves (#91).

const std = @import("std");
const Io = std.Io;

pub const Error = error{
    IoReadFailed,
    IoWriteFailed,
    StreamClosed,
};

/// Pump one chunk from `r` into `w`. Returns the number of bytes pumped (0 on EOF).
pub fn pumpOnce(r: *Io.Reader, w: *Io.Writer, buf: []u8) Error!usize {
    const n = r.readSliceShort(buf) catch return error.IoReadFailed;
    if (n == 0) return 0;
    Io.Writer.writeAll(w, buf[0..n]) catch return error.IoWriteFailed;
    Io.Writer.flush(w) catch return error.IoWriteFailed;
    return n;
}

/// Run a single pump step in both directions (non-blocking best effort).
/// Returns total bytes pumped this tick across both halves so the caller can
/// account against a per-bridge `data_bytes` budget.
pub fn pumpBidirectional(
    hop_r: *Io.Reader,
    hop_w: *Io.Writer,
    stop_r: *Io.Reader,
    stop_w: *Io.Writer,
    buf: []u8,
) Error!usize {
    var total: usize = 0;
    total += pumpOnce(hop_r, stop_w, buf) catch |e| switch (e) {
        error.StreamClosed => 0,
        else => |x| return x,
    };
    total += pumpOnce(stop_r, hop_w, buf) catch |e| switch (e) {
        error.StreamClosed => 0,
        else => |x| return x,
    };
    return total;
}

test "pumpOnce copies bytes" {
    var in_buf: [8]u8 = .{ 1, 2, 3, 4, 0, 0, 0, 0 };
    var out_buf: [8]u8 = undefined;
    var tmp: [8]u8 = undefined;
    var r = Io.Reader.fixed(in_buf[0..4]);
    var w = Io.Writer.fixed(&out_buf);
    const n = try pumpOnce(&r, &w, &tmp);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqual(@as(usize, 4), w.end);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, out_buf[0..4]);
}

test "pumpOnce returns 0 on EOF" {
    var in_buf: [4]u8 = undefined;
    var out_buf: [8]u8 = undefined;
    var tmp: [8]u8 = undefined;
    var r = Io.Reader.fixed(in_buf[0..0]);
    var w = Io.Writer.fixed(&out_buf);
    const n = try pumpOnce(&r, &w, &tmp);
    try std.testing.expectEqual(@as(usize, 0), n);
}
