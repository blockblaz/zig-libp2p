//! Bidirectional byte pump between two relay stream halves (#91).

const std = @import("std");
const Io = std.Io;

pub const Error = error{
    IoReadFailed,
    IoWriteFailed,
    StreamClosed,
};

/// Pump bytes from `a_to_b_r` into `a_to_b_w` until EOF on the read side.
pub fn pumpOnce(r: *Io.Reader, w: *Io.Writer, buf: []u8) Error!bool {
    const n = r.readSliceShort(buf) catch return error.IoReadFailed;
    if (n == 0) return false;
    Io.Writer.writeAll(w, buf[0..n]) catch return error.IoWriteFailed;
    Io.Writer.flush(w) catch return error.IoWriteFailed;
    return true;
}

/// Run a single pump step in both directions (non-blocking best effort).
pub fn pumpBidirectional(
    hop_r: *Io.Reader,
    hop_w: *Io.Writer,
    stop_r: *Io.Reader,
    stop_w: *Io.Writer,
    buf: []u8,
) Error!void {
    _ = pumpOnce(hop_r, stop_w, buf) catch |e| switch (e) {
        error.StreamClosed => {},
        else => |x| return x,
    };
    _ = pumpOnce(stop_r, hop_w, buf) catch |e| switch (e) {
        error.StreamClosed => {},
        else => |x| return x,
    };
}

test "pumpOnce copies bytes" {
    var in_buf: [8]u8 = .{ 1, 2, 3, 4, 0, 0, 0, 0 };
    var out_buf: [8]u8 = undefined;
    var tmp: [8]u8 = undefined;
    var r = Io.Reader.fixed(in_buf[0..4]);
    var w = Io.Writer.fixed(&out_buf);
    const more = try pumpOnce(&r, &w, &tmp);
    try std.testing.expect(more);
    try std.testing.expectEqual(@as(usize, 4), w.end);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, out_buf[0..4]);
}
