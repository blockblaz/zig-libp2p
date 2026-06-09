//! In-memory AutoNAT v1 round trip (client dial → server dial-back stub → response).

const std = @import("std");
const Io = std.Io;
const zl = @import("zig_libp2p");

pub fn main() !void {
    const a = std.heap.page_allocator;

    const DialStub = struct {
        fn dial(ctx: ?*anyopaque, addr: []const u8, nonce: u64) zl.autonat.DialBackResult {
            _ = ctx;
            _ = nonce;
            // Simulate successful dial-back when target is a public testnet address.
            if (std.mem.indexOf(u8, addr, "203.0.113") != null) return .ok;
            return .dial_error;
        }
    };

    var srv = zl.autonat.Server.init(a, .{}, DialStub.dial);

    // Client builds v1 Dial probe.
    var client = zl.autonat.Client.init(a, .{ .policy = .{ .success_threshold = 0 } });
    defer client.deinit();
    const me = try zl.identity.PeerId.random();
    const addrs = [_][]const u8{"/ip4/203.0.113.5/udp/4001/quic-v1"};
    const probe = (try client.poll(0, me, &addrs, false)).?;
    defer client.freeProbeMessage(probe.wire_message);

    // Pipe probe into server (observed IP matches dial target).
    var in_buf: [4096]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var w_in = Io.Writer.fixed(&in_buf);
    try zl.autonat.wire.writeLengthPrefixed(&w_in, probe.wire_message);
    const in_len = w_in.end;

    var r = Io.Reader.fixed(in_buf[0..in_len]);
    var w_out = Io.Writer.fixed(&out_buf);
    try srv.handleV1Stream(&r, &w_out, .{ .v4 = .{ 203, 0, 113, 5 } }, false);
    const out_len = w_out.end;

    // Client reads response.
    var r_resp = Io.Reader.fixed(out_buf[0..out_len]);
    const resp_frame = try zl.autonat.wire.readLengthPrefixedAlloc(&r_resp, a, zl.autonat.wire.Limits.standard.max_frame_bytes);
    defer a.free(resp_frame);
    const msg = try zl.autonat.wire.decodeV1Owned(a, resp_frame, .standard);
    defer zl.autonat.wire.freeV1Owned(a, msg);
    switch (msg) {
        .dial_response => |dr| {
            client.handleV1DialResponse(dr);
        },
        else => return error.UnexpectedResponse,
    }

    std.debug.print("autonat_membuf: nat_status={s}\n", .{@tagName(client.natStatus())});
    if (client.natStatus() != .public) return error.ExpectedPublic;
}
