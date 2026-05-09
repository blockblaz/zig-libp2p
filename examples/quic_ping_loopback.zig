//! Run a single-threaded libp2p QUIC loopback: TLS + multistream + `/ipfs/ping/1.0.0` (#15).
//! Uses `test/fixtures/quic_loopback/cert.pem` and `key.pem` — run from the **repository root**
//! (`zig build test` / `zig build run -- example-quic-ping-loopback`).

const std = @import("std");
const zig_libp2p = @import("zig_libp2p");

pub fn main() !void {
    const a = std.heap.page_allocator;
    try zig_libp2p.transport.quic_endpoint.loopbackPingOnce(
        a,
        "test/fixtures/quic_loopback/cert.pem",
        "test/fixtures/quic_loopback/key.pem",
    );
    std.debug.print("quic loopback ping ok\n", .{});
}
