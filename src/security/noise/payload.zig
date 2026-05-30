//! Protobuf `NoiseHandshakePayload` / nested `NoiseExtensions` (libp2p Noise spec).

const std = @import("std");
const wire = @import("../../protobuf/wire.zig");

pub const Error = wire.Error || std.mem.Allocator.Error || error{
    MissingIdentityKey,
    MissingIdentitySig,
};

/// Field numbers match go-libp2p / rust-libp2p `structs.proto`.
pub const field_identity_key: u32 = 1;
pub const field_identity_sig: u32 = 2;
pub const field_extensions: u32 = 3;
pub const ext_field_stream_muxer: u32 = 1;

pub const Decoded = struct {
    identity_key: []const u8,
    identity_sig: []const u8,
    /// Slices borrow from `extensions_bytes` (empty if no extensions field).
    stream_muxers: []const []const u8,
    extensions_bytes: []const u8,
};

/// Encode `NoiseHandshakePayload`. Caller frees returned buffer.
pub fn encode(
    allocator: std.mem.Allocator,
    identity_key: []const u8,
    identity_sig: []const u8,
    stream_muxers: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);
    try wire.appendLengthDelimited(&list, allocator, field_identity_key, identity_key);
    try wire.appendLengthDelimited(&list, allocator, field_identity_sig, identity_sig);
    if (stream_muxers.len != 0) {
        var nested = std.ArrayList(u8).empty;
        defer nested.deinit(allocator);
        for (stream_muxers) |m| {
            try wire.appendLengthDelimited(&nested, allocator, ext_field_stream_muxer, m);
        }
        try wire.appendLengthDelimited(&list, allocator, field_extensions, nested.items);
    }
    return try list.toOwnedSlice(allocator);
}

fn parseExtensions(into: *Decoded, ext: []const u8, mux_scratch: *std.ArrayList([]const u8), allocator: std.mem.Allocator) Error!void {
    into.extensions_bytes = ext;
    mux_scratch.clearRetainingCapacity();
    var i: usize = 0;
    while (i < ext.len) {
        const key = try wire.decodeFieldKey(ext[i..]);
        i += key.len;
        const val = try wire.nextFieldValueLimited(ext[i..], key.wire_type, 4096);
        i += val.total;
        if (key.field_number == ext_field_stream_muxer and key.wire_type == .length_delimited) {
            try mux_scratch.append(allocator, val.value);
        }
    }
    into.stream_muxers = mux_scratch.items;
}

/// Parse a `NoiseHandshakePayload`. `mux_scratch` is reused for `stream_muxers` slices (into `extensions_bytes`).
pub fn decode(
    buf: []const u8,
    max_payload: usize,
    mux_scratch: *std.ArrayList([]const u8),
    allocator: std.mem.Allocator,
) Error!Decoded {
    var out: Decoded = .{
        .identity_key = &[_]u8{},
        .identity_sig = &[_]u8{},
        .stream_muxers = &[_][]const u8{},
        .extensions_bytes = &[_]u8{},
    };
    var i: usize = 0;
    while (i < buf.len) {
        const key = try wire.decodeFieldKey(buf[i..]);
        i += key.len;
        const val = try wire.nextFieldValueLimited(buf[i..], key.wire_type, max_payload);
        i += val.total;
        switch (key.field_number) {
            field_identity_key => out.identity_key = val.value,
            field_identity_sig => out.identity_sig = val.value,
            field_extensions => try parseExtensions(&out, val.value, mux_scratch, allocator),
            else => {},
        }
    }
    if (out.identity_key.len == 0) return error.MissingIdentityKey;
    if (out.identity_sig.len == 0) return error.MissingIdentitySig;
    return out;
}

test "NoiseHandshakePayload round trip" {
    const a = std.testing.allocator;
    var mux_scratch = std.ArrayList([]const u8).empty;
    defer mux_scratch.deinit(a);

    const enc = try encode(a, "id-key", "sig", &.{ "/yamux/1.0.0", "/mplex/6.7.0" });
    defer a.free(enc);

    const dec = try decode(enc, 4096, &mux_scratch, a);
    try std.testing.expectEqualStrings("id-key", dec.identity_key);
    try std.testing.expectEqualStrings("sig", dec.identity_sig);
    try std.testing.expectEqual(@as(usize, 2), dec.stream_muxers.len);
    try std.testing.expectEqualStrings("/yamux/1.0.0", dec.stream_muxers[0]);
    try std.testing.expectEqualStrings("/mplex/6.7.0", dec.stream_muxers[1]);
}
