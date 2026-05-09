//! In-memory multistream-select 1.0.0 handshake (same bytes as first QUIC/TCP substream).

const std = @import("std");
const zl = @import("zig_libp2p");

const neg = zl.transport.multistream_negotiate;

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    const proto = zl.transport.quic_v1.multistream_protocol_id;

    var to_server = std.ArrayList(u8).empty;
    defer to_server.deinit(gpa);
    var to_client = std.ArrayList(u8).empty;
    defer to_client.deinit(gpa);

    try neg.initiatorSendMultistreamHeader(&to_server, gpa);

    var rs: []const u8 = to_server.items;
    try neg.responderReadMultistreamOffer(&rs, neg.default_max_body_len);
    try compactAfterRead(&to_server, gpa, rs);

    try neg.responderSendMultistreamHeader(&to_client, gpa);

    var rc: []const u8 = to_client.items;
    try neg.initiatorReadPeerMultistream(&rc, neg.default_max_body_len);
    try compactAfterRead(&to_client, gpa, rc);

    try neg.initiatorSendProtocol(&to_server, gpa, proto);
    rs = to_server.items;
    const offered = try neg.responderReadProtocolOffer(&rs, neg.default_max_body_len);
    var offered_copy_buf: [512]u8 = undefined;
    if (offered.len > offered_copy_buf.len) return error.LineTooLong;
    @memcpy(offered_copy_buf[0..offered.len], offered);
    const offered_copy = offered_copy_buf[0..offered.len];
    try compactAfterRead(&to_server, gpa, rs);
    if (!std.mem.eql(u8, proto, offered_copy)) return error.ProtocolMismatch;
    try neg.responderReplyProtocol(&to_client, gpa, offered_copy, proto);

    rc = to_client.items;
    try neg.initiatorReadProtocolAck(&rc, proto, neg.default_max_body_len);
    try compactAfterRead(&to_client, gpa, rc);

    std.debug.print("negotiated {s}\n", .{proto});
}

fn compactAfterRead(list: *std.ArrayList(u8), allocator: std.mem.Allocator, tail: []const u8) !void {
    list.clearRetainingCapacity();
    try list.appendSlice(allocator, tail);
}
