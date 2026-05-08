//! libp2p Identify 1.0.0 (`/ipfs/id/1.0.0`): protobuf `Identify` over a single stream payload.
//!
//! Spec: https://github.com/libp2p/specs/blob/master/identify/README.md
//!
//! After multistream-select negotiates [`protocol_line`], each side sends one protobuf
//! `Identify` message (raw bytes until EOF). The embedder supplies listen addresses,
//! observed address for the peer, and registered protocol IDs; use [`Identify.handleInbound`]
//! and [`Identify.onConnectionEstablished`] to run the exchange on `std.Io` streams.

const std = @import("std");
const Io = std.Io;
const proto = @import("protobuf/wire.zig");
const pid = @import("peer_id");

/// Multistream negotiation line including newline (Identify 1.0.0).
pub const protocol_line: []const u8 = "/ipfs/id/1.0.0\n";

pub const Error = proto.Error || error{
    WireLimitExceeded,
    TooManyListenAddrs,
    TooManyProtocols,
    IdentifyMessageTooLarge,
    UnsupportedIdentifyField,
};

pub const Limits = struct {
    /// Maximum total bytes read for one Identify payload (until stream end).
    max_message_bytes: usize = 64 * 1024,
    max_string_field_bytes: usize = 4096,
    max_addr_bytes: usize = 1024,
    max_listen_addrs: usize = 128,
    max_protocols: usize = 256,
    max_protocol_id_bytes: usize = 1024,
    max_public_key_bytes: usize = 8192,
    max_signed_peer_record_bytes: usize = 8192,
    max_unknown_chunk: usize = 4096,

    pub const standard: Limits = .{};
};

/// Borrowing view of a decoded `Identify` (slices valid until [`MessageOwned`] is freed).
pub const MessageView = struct {
    protocol_version: ?[]const u8 = null,
    agent_version: ?[]const u8 = null,
    public_key: ?[]const u8 = null,
    listen_addrs: []const []const u8 = &.{},
    protocols: []const []const u8 = &.{},
    observed_addr: ?[]const u8 = null,
    signed_peer_record: ?[]const u8 = null,
};

/// Owned decode of an `Identify` protobuf.
pub const MessageOwned = struct {
    protocol_version: ?[]u8 = null,
    agent_version: ?[]u8 = null,
    public_key: ?[]u8 = null,
    listen_addrs: [][]u8 = &[_][]u8{},
    protocols: [][]u8 = &[_][]u8{},
    observed_addr: ?[]u8 = null,
    signed_peer_record: ?[]u8 = null,

    pub fn asView(self: *const MessageOwned) MessageView {
        return .{
            .protocol_version = if (self.protocol_version) |x| x else null,
            .agent_version = if (self.agent_version) |x| x else null,
            .public_key = if (self.public_key) |x| x else null,
            .listen_addrs = self.listen_addrs,
            .protocols = self.protocols,
            .observed_addr = if (self.observed_addr) |x| x else null,
            .signed_peer_record = if (self.signed_peer_record) |x| x else null,
        };
    }

    pub fn deinit(self: *MessageOwned, allocator: std.mem.Allocator) void {
        if (self.protocol_version) |x| allocator.free(x);
        if (self.agent_version) |x| allocator.free(x);
        if (self.public_key) |x| allocator.free(x);
        for (self.listen_addrs) |x| allocator.free(x);
        allocator.free(self.listen_addrs);
        for (self.protocols) |x| allocator.free(x);
        allocator.free(self.protocols);
        if (self.observed_addr) |x| allocator.free(x);
        if (self.signed_peer_record) |x| allocator.free(x);
        self.* = .{};
    }
};

fn appendOptLd(list: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, payload: ?[]const u8) std.mem.Allocator.Error!void {
    if (payload) |p| {
        try proto.appendLengthDelimited(list, allocator, field, p);
    }
}

/// Encode an `Identify` message to a single protobuf blob.
pub fn encode(allocator: std.mem.Allocator, msg: MessageView) (Error || std.mem.Allocator.Error)![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);
    try appendOptLd(&list, allocator, 5, msg.protocol_version);
    try appendOptLd(&list, allocator, 6, msg.agent_version);
    try appendOptLd(&list, allocator, 1, msg.public_key);
    for (msg.listen_addrs) |a| try proto.appendLengthDelimited(&list, allocator, 2, a);
    for (msg.protocols) |p| try proto.appendLengthDelimited(&list, allocator, 3, p);
    try appendOptLd(&list, allocator, 4, msg.observed_addr);
    try appendOptLd(&list, allocator, 8, msg.signed_peer_record);
    return try list.toOwnedSlice(allocator);
}

fn maxForField(field: u32, limits: Limits) usize {
    return switch (field) {
        1 => limits.max_public_key_bytes,
        2 => limits.max_addr_bytes,
        3 => limits.max_protocol_id_bytes,
        4 => limits.max_addr_bytes,
        5, 6 => limits.max_string_field_bytes,
        8 => limits.max_signed_peer_record_bytes,
        else => limits.max_unknown_chunk,
    };
}

/// Decode `Identify` from wire bytes (untrusted).
pub fn decodeOwned(allocator: std.mem.Allocator, wire: []const u8, limits: Limits) (Error || std.mem.Allocator.Error)!MessageOwned {
    if (wire.len > limits.max_message_bytes) return error.WireLimitExceeded;

    var out: MessageOwned = .{};
    errdefer out.deinit(allocator);

    var listen = std.ArrayList([]u8).empty;
    defer {
        for (listen.items) |x| allocator.free(x);
        listen.deinit(allocator);
    }
    var protos = std.ArrayList([]u8).empty;
    defer {
        for (protos.items) |x| allocator.free(x);
        protos.deinit(allocator);
    }

    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const cap = maxForField(key.field_number, limits);
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, cap);
        off += nv.total;

        switch (key.field_number) {
            1 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedIdentifyField;
                const duped = try allocator.dupe(u8, nv.value);
                if (out.public_key) |old| allocator.free(old);
                out.public_key = duped;
            },
            2 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedIdentifyField;
                if (listen.items.len >= limits.max_listen_addrs) return error.TooManyListenAddrs;
                try listen.append(allocator, try allocator.dupe(u8, nv.value));
            },
            3 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedIdentifyField;
                if (protos.items.len >= limits.max_protocols) return error.TooManyProtocols;
                try protos.append(allocator, try allocator.dupe(u8, nv.value));
            },
            4 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedIdentifyField;
                const duped = try allocator.dupe(u8, nv.value);
                if (out.observed_addr) |old| allocator.free(old);
                out.observed_addr = duped;
            },
            5 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedIdentifyField;
                const duped = try allocator.dupe(u8, nv.value);
                if (out.protocol_version) |old| allocator.free(old);
                out.protocol_version = duped;
            },
            6 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedIdentifyField;
                const duped = try allocator.dupe(u8, nv.value);
                if (out.agent_version) |old| allocator.free(old);
                out.agent_version = duped;
            },
            8 => {
                if (key.wire_type != .length_delimited) return error.UnsupportedIdentifyField;
                const duped = try allocator.dupe(u8, nv.value);
                if (out.signed_peer_record) |old| allocator.free(old);
                out.signed_peer_record = duped;
            },
            else => {},
        }
    }

    out.listen_addrs = try listen.toOwnedSlice(allocator);
    listen = .{};
    out.protocols = try protos.toOwnedSlice(allocator);
    protos = .{};

    return out;
}

/// Read until end of stream (or `max_total`), returning one contiguous payload.
pub fn readIdentifyWireAlloc(r: *Io.Reader, allocator: std.mem.Allocator, max_total: usize) (Io.Reader.ShortError || std.mem.Allocator.Error || error{IdentifyMessageTooLarge})![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try r.readSliceShort(&buf);
        if (n == 0) break;
        const new_len = try std.math.add(usize, list.items.len, n);
        if (new_len > max_total) return error.IdentifyMessageTooLarge;
        try list.appendSlice(allocator, buf[0..n]);
    }
    return try list.toOwnedSlice(allocator);
}

/// Parameters for the Identify message we send (listen addrs, protocols we speak, optional keys).
pub const ReplyParams = struct {
    listen_addrs: []const []const u8,
    protocols: []const []const u8,
    public_key: ?[]const u8 = null,
    /// Multiaddr bytes the peer observes for our side (responder fills from dialer socket, etc.).
    observed_addr: ?[]const u8 = null,
    signed_peer_record: ?[]const u8 = null,
};

/// Long-lived Identify handler: owns default protocol and agent strings.
pub const Identify = struct {
    allocator: std.mem.Allocator,
    agent_version: []u8,
    protocol_version: []u8,

    pub fn init(allocator: std.mem.Allocator, agent_version: []const u8) std.mem.Allocator.Error!Identify {
        return .{
            .allocator = allocator,
            .agent_version = try allocator.dupe(u8, agent_version),
            .protocol_version = try allocator.dupe(u8, "ipfs/0.1.0"),
        };
    }

    pub fn deinit(self: *Identify) void {
        self.allocator.free(self.agent_version);
        self.allocator.free(self.protocol_version);
    }

    fn replyView(self: *const Identify, params: ReplyParams) MessageView {
        return .{
            .protocol_version = self.protocol_version,
            .agent_version = self.agent_version,
            .public_key = params.public_key,
            .listen_addrs = params.listen_addrs,
            .protocols = params.protocols,
            .observed_addr = params.observed_addr,
            .signed_peer_record = params.signed_peer_record,
        };
    }

    /// Responder: read peer Identify, invoke `onIdentified`, then write our Identify.
    pub fn handleInbound(
        self: *Identify,
        peer: pid.PeerId,
        r: *Io.Reader,
        w: *Io.Writer,
        limits: Limits,
        reply_params: ReplyParams,
        context: anytype,
        comptime onIdentified: fn (ctx: @TypeOf(context), peer_id: pid.PeerId, msg: MessageView) void,
    ) (Error || Io.Reader.ShortError || Io.Writer.Error || std.mem.Allocator.Error)!void {
        const wire = try readIdentifyWireAlloc(r, self.allocator, limits.max_message_bytes);
        defer self.allocator.free(wire);
        var owned = try decodeOwned(self.allocator, wire, limits);
        defer owned.deinit(self.allocator);
        onIdentified(context, peer, owned.asView());
        const rv = self.replyView(reply_params);
        const out = try encode(self.allocator, rv);
        defer self.allocator.free(out);
        try Io.Writer.writeAll(w, out);
        try Io.Writer.flush(w);
    }

    /// Initiator: write our Identify first, then read the peer's (typical after stream open + multistream).
    pub fn onConnectionEstablished(
        self: *Identify,
        peer: pid.PeerId,
        r: *Io.Reader,
        w: *Io.Writer,
        limits: Limits,
        reply_params: ReplyParams,
        context: anytype,
        comptime onIdentified: fn (ctx: @TypeOf(context), peer_id: pid.PeerId, msg: MessageView) void,
    ) (Error || Io.Reader.ShortError || Io.Writer.Error || std.mem.Allocator.Error)!void {
        const rv = self.replyView(reply_params);
        const out = try encode(self.allocator, rv);
        defer self.allocator.free(out);
        try Io.Writer.writeAll(w, out);
        try Io.Writer.flush(w);

        const wire = try readIdentifyWireAlloc(r, self.allocator, limits.max_message_bytes);
        defer self.allocator.free(wire);
        var owned = try decodeOwned(self.allocator, wire, limits);
        defer owned.deinit(self.allocator);
        onIdentified(context, peer, owned.asView());
    }
};

test "protocol_line ends with newline" {
    try std.testing.expect(std.mem.endsWith(u8, protocol_line, "\n"));
}

test "identify encode decode round trip" {
    const a = std.testing.allocator;
    const la1 = [_]u8{ 0x04, 0x7f, 0x00, 0x00, 0x01, 0x02, 0x03 };
    const la2 = [_]u8{ 0x04, 0x7f, 0x00, 0x00, 0x01, 0x02, 0x04 };
    const view: MessageView = .{
        .protocol_version = "ipfs/0.1.0",
        .agent_version = "zig-libp2p/test",
        .public_key = &[_]u8{ 0xAA, 0xBB },
        .listen_addrs = &.{ &la1, &la2 },
        .protocols = &.{ "/ipfs/id/1.0.0", "/ipfs/ping/1.0.0" },
        .observed_addr = &[_]u8{ 1, 2, 3 },
    };
    const buf = try encode(a, view);
    defer a.free(buf);
    var dec = try decodeOwned(a, buf, .standard);
    defer dec.deinit(a);
    const dv = dec.asView();
    try std.testing.expectEqualStrings("ipfs/0.1.0", dv.protocol_version.?);
    try std.testing.expectEqualStrings("zig-libp2p/test", dv.agent_version.?);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, dv.public_key.?);
    try std.testing.expectEqual(@as(usize, 2), dv.listen_addrs.len);
    try std.testing.expectEqualSlices(u8, &la1, dv.listen_addrs[0]);
    try std.testing.expectEqualSlices(u8, &la2, dv.listen_addrs[1]);
    try std.testing.expectEqual(@as(usize, 2), dv.protocols.len);
    try std.testing.expectEqualStrings("/ipfs/id/1.0.0", dv.protocols[0]);
    try std.testing.expectEqualStrings("/ipfs/ping/1.0.0", dv.protocols[1]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, dv.observed_addr.?);
}

test "Identify handleInbound and onConnectionEstablished" {
    const a = std.testing.allocator;
    var id = try Identify.init(a, "agent-a/1");
    defer id.deinit();

    const peer = try pid.PeerId.random();

    const Context = struct {
        seen_agent: ?[]const u8 = null,
        fn onInbound(ctx: *@This(), _: pid.PeerId, msg: MessageView) void {
            ctx.seen_agent = msg.agent_version;
        }
    };

    // Responder path: inbound wire is initiator's message.
    var inbound_buf: [256]u8 = undefined;
    const init_view: MessageView = .{
        .protocol_version = "ipfs/0.1.0",
        .agent_version = "agent-b/1",
        .protocols = &.{"/x"},
    };
    const init_wire = try encode(a, init_view);
    defer a.free(init_wire);
    @memcpy(inbound_buf[0..init_wire.len], init_wire);
    var rr = Io.Reader.fixed(inbound_buf[0..init_wire.len]);

    var out_buf: [512]u8 = undefined;
    var ww = Io.Writer.fixed(&out_buf);

    var ctx: Context = .{};
    try id.handleInbound(peer, &rr, &ww, .standard, .{
        .listen_addrs = &.{&[_]u8{9}},
        .protocols = &.{"/y"},
        .observed_addr = &[_]u8{8},
    }, &ctx, Context.onInbound);
    try std.testing.expectEqualStrings("agent-b/1", ctx.seen_agent.?);

    const reply_slice = ww.buffered();
    var dec_reply = try decodeOwned(a, reply_slice, .standard);
    defer dec_reply.deinit(a);
    try std.testing.expectEqualStrings("agent-a/1", dec_reply.asView().agent_version.?);
    try std.testing.expectEqual(@as(usize, 1), dec_reply.asView().listen_addrs.len);
    try std.testing.expectEqual(@as(u8, 9), dec_reply.asView().listen_addrs[0][0]);

    // Initiator path: write then read.
    var ctx2: Context = .{};
    var pipe_out: [512]u8 = undefined;
    var w2 = Io.Writer.fixed(&pipe_out);
    const respond_view: MessageView = .{
        .agent_version = "agent-b/2",
        .protocols = &.{"/p"},
    };
    const respond_wire = try encode(a, respond_view);
    defer a.free(respond_wire);
    var r2 = Io.Reader.fixed(respond_wire);

    try id.onConnectionEstablished(peer, &r2, &w2, .standard, .{
        .listen_addrs = &.{},
        .protocols = &.{"/q"},
    }, &ctx2, Context.onInbound);
    try std.testing.expectEqualStrings("agent-b/2", ctx2.seen_agent.?);
    const sent = w2.buffered();
    var dec_sent = try decodeOwned(a, sent, .standard);
    defer dec_sent.deinit(a);
    try std.testing.expectEqualStrings("agent-a/1", dec_sent.asView().agent_version.?);
}
