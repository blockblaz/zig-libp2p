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
const proto = @import("../../primitives/protobuf/wire.zig");
const pid = @import("peer_id");

/// Multistream negotiation line including newline (Identify 1.0.0).
pub const protocol_line: []const u8 = "/ipfs/id/1.0.0\n";

/// Multistream negotiation line for Identify Push (#88): same wire payload, one-way.
/// Spec: https://github.com/libp2p/specs/blob/master/identify/README.md#identify-push
pub const push_protocol_line: []const u8 = "/ipfs/id/push/1.0.0\n";

/// libp2p RFC 0002 Signed Envelope — domain prefix the signature covers (#88).
/// Spec: https://github.com/libp2p/specs/blob/master/RFC/0002-signed-envelopes.md
pub const signed_envelope_domain: []const u8 = "libp2p-peer-record";

/// `payload_type` multicodec for a [`PeerRecord`] inside a SignedEnvelope (RFC 0002 §appendix).
pub const peer_record_payload_type: []const u8 = &.{ 0x03, 0x01 };

pub const Error = proto.Error || error{
    /// Same global tag as [`errors.GossipsubError.PayloadTooLarge`] / [`errors.ReqRespError.PayloadTooLarge`] (#45).
    PayloadTooLarge,
    TooManyListenAddrs,
    TooManyProtocols,
    IdentifyMessageTooLarge,
    UnsupportedIdentifyField,
    /// Signed envelope signature failed RFC 0002 verification (#123).
    BadSignature,
    /// `signed_peer_record` payload type is not a libp2p PeerRecord.
    InvalidSignedEnvelopePayloadType,
    /// PeerRecord `peer_id` does not match the authenticated transport peer.
    SignedPeerRecordPeerIdMismatch,
    MalformedSignedEnvelope,
    MalformedPeerRecord,
    BufferTooSmall,
} || std.mem.Allocator.Error;

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
    if (wire.len > limits.max_message_bytes) return error.PayloadTooLarge;

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
    listen = .empty;
    out.protocols = try protos.toOwnedSlice(allocator);
    protos = .empty;

    return out;
}

/// Read until end of stream (or `max_total`), returning one contiguous payload.
pub fn readIdentifyWireAlloc(r: *Io.Reader, allocator: std.mem.Allocator, max_total: usize) (Io.Reader.ShortError || std.mem.Allocator.Error || error{ IdentifyMessageTooLarge, Overflow })![]u8 {
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

    fn verifyInboundSignedPeerRecordIfPresent(
        self: *Identify,
        transport_peer: pid.PeerId,
        msg: *const MessageOwned,
    ) Error!void {
        const spr = msg.signed_peer_record orelse return;
        var rec = try verifySignedPeerRecord(self.allocator, spr, transport_peer);
        rec.deinit(self.allocator);
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
    ) (Error || Io.Reader.ShortError || Io.Writer.Error || std.mem.Allocator.Error || error{Overflow})!void {
        const wire = try readIdentifyWireAlloc(r, self.allocator, limits.max_message_bytes);
        defer self.allocator.free(wire);
        var owned = try decodeOwned(self.allocator, wire, limits);
        defer owned.deinit(self.allocator);
        try self.verifyInboundSignedPeerRecordIfPresent(peer, &owned);
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
    ) (Error || Io.Reader.ShortError || Io.Writer.Error || std.mem.Allocator.Error || error{Overflow})!void {
        const rv = self.replyView(reply_params);
        const out = try encode(self.allocator, rv);
        defer self.allocator.free(out);
        try Io.Writer.writeAll(w, out);
        try Io.Writer.flush(w);

        const wire = try readIdentifyWireAlloc(r, self.allocator, limits.max_message_bytes);
        defer self.allocator.free(wire);
        var owned = try decodeOwned(self.allocator, wire, limits);
        defer owned.deinit(self.allocator);
        try self.verifyInboundSignedPeerRecordIfPresent(peer, &owned);
        onIdentified(context, peer, owned.asView());
    }

    /// Send-only Identify Push (`/ipfs/id/push/1.0.0`): write our Identify and close (#88).
    /// The receiver decodes the same wire format as plain Identify; there is no reply.
    pub fn sendPush(
        self: *const Identify,
        w: *Io.Writer,
        reply_params: ReplyParams,
    ) (Error || Io.Writer.Error || std.mem.Allocator.Error)!void {
        const rv = self.replyView(reply_params);
        const out = try encode(self.allocator, rv);
        defer self.allocator.free(out);
        try Io.Writer.writeAll(w, out);
        try Io.Writer.flush(w);
    }

    /// Receive-only Identify Push handler (#88): read the wire payload, decode, invoke
    /// `onIdentified`. No reply is written. `MessageView` slices passed to the callback
    /// are borrowed from the deferred `MessageOwned` and MUST be copied if the caller
    /// wants to retain them.
    pub fn handlePushInbound(
        self: *Identify,
        peer: pid.PeerId,
        r: *Io.Reader,
        limits: Limits,
        context: anytype,
        comptime onIdentified: fn (ctx: @TypeOf(context), peer_id: pid.PeerId, msg: MessageView) void,
    ) (Error || Io.Reader.ShortError || std.mem.Allocator.Error || error{Overflow})!void {
        const wire = try readIdentifyWireAlloc(r, self.allocator, limits.max_message_bytes);
        defer self.allocator.free(wire);
        var owned = try decodeOwned(self.allocator, wire, limits);
        defer owned.deinit(self.allocator);
        try self.verifyInboundSignedPeerRecordIfPresent(peer, &owned);
        onIdentified(context, peer, owned.asView());
    }
};

// ---------------------------------------------------------------------------
// libp2p Signed Envelope + PeerRecord (RFC 0002), see [`signed_envelope_domain`].
// ---------------------------------------------------------------------------

pub const SignedEnvelopeOwned = struct {
    /// libp2p PublicKey protobuf (matches Identify field 1).
    public_key: []u8,
    /// Multicodec bytes identifying the payload type (e.g. [`peer_record_payload_type`]).
    payload_type: []u8,
    /// Raw payload bytes the signature covers (e.g. an encoded [`PeerRecordOwned`]).
    payload: []u8,
    /// Signature bytes verified by [`signedEnvelopeVerifyMessage`] + the embedder's key.
    signature: []u8,

    pub fn deinit(self: *SignedEnvelopeOwned, allocator: std.mem.Allocator) void {
        allocator.free(self.public_key);
        allocator.free(self.payload_type);
        allocator.free(self.payload);
        allocator.free(self.signature);
        self.* = undefined;
    }
};

/// Decode a SignedEnvelope wire blob (RFC 0002). Required fields are `public_key`,
/// `payload_type`, `payload`, and `signature`; missing any of them returns `error.MalformedSignedEnvelope`.
pub fn decodeSignedEnvelope(allocator: std.mem.Allocator, wire: []const u8) (Error || std.mem.Allocator.Error || error{MalformedSignedEnvelope})!SignedEnvelopeOwned {
    if (wire.len > 64 * 1024) return error.PayloadTooLarge;
    var public_key: ?[]u8 = null;
    var payload_type: ?[]u8 = null;
    var payload: ?[]u8 = null;
    var signature: ?[]u8 = null;
    errdefer {
        if (public_key) |x| allocator.free(x);
        if (payload_type) |x| allocator.free(x);
        if (payload) |x| allocator.free(x);
        if (signature) |x| allocator.free(x);
    }

    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, 32 * 1024);
        off += nv.total;
        if (key.wire_type != .length_delimited) continue;
        switch (key.field_number) {
            1 => {
                if (public_key != null) continue;
                public_key = try allocator.dupe(u8, nv.value);
            },
            2 => {
                if (payload_type != null) continue;
                payload_type = try allocator.dupe(u8, nv.value);
            },
            3 => {
                if (payload != null) continue;
                payload = try allocator.dupe(u8, nv.value);
            },
            5 => {
                if (signature != null) continue;
                signature = try allocator.dupe(u8, nv.value);
            },
            else => {},
        }
    }

    return SignedEnvelopeOwned{
        .public_key = public_key orelse return error.MalformedSignedEnvelope,
        .payload_type = payload_type orelse return error.MalformedSignedEnvelope,
        .payload = payload orelse return error.MalformedSignedEnvelope,
        .signature = signature orelse return error.MalformedSignedEnvelope,
    };
}

/// Build the signature-domain message a SignedEnvelope signer must produce / a
/// verifier must check: `varint(domain_len) || domain || varint(payload_type_len)
/// || payload_type || varint(payload_len) || payload` (RFC 0002 §"Signature").
/// `out_buf` must be at least `domain.len + payload_type.len + payload.len + 24`.
pub fn signedEnvelopeVerifyMessage(
    out_buf: []u8,
    domain: []const u8,
    payload_type: []const u8,
    payload: []const u8,
) error{BufferTooSmall}![]const u8 {
    const need = domain.len + payload_type.len + payload.len + 24;
    if (out_buf.len < need) return error.BufferTooSmall;
    var i: usize = 0;
    i += writeUvarint(out_buf[i..], domain.len);
    @memcpy(out_buf[i..][0..domain.len], domain);
    i += domain.len;
    i += writeUvarint(out_buf[i..], payload_type.len);
    @memcpy(out_buf[i..][0..payload_type.len], payload_type);
    i += payload_type.len;
    i += writeUvarint(out_buf[i..], payload.len);
    @memcpy(out_buf[i..][0..payload.len], payload);
    i += payload.len;
    return out_buf[0..i];
}

fn writeUvarint(out: []u8, value: usize) usize {
    var v = value;
    var i: usize = 0;
    while (v >= 0x80) : (i += 1) {
        out[i] = @as(u8, @intCast(v & 0x7f)) | 0x80;
        v >>= 7;
    }
    out[i] = @intCast(v);
    return i + 1;
}

pub const PeerRecordOwned = struct {
    /// libp2p PeerId bytes (multihash of the libp2p public key protobuf).
    peer_id: []u8,
    /// Monotonic record version per-peer; lets receivers ignore stale updates.
    seq: u64,
    /// Listen multiaddrs (each a length-prefixed binary multiaddr, wire-format identical
    /// to Identify `listen_addrs`).
    addresses: [][]u8,

    pub fn deinit(self: *PeerRecordOwned, allocator: std.mem.Allocator) void {
        allocator.free(self.peer_id);
        for (self.addresses) |a| allocator.free(a);
        allocator.free(self.addresses);
        self.* = undefined;
    }
};

/// Decode a libp2p RFC 0002 PeerRecord protobuf.
///
/// Wire: `bytes peer_id = 1; uint64 seq = 2; repeated AddressInfo addresses = 3;`
/// where `AddressInfo { bytes multiaddr = 1; }`.
pub fn decodePeerRecord(allocator: std.mem.Allocator, wire: []const u8) (Error || std.mem.Allocator.Error || error{MalformedPeerRecord})!PeerRecordOwned {
    if (wire.len > 32 * 1024) return error.PayloadTooLarge;
    var peer_id: ?[]u8 = null;
    var seq: u64 = 0;
    var addresses = std.ArrayList([]u8).empty;
    errdefer {
        if (peer_id) |x| allocator.free(x);
        for (addresses.items) |a| allocator.free(a);
        addresses.deinit(allocator);
    }

    var off: usize = 0;
    while (off < wire.len) {
        const key = try proto.decodeFieldKey(wire[off..]);
        off += key.len;
        const nv = try proto.nextFieldValueLimited(wire[off..], key.wire_type, 8 * 1024);
        off += nv.total;
        switch (key.field_number) {
            1 => {
                if (key.wire_type != .length_delimited) return error.MalformedPeerRecord;
                if (peer_id != null) continue;
                peer_id = try allocator.dupe(u8, nv.value);
            },
            2 => {
                if (key.wire_type != .varint) return error.MalformedPeerRecord;
                const vv = try proto.decodeVarUInt64(nv.value);
                seq = vv.value;
            },
            3 => {
                if (key.wire_type != .length_delimited) return error.MalformedPeerRecord;
                if (addresses.items.len >= 128) return error.PayloadTooLarge;
                // Parse the nested AddressInfo { multiaddr = 1; } message.
                var addr_off: usize = 0;
                while (addr_off < nv.value.len) {
                    const ak = try proto.decodeFieldKey(nv.value[addr_off..]);
                    addr_off += ak.len;
                    const av = try proto.nextFieldValueLimited(nv.value[addr_off..], ak.wire_type, 1024);
                    addr_off += av.total;
                    if (ak.field_number == 1 and ak.wire_type == .length_delimited) {
                        try addresses.append(allocator, try allocator.dupe(u8, av.value));
                        break; // one multiaddr per AddressInfo
                    }
                }
            },
            else => {},
        }
    }

    return PeerRecordOwned{
        .peer_id = peer_id orelse return error.MalformedPeerRecord,
        .seq = seq,
        .addresses = try addresses.toOwnedSlice(allocator),
    };
}

fn verifySignedEnvelopeSignature(
    key_type: pid.KeyType,
    key_data: []const u8,
    signature: []const u8,
    message: []const u8,
) Error!void {
    const Ed25519 = std.crypto.sign.Ed25519;
    const Secp256k1 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    switch (key_type) {
        .ED25519 => {
            if (signature.len != Ed25519.Signature.encoded_length) return error.BadSignature;
            const pk = Ed25519.PublicKey.fromBytes(key_data[0..Ed25519.PublicKey.encoded_length].*) catch
                return error.BadSignature;
            const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            sig.verify(message, pk) catch return error.BadSignature;
        },
        .SECP256K1 => {
            const pk = Secp256k1.PublicKey.fromSec1(key_data) catch return error.BadSignature;
            const sig = Secp256k1.Signature.fromDer(signature) catch return error.BadSignature;
            sig.verify(message, pk) catch return error.BadSignature;
        },
        .ECDSA => {
            const sec1 = sec1FromSubjectPublicKeyInfoPkix(key_data) catch return error.BadSignature;
            const pk = EcdsaP256.PublicKey.fromSec1(sec1) catch return error.BadSignature;
            const sig = EcdsaP256.Signature.fromDer(signature) catch return error.BadSignature;
            sig.verify(message, pk) catch return error.BadSignature;
        },
        else => return error.BadSignature,
    }
}

fn sec1FromSubjectPublicKeyInfoPkix(spki: []const u8) Error![]const u8 {
    const seq = try readConstructedTLV(spki, 0, 0x30);
    if (seq.next != spki.len) return error.BadSignature;
    var pos: usize = 0;
    const algo = try readConstructedTLV(seq.payload, pos, 0x30);
    pos = algo.next;
    const bitstr = try readConstructedTLV(seq.payload, pos, 0x03);
    if (bitstr.payload.len < 2 or bitstr.payload[0] != 0) return error.BadSignature;
    return bitstr.payload[1..];
}

fn readConstructedTLV(buf: []const u8, pos: usize, expected_tag: u8) Error!struct { payload: []const u8, next: usize } {
    if (pos >= buf.len or buf[pos] != expected_tag) return error.BadSignature;
    const lh = try readShortDerLength(buf, pos + 1);
    const start = pos + 1 + lh.header;
    const end = start + lh.len;
    if (end > buf.len) return error.BadSignature;
    return .{ .payload = buf[start..end], .next = end };
}

fn readShortDerLength(buf: []const u8, pos: usize) Error!struct { len: usize, header: usize } {
    if (pos >= buf.len) return error.BadSignature;
    const first = buf[pos];
    if (first & 0x80 == 0) {
        return .{ .len = first, .header = 1 };
    }
    const nbytes = first & 0x7f;
    if (nbytes == 0 or nbytes > 4 or pos + 1 + nbytes > buf.len) return error.BadSignature;
    var len: usize = 0;
    for (buf[pos + 1 .. pos + 1 + nbytes]) |b| {
        len = (len << 8) | b;
    }
    return .{ .len = len, .header = 1 + nbytes };
}

/// Verify RFC 0002 `signed_peer_record` and return the decoded [`PeerRecordOwned`].
/// `transport_peer` must be the peer authenticated by the security layer (TLS / Noise).
pub fn verifySignedPeerRecord(
    allocator: std.mem.Allocator,
    signed_peer_record_wire: []const u8,
    transport_peer: pid.PeerId,
) (Error || std.mem.Allocator.Error)!PeerRecordOwned {
    var env = try decodeSignedEnvelope(allocator, signed_peer_record_wire);
    defer env.deinit(allocator);

    if (!std.mem.eql(u8, env.payload_type, peer_record_payload_type))
        return error.InvalidSignedEnvelopePayloadType;

    var msg_buf: [96 * 1024]u8 = undefined;
    const message = try signedEnvelopeVerifyMessage(
        &msg_buf,
        signed_envelope_domain,
        env.payload_type,
        env.payload,
    );

    const reader = pid.PublicKeyReader.init(env.public_key) catch return error.BadSignature;
    try verifySignedEnvelopeSignature(reader.getType(), reader.getData(), env.signature, message);

    const key_dup = try allocator.dupe(u8, reader.getData());
    defer allocator.free(key_dup);
    var pk = pid.PublicKey{ .type = reader.getType(), .data = key_dup };
    const envelope_peer = pid.PeerId.fromPublicKey(allocator, &pk) catch return error.BadSignature;
    if (!envelope_peer.eql(&transport_peer)) return error.SignedPeerRecordPeerIdMismatch;

    var rec = try decodePeerRecord(allocator, env.payload);
    errdefer rec.deinit(allocator);

    var transport_bytes: [128]u8 = undefined;
    const tb = transport_peer.toBytes(&transport_bytes) catch return error.SignedPeerRecordPeerIdMismatch;
    if (!std.mem.eql(u8, tb, rec.peer_id)) return error.SignedPeerRecordPeerIdMismatch;

    return rec;
}

/// Test-only helper: build a SignedEnvelope wire blob (RFC 0002) wrapping a
/// `PeerRecord` payload, signed by an Ed25519 keypair. Exposed for unit tests
/// in other modules (e.g. gossipsub PX envelope verification).
pub fn encodeSignedPeerRecordTestWire(
    allocator: std.mem.Allocator,
    host_kp: std.crypto.sign.Ed25519.KeyPair,
    peer_record_wire: []const u8,
    opts: struct {
        corrupt_signature: bool = false,
    },
) anyerror![]u8 {
    const host_pub_proto = blk: {
        var pk = pid.PublicKey{ .type = .ED25519, .data = &host_kp.public_key.bytes };
        break :blk try pk.encode(allocator);
    };
    defer allocator.free(host_pub_proto);

    var msg_buf: [96 * 1024]u8 = undefined;
    const message = try signedEnvelopeVerifyMessage(
        &msg_buf,
        signed_envelope_domain,
        peer_record_payload_type,
        peer_record_wire,
    );
    const sig = host_kp.sign(message, null) catch return error.BadSignature;
    var sig_bytes = sig.toBytes();
    if (opts.corrupt_signature) sig_bytes[0] ^= 0xff;

    var wire = std.ArrayList(u8).empty;
    errdefer wire.deinit(allocator);
    try proto.appendLengthDelimited(&wire, allocator, 1, host_pub_proto);
    try proto.appendLengthDelimited(&wire, allocator, 2, peer_record_payload_type);
    try proto.appendLengthDelimited(&wire, allocator, 3, peer_record_wire);
    try proto.appendLengthDelimited(&wire, allocator, 5, &sig_bytes);
    return try wire.toOwnedSlice(allocator);
}

/// Test-only helper: build a bare `PeerRecord` protobuf body. Exposed for
/// reuse from other modules' unit tests.
pub fn encodePeerRecordTestWire(allocator: std.mem.Allocator, peer_id_bytes: []const u8, seq: u64) ![]u8 {
    var wire = std.ArrayList(u8).empty;
    errdefer wire.deinit(allocator);
    try proto.appendLengthDelimited(&wire, allocator, 1, peer_id_bytes);
    try proto.appendFieldKey(&wire, allocator, 2, .varint);
    try proto.appendVarUInt64(&wire, allocator, seq);
    return try wire.toOwnedSlice(allocator);
}

test "verifySignedPeerRecord rejects bad signature" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0xA1);
    const host_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    var transport_pk = pid.PublicKey{ .type = .ED25519, .data = &host_kp.public_key.bytes };
    const transport = try pid.PeerId.fromPublicKey(a, &transport_pk);

    var peer_id_buf: [128]u8 = undefined;
    const peer_id_bytes = try transport.toBytes(&peer_id_buf);
    const rec_wire = try encodePeerRecordTestWire(a, peer_id_bytes, 1);
    defer a.free(rec_wire);

    const spr = try encodeSignedPeerRecordTestWire(a, host_kp, rec_wire, .{ .corrupt_signature = true });
    defer a.free(spr);

    try std.testing.expectError(error.BadSignature, verifySignedPeerRecord(a, spr, transport));
}

test "verifySignedPeerRecord rejects transport peer mismatch" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0xA2);
    const host_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    var signing_pk = pid.PublicKey{ .type = .ED25519, .data = &host_kp.public_key.bytes };
    const signing_peer = try pid.PeerId.fromPublicKey(a, &signing_pk);

    var peer_id_buf: [128]u8 = undefined;
    const peer_id_bytes = try signing_peer.toBytes(&peer_id_buf);
    const rec_wire = try encodePeerRecordTestWire(a, peer_id_bytes, 1);
    defer a.free(rec_wire);

    const spr = try encodeSignedPeerRecordTestWire(a, host_kp, rec_wire, .{});
    defer a.free(spr);

    const other = try pid.PeerId.random();
    try std.testing.expectError(
        error.SignedPeerRecordPeerIdMismatch,
        verifySignedPeerRecord(a, spr, other),
    );
}

test "verifySignedPeerRecord rejects peer_id field mismatch" {
    const a = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0xA3);
    const host_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    var transport_pk = pid.PublicKey{ .type = .ED25519, .data = &host_kp.public_key.bytes };
    const transport = try pid.PeerId.fromPublicKey(a, &transport_pk);

    const rec_wire = try encodePeerRecordTestWire(a, "wrong-peer-id-bytes", 1);
    defer a.free(rec_wire);

    const spr = try encodeSignedPeerRecordTestWire(a, host_kp, rec_wire, .{});
    defer a.free(spr);

    try std.testing.expectError(
        error.SignedPeerRecordPeerIdMismatch,
        verifySignedPeerRecord(a, spr, transport),
    );
}

test "protocol_line ends with newline" {
    try std.testing.expect(std.mem.endsWith(u8, protocol_line, "\n"));
}

test "push_protocol_line is well-formed" {
    try std.testing.expect(std.mem.endsWith(u8, push_protocol_line, "\n"));
    try std.testing.expect(std.mem.startsWith(u8, push_protocol_line, "/ipfs/id/push/"));
}

test "Identify.sendPush writes our message; handlePushInbound reads it" {
    const a = std.testing.allocator;
    var id_sender = try Identify.init(a, "agent-sender/1");
    defer id_sender.deinit();
    var id_receiver = try Identify.init(a, "agent-receiver/1");
    defer id_receiver.deinit();

    var pipe: [512]u8 = undefined;
    var ww = Io.Writer.fixed(&pipe);
    try id_sender.sendPush(&ww, .{ .listen_addrs = &.{}, .protocols = &.{"/x"} });
    const written = ww.buffered();
    var rr = Io.Reader.fixed(written);

    const Context = struct {
        allocator: std.mem.Allocator,
        seen_agent: ?[]u8 = null,
        fn cb(ctx: *@This(), _: pid.PeerId, msg: MessageView) void {
            if (msg.agent_version) |av| ctx.seen_agent = ctx.allocator.dupe(u8, av) catch null;
        }
    };
    var ctx: Context = .{ .allocator = a };
    defer if (ctx.seen_agent) |s| a.free(s);

    const peer = try pid.PeerId.random();
    try id_receiver.handlePushInbound(peer, &rr, .standard, &ctx, Context.cb);
    try std.testing.expectEqualStrings("agent-sender/1", ctx.seen_agent.?);
}

test "SignedEnvelope decode requires public_key, payload_type, payload, signature" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).empty;
    defer list.deinit(a);
    try proto.appendLengthDelimited(&list, a, 1, "pubkey-bytes");
    try proto.appendLengthDelimited(&list, a, 2, peer_record_payload_type);
    try proto.appendLengthDelimited(&list, a, 3, "the-payload");
    try proto.appendLengthDelimited(&list, a, 5, "sig-bytes");

    var env = try decodeSignedEnvelope(a, list.items);
    defer env.deinit(a);
    try std.testing.expectEqualStrings("pubkey-bytes", env.public_key);
    try std.testing.expectEqualSlices(u8, peer_record_payload_type, env.payload_type);
    try std.testing.expectEqualStrings("the-payload", env.payload);
    try std.testing.expectEqualStrings("sig-bytes", env.signature);
}

test "SignedEnvelope decode rejects missing signature" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).empty;
    defer list.deinit(a);
    try proto.appendLengthDelimited(&list, a, 1, "pubkey-bytes");
    try proto.appendLengthDelimited(&list, a, 2, peer_record_payload_type);
    try proto.appendLengthDelimited(&list, a, 3, "the-payload");
    try std.testing.expectError(error.MalformedSignedEnvelope, decodeSignedEnvelope(a, list.items));
}

test "signedEnvelopeVerifyMessage layout" {
    var buf: [256]u8 = undefined;
    const msg = try signedEnvelopeVerifyMessage(&buf, signed_envelope_domain, peer_record_payload_type, "payload-x");
    // Expect: varint(18) "libp2p-peer-record" varint(2) 0x03 0x01 varint(9) "payload-x"
    try std.testing.expectEqual(@as(u8, signed_envelope_domain.len), msg[0]);
    try std.testing.expectEqualStrings(signed_envelope_domain, msg[1 .. 1 + signed_envelope_domain.len]);
    const after_domain = 1 + signed_envelope_domain.len;
    try std.testing.expectEqual(@as(u8, 2), msg[after_domain]);
    try std.testing.expectEqualSlices(u8, peer_record_payload_type, msg[after_domain + 1 .. after_domain + 3]);
    try std.testing.expectEqual(@as(u8, 9), msg[after_domain + 3]);
    try std.testing.expectEqualStrings("payload-x", msg[after_domain + 4 ..][0..9]);
}

test "PeerRecord decode reads peer_id, seq, addresses" {
    const a = std.testing.allocator;
    var inner_addr = std.ArrayList(u8).empty;
    defer inner_addr.deinit(a);
    try proto.appendLengthDelimited(&inner_addr, a, 1, &[_]u8{ 0x04, 0x7f, 0x00, 0x00, 0x01 });

    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(a);
    try proto.appendLengthDelimited(&wire, a, 1, "peerid-bytes");
    try proto.appendFieldKey(&wire, a, 2, .varint);
    try proto.appendVarUInt64(&wire, a, 42);
    try proto.appendLengthDelimited(&wire, a, 3, inner_addr.items);

    var rec = try decodePeerRecord(a, wire.items);
    defer rec.deinit(a);
    try std.testing.expectEqualStrings("peerid-bytes", rec.peer_id);
    try std.testing.expectEqual(@as(u64, 42), rec.seq);
    try std.testing.expectEqual(@as(usize, 1), rec.addresses.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x04, 0x7f, 0x00, 0x00, 0x01 }, rec.addresses[0]);
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

    // `MessageView` is a borrowing view backed by the `MessageOwned` decoded inside
    // `handleInbound` / `onConnectionEstablished`. That `MessageOwned` is freed via
    // `defer owned.deinit(allocator)` on the way out, so the callback MUST copy any
    // bytes it wants to hold past the call.
    const Context = struct {
        allocator: std.mem.Allocator,
        seen_agent: ?[]u8 = null,
        fn onInbound(ctx: *@This(), _: pid.PeerId, msg: MessageView) void {
            if (msg.agent_version) |av| {
                ctx.seen_agent = ctx.allocator.dupe(u8, av) catch null;
            }
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

    var ctx: Context = .{ .allocator = a };
    defer if (ctx.seen_agent) |s| a.free(s);
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
    var ctx2: Context = .{ .allocator = a };
    defer if (ctx2.seen_agent) |s| a.free(s);
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
