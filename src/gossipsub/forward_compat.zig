//! Diagnostic logging for unknown protobuf fields seen on inbound gossipsub
//! RPC frames.
//!
//! Per protobuf spec (and as fixed in [`rpc.zig`] / [`control.zig`]) decoders
//! must skip unknown fields silently for forward compatibility. That makes us
//! tolerant of `rust-libp2p` / `go-libp2p` peers that ship extra vendor
//! fields, but it also hides the fact that those fields exist. We want to
//! eventually file an upstream issue documenting exactly what other
//! implementations put on the wire, so this module logs each unique
//! `(scope, field_number, wire_type)` triple **once** at `info` level on
//! first sighting; subsequent occurrences are silent.
//!
//! Deduplication uses a per-scope bit-set (atomic u64, lock-free) covering
//! field numbers `0..63` and wire types `0..7`. Field numbers `>= 64` are
//! always logged — they should be exceedingly rare for gossipsub-shaped
//! messages and the noise is acceptable for the diagnostic use case.
//!
//! Once we know what these fields are and decide whether to support them in
//! `zig-libp2p`, this module can be deleted along with the call sites.

const std = @import("std");
const wire = @import("../protobuf/wire.zig");

const log = std.log.scoped(.gossipsub_forward_compat);

/// Decoder location where an unknown field was observed. Add new variants as
/// more decoders gain logging.
pub const Scope = enum {
    /// Inner field inside `SubOpts` (`subscriptions[i]`).
    rpc_sub_opts,
    /// Top-level field inside `ControlMessage`.
    control_message,
    /// Inner field inside `ControlIHave`.
    control_ihave,
    /// Inner field inside `ControlIWant`.
    control_iwant,
    /// Inner field inside `ControlIDontWant`.
    control_idontwant,
    /// Inner field inside `ControlGraft`.
    control_graft,
    /// Inner field inside `ControlPrune`.
    control_prune,
    /// Inner field inside `ControlPrune.PeerInfo` (PX).
    control_peer_info,
    /// Inner field inside `ControlExtensions`.
    control_extensions,
};

// One bit per (scope, field_number 0..63, wire_type 0..7) = 64 * 8 = 512 bits.
// Pack as 8x u64; index = field_number * 8 + wire_type_raw. Atomic OR keeps
// the dedup check lock-free across all reactor threads.
const Bitset = struct {
    words: [8]std.atomic.Value(u64) = .{
        .init(0), .init(0), .init(0), .init(0),
        .init(0), .init(0), .init(0), .init(0),
    },

    fn markAndCheck(self: *Bitset, field_number: u32, wire_type_raw: u32) bool {
        const bit_idx: u32 = field_number * 8 + wire_type_raw;
        const word_idx: usize = bit_idx / 64;
        const bit_in_word: u6 = @intCast(bit_idx % 64);
        const mask: u64 = @as(u64, 1) << bit_in_word;
        const prev = self.words[word_idx].fetchOr(mask, .monotonic);
        return (prev & mask) == 0;
    }
};

var bitsets: [@typeInfo(Scope).@"enum".fields.len]Bitset = blk: {
    var arr: [@typeInfo(Scope).@"enum".fields.len]Bitset = undefined;
    for (&arr) |*b| b.* = .{};
    break :blk arr;
};

/// Record an unknown field. Logs once per `(scope, field_number, wire_type)`
/// at `info` so first occurrences are visible without changing log level;
/// further occurrences are silent.
pub fn noteUnknownField(scope: Scope, field_number: u32, wire_type: wire.WireType) void {
    const wt_raw: u32 = @intFromEnum(wire_type);

    // Out-of-range field numbers always log (rare path, no dedup).
    const first = if (field_number < 64 and wt_raw < 8) blk: {
        const idx: usize = @intFromEnum(scope);
        break :blk bitsets[idx].markAndCheck(field_number, wt_raw);
    } else true;

    if (!first) return;

    log.info(
        "unknown protobuf field on inbound gossipsub frame: scope={s} field_number={d} wire_type={s} (skipping for forward compat; tracking issue: log once per triple)",
        .{ @tagName(scope), field_number, @tagName(wire_type) },
    );
}

test "noteUnknownField logs first occurrence then dedups" {
    // We cannot easily assert on logger output here without a custom log
    // sink, but we can at least exercise the bit-flipping bookkeeping to
    // ensure the dedup state machine behaves.
    var bs: Bitset = .{};
    try std.testing.expect(bs.markAndCheck(7, 2));
    try std.testing.expect(!bs.markAndCheck(7, 2));
    try std.testing.expect(bs.markAndCheck(7, 0));
    try std.testing.expect(bs.markAndCheck(8, 2));
    try std.testing.expect(!bs.markAndCheck(8, 2));
}

test "noteUnknownField handles out-of-range field numbers without panicking" {
    noteUnknownField(.rpc_sub_opts, 999_999, .varint);
    noteUnknownField(.control_message, 64, .length_delimited);
}
