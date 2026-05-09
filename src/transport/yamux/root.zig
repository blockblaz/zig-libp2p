//! Yamux v0 stream multiplexer (libp2p profile).
//!
//! See `session.zig` for the full state machine and edge-case notes.  This
//! file just re-exports the public API.

const session_mod = @import("session.zig");
const frame_mod = @import("frame.zig");

pub const Session = session_mod.Session;
pub const Stream = session_mod.Stream;
pub const Role = session_mod.Role;
pub const Config = session_mod.Config;
pub const SessionError = session_mod.SessionError;

pub const Header = frame_mod.Header;
pub const Type = frame_mod.Type;
pub const Flags = frame_mod.Flags;
pub const GoAwayCode = frame_mod.GoAwayCode;

/// Multistream-select id zig-libp2p will use when negotiating Yamux on top of
/// a TCP+security stream (e.g. `/multistream/1.0.0` → `/yamux/1.0.0`).
pub const multistream_protocol_id: []const u8 = "/yamux/1.0.0";

test {
    _ = @import("frame.zig");
    _ = @import("session.zig");
}
