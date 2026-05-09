//! Mplex (`/mplex/6.7.0`) stream multiplexer (libp2p profile).
//!
//! See `session.zig` for the state machine, edge-case notes, and tests.

const session_mod = @import("session.zig");
const frame_mod = @import("frame.zig");

pub const Session = session_mod.Session;
pub const Stream = session_mod.Stream;
pub const Direction = session_mod.Direction;
pub const Config = session_mod.Config;
pub const SessionError = session_mod.SessionError;

pub const Header = frame_mod.Header;
pub const Flag = frame_mod.Flag;
pub const FrameError = frame_mod.FrameError;
pub const default_max_frame_payload = frame_mod.default_max_frame_payload;
pub const multistream_protocol_id = frame_mod.multistream_protocol_id;

test {
    _ = @import("frame.zig");
    _ = @import("session.zig");
}
