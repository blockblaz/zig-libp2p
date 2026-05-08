//! Pure-Zig libp2p stack for Lean Ethereum clients (Zeam integration).
//!
//! The Zeam-compatible C ABI lives in the static library root `zeam_glue_root.zig`
//! (see `build.zig`); this module is the dependency-friendly API surface.

pub const protocol = @import("protocol.zig");
