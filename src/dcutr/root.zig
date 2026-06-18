//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/dcutr/root.zig");

pub const Coordinator = _shim_src.Coordinator;
pub const CoordinatorConfig = _shim_src.CoordinatorConfig;
pub const DirectDialRequest = _shim_src.DirectDialRequest;
pub const coordinator = _shim_src.coordinator;
pub const protocol_id = _shim_src.protocol_id;
pub const retry = _shim_src.retry;
pub const wire = _shim_src.wire;
