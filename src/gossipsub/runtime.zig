//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../protocols/gossipsub/runtime.zig");

pub const Gossipsub = _shim_src.Gossipsub;
pub const GossipsubConfig = _shim_src.GossipsubConfig;
pub const InitConfigError = _shim_src.InitConfigError;
pub const OutDelivery = _shim_src.OutDelivery;
pub const OutDeliveryKind = _shim_src.OutDeliveryKind;
pub const TopicValidator = _shim_src.TopicValidator;
pub const ValidationResult = _shim_src.ValidationResult;
