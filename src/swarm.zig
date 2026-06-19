//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./core/swarm.zig");

pub const CommandDispatchHook = _shim_src.CommandDispatchHook;
pub const DeferredCommandQueue = _shim_src.DeferredCommandQueue;
pub const DcutrFailReason = _shim_src.DcutrFailReason;
pub const Event = _shim_src.Event;
pub const EventQueuePolicy = _shim_src.EventQueuePolicy;
pub const GossipMessage = _shim_src.GossipMessage;
pub const InitError = _shim_src.InitError;
pub const LogLevel = _shim_src.LogLevel;
pub const NextEventError = _shim_src.NextEventError;
pub const OwnedCommand = _shim_src.OwnedCommand;
pub const RelayReservationKind = _shim_src.RelayReservationKind;
pub const RpcError = _shim_src.RpcError;
pub const RpcRequest = _shim_src.RpcRequest;
pub const RpcResponseChunk = _shim_src.RpcResponseChunk;
pub const RpcResponseEnd = _shim_src.RpcResponseEnd;
pub const SubmitError = _shim_src.SubmitError;
pub const Swarm = _shim_src.Swarm;
pub const SwarmCommand = _shim_src.SwarmCommand;
pub const TrimReason = _shim_src.TrimReason;
pub const command_capacity = _shim_src.command_capacity;
pub const commands_per_tick = _shim_src.commands_per_tick;
pub const default_event_capacity = _shim_src.default_event_capacity;
pub const default_hook_deadline_ms = _shim_src.default_hook_deadline_ms;
pub const destroyCommand = _shim_src.destroyCommand;
