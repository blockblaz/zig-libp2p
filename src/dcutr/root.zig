//! DCUtR — Direct Connection Upgrade through Relay (#91).

pub const wire = @import("wire.zig");
pub const coordinator = @import("coordinator.zig");

pub const Coordinator = coordinator.Coordinator;
pub const CoordinatorConfig = coordinator.Config;
pub const DirectDialRequest = coordinator.DirectDialRequest;
pub const protocol_id = wire.protocol_id;

test {
    _ = @import("wire.zig");
    _ = @import("coordinator.zig");
}
