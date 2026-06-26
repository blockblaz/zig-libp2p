const std = @import("std");

const deps_mod = @import("deps.zig");

/// Opt-in long / loopback tests kept out of `zig build test` for CI speed ([#235](https://github.com/blockblaz/zig-libp2p/issues/235)).
pub fn addSoakStep(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step {
    const d = deps_mod.createDeps(b, target, optimize, .{ .enable_soak_tests = true });

    const soak_tests = b.addTest(.{
        .name = "soak",
        .root_module = d.mod,
        .filters = &.{
            "QuicRuntime: long-running sustained gossipsub",
            "QuicRuntime: gossip saturation race repro",
        },
    });
    const run_soak = b.addRunArtifact(soak_tests);
    const soak_step = b.step(
        "soak-test",
        "Run opt-in long QUIC sustained gossipsub soak test (#235)",
    );
    soak_step.dependOn(&run_soak.step);
    return soak_step;
}
