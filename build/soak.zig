const std = @import("std");

/// Opt-in long / loopback tests kept out of `zig build test` for CI speed ([#235](https://github.com/blockblaz/zig-libp2p/issues/235)).
pub fn addSoakStep(b: *std.Build, mod: *std.Build.Module) *std.Build.Step {
    const soak_tests = b.addTest(.{
        .name = "soak",
        .root_module = mod,
        .filters = &.{
            "QuicRuntime: long-running sustained gossipsub",
            "quic tls remote peer id matches listener key",
        },
    });
    const run_soak = b.addRunArtifact(soak_tests);
    const soak_step = b.step(
        "soak-test",
        "Run opt-in long QUIC loopback / sustained gossipsub tests (#235)",
    );
    soak_step.dependOn(&run_soak.step);
    return soak_step;
}
