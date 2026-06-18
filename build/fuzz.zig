const std = @import("std");

pub fn addFuzzStep(b: *std.Build, mod: *std.Build.Module) *std.Build.Step {
    const wire_fuzz_tests = b.addTest(.{
        .name = "wire-fuzz",
        .root_module = mod,
        .filters = &.{"wire fuzz"},
    });
    const run_wire_fuzz = b.addRunArtifact(wire_fuzz_tests);
    const fuzz_step = b.step(
        "fuzz",
        "Run `wire fuzz …` tests (std.testing.fuzz smoke); long libFuzzer runs: zig build test --fuzz (#44)",
    );
    fuzz_step.dependOn(&run_wire_fuzz.step);
    return fuzz_step;
}
