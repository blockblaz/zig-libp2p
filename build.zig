const std = @import("std");

const deps_mod = @import("build/deps.zig");
const examples_mod = @import("build/examples.zig");
const fuzz_mod = @import("build/fuzz.zig");
const soak_mod = @import("build/soak.zig");
const interop_mod = @import("build/interop.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const d = deps_mod.createDeps(b, target, optimize, .{});

    const unit_tests = b.addTest(.{
        .root_module = d.mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    _ = fuzz_mod.addFuzzStep(b, d.mod);
    _ = soak_mod.addSoakStep(b, target, optimize);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench_mod.addImport("zig_libp2p", d.mod);
    const bench_exe = b.addExecutable(.{
        .name = "zig-libp2p-bench",
        .root_module = bench_mod,
    });
    b.installArtifact(bench_exe);
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run microbenchmarks for hot paths (#19)");
    bench_step.dependOn(&run_bench.step);

    const test_step = b.step("test", "Run library unit tests, smoke-run most examples, compile TCP status example");
    test_step.dependOn(&run_unit_tests.step);

    _ = examples_mod.addExamples(b, d, target, optimize, test_step, &run_unit_tests.step);
    _ = interop_mod.addInteropSteps(b, d, target, optimize);
}
