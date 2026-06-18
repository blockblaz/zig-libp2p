const std = @import("std");
const deps_mod = @import("deps.zig");

pub fn addExamples(
    b: *std.Build,
    d: deps_mod.Deps,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    unit_test_step: *std.Build.Step,
) *std.Build.Step {
    const examples_step = b.step("examples", "Build example programs (installed to prefix/bin)");
    var prev_example_run: ?*std.Build.Step = null;

    for (deps_mod.examples) |ex| {
        const ex_mod = b.createModule(.{
            .root_source_file = b.path(ex.root),
            .target = target,
            .optimize = optimize,
        });
        ex_mod.addImport("zig_libp2p", d.mod);
        if (std.mem.eql(u8, ex.exe_name, "interop-quic-node")) {
            ex_mod.addImport("multiaddr", d.multiaddr);
            ex_mod.addImport("zquic", d.zquic);
        }

        const exe = b.addExecutable(.{
            .name = ex.exe_name,
            .root_module = ex_mod,
        });
        const install_ex = b.addInstallArtifact(exe, .{});
        b.getInstallStep().dependOn(&install_ex.step);
        examples_step.dependOn(&install_ex.step);

        exe.step.dependOn(unit_test_step);
        if (prev_example_run) |prev| exe.step.dependOn(prev);

        const smoke_run = !std.mem.eql(u8, ex.exe_name, "example-req-resp-tcp-status") and
            !std.mem.eql(u8, ex.exe_name, "interop-quic-node") and
            !std.mem.eql(u8, ex.exe_name, "gen-libp2p-cert");
        if (smoke_run) {
            const run_ex = b.addRunArtifact(exe);
            run_ex.step.dependOn(&exe.step);
            if (prev_example_run) |prev| run_ex.step.dependOn(prev);
            prev_example_run = &run_ex.step;
            test_step.dependOn(&run_ex.step);
        } else {
            test_step.dependOn(&exe.step);
            prev_example_run = &exe.step;
        }
    }

    return examples_step;
}
