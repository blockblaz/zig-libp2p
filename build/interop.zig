const std = @import("std");
const deps_mod = @import("deps.zig");

pub fn addInteropSteps(b: *std.Build, d: deps_mod.Deps, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) struct {
    interop: *std.Build.Step,
    matrix: *std.Build.Step,
} {
    const interop_mod = b.createModule(.{
        .root_source_file = b.path("harness/tcp/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    interop_mod.addImport("zig_libp2p", d.mod);
    interop_mod.addImport("multiaddr", d.multiaddr);

    const interop_exe = b.addExecutable(.{
        .name = "transport-interop",
        .root_module = interop_mod,
    });
    const install_interop = b.addInstallArtifact(interop_exe, .{});
    const interop_step = b.step("interop", "Build unified-testing transport interop binary");
    interop_step.dependOn(&install_interop.step);

    const interop_matrix_cmd = b.addSystemCommand(&.{
        "bash",
        "harness/quic/run_matrix.sh",
        "zig,go-libp2p",
        "handshake,ping",
    });
    interop_matrix_cmd.step.dependOn(b.getInstallStep());
    const interop_matrix_step = b.step(
        "interop-matrix",
        "Run QUIC cross-impl matrix (requires interop-quic-node-go under harness/quic/impls/go-libp2p/)",
    );
    interop_matrix_step.dependOn(&interop_matrix_cmd.step);

    return .{ .interop = interop_step, .matrix = interop_matrix_step };
}
