const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("zig_libp2p", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const glue_mod = b.createModule(.{
        .root_source_file = b.path("src/zeam_glue_root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zig_libp2p", .module = mod },
        },
    });

    const lib = b.addLibrary(.{
        .name = "zig-libp2p",
        .linkage = .static,
        .root_module = glue_mod,
    });
    lib.root_module.link_libc = true;
    b.installArtifact(lib);

    const unit_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
