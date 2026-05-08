const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const multiaddr_dep = b.dependency("multiaddr", .{
        .target = target,
        .optimize = optimize,
    });

    const snappyz = b.dependency("zig_snappy", .{
        .target = target,
        .optimize = optimize,
    }).module("snappyz");

    const snappyframesz = b.dependency("snappyframesz", .{
        .target = target,
        .optimize = optimize,
    }).module("snappyframesz.zig");

    const peer_id_mod = b.dependency("peer_id", .{
        .target = target,
        .optimize = optimize,
    }).module("peer-id");

    const mod = b.addModule("zig_libp2p", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("multiaddr", multiaddr_dep.module("multiaddr"));
    mod.addImport("snappyz", snappyz);
    mod.addImport("snappyframesz", snappyframesz);
    mod.addImport("peer_id", peer_id_mod);

    const unit_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
