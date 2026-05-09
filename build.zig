const std = @import("std");

const examples: []const struct {
    exe_name: []const u8,
    root: []const u8,
} = &.{
    .{ .exe_name = "example-varint", .root = "examples/varint.zig" },
    .{ .exe_name = "example-addr-list-csv", .root = "examples/addr_list_csv.zig" },
    .{ .exe_name = "example-multistream-negotiate", .root = "examples/multistream_negotiate.zig" },
    .{ .exe_name = "example-gossipsub-mesh", .root = "examples/gossipsub_mesh.zig" },
    .{ .exe_name = "example-ping-membuf", .root = "examples/ping_membuf.zig" },
    .{ .exe_name = "example-req-resp-tcp-status", .root = "examples/req_resp_tcp_status.zig" },
};

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

    const zquic_mod = b.dependency("zquic", .{
        .target = target,
        .optimize = optimize,
    }).module("zquic");

    const mod = b.addModule("zig_libp2p", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("multiaddr", multiaddr_dep.module("multiaddr"));
    mod.addImport("snappyz", snappyz);
    mod.addImport("snappyframesz", snappyframesz);
    mod.addImport("peer_id", peer_id_mod);
    mod.addImport("zquic", zquic_mod);

    const unit_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run library unit tests, then smoke-run example programs");
    test_step.dependOn(&run_unit_tests.step);

    const examples_step = b.step("examples", "Build example programs (installed to prefix/bin)");

    // Run example smoke tests one after another. Parallel runs were observed to hang
    // indefinitely (likely Io.Threaded + TCP accept/dial ordering under load).
    var prev_example_run: ?*std.Build.Step = null;

    for (examples) |ex| {
        const ex_mod = b.createModule(.{
            .root_source_file = b.path(ex.root),
            .target = target,
            .optimize = optimize,
        });
        ex_mod.addImport("zig_libp2p", mod);

        const exe = b.addExecutable(.{
            .name = ex.exe_name,
            .root_module = ex_mod,
        });
        b.installArtifact(exe);
        examples_step.dependOn(&exe.step);

        const run_ex = b.addRunArtifact(exe);
        run_ex.step.dependOn(&run_unit_tests.step);
        if (prev_example_run) |prev| run_ex.step.dependOn(prev);
        prev_example_run = &run_ex.step;
        test_step.dependOn(&run_ex.step);
    }
}
