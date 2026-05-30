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
    .{ .exe_name = "example-swarm-tick", .root = "examples/swarm_tick.zig" },
    .{ .exe_name = "example-req-resp-tcp-status", .root = "examples/req_resp_tcp_status.zig" },
    .{ .exe_name = "example-quic-ping-loopback", .root = "examples/quic_ping_loopback.zig" },
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

    const zig_varint_mod = b.dependency("zig_varint", .{
        .target = target,
        .optimize = optimize,
    }).module("zig_varint");

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
    mod.addImport("zig_varint", zig_varint_mod);

    const unit_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const wire_fuzz_tests = b.addTest(.{
        .name = "wire-fuzz",
        .root_module = mod,
        .filters = &.{"wire fuzz"},
    });
    const run_wire_fuzz = b.addRunArtifact(wire_fuzz_tests);
    const fuzz_step = b.step("fuzz", "Run `wire fuzz …` tests (std.testing.fuzz smoke); long libFuzzer runs: zig build test --fuzz (#44)");
    fuzz_step.dependOn(&run_wire_fuzz.step);

    // Microbenchmark binary (#19). Tiny, deterministic, grep-friendly output;
    // CI builds it under the test step so a compile regression is caught.
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench_mod.addImport("zig_libp2p", mod);
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

    const examples_step = b.step("examples", "Build example programs (installed to prefix/bin)");

    // Run example smoke tests one after another. Parallel runs were observed to hang
    // indefinitely (likely Io.Threaded + TCP accept/dial ordering under load).
    //
    // The TCP status binary is only compiled under `zig build test`, not executed: the
    // same Io.Threaded + accept/dial pattern can stall CI on Linux as well as locally on Darwin.
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

        exe.step.dependOn(&run_unit_tests.step);
        if (prev_example_run) |prev| exe.step.dependOn(prev);

        const smoke_run = !std.mem.eql(u8, ex.exe_name, "example-req-resp-tcp-status");
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
}
