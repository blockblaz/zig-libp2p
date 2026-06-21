const std = @import("std");

pub const Examples = struct {
    exe_name: []const u8,
    root: []const u8,
};

pub const examples: []const Examples = &.{
    .{ .exe_name = "example-varint", .root = "examples/varint.zig" },
    .{ .exe_name = "example-addr-list-csv", .root = "examples/addr_list_csv.zig" },
    .{ .exe_name = "example-multistream-negotiate", .root = "examples/multistream_negotiate.zig" },
    .{ .exe_name = "example-gossipsub-mesh", .root = "examples/gossipsub_mesh.zig" },
    .{ .exe_name = "example-ping-membuf", .root = "examples/ping_membuf.zig" },
    .{ .exe_name = "example-autonat-membuf", .root = "examples/autonat_membuf.zig" },
    .{ .exe_name = "example-kad-dht-membuf", .root = "examples/kad_dht_membuf.zig" },
    .{ .exe_name = "example-rendezvous-membuf", .root = "examples/rendezvous_membuf.zig" },
    .{ .exe_name = "example-relay-membuf", .root = "examples/relay_membuf.zig" },
    .{ .exe_name = "example-dcutr-membuf", .root = "examples/dcutr_membuf.zig" },
    .{ .exe_name = "example-swarm-tick", .root = "examples/swarm_tick.zig" },
    .{ .exe_name = "example-req-resp-tcp-status", .root = "examples/req_resp_tcp_status.zig" },
    .{ .exe_name = "example-quic-ping-loopback", .root = "examples/quic_ping_loopback.zig" },
    .{ .exe_name = "example-host-quic-node", .root = "examples/host_quic_node.zig" },
    .{ .exe_name = "interop-quic-node", .root = "examples/interop_quic_node.zig" },
    .{ .exe_name = "gen-libp2p-cert", .root = "examples/gen_libp2p_cert.zig" },
};

pub const Deps = struct {
    mod: *std.Build.Module,
    multiaddr: *std.Build.Module,
    zquic: *std.Build.Module,
};

pub const CreateDepsOptions = struct {
    enable_soak_tests: bool = false,
    /// Forward `-Dshadow=true` into the transitive `zquic` dependency so its
    /// syscall layer (compat.zig + batch_io.zig) routes through libc and the
    /// Shadow simulator's `LD_PRELOAD` shim can intercept. See README.
    shadow: bool = false,
};

pub fn createDeps(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    opts: CreateDepsOptions,
) Deps {
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
        .shadow = opts.shadow,
    }).module("zquic");

    const zquic_rsa_mod = b.createModule(.{
        .root_source_file = b.path("vendor/zquic_rsa/rsa.zig"),
        .target = target,
        .optimize = optimize,
    });

    const zig_varint_mod = b.dependency("zig_varint", .{
        .target = target,
        .optimize = optimize,
    }).module("zig_varint");

    const zquic_tls_mod = b.createModule(.{
        .root_source_file = b.path("vendor/zquic_tls/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const mod = b.addModule("zig_libp2p", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("multiaddr", multiaddr_dep.module("multiaddr"));
    mod.addImport("snappyz", snappyz);
    mod.addImport("snappyframesz", snappyframesz);
    mod.addImport("peer_id", peer_id_mod);
    mod.addImport("zquic", zquic_mod);
    mod.addImport("zquic_rsa", zquic_rsa_mod);
    mod.addImport("zquic_tls", zquic_tls_mod);
    mod.addImport("zig_varint", zig_varint_mod);

    const test_options = b.addOptions();
    test_options.addOption(bool, "enable_soak_tests", opts.enable_soak_tests);
    mod.addOptions("test_options", test_options);

    return .{
        .mod = mod,
        .multiaddr = multiaddr_dep.module("multiaddr"),
        .zquic = zquic_mod,
    };
}
