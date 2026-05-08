//! C ABI matching Zeam `pkgs/network/src/ethlibp2p.zig` and `rust/libp2p-glue`.
//!
//! Current behaviour is a **lifecycle stub**: parameters are released, readiness
//! is signalled, and the bridge thread blocks until `stop_network`, so Zeam can
//! join the thread. Gossip, RPC, and transports are not implemented yet.

const std = @import("std");
const c = std.c;
const protocol = @import("zig_libp2p").protocol;

comptime {
    _ = protocol; // keep protocol linked for upcoming stack wiring
}

fn monotonicNs() i128 {
    var ts: c.timespec = undefined;
    _ = c.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

fn sleepMs(ms: u32) void {
    var req: c.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((@as(u64, ms % 1000)) * std.time.ns_per_ms),
    };
    while (c.nanosleep(&req, &req) != 0) {}
}

pub const CreateNetworkParams = extern struct {
    network_id: u32,
    padding: u32,
    zig_handler: u64,
    local_private_key: [*c]const u8,
    listen_addresses: [*c]const u8,
    connect_addresses: [*c]const u8,
};

const max_networks = 3;
const swarm_drop_reasons = 3;

var g_ready: [max_networks]std.atomic.Value(bool) = .{
    .init(false), .init(false), .init(false),
};
var g_shutdown: [max_networks]std.atomic.Value(bool) = .{
    .init(false), .init(false), .init(false),
};
var g_mesh_peers: [max_networks]std.atomic.Value(u64) = .{
    .init(0), .init(0), .init(0),
};
var g_swarm_cmd_dropped: [swarm_drop_reasons]std.atomic.Value(u64) = .{
    .init(0), .init(0), .init(0),
};

extern fn releaseStartNetworkParams(
    zig_handler: u64,
    local_private_key: [*c]const u8,
    listen_addresses: [*c]const u8,
    connect_addresses: [*c]const u8,
) callconv(.c) void;

export fn create_and_run_network(params: *const CreateNetworkParams) callconv(.c) void {
    if (@intFromPtr(params) == 0) return;
    const p = params.*;
    const nid = p.network_id;
    if (nid >= max_networks) return;

    if (@intFromPtr(p.local_private_key) == 0 or
        @intFromPtr(p.listen_addresses) == 0 or
        @intFromPtr(p.connect_addresses) == 0)
    {
        return;
    }

    g_shutdown[@intCast(nid)].store(false, .release);
    releaseStartNetworkParams(
        p.zig_handler,
        p.local_private_key,
        p.listen_addresses,
        p.connect_addresses,
    );

    g_ready[@intCast(nid)].store(true, .release);

    while (!g_shutdown[@intCast(nid)].load(.acquire)) {
        sleepMs(1);
    }

    g_ready[@intCast(nid)].store(false, .release);
    g_mesh_peers[@intCast(nid)].store(0, .monotonic);
}

export fn wait_for_network_ready(network_id: u32, timeout_ms: u64) callconv(.c) bool {
    if (network_id >= max_networks) return false;
    const deadline_ns = monotonicNs() + (@as(i128, @intCast(timeout_ms)) * std.time.ns_per_ms);
    while (monotonicNs() < deadline_ns) {
        if (g_ready[@intCast(network_id)].load(.acquire)) return true;
        sleepMs(1);
    }
    return g_ready[@intCast(network_id)].load(.acquire);
}

export fn stop_network(network_id: u32) callconv(.c) void {
    if (network_id >= max_networks) return;
    g_shutdown[@intCast(network_id)].store(true, .release);
}

export fn publish_msg_to_rust_bridge(
    network_id: u32,
    topic_str: [*:0]const u8,
    message_ptr: [*]const u8,
    message_len: usize,
) callconv(.c) bool {
    _ = network_id;
    _ = topic_str;
    _ = message_ptr;
    _ = message_len;
    return false;
}

export fn subscribe_gossip_topic_to_rust_bridge(network_id: u32, topic_str: [*:0]const u8) callconv(.c) bool {
    _ = network_id;
    _ = topic_str;
    return false;
}

export fn send_rpc_request(
    network_id: u32,
    peer_id: [*:0]const u8,
    protocol_tag: u32,
    request_ptr: [*]const u8,
    request_len: usize,
) callconv(.c) u64 {
    _ = network_id;
    _ = peer_id;
    _ = protocol_tag;
    _ = request_ptr;
    _ = request_len;
    return 0;
}

export fn send_rpc_response_chunk(
    network_id: u32,
    channel_id: u64,
    response_ptr: [*]const u8,
    response_len: usize,
) callconv(.c) void {
    _ = network_id;
    _ = channel_id;
    _ = response_ptr;
    _ = response_len;
}

export fn send_rpc_end_of_stream(network_id: u32, channel_id: u64) callconv(.c) void {
    _ = network_id;
    _ = channel_id;
}

export fn send_rpc_error_response(
    network_id: u32,
    channel_id: u64,
    message_ptr: [*:0]const u8,
) callconv(.c) void {
    _ = network_id;
    _ = channel_id;
    _ = message_ptr;
}

export fn get_swarm_command_dropped_total(reason_tag: u32) callconv(.c) u64 {
    if (reason_tag >= swarm_drop_reasons) return 0;
    return g_swarm_cmd_dropped[@intCast(reason_tag)].load(.monotonic);
}

export fn get_mesh_peers_total(network_id: u32) callconv(.c) u64 {
    if (network_id >= max_networks) return 0;
    return g_mesh_peers[@intCast(network_id)].load(.monotonic);
}
