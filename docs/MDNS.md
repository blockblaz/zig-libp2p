# mDNS LAN peer discovery

Multicast DNS peer discovery for zero-config LAN deployments ([#207](https://github.com/blockblaz/zig-libp2p/issues/207)). Spec: [libp2p/discovery/mdns](https://github.com/libp2p/specs/blob/master/discovery/mdns.md).

## Protocol

| Item | Value |
|------|-------|
| Service | `_p2p._udp.local` |
| Query | PTR `_p2p._udp.local` |
| Response | PTR + TXT `dnsaddr=/…/p2p/<PeerId>` |
| Transport | UDP multicast `224.0.0.251:5353` / `[ff02::fb]:5353` |

## Modules

Import via `zig_libp2p.discovery`:

| Module | Purpose |
|--------|---------|
| `dns_wire` | Minimal DNS PTR/TXT encode + decode for mDNS packets |
| `mdns` | Multicast socket service, query/broadcast, discovery parsing |

## Host integration

```zig
const host = try zl.host.Host.create(.{
    .allocator = allocator,
    .local_peer = local_peer,
    .gossipsub = .{ /* … */ },
    .mdns = .{ .enable = true },
});
try host.addListenAddr("/ip4/192.168.1.5/udp/4001/quic-v1");
```

`Host.runPeriodicTicks` then:

1. Syncs Identify listen addrs into the mDNS advertiser.
2. Multicasts a PTR query on the configured interval (default 10s).
3. Responds to peer queries with PTR + `dnsaddr` TXT records.
4. Emits `swarm.Event.peer_discovered { peer, addrs, source: .mdns }`.
5. Calls `registerKnownPeer` for each discovered multiaddr (auto-dial via connection manager).

## Standalone service

```zig
var svc = try zl.discovery.mdns.Service.init(allocator, local_peer, .{
    .live_sockets = true,
    .enable_ipv4 = true,
    .enable_ipv6 = true,
});
defer svc.deinit();
try svc.setListenAddrs(&.{"/ip4/192.168.0.2/udp/4001/quic-v1"});
const found = try svc.tick(now_ms);
defer svc.freeDiscoveries(found);
```

For tests or custom reactors, set `.live_sockets = false` and feed datagrams with `handleDatagram`.

## Configuration

| Field | Default | Notes |
|-------|---------|-------|
| `query_interval_ms` | 10_000 | Multicast PTR query period |
| `discovery_cooldown_ms` | 5_000 | Suppress duplicate `peer_discovered` for same peer |
| `response_cooldown_ms` | 1_000 | Rate-limit outbound mDNS responses |
| `interface_index` | `null` | Optional multicast interface index |
| `live_sockets` | `true` | Disable for unit tests |
| `allow_public_addrs` | `false` | Accept discovered `dnsaddr` records pointing at public/global IPs |

Loopback and wildcard listen addrs are not advertised or accepted on ingest.
Because mDNS is link-local, discovered `dnsaddr` records that resolve to a
public/global IP are also rejected by default — a private / link-local / ULA
address is expected — so an on-link peer cannot steer the node into dialing an
arbitrary internet host. Set `allow_public_addrs = true` for networks where LAN
peers legitimately carry public IPs.

## Acceptance (#207)

- DNS wire codec for libp2p mDNS PTR/TXT query + response
- IPv4 + IPv6 multicast sockets with cooldown / rate limits
- `swarm.Event.peer_discovered` + Host `registerKnownPeer` wiring
- In-memory query/response + Host integration tests
