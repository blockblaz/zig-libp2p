# `core/` — node runtime

The embedder-facing runtime: the objects an application holds and drives. Sits
above [`primitives/`](../primitives/README.md) and wires together the
[`protocols/`](../protocols/README.md).

| Module | Role |
|--------|------|
| `host.zig` | `Host` — the top-level node: owns the swarm, gossipsub, req/resp, identify, connection manager; exposes subscribe/publish/dial and `runPeriodicTicks`. |
| `swarm.zig` | `Swarm` — connection/stream lifecycle, command queue, and the `Event` union the embedder drains. |
| `connection_manager.zig` | Connection limits, trimming policy, dial scheduling, known-peer table. |
| `peer_events.zig` | Peer lifecycle event payloads (`peer_connected`, `peer_discovered`, `peer_connection_failed`, …). |
| `layer_events.zig` | Cross-layer event plumbing between transport, security, and protocols. |
| `peer_protocols.zig` | Per-peer protocol set learned from Identify (e.g. used by AutoNAT to find servers). |
| `identify_advertisement.zig` | Local listen-addr / protocol advertisement used by Identify and Identify-Push. |

The canonical end-to-end wiring example is
[`examples/host_quic_node.zig`](../../examples/host_quic_node.zig).
