# `protocols/` — libp2p protocols

One folder per protocol. Each is self-contained (wire codec + state machine) and
wired into the node by [`core/`](../core/README.md); transport-specific glue
(opening streams, framing) lives in [`transport/`](../transport/README.md).

| Folder | Protocol | Notes / docs |
|--------|----------|--------------|
| `ping/` | `/ipfs/ping/1.0.0` | liveness round-trip |
| `identify/` | `/ipfs/id/1.0.0` + `/ipfs/id/push/1.0.0` | peer info exchange, signed peer records (RFC 0002), Identify-Push |
| `gossipsub/` | gossipsub v1.1 | mesh, scoring, PX, IDONTWANT, FANOUT — pub/sub |
| `gossip/` | gossipsub wire | shared message/RPC codec used by `gossipsub/` |
| `req_resp/` | request/response | length-prefixed SSZ-snappy framing |
| `autonat/` | AutoNAT v1 | reachability probing — [docs/AUTONAT.md](../../docs/AUTONAT.md) |
| `kad_dht/` | Kademlia DHT | routing table, lookups, provider records, record validators — [docs/KAD_DHT.md](../../docs/KAD_DHT.md) |
| `relay/` | Circuit Relay v2 | reservations + `/p2p-circuit` |
| `dcutr/` | DCUtR | hole punching over relayed connections |
| `discovery/` | mDNS | LAN peer discovery — [docs/MDNS.md](../../docs/MDNS.md) |
| `rendezvous/` | `/rendezvous/1.0.0` | namespace-scoped discovery — [docs/RENDEZVOUS.md](../../docs/RENDEZVOUS.md) |

The full spec-coverage matrix (implemented / partial / planned) is in the
[top-level README](../../README.md#libp2p-spec-coverage).
