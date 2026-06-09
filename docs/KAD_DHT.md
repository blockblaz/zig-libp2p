# Kademlia DHT (kad-dht)

Implements libp2p Kademlia DHT wire codecs, routing table, iterative lookups, and record storage ([#93](https://github.com/ch4r10t33r/zig-libp2p/issues/93)). Spec: [libp2p/kad-dht](https://github.com/libp2p/specs/tree/master/kad-dht).

## Protocol

| ID | Use |
|----|-----|
| `/ipfs/kad/1.0.0` | Default public DHT |
| `/lan/kad/1.0.0` | LAN-scoped DHT |

## Modules

Import via `zig_libp2p.kad_dht`:

| Module | Purpose |
|--------|---------|
| `keyspace` | sha256 keys, XOR distance, common-prefix length |
| `routing_table` | CPL-indexed k-buckets (k=20), LRU eviction per bucket |
| `wire` | Length-prefixed protobuf `Message` / `Record` / `Peer` codec |
| `record_store` | Value + provider records with TTL (default 24 h) |
| `query` | Iterative `findNode` / `findProviders` (alpha=3 default) |
| `server` | Inbound RPC handler on `std.Io` streams |
| `client` | Bootstrap + high-level lookups |
| `mode` | Client vs server mode (maps from AutoNAT `NatStatus`) |

## Parameters (issue #93)

| Parameter | Default |
|-----------|---------|
| k (replication) | 20 |
| alpha (concurrency) | 3 |
| Provider TTL | 24 h |
| Provider republish | 12 h |

## Embedder wiring

Transport remains embedder-owned (same pattern as AutoNAT / Identify):

1. **Server mode:** negotiate `/ipfs/kad/1.0.0`, dispatch stream to `Server.handleStream`. Only server-mode peers are inserted into remote routing tables.
2. **Client mode:** use `Client` + `QueryPeerFn` to open streams, write length-prefixed requests, read responses.
3. **Bootstrap:** `Client.bootstrap` seeds configured peers then runs `findNode(local_id)`.
4. **AutoNAT integration:** `kad_dht.modeFromNatStatus(autonat_client.natStatus())` selects client vs server mode.

```zig
const zl = @import("zig_libp2p");

fn queryPeer(ctx: ?*anyopaque, peer_id: []const u8, req: zl.kad_dht.MessageView, out: *zl.kad_dht.MessageOwned) !void {
    _ = ctx;
    _ = peer_id;
    _ = req;
    _ = out;
    // Dial peer, negotiate kad protocol, exchange framed messages.
}

var client = try zl.kad_dht.Client.init(allocator, local_id, .{}, queryPeer);
try client.bootstrap(&boot_peers, now_ms);
const providers = try client.findProviders(content_key, now_ms);
defer client.freeProviders(providers);
```

## Example

[`examples/kad_dht_membuf.zig`](../examples/kad_dht_membuf.zig) — `FIND_NODE` round-trip through in-memory buffers (CI smoke-run).

## Acceptance (issue #93)

Library MVP covers routing table, wire codec, iterative lookups, provider store, and bootstrap API. Live-network acceptance (bootstrap.libp2p.io, cross-impl interop) remains embedder/manual validation.
