# Kademlia DHT (kad-dht)

Implements libp2p Kademlia DHT wire codecs, routing table, iterative lookups, and record storage ([#93](https://github.com/blockblaz/zig-libp2p/issues/93)). Host lifecycle wiring ([#203](https://github.com/blockblaz/zig-libp2p/issues/203)) connects AutoNAT mode promotion, provider republish, and routing-table eviction on disconnect. Spec: [libp2p/kad-dht](https://github.com/libp2p/specs/tree/master/kad-dht).

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
| `record_validator` | Prefix-registered `PUT_VALUE` validators (`accept` / `reject` / `ignore`) ([#198](https://github.com/blockblaz/zig-libp2p/issues/198)) |
| `ipns_validator` | Built-in `/ipns/` validator (IpnsEntry protobuf, DAG-CBOR `data`, Ed25519 `signatureV2`, monotonic sequence, EOL expiry) |
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

## Host integration (#203)

Wire a `kad_dht.Client` into `Host` via [`setKadDhtClient`](../src/host.zig):

```zig
var kad = try zl.kad_dht.Client.init(allocator, local_id_b58, .{}, query_peer);
host.setKadDhtClient(&kad);
```

When AutoNAT is enabled, `Host.runPeriodicTicks` promotes or demotes DHT mode:

- **Public** → `kad.setMode(.server)`
- **Private / unknown** → `kad.setMode(.client)`

On each heartbeat, `Host` also:

1. Calls `kad.republishProviders` for local provider keys past the republish window (uses Identify listen addrs).
2. On `onConnectionClosed`, calls `kad.onPeerDisconnected` so dead peers are removed from the routing table.

Outbound `ADD_PROVIDER` fan-out uses the embedder-supplied [`QueryPeerFn`](src/kad_dht/query.zig) on the client.

## Manual / embedder wiring

Transport remains embedder-owned when not using bundled QUIC kad streams:

1. **Server mode:** negotiate `/ipfs/kad/1.0.0`, dispatch stream to `Server.handleStream`. Only server-mode peers are inserted into remote routing tables.
2. **Client mode:** use `Client` + `QueryPeerFn` to open streams, write length-prefixed requests, read responses.
3. **Bootstrap:** `Client.bootstrap` seeds configured peers then runs `findNode(local_id)`.
4. **Provider ads:** `Client.announceProvider` or `addLocalProvider` + periodic `republishProviders`.
5. **AutoNAT integration:** `kad_dht.modeFromNatStatus(autonat_client.natStatus())` or rely on Host glue when `setKadDhtClient` is set.

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

## Acceptance

**#93 (library MVP):** routing table, wire codec, iterative lookups, provider store, bootstrap API.

**#203 (lifecycle):**

- AutoNAT status change → `kad.setMode` via Host glue (#206 + #203).
- Periodic provider republish via `republishProviders` / `providersNeedingRepublish`.
- `onConnectionClosed` → routing-table peer eviction.
- In-memory integration tests for advertise / lookup / republish / mode promotion.

Live-network acceptance (bootstrap.libp2p.io, cross-impl interop) remains embedder/manual validation.

**#198 (record validators):**

- `RecordValidator` registry with longest-prefix matching.
- `RecordStore.putValue` consults validators before storage; rejects increment `ValidationStats`.
- Optional `Server.Config.on_validation_reject` hook for peer-score docking.
- `/ipns/` validator per the [IPNS record spec](https://specs.ipfs.tech/ipns/ipns-record/): parses the `IpnsEntry` protobuf and DAG-CBOR `data`, verifies Ed25519 `signatureV2` over `"ipns-signature:" ‖ data` against the key inlined in the name, enforces monotonic `Sequence`, and rejects records past their EOL `Validity`. Ed25519 names only.

```zig
var reg = zl.kad_dht.RecordValidator.init(allocator);
defer reg.deinit();
try zl.kad_dht.ipns_validator.register(&reg, &allocator);

var stats: zl.kad_dht.ValidationStats = .{};
var server = try zl.kad_dht.Server.init(allocator, local_id, .{
    .records = .{ .validators = &reg, .validation_stats = &stats },
});
```
