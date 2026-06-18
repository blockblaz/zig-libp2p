# Architecture

How zig-libp2p layers fit together. The on-disk layout mirrors this model after the
[repository rationalization](REPO_LAYOUT.md) (phases 0–2).

## Layer stack

```
┌─────────────────────────────────────────────────────────────┐
│  Embedder (zeam, examples/host_quic_node, interop nodes)    │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  core/          Host, Swarm, ConnectionManager, peer events   │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────────┐
│ protocols/    │   │ transport/    │   │ security/         │
│ gossipsub     │   │ quic, tcp, ws │   │ libp2p TLS, noise │
│ req_resp      │   │ yamux, mplex  │   └───────────────────┘
│ kad_dht, …    │   └───────────────┘
└───────────────┘
        │
        ▼
┌───────────────┐
│ primitives/   │  identity, varint, multistream, protobuf wire
└───────────────┘
```

## Runtime flow (QUIC node)

1. **Embedder** creates a `Host` (`core/host.zig`) with local key material from `primitives/identity.zig`.
2. **Transport** (`transport/quic_runtime.zig`) owns UDP listen/dial, TLS handshake, and per-connection stream I/O.
3. **Multistream-select** (`transport/stream_multistream.zig`) negotiates protocol IDs on each stream.
4. **Protocol handlers** dispatch to `protocols/*` (ping, identify, gossipsub RPC, req/resp, AutoNAT, relay, DCUtR, DHT).
5. **Swarm** (`core/swarm.zig`) surfaces connection and discovery events; **ConnectionManager** tracks dial/backoff policy.

## Public API

Consumers import a single module:

```zig
const zig_libp2p = @import("zig_libp2p");
```

`src/root.zig` re-exports the flat names used today (`host`, `gossipsub`, `kad_dht`, …). Canonical
nested paths are also available:

- `zig_libp2p.core.host`
- `zig_libp2p.primitives.identity`
- `zig_libp2p.protocols.kad_dht` (via the flat `kad_dht` alias today)

Legacy shim files under `src/*.zig` and `src/<protocol>/` forward to the new locations so internal
imports keep working during migration.

## Non-public code

- `internal/wire_boundaries.zig` — fuzz/smoke helpers for wire parsers (not part of the embedder API).
- `src/vendor/` — vendored TLS/RSA pieces required for Zig 0.16 builds (see REPO_LAYOUT.md phase 5).

## Harnesses

Cross-impl conformance lives outside `src/` in [`harness/`](../harness/README.md); it exercises the
same wire paths as production nodes but is not linked into the library package.
