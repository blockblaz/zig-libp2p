# `src/` — library source

zig-libp2p is organized by libp2p **layer** rather than by transport:

```
primitives → core → protocols → transport
```

The public API is the facade in [`root.zig`](root.zig) (`@import("zig_libp2p")`);
everything below it is internal and may move before the
[1.0 API freeze](https://github.com/blockblaz/zig-libp2p/issues/172).

| Folder | Layer | What lives here |
|--------|-------|-----------------|
| [`primitives/`](primitives/README.md) | building blocks | identity, keypairs, varint, multistream-select, protobuf, metrics — wire-agnostic helpers |
| [`core/`](core/README.md) | node runtime | `Host`, `Swarm`, connection manager, peer/layer events — the embedder-facing surface |
| [`protocols/`](protocols/README.md) | libp2p protocols | one folder per protocol: gossipsub, kad-dht, identify, autonat, relay, dcutr, rendezvous, … |
| [`transport/`](transport/README.md) | transports & muxers | QUIC stack, TCP, WebSocket, yamux/mplex, multistream negotiation |
| [`security/`](security/README.md) | secure channels | libp2p TLS 1.3 and Noise |
| `internal/` | internal | shared invariants not part of any layer (`wire_boundaries.zig`) |
| `testdata/` | fixtures | `@embedFile` test inputs (e.g. the RSA key for `zquic_rsa`) |
| `vendor/zquic_tls/` | shim | re-export only; the canonical vendored tree lives at the repo-root [`vendor/`](../vendor/README.md) |

## Compatibility shims

The flat `src/*.zig` files and legacy paths (e.g. `src/autonat/root.zig`,
`src/transport/quic_*.zig`) are thin shims that re-export from the new locations
so existing `@import` paths keep working through the 1.0 freeze. New code should
import the canonical paths under `core/`, `primitives/`, `protocols/`, etc.

See [`docs/REPO_LAYOUT.md`](../docs/REPO_LAYOUT.md) for the full rationale and
[`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) for the layer diagram.
