# zig-libp2p

[![project-libp2p](https://img.shields.io/badge/project-libp2p-yellow.svg?style=flat-square)](https://libp2p.io/)
[![CI](https://img.shields.io/github/actions/workflow/status/blockblaz/zig-libp2p/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/blockblaz/zig-libp2p/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/zig-0.16.0-f7a41d.svg?style=flat-square)](https://ziglang.org/)
[![Release](https://img.shields.io/github/v/tag/blockblaz/zig-libp2p?style=flat-square&label=release&sort=semver)](https://github.com/blockblaz/zig-libp2p/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)

A pure-Zig implementation of [libp2p](https://libp2p.io/), the modular peer-to-peer
networking stack. zig-libp2p targets the **lean-consensus / Ethereum-consensus
subset** of libp2p — QUIC transport, gossipsub, and request/response — and is
verified to interoperate with [go-libp2p](https://github.com/libp2p/go-libp2p)
and [rust-libp2p](https://github.com/libp2p/rust-libp2p) on the wire.

It was built for the [zeam](https://github.com/blockblaz/zeam) lean-Ethereum
client, but the `Host` API is client-agnostic and usable by any Zig project that
needs a libp2p node.

> **Status: pre-1.0.** The public API is still evolving toward a 1.0 freeze
> ([#172](https://github.com/blockblaz/zig-libp2p/issues/172)). Pin a release
> tag in your `build.zig.zon` and review the [changelog](CHANGELOG.md) before
> upgrading.

## Highlights

- **QUIC-first transport** (RFC 9000/9001) with libp2p TLS 1.3, backed by the
  companion [`zquic`](https://github.com/ch4r10t33r/zquic) stack — no C
  dependencies, builds in a `FROM scratch` container.
- **Gossipsub v1.1** (StrictNoSign) with mesh maintenance, peer scoring, PX,
  IDONTWANT, direct peers, and FANOUT.
- **Request/response** with length-prefixed SSZ + snappy framing.
- **Cross-implementation interop** continuously exercised in CI against
  go-libp2p and rust-libp2p (handshake, ping, gossipsub, req/resp).
- **Single dependency, single import** — `@import("zig_libp2p")` exposes the
  whole surface; one `Host` object drives transport, muxing, and protocols.

## Getting started

### Requirements

- [Zig](https://ziglang.org/) **0.16.0**
- [`zquic`](https://github.com/ch4r10t33r/zquic), pinned transitively and
  re-exported as `zig_libp2p.zquic`

### Add it to your build

Add the dependency to your `build.zig.zon` (pin a released tag):

```sh
zig fetch --save "https://github.com/blockblaz/zig-libp2p/archive/refs/tags/v0.1.95.tar.gz"
```

Then wire it into `build.zig`:

```zig
const zig_libp2p = b.dependency("zig_libp2p", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_libp2p", zig_libp2p.module("zig_libp2p"));
```

### Hello, node

The public surface lives in [`src/root.zig`](src/root.zig); the canonical
end-to-end wiring (host creation, QUIC listen/dial, gossipsub, req/resp, event
loop) is [`examples/host_quic_node.zig`](examples/host_quic_node.zig). Build the
examples and run it with:

```sh
zig build examples
./zig-out/bin/example-host-quic-node
```

## libp2p spec coverage

Coverage of the [libp2p specifications](https://github.com/libp2p/specs),
organized by spec area. zig-libp2p targets the subset required by lean /
Ethereum consensus, so some libp2p features are intentionally out of scope.

**Legend:** ✅ implemented · 🚧 partial / experimental · ⬜ planned · ⛔ out of scope

### Transports

| Spec | Status | Notes |
|------|:------:|-------|
| TCP | ✅ | `transport.tcp` |
| QUIC v1 (RFC 9000/9001) | ✅ | primary transport, via `zquic`; interop go ✅ · rust ✅ |
| WebSocket — `/ws` (RFC 6455) | ✅ | `transport.ws*`; unit-tested |
| Secure WebSocket — `/wss` | ⬜ | [#94](https://github.com/blockblaz/zig-libp2p/issues/94) |
| WebTransport | ⬜ | [#94](https://github.com/blockblaz/zig-libp2p/issues/94) |
| WebRTC | ⬜ | [#94](https://github.com/blockblaz/zig-libp2p/issues/94) |

### Secure channels

| Spec | Status | Notes |
|------|:------:|-------|
| TLS 1.3 (libp2p TLS, RFC 0001) | ✅ | over QUIC and TCP (`/tls/1.0.0`); interop go ✅ · rust ✅ |
| Noise (`/noise`, XX) | ✅ | RSA, ECDSA-P256, secp256k1, ed25519 identities |

### Stream multiplexing

| Spec | Status | Notes |
|------|:------:|-------|
| QUIC native streams | ✅ | default for the QUIC transport |
| yamux | ✅ | `transport.yamux` |
| mplex | ✅ | `transport.mplex` |

### Protocol negotiation

| Spec | Status | Notes |
|------|:------:|-------|
| multistream-select 1.0 | ✅ | `transport.stream_multistream` |

### Peer identity

| Spec | Status | Notes |
|------|:------:|-------|
| Peer IDs / keypairs | ✅ | `identity`, `keypair` |
| Signed peer records (RFC 0002) | ✅ | `identify.verifySignedPeerRecord` |

### Publish / subscribe

| Spec | Status | Notes |
|------|:------:|-------|
| gossipsub v1.1 (StrictNoSign) | ✅ | mesh, peer scoring ([#199](https://github.com/blockblaz/zig-libp2p/issues/199)), PX, IDONTWANT, direct peers, FANOUT; interop go ✅ · rust ✅ |
| floodsub | ⛔ | superseded by gossipsub |

### Peer discovery & content routing

| Spec | Status | Notes |
|------|:------:|-------|
| Bootstrap (static dial) | ✅ | `connect_peers` via `connection_manager` |
| Kademlia DHT | ✅ | `kad_dht`, `host`; lifecycle ([#203](https://github.com/blockblaz/zig-libp2p/issues/203)), record validators ([#198](https://github.com/blockblaz/zig-libp2p/issues/198)) |
| mDNS (LAN discovery) | ✅ | `discovery.mdns`, `host`; `peer_discovered` events ([#207](https://github.com/blockblaz/zig-libp2p/issues/207)) |
| Rendezvous | ✅ | `rendezvous` client/server, cookie paging, `peer_discovered` ([#209](https://github.com/blockblaz/zig-libp2p/issues/209)) |

### NAT traversal

| Spec | Status | Notes |
|------|:------:|-------|
| AutoNAT v1 | ✅ | `autonat`; active probing, dial-back verification, sliding-window vote aggregation ([#206](https://github.com/blockblaz/zig-libp2p/issues/206)). v2 wire codecs present; v2 transport wiring pending |
| Circuit Relay v2 | 🚧 | `relay`, QUIC runtime; `/p2p-circuit` dial + reservation refresh ([#204](https://github.com/blockblaz/zig-libp2p/issues/204)) |
| DCUtR (hole punching) | ✅ | `dcutr`; auto-trigger on relayed connections with retry ([#205](https://github.com/blockblaz/zig-libp2p/issues/205)) |

### Utility & application protocols

| Spec | Status | Notes |
|------|:------:|-------|
| ping (`/ipfs/ping/1.0.0`) | ✅ | interop go ✅ · rust ✅ |
| identify (`/ipfs/id/1.0.0`) | ✅ | `identify` |
| identify-push (`/ipfs/id/push/1.0.0`) | ✅ | `identify`, `host`, QUIC runtime auto-opens push streams |
| Request/response (length-prefixed, SSZ-snappy) | ✅ | `req_resp`; interop go ✅ · rust ✅ |

### Not yet implemented

| Spec | Status | Notes |
|------|:------:|-------|
| Private networks (PSK / pnet) | ⬜ | [#171](https://github.com/blockblaz/zig-libp2p/issues/171) |
| Resource manager (scope-based limits) | ⬜ | [#169](https://github.com/blockblaz/zig-libp2p/issues/169) |

The live cross-impl interop matrix is in
[`harness/quic/README.md`](harness/quic/README.md); the full module map is
[`src/root.zig`](src/root.zig) and the layout rationale is
[`docs/REPO_LAYOUT.md`](docs/REPO_LAYOUT.md).

## Interoperability

Cross-implementation conformance is part of CI. To run the QUIC matrix locally
against go-libp2p (add `rust-libp2p` once its binary is built):

```sh
zig build -Doptimize=ReleaseFast
(cd harness/quic/impls/go-libp2p && go build -o interop-quic-node-go .)
harness/quic/run_matrix.sh zig,go-libp2p handshake,ping,gossipsub,reqresp
```

Or simply `zig build interop-matrix`. Harness details and the full status table
live in [`harness/README.md`](harness/README.md).

## Examples

All examples are under [`examples/`](examples/) and install to `zig-out/bin/`
via `zig build`:

| Example | What it shows |
|---------|---------------|
| `example-host-quic-node` | Full `Host` + QUIC lifecycle (production wiring) |
| `interop-quic-node` | Env-driven endpoint used by the cross-impl matrix |
| `gen-libp2p-cert` | Mint a libp2p TLS certificate + derive its peer id |
| `example-gossipsub-mesh` | Gossipsub publish/subscribe over a mesh |
| `example-quic-ping-loopback` | QUIC ping round-trip on loopback |
| `example-autonat-membuf`, `example-kad-dht-membuf` | In-memory AutoNAT / Kademlia smoke |

See [`examples/README.md`](examples/README.md) for the complete list.

## Documentation

- **Repository layout** — [`docs/REPO_LAYOUT.md`](docs/REPO_LAYOUT.md) · **Architecture** — [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Security model & wire limits** — [`docs/SECURITY.md`](docs/SECURITY.md)
- **AutoNAT** — [`docs/AUTONAT.md`](docs/AUTONAT.md) · **Kademlia DHT** — [`docs/KAD_DHT.md`](docs/KAD_DHT.md) · **mDNS** — [`docs/MDNS.md`](docs/MDNS.md)
- **Async swarm design** — [`docs/async-swarm.md`](docs/async-swarm.md)
- **zeam integration notes** — [`docs/zeam-parity.md`](docs/zeam-parity.md)

## Roadmap

Per-protocol gaps are tracked in the spec-coverage tables above. The broader
milestones toward a stable release:

- **1.0-RC API freeze + semver** — [#172](https://github.com/blockblaz/zig-libp2p/issues/172)
- **Third-party security audit + disclosure policy** — [#170](https://github.com/blockblaz/zig-libp2p/issues/170)
- **Async swarm** (`std.Io` co-scheduled, moving off the threaded runtime) — [#57](https://github.com/blockblaz/zig-libp2p/issues/57)

Spec-compliance umbrella: [#80](https://github.com/blockblaz/zig-libp2p/issues/80).

## Development

```sh
zig fmt --check .     # formatting
zig build test        # unit tests + example smoke-runs
zig build fuzz        # wire-decoder fuzzing via std.testing.fuzz
```

CI workflows and the release-please automation live in
[`.github/workflows/`](.github/workflows/).

## Contributing

Contributions are welcome. Please open an issue to discuss substantial changes
first, keep `zig fmt` clean, and make sure `zig build test` passes. New protocol
behaviour should come with unit tests and, where it crosses the wire, an entry
in the interop matrix.

## Security

Wire-size limits and the threat model are documented in
[`docs/SECURITY.md`](docs/SECURITY.md). A coordinated-disclosure policy is
tracked in [#170](https://github.com/blockblaz/zig-libp2p/issues/170); until it
lands, please report vulnerabilities privately to the maintainer rather than via
public issues.

## License

Released under the [MIT License](LICENSE).

## Acknowledgements

Built on the [libp2p specifications](https://github.com/libp2p/specs) and
verified against [go-libp2p](https://github.com/libp2p/go-libp2p) and
[rust-libp2p](https://github.com/libp2p/rust-libp2p).
