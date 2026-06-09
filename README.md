# zig-libp2p

Pure-Zig implementation of the **lean-consensus / Eth2 libp2p subset**: QUIC + libp2p TLS, multistream-select, gossipsub v1.1 (StrictNoSign), length-prefixed req/resp, ping, identify, noise/XX, TCP. Built for [zeam](https://github.com/blockblaz/zeam) but usable by any lean/Eth2 client.

> **Pre-1.0** — see [#172](https://github.com/ch4r10t33r/zig-libp2p/issues/172) for the freeze + semver plan. Pin a tag in `build.zig.zon`.

## Supported

| Spec | Module | Cross-impl interop |
|------|--------|--------------------|
| QUIC v1 (RFC 9000/9001) | `transport.quic_*` + `zquic` | zig ↔ go-libp2p ✅ |
| libp2p TLS 1.3 on QUIC (RFC 0001) | `security.libp2p_tls` + `security.libp2p_tls_cert` | zig ↔ go-libp2p ✅ |
| libp2p TLS on TCP (`/tls/1.0.0`) | `transport.tcp_tls` | manual |
| TCP transport | `transport.tcp` | — |
| Noise XX (`/noise`) | `security.noise` (RSA, ECDSA-P256, secp256k1, ed25519) | manual |
| Yamux + Mplex muxing | `transport.yamux`, `transport.mplex` | — |
| Multistream-select (delimited) | `transport.stream_multistream`, `transport.multistream_negotiate` | ✅ |
| `/ipfs/ping/1.0.0` | `ping` | zig ↔ go-libp2p ✅ (8/8) |
| `/ipfs/id/1.0.0` (Identify) | `identify` | responder stub ✅ |
| RFC 0002 signed peer record | `identify.verifySignedPeerRecord` | ✅ |
| Gossipsub v1.1 — StrictNoSign | `gossipsub.*` | zig ↔ go-libp2p ✅ |
| Length-prefixed req/resp + SSZ-snappy | `req_resp.*` | zig ↔ zig ✅ |
| Host / Swarm / Connection manager / metrics | `host`, `swarm`, `connection_manager`, `metrics` | — |

Live cross-impl matrix: [interop_quic/README.md](interop_quic/README.md). Threat model + wire caps: [docs/SECURITY.md](docs/SECURITY.md).

## Not supported (tracked)

Out of scope for the lean/Eth2 surface. PRs welcome on the linked issues.

| Spec | Status | Issue |
|------|--------|-------|
| Kademlia DHT | not planned for 1.0 | [#93](https://github.com/ch4r10t33r/zig-libp2p/issues/93) |
| Circuit Relay v2 + DCUtR hole punching | not planned for 1.0 | [#91](https://github.com/ch4r10t33r/zig-libp2p/issues/91) |
| AutoNAT | not planned for 1.0 | [#92](https://github.com/ch4r10t33r/zig-libp2p/issues/92) |
| WebSocket / WebTransport / WebRTC | not planned for 1.0 | [#94](https://github.com/ch4r10t33r/zig-libp2p/issues/94) |
| Resource manager (rcmgr scope-based) | planned | [#169](https://github.com/ch4r10t33r/zig-libp2p/issues/169) |
| PSK / pnet (private networks) | planned | [#171](https://github.com/ch4r10t33r/zig-libp2p/issues/171) |
| Async swarm (`std.Io.Threaded` → async) | planned | [#57](https://github.com/ch4r10t33r/zig-libp2p/issues/57) |
| Third-party security audit + disclosure | planned | [#170](https://github.com/ch4r10t33r/zig-libp2p/issues/170) |
| zig ↔ rust-libp2p cross-impl matrix row | in progress | [#166](https://github.com/ch4r10t33r/zig-libp2p/issues/166) |
| 1.0-RC API freeze | planned | [#172](https://github.com/ch4r10t33r/zig-libp2p/issues/172) |

Spec-compliance umbrella: [#80](https://github.com/ch4r10t33r/zig-libp2p/issues/80).

## Requirements

- **Zig** 0.16.0
- **zquic** pinned in `build.zig.zon`, re-exported as `zig_libp2p.zquic`

## Usage

```zig
const zig_libp2p = b.dependency("zig_libp2p", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_libp2p", zig_libp2p.module("zig_libp2p"));
```

Application code: `@import("zig_libp2p")` — public surface in [`src/root.zig`](./src/root.zig). Canonical wiring: [examples/host_quic_node.zig](examples/host_quic_node.zig).

Pin by tag (e.g. `v0.1.15`) in the `build.zig.zon` URL.

## Examples

Under [`examples/`](./examples/). `zig build` installs to `zig-out/bin/`. Notable:

- `example-host-quic-node` — `Host` + QUIC lifecycle hooks (production wiring shape).
- `interop-quic-node` — env-driven interop endpoint used by the cross-impl matrix.
- `gen-libp2p-cert` — mint a libp2p TLS cert + peer id.
- `example-quic-ping-loopback`, `example-gossipsub-mesh`, `example-swarm-tick`, `example-ping-membuf`, `example-req-resp-tcp-status`, `example-multistream-negotiate` — focused single-protocol demos.

Build details: [examples/README.md](examples/README.md).

## QUIC cross-impl interop

```sh
zig build -Doptimize=ReleaseFast
(cd interop_quic/impls/go-libp2p && go build -o interop-quic-node-go .)
interop_quic/run_matrix.sh zig,go-libp2p handshake,ping,gossipsub,reqresp
```

Or: `zig build interop-matrix`. Status table + harness docs: [interop_quic/README.md](interop_quic/README.md).

## Development

- `zig fmt --check .`
- `zig build test` — unit tests + example smoke-runs
- `zig build fuzz` — `wire fuzz …` tests via `std.testing.fuzz`
- CI workflows + release-please: [.github/workflows/](./.github/workflows/)

zeam integration (audience-specific): [docs/zeam-parity.md](docs/zeam-parity.md).

## Repository

https://github.com/ch4r10t33r/zig-libp2p
