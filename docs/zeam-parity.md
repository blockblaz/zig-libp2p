# Zeam parity

This document is the **Zeam-facing** feature index for replacing `libp2p-glue` with `zig-libp2p`. Behavioural contract and sub-issue checklist: [#31](https://github.com/ch4r10t33r/zig-libp2p/issues/31) (**closed**, library-complete).

## Issue hygiene (superseded trackers)

These GitHub issues predate the current tree; behaviour is implemented and the issues are closed as part of [PR hygiene](https://github.com/ch4r10t33r/zig-libp2p/pulls):

| Issue | Superseded by |
|-------|----------------|
| [#17](https://github.com/ch4r10t33r/zig-libp2p/issues/17) Gossipsub mesh behaviour | [#39](https://github.com/ch4r10t33r/zig-libp2p/issues/39) `gossipsub.runtime` |
| [#18](https://github.com/ch4r10t33r/zig-libp2p/issues/18) Gossipsub scoring / backpressure | [#39](https://github.com/ch4r10t33r/zig-libp2p/issues/39) behaviour scores + outbox caps |
| [#20](https://github.com/ch4r10t33r/zig-libp2p/issues/20) Non-QUIC transports | [#35](https://github.com/ch4r10t33r/zig-libp2p/issues/35) TCP + Noise; QUIC is primary. TCP TLS: [#86](https://github.com/ch4r10t33r/zig-libp2p/issues/86) |

## [#31](https://github.com/ch4r10t33r/zig-libp2p/issues/31) tracker — library-complete

All behaviour layers listed in #31 are implemented in this repo (see **Surface checklist** below). There is no Rust FFI and no C-ABI callbacks.

| #31 sketch | In-tree replacement |
|------------|---------------------|
| `libp2p.Node.init` / `deinit` | [`host.Host.create`](../src/host.zig) / `destroy` — public alias [`zig_libp2p.Node`](../src/root.zig) |
| `subscribe` / `publish` | `Host.subscribe`, `Host.publish` (and underlying `gossipsub.runtime`) |
| `while (node.nextEvent())` | `Host.nextEvent` → `Swarm.nextEvent` |
| TCP + Noise + Yamux/Mplex + QUIC | `transport.tcp`, `security.noise`, `transport.yamux` / `transport.mplex`, `transport.quic_*` |
| Keypair from PEM | `keypair` module |

**Intentionally not in this library:** a single process that owns UDP/TCP listen sockets, certificate paths, and bootnode policy. That stays in the embedder (Zeam, lean-quickstart, etc.). Canonical wiring: [`examples/host_quic_node.zig`](../examples/host_quic_node.zig).

**Follow-on (out of #31 scope):** Zeam deleting `libp2p-glue` and switching `pkgs/network` to `@import("zig_libp2p")` ([#86](https://github.com/ch4r10t33r/zig-libp2p/issues/86) TCP `/tls/1.0.0` if Zeam needs non-QUIC TLS, [#57](https://github.com/ch4r10t33r/zig-libp2p/issues/57) async swarm).

## Surface checklist

| Surface | Status | Issue |
|---------|--------|-------|
| Multistream-select | Done | — |
| Varint / protobuf wire | Done | — |
| Lean req/resp codec | Done | — |
| Gossipsub codec | Done | — |
| Snappy framing | Done | — |
| TCP transport | Done | [#35](https://github.com/ch4r10t33r/zig-libp2p/issues/35) |
| QUIC /quic-v1 transport (listen, dial, UDP drive, accept) | Done | [#15](https://github.com/ch4r10t33r/zig-libp2p/issues/15) — [`transport.quic_endpoint`](../src/transport/quic_endpoint.zig) + zquic |
| QUIC multiaddr + per-stream negotiate | Done | [#37](https://github.com/ch4r10t33r/zig-libp2p/issues/37) — `listenMultiaddr` / `dialMultiaddr` / `dialExtended`, `QuicLifecycleHooks`, `popNextUnreportedPeerBidiStream`, per-stream [`stream_multistream.responderHandshakeMultistreamAmong`](../src/transport/stream_multistream.zig); two-stream loopback test. Outbound server PeerId: [`quic_peer_identity`](../src/transport/quic_peer_identity.zig). |
| libp2p TLS on QUIC (ALPN, peer auth) | Done | [#16](https://github.com/ch4r10t33r/zig-libp2p/issues/16) — zquic **1.6.11** (TLS `CertificateRequest` wire fix); [`quic_peer_identity`](../src/transport/quic_peer_identity.zig). |
| `QuicRuntime` in-memory TLS PEM | Done | [#129](https://github.com/ch4r10t33r/zig-libp2p/issues/129) — [`TlsPemSource`](../src/transport/quic_runtime.zig) `.paths` or `.pem_bytes` (ephemeral files for zquic, unlinked on `destroy`) |
| Gossipsub PRUNE backoff (60 s default) | Done | [#83](https://github.com/ch4r10t33r/zig-libp2p/issues/83) |
| Ping behaviour (`/ipfs/ping/1.0.0`) | Done | [#42](https://github.com/ch4r10t33r/zig-libp2p/issues/42) |
| KeyPair / PEM → PeerId | Done | [#47](https://github.com/ch4r10t33r/zig-libp2p/issues/47) |
| Swarm / network runtime | Done | [#34](https://github.com/ch4r10t33r/zig-libp2p/issues/34) — `std.Io.Threaded` command queue (8192) + event channel, 256 cmd/tick, `Swarm.initWithConfig` / `Swarm.tick`, `Swarm.startBackground` / `Swarm.run`; dial command carries optional `expected_peer`; transport still embedder-owned |
| Noise XX | Done | [#36](https://github.com/ch4r10t33r/zig-libp2p/issues/36) — [`security.noise`](../src/security/noise/libp2p_noise.zig) XX + libp2p identity protobuf; [`stream_upgrade`](../src/security/noise/stream_upgrade.zig) multistream `/noise`; unit tests + TCP loopback handshake (Darwin TCP skipped like `wire_tcp`); rust-libp2p interop manual |
| libp2p TLS on TCP (`/tls/1.0.0`) | Done | [#86](https://github.com/ch4r10t33r/zig-libp2p/issues/86) — [`transport.tcp_tls`](../src/transport/tcp_tls.zig) / [`stream_upgrade`](../src/transport/tcp_tls/stream_upgrade.zig): multistream + TLS 1.3 (ALPN `libp2p`) via vendored `zquic_tls` `nonblock` handshake; libp2p cert verify on client; TCP loopback test (Darwin skipped); rust-libp2p interop manual |
| Noise RSA + ECDSA-P256 identities | Done | [#87](https://github.com/ch4r10t33r/zig-libp2p/issues/87) — `identity.verifySignature` for `.RSA` (PKCS#1 v1.5 / SHA-256) and `.ECDSA` (SPKI-wrapped P-256); round-trip tests in `identity.zig` |
| Connection manager | Done | [#38](https://github.com/ch4r10t33r/zig-libp2p/issues/38) — `connection_manager` + `peer_events` (`Direction.unknown`), dial string without `/p2p`, reconnect backoff, refcount + events, optional `setReqResp`; embedder wires transport → `tick` / `onDialFailure` / `onConnectionEstablished` / `onConnectionClosed` |
| Gossipsub mesh runtime | Done | [#39](https://github.com/ch4r10t33r/zig-libp2p/issues/39) |
| Gossipsub PRUNE + unsubscribe backoff | Done | [#83](https://github.com/ch4r10t33r/zig-libp2p/issues/83) |
| Req/resp behaviour | Done | [#40](https://github.com/ch4r10t33r/zig-libp2p/issues/40) — `req_resp.runtime` (timeouts, `channel_id`, `onPeerDisconnected`); `wire_framing`, `wire_tcp`, `wire_quic`; `connection_manager.setReqResp` notifies `ReqResp` on last session close; end-to-end on live streams remains embedder transport + `swarm` |
| Identify (`/ipfs/id/1.0.0`) | Done | [#41](https://github.com/ch4r10t33r/zig-libp2p/issues/41) |
| Metrics (Prometheus-style) | Done | [#43](https://github.com/ch4r10t33r/zig-libp2p/issues/43) — [`metrics`](../src/metrics.zig), [`SwarmConfig`](../src/swarm.zig), [`GossipsubConfig`](../src/gossipsub/runtime.zig) |
| Typed error sets (layers) | Done | [#45](https://github.com/ch4r10t33r/zig-libp2p/issues/45) — `errors` + `layer_events` + transport mappers; `setLastErrorMessage` / `lastErrorMessage` |
| Fuzz / stress / interop harness | Done (CI scope) | [#44](https://github.com/ch4r10t33r/zig-libp2p/issues/44) — `zig build fuzz`; [`wire_boundaries.zig`](../src/wire_boundaries.zig). Long libFuzzer runs and full rust-libp2p matrix: manual ([`tests/interop/README.md`](../tests/interop/README.md)). |

## Embedder notes

Forwarding transport events into [`connection_manager`](../src/connection_manager.zig) and [`swarm`](../src/swarm.zig), and binding req/resp to real substreams, remains application-owned (behaviour is in-tree; wiring is not automatic).

QUIC UDP pumping: [`transport.quic_endpoint`](../src/transport/quic_endpoint.zig) `drive` + zquic. QUIC dial path: default TLS PeerId verification via [`quic_peer_identity`](../src/transport/quic_peer_identity.zig). Non-zquic TLS: use [`peerIdFromVerifiedCertificate`](../src/security/libp2p_tls.zig) at the handshake boundary.

## Pinned versions

| Requirement | Version / note |
|-------------|----------------|
| Zig | **0.16.0** (`minimum_zig_version` in `build.zig.zon`) |
| QUIC stack | **zquic 1.6.11** (pinned in `build.zig.zon`; re-exported as `zig_libp2p.zquic`) |
| QUIC cross-impl (Phase B) | Done | [#166](https://github.com/ch4r10t33r/zig-libp2p/issues/166) — handshake + ping + gossipsub green zig↔go; harness in [`interop_quic/`](../interop_quic/) |

## Development

- **Tests:** `zig build test` runs library tests and smoke-runs most `example-*` binaries. `example-req-resp-tcp-status` is **compile-only** in that step (TCP + `Io.Threaded` can hang CI); run it manually from `zig-out/bin/`; [`req_resp/wire_tcp.zig`](../src/req_resp/wire_tcp.zig) integration tests cover the path on non-Darwin targets.
- **Fuzz:** `zig build fuzz` runs `wire fuzz …` tests (`std.testing.fuzz` smoke). Long sessions: `zig build test --fuzz` with the Zig fuzzing UI.
- **CI:** `zig fmt --check .`, `zig build test`, `zig build fuzz`, `zig build examples`, `zig build` — see [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).
- **Releases:** [release-please](https://github.com/googleapis/release-please) ([`.github/workflows/release-please.yml`](../.github/workflows/release-please.yml)). It does **not** run on every push: use **Actions → release-please → Run workflow** to open or refresh the release PR; merging that PR (branch name `release-please--branches--main`) triggers the publish step. [Conventional Commits](https://www.conventionalcommits.org/) keep `CHANGELOG.md` aligned with `build.zig.zon`. If the job cannot create PRs, enable **Allow GitHub Actions to create and approve pull requests** under repository Actions settings, or set secret `RELEASE_PLEASE_TOKEN` to a PAT with Contents and Pull requests write (the workflow prefers that token when set).

## Roadmap / hygiene

[#31](https://github.com/ch4r10t33r/zig-libp2p/issues/31) is closed (library-complete). Active: [#166](https://github.com/ch4r10t33r/zig-libp2p/issues/166) QUIC cross-impl (last ping pair), [#57](https://github.com/ch4r10t33r/zig-libp2p/issues/57) async swarm.

**Examples contract:** new public APIs should add or extend an `examples/` program that exits 0 under `zig build test`, unless documented as compile-only. Avoid a second `addTest` root on the same `zig_libp2p` module (Zig 0.16 type identity).
