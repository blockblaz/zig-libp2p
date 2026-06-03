# Changelog

## [0.1.3](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.2...v0.1.3) (2026-06-03)


### Features

* **transport:** gossipsub publish + inbound on the wire ([#117](https://github.com/ch4r10t33r/zig-libp2p/issues/117)) ([e17b95d](https://github.com/ch4r10t33r/zig-libp2p/commit/e17b95d1facf73eda19ba333d3abe87802f20e88))

## [0.1.2](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.1...v0.1.2) (2026-06-03)


### Features

* **security:** libp2p TLS self-signed certificate generator ([#114](https://github.com/ch4r10t33r/zig-libp2p/issues/114)) ([71be9c5](https://github.com/ch4r10t33r/zig-libp2p/commit/71be9c5174627be552987518f2bb8b6e0c334e2c))
* **swarm:** CommandDispatchHook for real-transport interception ([#113](https://github.com/ch4r10t33r/zig-libp2p/issues/113)) ([7008756](https://github.com/ch4r10t33r/zig-libp2p/commit/7008756721ab5f0e4ed4318e68754bf20e7d47bd))
* **transport:** QuicRuntime + libp2p_tls_cert ECDSA-P-256 path ([#115](https://github.com/ch4r10t33r/zig-libp2p/issues/115)) ([ce93883](https://github.com/ch4r10t33r/zig-libp2p/commit/ce9388317054bf8a0a32974c5e3139ba08edf19f))

## [0.1.1](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.0...v0.1.1) (2026-06-02)


### Bug Fixes

* **host:** correct req/resp Error type namespace ([#111](https://github.com/ch4r10t33r/zig-libp2p/issues/111)) ([fb2faca](https://github.com/ch4r10t33r/zig-libp2p/commit/fb2facae9377c8bebf75c30aa2dda9b5e7f027e7))

## 0.1.0 (2026-06-02)

First tagged release. Pure-Zig libp2p building blocks for Lean Ethereum
clients; minimum Zig version 0.16.0.

### Subsystems

- **Gossipsub v1.1 runtime** with PRUNE back-off enforcement
  (per-(peer,topic) windows, graft-flood refusal, reciprocal back-off),
  topic-validator hook (`accept`/`reject`/`ignore` mapped to behaviour-
  score deltas), direct peers (always-mesh, bypass back-off), IDONTWANT
  runtime suppression, PRUNE PX wire (encode/decode) + a
  `popDialSuggestion` queue, lazy IHAVE gossip toward non-mesh peers,
  IWANT fulfilment from a bounded pull cache, targeted outbox with
  global + per-peer caps, and `(from, seqno)` defense-in-depth dedup.
- **Req/resp runtime** matching the Lean codec spec exactly
  (`varint(uncompressed_len) || snappy_framed_payload`); registered
  inbound channels with per-channel timeouts; on-disconnect cleanup
  hook from the connection manager.
- **Identify 1.0.0** + **identify push** (`/ipfs/id/push/1.0.0`); libp2p
  RFC 0002 SignedEnvelope decode; PeerRecord decode; the canonical
  signature-domain message builder.
- **libp2p TLS 1.3** over QUIC with full verification: X.509 self-sig,
  validity window, SignedKey signature against
  `"libp2p-tls-handshake:" || SPKI`, and PeerId derivation. Spec
  vectors 1–4 covered. Unverified helper renamed to make the security
  trade-off explicit.
- **Noise XX** with Ed25519, Secp256k1, and ECDSA-P256 identity-key
  verification. RSA explicitly deferred with a typed
  `UnsupportedNoiseIdentityKeyType`.
- **QUIC v1 transport** on bundled zquic: listen, dial, non-blocking
  UDP `drive`, `pollAccept`, per-stream multistream-select. Configurable
  over-cap policy with `on_inbound_stream_over_cap_breach` callback.
- **TCP transport** + multistream-select; Noise XX stream upgrade;
  libp2p-TLS wire-protocol scaffold (`/tls/1.0.0` constants +
  `verifyPeerLeafCertificate`). Full TCP-TLS handshake pump deferred
  until upstream zquic re-exports `tls.nonblock`.
- **Connection manager** with known-peer dial scheduling, capped
  reconnect back-off, `ConnectionLimits { max_per_peer, max_total,
  high_watermark, low_watermark }`, and `Event.connection_trim_recommended`
  with typed reason codes.
- **Yamux** + **mplex** stream multiplexers (full state machines, edge-
  case tests).

### Lifecycle

- **`Swarm`** — bounded command queue, bounded event queue, threaded
  background mode or explicit `tick`. `waitUntilReady` synchronous
  signal so embedders can park until the worker enters its loop.
- **`Host`** — canonical wiring of Swarm + Gossipsub + ReqResp +
  ConnectionManager into one initializable object; type-safe
  passthroughs for `subscribe` / `publish` / `sendRequest` and
  transport hooks for `onConnectionEstablished` / `onConnectionClosed`
  / `onDialFailure` / `handleGossipRpc`. Worked example in
  `examples/host_quic_node.zig`.

### Observability

- Prometheus-style metrics: `lean_gossip_mesh_peers{network_id}` gauge,
  `swarm_command_dropped_total{network_id, reason}` counter with
  `full` / `closed` / `uninitialized` reasons.
- Per-listener counters: `inboundStreamsReportedCount`,
  `silentlySkippedInboundStreamsCount`, `overCapBreachCount`.
- Per-subsystem observability hooks: `graftRefusedDuringBackoffCount`,
  `inboundDroppedSeqnoReplayCount`, `activeBackoffCount`,
  `validatorRejectCount` / `validatorIgnoreCount`,
  `suppressedOutboundIDontWantCount`, `idontwantCount`,
  `dialSuggestionCount`, `trimRecommendationCount`,
  `activeConnectionCount`.

### Test + bench infrastructure

- `zig build test` — 283/283 tests pass on Linux + macOS.
- `zig build fuzz` — wire-conformance harness over varint, req/resp
  frame headers, gossipsub RPC / control, yamux + mplex frames, Snappy,
  and gossipsub `Message` decode.
- `zig build bench` — microbenchmarks for hot paths (varint encode /
  decode, gossipsub PRUNE round trip, dup-cache hit / miss, yamux
  header parse). Runs as part of CI.
- `interop.yml` — nightly extended fuzz budget + a placeholder for the
  rust-libp2p ping-responder Docker pairing (TODO).

### Known limitations

- Gossipsub v1.2 polish (flood publish, adaptive gossip, IHAVE/IWANT
  per-heartbeat caps, PRUNE PX auto-dial) is partial.
- TCP libp2p-TLS handshake pump is wire-scaffold-only; the actual TLS
  pump is blocked on upstream zquic re-exporting `tls.nonblock`.
- WebSocket / WSS / WebRTC transports, Kademlia DHT, AutoNAT,
  Circuit Relay v2, DCUtR hole punching, and discv5 / ENR are not
  implemented (tracked in #91 / #92 / #93 / #94).
- `std.Io` async swarm migration design landed in `docs/async-swarm.md`;
  the port itself is gated on Zig's `std.Io` API settling (#57).
- Four loopback test modules (`security/noise/stream_upgrade.zig`,
  `transport/quic_endpoint.zig`, `transport/tcp.zig`,
  `req_resp/wire_tcp.zig`) are excluded from CI test discovery to
  avoid an `Io.Threaded` + parallel accept/dial deadlock; their
  wire-level logic is exercised via sibling unit-test modules that
  don't open real sockets.
