# Changelog

## Unreleased

## [0.1.18](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.17...v0.1.18) (2026-06-10)

### Fixed

* **transport/quic_runtime:** use go-multistream delimited framing on outbound
  req/resp and publish streams so rust-libp2p responders accept the handshake
  ([#184](https://github.com/ch4r10t33r/zig-libp2p/issues/184)). Replace the
  legacy two-newline inbound pre-buffer with incremental responder negotiation.
  Answer inbound `/ipfs/id/1.0.0` and `/ipfs/ping/1.0.0` streams from
  rust-libp2p peers.

## [0.1.17](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.16...v0.1.17) (2026-06-10)

### Features

* **relay,dcutr:** Circuit Relay v2 wire codec, reservation/client/server modules, live QUIC
  bridging, and DCUtR hole-punch coordination. Closes
  [#91](https://github.com/ch4r10t33r/zig-libp2p/issues/91). Guide:
  [docs/RELAY.md](docs/RELAY.md), [docs/DCUTR.md](docs/DCUTR.md).
* **transport/quic_runtime:** persistent per-peer `/meshsub/1.0.0` stream to avoid resubscribe
  churn; closes [#183](https://github.com/ch4r10t33r/zig-libp2p/issues/183).

### Notes

* Relay/DCUtR interop smoke tests (`interop_quic/relay_test.sh`) cover zig↔zig paths; go/rust
  matrix and full NAT hole punch over shared sockets remain follow-up work.

## [0.1.16](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.15...v0.1.16) (2026-06-09)

### Features

* **autonat:** AutoNAT v1 (`/libp2p/autonat/1.0.0`) and v2 (`/libp2p/autonat/2/*`) wire codecs,
  client probe scheduling, server dial-back handlers with embedder `DialBackFn`, and reachability
  aggregation (`NatStatus`). Closes [#92](https://github.com/ch4r10t33r/zig-libp2p/issues/92).
  Guide: [docs/AUTONAT.md](docs/AUTONAT.md).
* **kad_dht:** Kademlia DHT (`/ipfs/kad/1.0.0`) routing table, wire codec, iterative
  `findNode` / `findProviders`, provider record store (24 h TTL), bootstrap API, and
  client/server mode. Closes [#93](https://github.com/ch4r10t33r/zig-libp2p/issues/93).
  Guide: [docs/KAD_DHT.md](docs/KAD_DHT.md).

## [0.1.15](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.14...v0.1.15) (2026-06-09)

### Fixed

* **transport/quic_runtime:** skip oversize gossipsub frames instead of dropping
  the entire inbound QUIC stream when a declared frame length exceeds the accept
  cap. One bad publish no longer tears down the peer's gossip path.

### Changed

* **gossipsub/wire_limits:** raise gossip RPC frame cap to **16 MiB** (from 4 MiB)
  for hash-sig Lean blocks and aggregates; add **128 MiB** absolute declared-length
  griefing cap.
* **req_resp/frame:** raise single-message uncompressed SSZ cap to **32 MiB** and
  per-stream accumulator to **64 MiB** for `blocks_by_root` / `blocks_by_range`.

## [0.1.14](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.13...v0.1.14) (2026-06-08)

### Fixed

* **security/libp2p_tls:** stop rejecting rust-libp2p/rcgen certificates with
  `CertificateNotYetValid`. `std.crypto.Certificate` parses every two-digit
  UTCTime year as `2000 + YY`, so rcgen's default `notBefore` of `1975-01-01`
  (also the libp2p TLS spec test vectors) was read as **2075** and every
  present-day handshake failed. We now verify the validity window per RFC 5280
  §4.1.2.5.1 (`YY >= 50` → `19YY`) and reuse std only for issuer + self-signature
  checks. This unblocks QUIC/TLS peering with quinn-based clients (ethlambda).

## [0.1.13](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.12...v0.1.13) (2026-06-08)

### Fixed

* **transport/quic_runtime:** gossipsub publish over inbound QUIC connections
  (server-initiated streams on accepted conns) so zeam can reach ethlambda when
  only the reverse dial succeeds; skip redundant outbound dials and dial-failure
  events when the peer is already connected inbound.

### Dependencies

* zquic bumped to **v1.6.15** — client Handshake CRYPTO reassembly for quinn
  outbound dials.

## [0.1.11](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.10...v0.1.11) (2026-06-08)

### Features

* **interop_quic:** gossipsub cross-impl green (4/4 zig↔go) — align go-libp2p
  role split with zig (client publishes, server receives).

### Dependencies

* zquic bumped to **v1.6.13** — fix AppAckTracker duplicate ACK ranges that
  panicked zig server under go-libp2p gossipsub traffic.

## [0.1.10](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.9...v0.1.10) (2026-06-08)

### Features

* **interop_quic:** full zig↔go-libp2p **ping** matrix (8/8 green) — preserve
  go MSSelect coalesced payload after multistream-select; inbound Identify on
  handshake server path.
* **transport/stream_multistream:** optional `tail` out-parameter on
  `responderHandshakeMultistreamAmong` for application bytes read ahead during
  negotiation.
* **ping:** `handleInboundPrefixed` for echo when part of the payload already
  arrived with the multistream handshake.

### Dependencies

* zquic bumped to **v1.6.12** — ignore quic-go `RETIRE_CONNECTION_ID` seq 0
  (RFC violation) so go-libp2p client → zig server ping completes.

## [0.1.9](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.8...v0.1.9) (2026-06-08)

### Features

* **interop_quic:** go-libp2p cross-impl over QUIC — delimited multistream-select
  (go-multistream v0.5), Identify responder stub on `/ipfs/id/1.0.0`, pending-stream
  ping server, and `zig build interop-matrix` (#166).
* **transport/multistream:** auto-detect peer framing (legacy `\n` vs uvarint-delimited
  tokens); mirror framing on responder replies.
* **transport/quic_raw_stream_io:** `writeAllFin` for half-closing raw app streams after
  Identify (go-libp2p reads delimited protobuf until EOF).

### Dependencies

* zquic bumped to **v1.6.11** — TLS `CertificateRequest` `signature_algorithms` list
  length prefix fix (cross-impl mutual-TLS handshake with go-libp2p / rust-libp2p).

## [0.1.8](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.7...v0.1.8) (2026-06-04)

### Features

* **tcp_tls:** TCP TLS responder requests a client certificate and verifies
  the libp2p extension (`negotiateResponder`); initiator accepts optional
  `client_auth` for mTLS (#86). Interop dialer sends client cert and enforces
  `/p2p/` from the listener multiaddr.
* **tcp_tls:** initiator now offers all three RFC 8446 TLS 1.3 cipher suites
  (`CHACHA20_POLY1305_SHA256`, `AES_128_GCM_SHA256`, `AES_256_GCM_SHA384`) and
  `x25519` + `secp256r1` + `secp384r1` named groups instead of a single-element
  list, enabling negotiation against rust-libp2p / go-libp2p peers regardless
  of their preferred order.
* **interop:** `fillRandomBytes` uses `getrandom` / `arc4random_buf` /
  `std.crypto.random` instead of a deterministic `0x42` fallback when libc is
  absent.

### Security

* **vendor/zquic_tls:** explicit size guard on the client-leaf-cert capture
  in `handshake_server.zig`. Previously the 8 KiB stack buffer was filled via
  `common.dupe` which `assert`s `buf.len >= data.len`: a hostile peer cert >
  8 KiB would abort the process in ReleaseSafe or overflow the buffer in
  ReleaseFast. Oversized certs now return `error.TlsRecordOverflow` from the
  TLS handshake (mapped to `error.SecurityUpgradeFailed` upstream).

### Tests

* **tcp_tls:** two new negative loopback tests in `stream_upgrade.zig`:
  * `negotiateResponder rejects when initiator omits client cert (mTLS required)`
  * `negotiateResponder rejects when client peer-id != expected_remote`
  These follow the same Darwin-skip / CI-not-force-discovered policy as the
  existing TCP-TLS loopback test (see `root.zig` exclusions); they compile
  in-tree and run when discovery is opted into locally.
* **tcp_tls:** dropped a latent `std.process.hasEnvVar("CI")` call from the
  existing loopback test — that symbol does not exist in Zig 0.16's
  `std.process` and only stayed compilable because the file is excluded from
  CI test discovery. Replaced with a comment pointing at the discovery
  exclusion as the real CI gate.

## [0.1.5](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.4...v0.1.5) (2026-06-03)


### Features

* **transport:** zero-copy in-memory TLS PEM — `TlsPemSource.pem_bytes` now
  threads bytes straight through to zquic v1.6.6's `ServerConfig.cert_pem` /
  `key_pem` and `ClientConfig.client_cert_pem` / `client_key_pem` (see
  [ch4r10t33r/zquic#129](https://github.com/ch4r10t33r/zquic/pull/129)) —
  nothing is written to disk.


### Behavior change (non-breaking)

* In v0.1.4 the `.pem_bytes` arm of `TlsPemSource` materialized ephemeral
  files under `/tmp/zlibp2p_runtime_{N}_{cert,key}.pem` and handed those
  paths to zquic; on `QuicRuntime.destroy` they were unlinked. That broke
  in containers without `/tmp` (e.g. `FROM scratch`). v0.1.5 removes the
  temp-file dance entirely. Public API (`TlsPemSource` shape and the
  `.paths` arm) is unchanged; only the `.pem_bytes` execution path moved
  off-disk.


### Dependencies

* zquic bumped from v1.6.5 to **v1.6.6** for the new in-memory PEM config
  fields.

## [0.1.4](https://github.com/ch4r10t33r/zig-libp2p/compare/v0.1.3...v0.1.4) (2026-06-03)


### Features

* **transport:** `QuicRuntime` accepts in-memory TLS PEM via `TlsPemSource` ([#129](https://github.com/ch4r10t33r/zig-libp2p/issues/129)) ([a318137](https://github.com/ch4r10t33r/zig-libp2p/commit/a31813773c4eef2843689611cebc12ba192bc8cf))


### Security

* address audit findings [#119](https://github.com/ch4r10t33r/zig-libp2p/issues/119)–[#127](https://github.com/ch4r10t33r/zig-libp2p/issues/127) ([#128](https://github.com/ch4r10t33r/zig-libp2p/issues/128)) ([d68171c](https://github.com/ch4r10t33r/zig-libp2p/commit/d68171c)):
  * cap QUIC `req_acc` / `gossip_acc` growth, verify libp2p TLS before marking handshake done, drop streams on TLS / handshake failure;
  * parse libp2p extension OID via TBSCertificate `[3] EXPLICIT Extensions` walk (not substring search);
  * bounded snappy decompression with output budget;
  * remove `firstUnaryResponseWireLen` O(n) trial decompress;
  * verify inbound `signed_peer_record` on Identify pull/push and connection-established paths;
  * remove `verify_libp2p_tls_peer` bypass — QUIC dial always verifies leaf;
  * remove misleading `peerIdFromCertificate` alias;
  * add `docs/SECURITY.md`;
  * secp256k1 host identity in `libp2p_tls_cert` (ephemeral cert key is ECDSA-P-256 per spec vector 3).

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
- Five loopback test modules (`security/noise/stream_upgrade.zig`,
  `transport/quic_endpoint.zig`, `transport/tcp.zig`,
  `transport/tcp_tls/stream_upgrade.zig`, `req_resp/wire_tcp.zig`) are
  excluded from CI test discovery to
  avoid an `Io.Threaded` + parallel accept/dial deadlock; their
  wire-level logic is exercised via sibling unit-test modules that
  don't open real sockets.
