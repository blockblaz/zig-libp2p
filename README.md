# zig-libp2p

Pure-Zig helpers for **libp2p-flavored** networking in Lean Ethereum clients: length-prefixed req/resp, gossipsub protobuf, multistream-select, QUIC-related constants, and shared dependencies (`peer_id`, `multiaddr`, Snappy) aligned with Zeam pins.

Tracking native replacement for Zeam’s `libp2p-glue`: [#31](https://github.com/ch4r10t33r/zig-libp2p/issues/31). The table below is the **maintained** Zeam-facing index; [#31](https://github.com/ch4r10t33r/zig-libp2p/issues/31) carries the full behavioural contract, sub-issue checklist, and API sketch.

## Zeam parity

| Surface | Status | Issue |
|---------|--------|-------|
| Multistream-select | Done | — |
| Varint / protobuf wire | Done | — |
| Lean req/resp codec | Done | — |
| Gossipsub codec | Done | — |
| Snappy framing | Done | — |
| TCP transport | Done | [#35](https://github.com/ch4r10t33r/zig-libp2p/issues/35) |
| QUIC /quic-v1 transport (listen, dial, UDP drive, accept) | Done | [#15](https://github.com/ch4r10t33r/zig-libp2p/issues/15) — [`transport.quic_endpoint`](#transport) + zquic |
| QUIC multiaddr + per-stream negotiate | Done | [#37](https://github.com/ch4r10t33r/zig-libp2p/issues/37) — [`transport.quic_endpoint`](./src/transport/quic_endpoint.zig): `listenMultiaddr` / `dialMultiaddr` / `dialExtended`, `QuicLifecycleHooks`, `popNextUnreportedPeerBidiStream`, per-stream [`stream_multistream.responderHandshakeMultistreamAmong`](./src/transport/stream_multistream.zig); two-stream loopback test. Server PeerId on outbound QUIC: [`transport.quic_peer_identity`](./src/transport/quic_peer_identity.zig). Rust listener interop: manual until [#44](https://github.com/ch4r10t33r/zig-libp2p/issues/44). |
| libp2p TLS on QUIC (ALPN, peer auth) | Partial | [#16](https://github.com/ch4r10t33r/zig-libp2p/issues/16) — Dialer: [`transport.quic_peer_identity`](#transport) + zquic `Client.peerLeafCertificateDer` verify the **server** leaf (`dialExtended` / `dialMultiaddr` default). Listener: client `Certificate` flight not in zquic yet → inbound PeerId from TLS TBD. |
| Ping behaviour (`/ipfs/ping/1.0.0`) | Done | [#42](https://github.com/ch4r10t33r/zig-libp2p/issues/42) |
| KeyPair / PEM → PeerId | Done | [#47](https://github.com/ch4r10t33r/zig-libp2p/issues/47) |
| Swarm / network runtime | Done | [#34](https://github.com/ch4r10t33r/zig-libp2p/issues/34) — `std.Io.Threaded` command queue (8192) + event channel, 256 cmd/tick, [`Swarm.initWithConfig`] / [`Swarm.tick`] embedder mode, [`Swarm.startBackground`]/[`Swarm.run`]; dial command carries optional `expected_peer`; transport still embedder-owned |
| Noise XX | Done | [#36](https://github.com/ch4r10t33r/zig-libp2p/issues/36) — [`security.noise`](./src/security/noise/libp2p_noise.zig) XX + libp2p identity protobuf; [`security.noise.stream_upgrade`](./src/security/noise/stream_upgrade.zig) multistream `/noise`; unit tests + TCP loopback handshake in `stream_upgrade` (Darwin TCP skipped like `wire_tcp`); rust-libp2p interop remains manual / [#44](https://github.com/ch4r10t33r/zig-libp2p/issues/44) |
| Connection manager | Done | [#38](https://github.com/ch4r10t33r/zig-libp2p/issues/38) — `connection_manager` + `peer_events` (`Direction.unknown`), dial string without `/p2p`, reconnect backoff, refcount + events, optional `setReqResp`; embedder wires transport → `tick` / `onDialFailure` / `onConnectionEstablished` / `onConnectionClosed` |
| Gossipsub mesh runtime | Done | [#39](https://github.com/ch4r10t33r/zig-libp2p/issues/39) — `gossipsub.runtime`: mesh + heartbeat, lazy IHAVE (`gossip_lazy`, `OutDeliveryKind.lazy_ihave`), IWANT → pull cache, `max_transmit_size_bytes`, global + per-peer outbox caps (drop oldest lazy first), `setPeerBehaviourScore` / `peerBehaviourScore` for GRAFT / PRUNE / lazy ordering |
| Req/resp behaviour | Done | [#40](https://github.com/ch4r10t33r/zig-libp2p/issues/40) — `req_resp.runtime` (15s request / 5min inbound idle timeouts, `channel_id`, `onPeerDisconnected`); `req_resp.wire_framing`, TCP `req_resp.wire_tcp`, QUIC `req_resp.wire_quic`; `connection_manager.setReqResp` notifies `ReqResp` on last session close; end-to-end on live streams remains embedder transport + [`swarm`](#api-overview) (#34) |
| Identify (`/ipfs/id/1.0.0`) | Done | [#41](https://github.com/ch4r10t33r/zig-libp2p/issues/41) |
| Metrics (Prometheus-style) | Not started | [#43](https://github.com/ch4r10t33r/zig-libp2p/issues/43) |
| Typed error sets (layers) | Done | [#45](https://github.com/ch4r10t33r/zig-libp2p/issues/45) — `errors` + `layer_events` + transport mappers; per-thread `setLastErrorMessage` / `lastErrorMessage` for Rust-style string context |
| Fuzz / stress / interop harness | Not started | [#44](https://github.com/ch4r10t33r/zig-libp2p/issues/44) |

**Still heavy lift for embedders:** forwarding transport events into [`connection_manager`](./src/connection_manager.zig) + [`swarm`](./src/swarm.zig) and binding req/resp to real substreams (behaviour in-tree; wiring remains app-owned). QUIC **UDP pumping** is [`transport.quic_endpoint.drive`](#transport) + zquic; QUIC **dial** path runs default TLS PeerId verification via [`transport.quic_peer_identity`](#transport). Non-zquic TLS still needs [`peerIdFromVerifiedCertificate`](./src/security/libp2p_tls.zig) at the right handshake boundary (#16).

| Requirement | Version / note |
|-------------|----------------|
| Zig | **0.16.0** (`minimum_zig_version` in `build.zig.zon`) |
| QUIC stack | **zquic ≥ 1.6.2** (pinned in `build.zig.zon`; local dev may use `path = \"../zquic\"`, re-exported as `zig_libp2p.zquic`) |

---

## Usage

Add the package in `build.zig.zon`, then in `build.zig`:

```zig
const zig_libp2p = b.dependency("zig_libp2p", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_libp2p", zig_libp2p.module("zig_libp2p"));
```

Application code: `@import("zig_libp2p")` — symbols below match `src/root.zig`.

**Tests:** `zig build test` runs the library test binary, then **smoke-runs** most `example-*` programs (exit code 0). The TCP status example is **compile-only** in that step (running it can stall: `Io.Threaded` + TCP accept/dial across threads is unreliable on Darwin and has hung CI on Linux). Run `./zig-out/bin/example-req-resp-tcp-status` manually after `zig build`; `src/req_resp/wire_tcp.zig` integration tests cover the same path on non-Darwin targets.  
**Examples:** `zig build` installs `example-*` binaries under the install prefix; `zig build examples` compiles them without installing. See [`examples/README.md`](./examples/README.md).  
**CI:** `zig fmt --check .`, `zig build test --summary all`, `zig build examples`, `zig build` (see `.github/workflows/ci.yml`).

---

## API overview

Imports use the `zig_libp2p` prefix (e.g. `zig_libp2p.varint`, `zig_libp2p.gossipsub.control`).

### Top-level modules

| Module | Role |
|--------|------|
| `errors` | Layered errors: `ReqRespError`, `GossipsubError`, `TransportError`; `setLastErrorMessage` / `lastErrorMessage` / `clearLastErrorMessage` (#45) |
| `layer_events` | Event carriers: `ReqRespFailure`, `GossipsubFailure`, `TransportFailure` (each has a `kind:` field for `switch`) (#45) |
| `peer_events` | Peer connection payloads: `Direction` (`inbound` / `outbound` / `unknown`), `DisconnectReason`, `ConnectionFailureResult`, connected / disconnected / failed event structs (#38) |
| `connection_manager` | Known-peer dial scheduling (multiaddr without `/p2p`), reconnect backoff, refcount + peer events (#38), `knownPeerStatus` / `KnownPeerDialStatus`; optional `setReqResp` → `ReqResp.onPeerDisconnected` on last session close (#40) |
| `swarm` | Bounded `submit` / `nextEvent`, `queueEvent`, `shutdown` (#34); `SwarmConfig` + `initWithConfig` (fixed `local_peer`), `tick` for single-threaded pumping, `commands_per_tick` / `command_capacity`; `RpcRequest.channel_id` (#40); dial stub forwards `expected_peer`; real I/O embedder-owned |
| `protocol` | Lean req/resp protocol id strings; `LeanSupportedProtocol` enum with `protocolId`, `fromInt`, `fromSlice` |
| `varint` | Unsigned varint encode (`encodeToScratch`) / decode (`decode`) |
| `addr_list` | Multiaddr CSV: `parseCsv` (`ParseCsvError`), `freeList` (uses bundled `multiaddr`) |
| `multistream` | Multistream-select 1.0.0 line I/O: `multistream_1_0_0`, `max_protocol_id_body_bytes`, `writeProtocolLine`, `writeProtocolLineWithMax`, `ProtocolLineError`, `trimNegotiationLine` |
| `ping` | Ping 1.0.0: `WireError` = `errors.ReqRespError`, `multistream_protocol_id`, `handleInbound`, `initiatorRoundTripMs`, `Ping` / `PingConfig` |
| `ping_wire_quic` | QUIC raw bidi stream: multistream + ping echo (`initiatorPingRoundTripMs`, `responderHandleInbound`); requires zquic UDP pumping (`quic_endpoint.drive`) |
| `identify` | Identify 1.0.0: oversized wire uses global `PayloadTooLarge` (same tag as other codecs); `encode` / `decodeOwned`, `Identify` helpers |
| `peer_id` | Re-export of `peer-id` package |
| `identity` | `PeerId`, `ParseError` aliases |
| `keypair` | PEM → `KeyPair`; `peerIdFromKeyPair` (`PeerIdFromKeyPairError`) |
| `snappyz` | Re-export of `zig_snappy` (block Snappy) |
| `snappyframesz` | Re-export of Snappy framing for libp2p streams |
| `zquic` | Full **zquic** library (QUIC/TLS); use for transport integration |

### `gossip`

| Submodule | Role |
|-----------|------|
| `gossip.topic` | Lean mesh topic types: `GossipTopic`, `LeanNetworkTopic`, `GossipEncoding`, `GossipTopicKind`, `SubnetId` |

### `gossipsub`

| Submodule | Role |
|-----------|------|
| `gossipsub.config` | Zeam gossipsub constants: `mesh_n` / `mesh_n_low` / `mesh_n_high`, `gossip_lazy`, `heartbeat_interval_ms`, `duplicate_cache_ttl_ms`, `history_length`, `max_transmit_size_bytes` (#39) |
| `gossipsub.message_id` | Wire message ID: `writeMessageId(topic, data, snappy_decompressed_ok, out20)` — SHA256 domain + topic len + topic + data, truncated to 20 bytes (#39) |
| `gossipsub.duplicate_cache` | TTL map `(topic, id)` → expiry; `prune`, `checkDuplicate` (#39) |
| `gossipsub.runtime` | `Gossipsub` + `GossipsubConfig` (`gossip_lazy`, `max_outbox_entries`, `max_queued_per_peer`, …); `OutDeliveryKind`; `setPeerBehaviourScore` / `peerBehaviourScore`; lazy IHAVE on `heartbeat`, IWANT → cached publish; `lazy_i_have_tx`, `dropped_lazy_ihave_backpressure`; `InitConfigError` (#39) |
| `gossipsub.rpc` | RPC envelope: `encodeEmptyControlRpc`, `encodeControlOnlyRpc`, `encodeSubscribe` / `decodeFirstSubscribe` / `decodeSubscribes` / `freeSubscribeViews`, `deinitSubscribeView`, `decodeControlPayload`, `encodePublish` / `decodeFirstPublish`, `decodePublishes` / `freePublishBlobs` |
| `gossipsub.control` | Control message fragments: **IHave** / **IWant** / **IDontWant** / **graft** / **prune**; **ControlExtensions** (`partialMessages`): `encodeControlExtensions`, `encodeControlMessageExtensionsOnly`, `decodeFirstControlExtensions`, `ControlExtensionsView` |
| `gossipsub.message` | `Message` protobuf: `MessageView`, `MessageOwned`, `encode`, `decode`, `MessageOwned.deinit` |

### `protobuf`

| Submodule | Role |
|-----------|------|
| `protobuf.wire` | Minimal proto2 wire: varints, field keys, length-delimited append/scan (`appendVarUInt64`, `decodeVarUInt64`, `appendFieldKey`, `appendLengthDelimited`, `decodeFieldKey`, `nextFieldValue`, `nextFieldValueLimited`, `LengthDelimitedTooLong`, `LengthDelimitedOverflow`) |

### `req_resp`

| Submodule | Role |
|-----------|------|
| `req_resp.frame` | Length-prefixed framing: `max_rpc_message_size`, `parseRequestHeader`, `parseResponseHeader`, `appendRequestPrefix`, `appendResponsePrefix`; `FrameError` = `errors.ReqRespError` |
| `req_resp.stream` | Incremental scan: `peekRpcUnaryRequest` / `peekRpcUnaryResponse`, `scanCompleteRequest` / `scanCompleteResponse`, `consumePrefix`, `InboundBuffer` |
| `req_resp.snappy_wire` | Snappy + framing for `ssz_snappy`: `compressBlock`, `decompressBlock`, `compressFramed`, `decompressFramed`, `buildRequestWire`, `buildResponseWire`, `decodeRequestSsz`, `decodeResponseSsz` |
| `req_resp.runtime` | `ReqResp` / `ReqRespConfig`: outbound `request_id`, inbound `channel_id`, `onPeerDisconnected` → `Disconnected`, `sendResponseChunk` / `finishResponseStream` / `sendErrorResponse`, `create`/`destroy`, `shutdown`, timeouts (#40) |
| `req_resp.wire_framing` | Shared `ssz_snappy` unary read/write on `std.Io.Reader`/`Writer` after protocol selection; `UnaryResponse` (#40) |
| `req_resp.wire_tcp` | TCP: one socket = one substream; `initiatorUnaryExchange`, `initiatorReadResponseSequence`, `responderUnarySequence` (`transport.tcp` multistream + `wire_framing`) (#40) |
| `req_resp.wire_quic` | QUIC raw bidi stream: same helpers as TCP using `quic_raw_stream_io` + `stream_multistream` + `wire_framing`; requires zquic UDP pumping (#40) |

### `transport`

| Submodule | Role |
|-----------|------|
| `transport.quic_v1` | QUIC v1 labels + zquic wiring: `multistream_protocol_id`, `tls_alpn` (alias of `security.libp2p_tls.quic_application_layer_protocol`), `libp2pZquicServerConfig` / `libp2pZquicClientConfig` (`raw_application_streams`), `appendFirstBidiStreamInitiatorHandshake` |
| `transport.quic` | QUIC transport entrypoint: re-exports `quic_v1` + `stream_multistream`, `parseQuicV1Endpoint`, `initLibp2pQuicServerFromMultiaddr` / `initLibp2pQuicClientFromMultiaddr` / `initLibp2pQuicClientFromEndpoint`, `bindUdpSocket` for `/udp/.../quic-v1` (and optional `/p2p`) |
| `transport.quic_endpoint` | **#15 / #37 / #16 (dial):** `QuicListener` (`listen`, `drive`, `pollAccept`, `QuicLifecycleHooks`, `popNextUnreportedPeerBidiStream`), `QuicOutbound` (`dial`, `dialExtended`, `dialMultiaddr`, `verifiedRemotePeerId`, `destroyAllocated`, …), `QuicOutboundDialOptions.verify_libp2p_tls_peer`, `listenMultiaddr`, `loopbackPingOnce`, `loopbackPingTwoStreams` |
| `transport.quic_peer_identity` | **#16:** `verifiedPeerIdFromLibp2pQuicClient` — libp2p TLS verify + optional `/p2p` match using zquic captured server leaf |
| `transport.transport_error` | Maps `std.Io.net`, multistream I/O, `security.libp2p_tls`, `security.noise.libp2p` (`fromLibp2pNoise`), and **zquic** (`fromZquicWireTransport`, `fromZquicOpenLocalStream`, typed `fromZquicIoSetup` / `fromZquicRun` on `ZquicIoSetupError` / `ZquicRunError`) into `TransportError` |
| `transport.stream_multistream` | Per-stream multistream-select on `std.Io.Reader` / `Writer`: `responderHandshakeMultistreamAmong` (#37), `StreamHandshakeError` = `errors.TransportError` \|\| `Allocator.Error`; `appendFirstStreamInitiatorHandshake` still uses `NegotiateError` for buffer-only builds |
| `transport.tcp` | TCP over `std.Io.net`: `listen` / `dial` / `acceptTuned` surface `TransportError` (plus `SocketTuningFailed` where tuning runs), `multistream_protocol_id`, thin wrappers around `stream_multistream` |
| `transport.multistream_negotiate` | **Bounded** multistream-select 1.0.0 on a byte cursor: `default_max_body_len`, `readNegotiationLine`, `validateProtocolId`, initiator/responder steps (`initiatorSendMultistreamHeader`, `responderReadProtocolOffer`, `responderReplyProtocol`, …), `NegotiateError` |

### `security`

| Submodule | Role |
|-----------|------|
| `security.libp2p_tls` | libp2p TLS 1.3 profile (#16): ALPN / multistream ids, extension OID, `peerIdFromCertificate` (parse only), `peerIdFromVerifiedCertificate` (self-signed X.509 + `SignedKey` over SPKI), spec vectors 1–4 |
| `security.noise` | Noise XX + libp2p framing (#36): `protocol` (handshake + transport keys), `payload` / `identity` (protobuf + static-key signing, `verifySignedPayload` rejects bad static-key sig), `libp2p_noise` (`/noise`, length-prefixed frames, `SecureChannel`), `stream_upgrade` (multistream + handshake; TCP loopback test on non-Darwin) |

---

## Roadmap

Priorities follow the [parity table](#zeam-parity) and [#31](https://github.com/ch4r10t33r/zig-libp2p/issues/31). Sensible next picks (after examples/CI hygiene):

1. **QUIC (#37) + TLS #16** — `transport.quic_endpoint` covers listen/dial/pump, per-stream multistream, lifecycle hooks; peer-id from peer leaf cert remains #16; Rust↔Zig QUIC interop manual until #44; `example-quic-ping-loopback` exercises loopback ping.
2. **Metrics #43** — counters/histograms behind a narrow interface.

Near term overlap: [#37](https://github.com/ch4r10t33r/zig-libp2p/issues/37) / [#16](https://github.com/ch4r10t33r/zig-libp2p/issues/16) QUIC + TLS verification. **ControlExtensions.partialMessages** wire helpers live in `gossipsub.control` (experimental fields). **Noise ↔ rust-libp2p** TCP interop: tracked under [#44](https://github.com/ch4r10t33r/zig-libp2p/issues/44) / Zeam harness.

**Examples contract:** new public APIs should get or extend an `examples/` program that still exits 0 under `zig build test` (smoke-run after unit tests), unless there is a documented reason to compile-only (like the TCP + `Io.Threaded` demo). Avoid a second `addTest` root on the same `zig_libp2p` module — it recompiles the library graph and breaks Zig 0.16 type identity.

---

## Repository

https://github.com/ch4r10t33r/zig-libp2p
