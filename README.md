# zig-libp2p

Pure-Zig helpers for **libp2p-flavored** networking in Lean Ethereum clients: length-prefixed req/resp, gossipsub protobuf, multistream-select, QUIC-related constants, and shared dependencies (`peer_id`, `multiaddr`, Snappy) aligned with Zeam pins.

Tracking native replacement for Zeam’s `libp2p-glue`: [#31](https://github.com/ch4r10t33r/zig-libp2p/issues/31).

## Zeam parity

| Surface | Status | Issue |
|---------|--------|-------|
| Multistream-select | Done | — |
| Varint / protobuf wire | Done | — |
| Lean req/resp codec | Done | — |
| Gossipsub codec | Done | — |
| Snappy framing | Done | — |
| TCP transport | Done | [#35](https://github.com/ch4r10t33r/zig-libp2p/issues/35) |
| QUIC multiaddr + per-stream negotiate | Partial | [#37](https://github.com/ch4r10t33r/zig-libp2p/issues/37) |
| libp2p TLS (PeerId from cert) | Partial | [#16](https://github.com/ch4r10t33r/zig-libp2p/issues/16) |
| Ping behaviour (`/ipfs/ping/1.0.0`) | Done | [#42](https://github.com/ch4r10t33r/zig-libp2p/issues/42) |
| KeyPair / PEM → PeerId | Done | [#47](https://github.com/ch4r10t33r/zig-libp2p/issues/47) |
| Swarm / network runtime | Not started | [#34](https://github.com/ch4r10t33r/zig-libp2p/issues/34) |
| Noise XX | Not started | [#36](https://github.com/ch4r10t33r/zig-libp2p/issues/36) |
| Connection manager | Not started | [#38](https://github.com/ch4r10t33r/zig-libp2p/issues/38) |
| Gossipsub mesh runtime | Not started | [#39](https://github.com/ch4r10t33r/zig-libp2p/issues/39) |
| Req/resp behaviour | Not started | [#40](https://github.com/ch4r10t33r/zig-libp2p/issues/40) |
| Identify (`/ipfs/id/1.0.0`) | Done | [#41](https://github.com/ch4r10t33r/zig-libp2p/issues/41) |
| Metrics (Prometheus-style) | Not started | [#43](https://github.com/ch4r10t33r/zig-libp2p/issues/43) |
| Typed error sets (layers) | Done | [#45](https://github.com/ch4r10t33r/zig-libp2p/issues/45) — `errors` + `layer_events` + transport mappers; per-thread `setLastErrorMessage` / `lastErrorMessage` for Rust-style string context |
| Fuzz / stress / interop harness | Not started | [#44](https://github.com/ch4r10t33r/zig-libp2p/issues/44) |

**Still heavy lift for embedders:** full swarm, connection manager, mesh, and **full** TLS `SignedKey` verification (today: parse + PeerId only in [`security.libp2p_tls`](#security)). QUIC listen/dial lifecycle remains primarily [zquic](https://github.com/ch4r10t33r/zquic) + [`transport.quic_v1`](#transport) presets.

| Requirement | Version / note |
|-------------|----------------|
| Zig | **0.16.0** (`minimum_zig_version` in `build.zig.zon`) |
| QUIC stack | **zquic 1.6.x** (pinned in `build.zig.zon`, re-exported as `zig_libp2p.zquic`) |

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

**Tests:** `zig build test`  
**CI:** `zig fmt --check .`, `zig build test --summary all`, `zig build` (see `.github/workflows/ci.yml`).

---

## API overview

Imports use the `zig_libp2p` prefix (e.g. `zig_libp2p.varint`, `zig_libp2p.gossipsub.control`).

### Top-level modules

| Module | Role |
|--------|------|
| `errors` | Layered errors: `ReqRespError`, `GossipsubError`, `TransportError`; `setLastErrorMessage` / `lastErrorMessage` / `clearLastErrorMessage` (#45) |
| `layer_events` | Event carriers: `ReqRespFailure`, `GossipsubFailure`, `TransportFailure` (each has a `kind:` field for `switch`) (#45) |
| `protocol` | Lean req/resp protocol id strings; `LeanSupportedProtocol` enum with `protocolId`, `fromInt`, `fromSlice` |
| `varint` | Unsigned varint encode (`encodeToScratch`) / decode (`decode`) |
| `addr_list` | Multiaddr CSV: `parseCsv` (`ParseCsvError`), `freeList` (uses bundled `multiaddr`) |
| `multistream` | Multistream-select 1.0.0 line I/O: `multistream_1_0_0`, `max_protocol_id_body_bytes`, `writeProtocolLine`, `writeProtocolLineWithMax`, `ProtocolLineError`, `trimNegotiationLine` |
| `ping` | Ping 1.0.0: `WireError` = `errors.ReqRespError`, `handleInbound`, `initiatorRoundTripMs`, `Ping` / `PingConfig` |
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
| `gossipsub.rpc` | RPC envelope: `encodeEmptyControlRpc`, `encodeSubscribe` / `decodeFirstSubscribe`, `deinitSubscribeView`, `decodeControlPayload`, `encodePublish` / `decodeFirstPublish` |
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

### `transport`

| Submodule | Role |
|-----------|------|
| `transport.quic_v1` | QUIC v1 labels + zquic wiring: `multistream_protocol_id`, `tls_alpn`, `libp2pZquicServerConfig` / `libp2pZquicClientConfig` (ALPN `libp2p`, `raw_application_streams`), `appendFirstBidiStreamInitiatorHandshake` |
| `transport.quic` | QUIC transport entrypoint: re-exports `quic_v1` + `stream_multistream`, `parseQuicV1Endpoint` from multiaddrs with `/udp/.../quic-v1` (and optional `/p2p`) |
| `transport.transport_error` | Maps `std.Io.net`, multistream I/O, `security.libp2p_tls`, and **zquic** (`fromZquicWireTransport`, `fromZquicOpenLocalStream`, typed `fromZquicIoSetup` / `fromZquicRun` on `ZquicIoSetupError` / `ZquicRunError`) into `TransportError` |
| `transport.stream_multistream` | Per-stream multistream-select on `std.Io.Reader` / `Writer`: `StreamHandshakeError` = `errors.TransportError` \|\| `Allocator.Error`; `appendFirstStreamInitiatorHandshake` still uses `NegotiateError` for buffer-only builds |
| `transport.tcp` | TCP over `std.Io.net`: `listen` / `dial` / `acceptTuned` surface `TransportError` (plus `SocketTuningFailed` where tuning runs), `multistream_protocol_id`, thin wrappers around `stream_multistream` |
| `transport.multistream_negotiate` | **Bounded** multistream-select 1.0.0 on a byte cursor: `default_max_body_len`, `readNegotiationLine`, `validateProtocolId`, initiator/responder steps (`initiatorSendMultistreamHeader`, `responderReadProtocolOffer`, `responderReplyProtocol`, …), `NegotiateError` |

### `security`

| Submodule | Role |
|-----------|------|
| `security.libp2p_tls` | libp2p TLS spec constants (`multistream_protocol_id`, `handshake_signature_prefix`, extension OID), `findLibp2pExtensionExtValue`, `parseSignedKey`, `peerIdFromCertificate` (spec test vectors; **no** signature verify yet) |

---

## Roadmap

Priorities follow the [parity table](#zeam-parity) (open issues linked there). Near term: [#37](https://github.com/ch4r10t33r/zig-libp2p/issues/37) QUIC ergonomics, [#34](https://github.com/ch4r10t33r/zig-libp2p/issues/34) swarm. **ControlExtensions.partialMessages** wire helpers live in `gossipsub.control` (experimental fields).

---

## Repository

https://github.com/ch4r10t33r/zig-libp2p
