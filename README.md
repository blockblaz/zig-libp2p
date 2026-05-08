# zig-libp2p

Pure-Zig helpers for **libp2p-flavored** networking in Lean Ethereum clients: length-prefixed req/resp, gossipsub protobuf, multistream-select, QUIC-related constants, and shared dependencies (`peer_id`, `multiaddr`, Snappy) aligned with Zeam pins.

**Not in scope yet:** full gossipsub mesh runtime, high-level QUIC listen/dial wrappers (embedders use [zquic](https://github.com/ch4r10t33r/zquic) directly with [`transport.quic_v1`](#transport) presets), and libp2p security/session upgrades beyond zquic TLS + ALPN. See [Roadmap](#roadmap).

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
| `protocol` | Lean req/resp protocol id strings; `LeanSupportedProtocol` enum with `protocolId`, `fromInt`, `fromSlice` |
| `varint` | Unsigned varint encode (`encodeToScratch`) / decode (`decode`) |
| `addr_list` | Multiaddr CSV: `parseCsv`, `freeList` (uses bundled `multiaddr`) |
| `multistream` | Multistream-select 1.0.0 line I/O: `multistream_1_0_0`, `max_protocol_id_body_bytes`, `writeProtocolLine`, `writeProtocolLineWithMax`, `ProtocolLineError`, `trimNegotiationLine` |
| `ping` | Ping 1.0.0: `protocol_line`, `payload_len` |
| `peer_id` | Re-export of `peer-id` package |
| `identity` | `PeerId`, `ParseError` aliases |
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
| `gossipsub.control` | Control message fragments: **IHave** / **IWant** / **IDontWant** / **graft** / **prune** — `encode*` / `decodeFirst*` / `deinit*` helpers |
| `gossipsub.message` | `Message` protobuf: `MessageView`, `MessageOwned`, `encode`, `decode`, `MessageOwned.deinit` |

### `protobuf`

| Submodule | Role |
|-----------|------|
| `protobuf.wire` | Minimal proto2 wire: varints, field keys, length-delimited append/scan (`appendVarUInt64`, `decodeVarUInt64`, `appendFieldKey`, `appendLengthDelimited`, `decodeFieldKey`, `nextFieldValue`, `nextFieldValueLimited`, `LengthDelimitedTooLong`, `LengthDelimitedOverflow`) |

### `req_resp`

| Submodule | Role |
|-----------|------|
| `req_resp.frame` | Length-prefixed framing: `max_rpc_message_size`, `parseRequestHeader`, `parseResponseHeader`, `appendRequestPrefix`, `appendResponsePrefix` |
| `req_resp.stream` | Incremental scan: `peekRpcUnaryRequest` / `peekRpcUnaryResponse`, `scanCompleteRequest` / `scanCompleteResponse`, `consumePrefix`, `InboundBuffer` |
| `req_resp.snappy_wire` | Snappy + framing for `ssz_snappy`: `compressBlock`, `decompressBlock`, `compressFramed`, `decompressFramed`, `buildRequestWire`, `buildResponseWire`, `decodeRequestSsz`, `decodeResponseSsz` |

### `transport`

| Submodule | Role |
|-----------|------|
| `transport.quic_v1` | QUIC v1 labels + zquic wiring: `multistream_protocol_id`, `tls_alpn`, `libp2pZquicServerConfig` / `libp2pZquicClientConfig` (ALPN `libp2p`, `raw_application_streams`), `appendFirstBidiStreamInitiatorHandshake` |
| `transport.multistream_negotiate` | **Bounded** multistream-select 1.0.0 on a byte cursor: `default_max_body_len`, `readNegotiationLine`, `validateProtocolId`, initiator/responder steps (`initiatorSendMultistreamHeader`, `responderReadProtocolOffer`, `responderReplyProtocol`, …), `NegotiateError` |

---

## Roadmap

- Finish `/quic-v1` **endpoint** ergonomics (listen/dial helpers, stream lifecycle) on zquic; presets and multistream stream open are in `transport.quic_v1`. Add libp2p security/session layer (Noise or dedicated TLS identity) as needed for devnets.
- Gossipsub mesh scoring and backpressure; optional **ControlExtensions** on the wire.

---

## Repository

https://github.com/ch4r10t33r/zig-libp2p
