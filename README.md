# zig-libp2p

Pure-Zig building blocks for **libp2p-style** networking: length-prefixed req/resp, gossipsub protobuf, multistream-select, TCP/QUIC transport helpers, Noise and TLS profiles, and re-exports for `peer_id`, `multiaddr`, and Snappy stacks.

**Zeam** (feature checklist, pins, CI/release notes): [docs/zeam-parity.md](docs/zeam-parity.md). [#31](https://github.com/ch4r10t33r/zig-libp2p/issues/31) (libp2p-glue replacement) is **library-complete**; use [`host.Host`](./src/host.zig) + transport wiring.

## Security

Lean/Eth2 devnets use gossipsub **StrictNoSign** (signatures on SSZ payloads, not on gossipsub envelopes). Transport auth, Identify signed peer records, and DoS limits are documented in [docs/SECURITY.md](docs/SECURITY.md).

## Requirements

- **Zig** 0.16.0 (`minimum_zig_version` in `build.zig.zon`)
- **zquic** ≥ 1.6.4 for QUIC examples and `zig_libp2p.zquic` (see `build.zig.zon`)

## Usage

Add the dependency in `build.zig.zon`, then in `build.zig`:

```zig
const zig_libp2p = b.dependency("zig_libp2p", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_libp2p", zig_libp2p.module("zig_libp2p"));
```

Application code: `@import("zig_libp2p")` — public API matches [`src/root.zig`](./src/root.zig).

## Examples

Programs live under [`examples/`](./examples/). `zig build` installs them to `zig-out/bin/`; `zig build examples` compiles only.

| Binary | Source | Description |
|--------|--------|-------------|
| `example-varint` | [varint.zig](examples/varint.zig) | Varint `encodeToScratch` / `decode` round trip |
| `example-addr-list-csv` | [addr_list_csv.zig](examples/addr_list_csv.zig) | Multiaddr CSV `parseCsv` / `freeList` |
| `example-multistream-negotiate` | [multistream_negotiate.zig](examples/multistream_negotiate.zig) | Buffer-only multistream-select for `/quic-v1` |
| `example-gossipsub-mesh` | [gossipsub_mesh.zig](examples/gossipsub_mesh.zig) | `Gossipsub.subscribe`, inbound GRAFT, mesh size |
| `example-ping-membuf` | [ping_membuf.zig](examples/ping_membuf.zig) | Ping 1.0.0 `handleInbound` with in-memory `Io.Reader` / `Writer` |
| `example-swarm-tick` | [swarm_tick.zig](examples/swarm_tick.zig) | `Swarm.tick` / `nextEvent` without background threads (Wasi-friendly) |
| `example-req-resp-tcp-status` | [req_resp_tcp_status.zig](examples/req_resp_tcp_status.zig) | Req/resp status unary over TCP loopback (`wire_tcp`); **compile-only** in `zig build test` to avoid CI hangs |
| `example-quic-ping-loopback` | [quic_ping_loopback.zig](examples/quic_ping_loopback.zig) | QUIC + TLS + multistream + ping via `quic_endpoint.loopbackPingOnce` (needs [`test/fixtures/quic_loopback/`](./test/fixtures/quic_loopback/) PEMs from repo root) |

Build/CI behaviour for examples: [examples/README.md](examples/README.md).

## API overview

Imports use the `zig_libp2p` prefix (e.g. `zig_libp2p.varint`, `zig_libp2p.gossipsub.control`).

### Top-level modules

| Module | Role |
|--------|------|
| `errors` | Layered errors: `ReqRespError`, `GossipsubError`, `TransportError`; `setLastErrorMessage` / `lastErrorMessage` / `clearLastErrorMessage` |
| `metrics` | `Metrics`: mesh and swarm counters; `writePrometheusText`, `snapshot` |
| `layer_events` | Event carriers: `ReqRespFailure`, `GossipsubFailure`, `TransportFailure` (discriminate on `kind`) |
| `peer_events` | Connection events: `Direction`, `DisconnectReason`, `ConnectionFailureResult`, connected / disconnected / failed payloads |
| `connection_manager` | Known-peer dial scheduling, reconnect backoff, refcount + peer events; optional `setReqResp` |
| `swarm` | Bounded `submit` / `nextEvent`, `queueEvent`, `shutdown`; `SwarmConfig`, `tick`, `startBackground` / `run` |
| `protocol` | Lean req/resp protocol ids; `LeanSupportedProtocol` |
| `varint` | Unsigned varint `encodeToScratch` / `decode` |
| `addr_list` | Multiaddr CSV `parseCsv`, `freeList` |
| `multistream` | Multistream-select 1.0.0 line I/O: `multistream_1_0_0`, `writeProtocolLine`, `trimNegotiationLine` |
| `ping` | Ping 1.0.0 wire helpers and round-trip timing |
| `ping_wire_quic` | Ping over QUIC raw bidi stream (multistream + echo); needs zquic UDP pumping |
| `identify` | Identify 1.0.0 `encode` / `decodeOwned` |
| `peer_id` | Re-export of `peer-id` |
| `identity` | `PeerId`, `ParseError` aliases |
| `keypair` | PEM → `KeyPair`; `peerIdFromKeyPair` |
| `snappyz` | Re-export of block Snappy |
| `snappyframesz` | Re-export of stream Snappy framing |
| `zquic` | Full zquic library (QUIC/TLS) |

### Metrics

Share one [`metrics.Metrics`](./src/metrics.zig) via [`SwarmConfig.metrics`](./src/swarm.zig) and [`GossipsubConfig.metrics`](./src/gossipsub/runtime.zig). Set `network_id` so mesh gauge and swarm drop counters share labels. Mesh gauge updates on subscribe/unsubscribe/disconnect/control/heartbeat. See [`metrics.zig`](./src/metrics.zig) for `setMeshPeers`, `recordSwarmCommandDropped`, exporters.

### `gossip`

| Submodule | Role |
|-----------|------|
| `gossip.topic` | `GossipTopic`, `LeanNetworkTopic`, `GossipEncoding`, `GossipTopicKind`, `SubnetId` |

### `gossipsub`

| Submodule | Role |
|-----------|------|
| `gossipsub.config` | Mesh and heartbeat constants, gossip lazy, transmit limits |
| `gossipsub.message_id` | Wire message id: SHA256-based 20-byte id |
| `gossipsub.duplicate_cache` | TTL duplicate cache `(topic, id)` |
| `gossipsub.runtime` | `Gossipsub`, `GossipsubConfig`, outbox caps, behaviour scores, lazy IHAVE / IWANT |
| `gossipsub.rpc` | RPC envelope encode/decode, subscribe/publish/control helpers |
| `gossipsub.control` | IHave, IWant, IDontWant, graft, prune; `ControlExtensions` |
| `gossipsub.message` | `Message` protobuf: `MessageView`, `MessageOwned`, `encode`, `decode` |

### `protobuf`

| Submodule | Role |
|-----------|------|
| `protobuf.wire` | Proto2 wire: varints, field keys, length-delimited append/scan, bounded length-delimited decode |

### `req_resp`

| Submodule | Role |
|-----------|------|
| `req_resp.frame` | Length-prefixed framing, `parseRequestHeader` / `parseResponseHeader`, append helpers |
| `req_resp.stream` | Incremental scan: `peekRpcUnary*`, `scanComplete*`, `consumePrefix(list, allocator, n)`, `InboundBuffer` |
| `req_resp.snappy_wire` | Snappy compress/decompress and framed req/resp wire |
| `req_resp.runtime` | `ReqResp`, sessions, streaming responses, timeouts, `onPeerDisconnected` |
| `req_resp.wire_framing` | Unary ssz_snappy read/write on `Io.Reader` / `Writer` |
| `req_resp.wire_tcp` | Unary exchange over TCP + multistream |
| `req_resp.wire_quic` | Same over QUIC raw streams + multistream |

### `transport`

| Submodule | Role |
|-----------|------|
| `transport.quic_v1` | QUIC v1 labels, ALPN, `libp2pZquicServerConfig` / `libp2pZquicClientConfig`, first-stream multistream preamble |
| `transport.quic` | `parseQuicV1Endpoint`, `initLibp2pQuicServerFromMultiaddr`, client init helpers, `bindUdpSocket` |
| `transport.quic_endpoint` | `QuicListener`, `QuicOutbound`, `dialExtended` / `dialMultiaddr`, TLS peer verification options, loopback ping helpers |
| `transport.quic_runtime` | `QuicRuntime`: gossipsub + req/resp on QUIC streams; `TlsPemSource` `.paths` or `.pem_bytes` ([#129](https://github.com/ch4r10t33r/zig-libp2p/issues/129)) |
| `transport.quic_peer_identity` | `verifiedPeerIdFromLibp2pQuicClient`, `verifiedPeerIdFromLibp2pQuicServerConn` (libp2p TLS + optional expected `PeerId`) |
| `transport.transport_error` | Map I/O, multistream, TLS, Noise, zquic errors into `TransportError` |
| `transport.stream_multistream` | Per-stream multistream on `Io.Reader` / `Writer`, including `responderHandshakeMultistreamAmong` |
| `transport.tcp` | TCP listen/dial/accept with multistream protocol id |
| `transport.multistream_negotiate` | Bounded byte-cursor multistream-select 1.0.0 |

### `security`

| Submodule | Role |
|-----------|------|
| `security.libp2p_tls` | libp2p TLS 1.3: ALPN, extension OID, certificate → `PeerId`, full verify path |
| `security.noise` | Noise XX, libp2p payloads, `SecureChannel`, TCP stream upgrade |

## Development

Tests, fuzz, CI, and release workflow: [docs/zeam-parity.md#development](docs/zeam-parity.md#development).

## Repository

https://github.com/ch4r10t33r/zig-libp2p
