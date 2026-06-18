# Rendezvous (#209)

Namespace-scoped peer discovery via a rendezvous point. Spec: [libp2p/rendezvous](https://github.com/libp2p/specs/blob/master/rendezvous/README.md).

## Protocol

| Item | Value |
|------|--------|
| Multistream ID | `/rendezvous/1.0.0` |
| Framing | uvarint length-prefixed protobuf `Message` |
| Messages | `REGISTER`, `UNREGISTER`, `DISCOVER` (+ responses) |

## Modules

| Module | Role |
|--------|------|
| `rendezvous.wire` | Protobuf codec, cookies, length-prefixed I/O |
| `rendezvous.store` | Server registration store + cookie paging |
| `rendezvous.server` | Inbound stream handler |
| `rendezvous.client` | Register / unregister / discover helpers |

## Embedder flow

1. Dial a rendezvous peer and negotiate `/rendezvous/1.0.0`.
2. `Client.writeRegister` → server `handleStream` → `readRegisterResponse`.
3. `Client.writeDiscover` → `readDiscoverResponse` (pass cookie from prior response for delta paging).
4. For each discovered peer, queue `swarm.Event.peer_discovered { source: .rendezvous, namespace }`.

## Example

```sh
zig build examples
./zig-out/bin/example-rendezvous-membuf
```

## Defaults

| Parameter | Value |
|-----------|--------|
| Default TTL | 2 h |
| Min / max TTL | 2 h / 72 h |
| Max namespace length | 255 |
| Max registrations per peer | 32 |

## Interop

Wire layout matches [rust-libp2p `protocols/rendezvous`](https://github.com/libp2p/rust-libp2p/tree/master/protocols/rendezvous). In-repo tests cover cookie paging and signed-peer-record registration; full QUIC cross-impl matrix is tracked in [#44](https://github.com/blockblaz/zig-libp2p/issues/44).
