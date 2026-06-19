# `transport/` — transports, muxers, and stream wiring

Carries protocol bytes over the wire and multiplexes streams. The QUIC runtime
is the primary path; TCP/WS + muxers exist for interop and non-QUIC peers.

| Path | Role |
|------|------|
| `quic/` | The QUIC stack — `config.zig`, `conn_table.zig`, `runtime.zig`, endpoint, raw-stream I/O, peer-identity verification, and the live relay/DCUtR glue. Backed by [`zquic`](https://github.com/ch4r10t33r/zquic). |
| `quic_*.zig` | Legacy shims re-exporting from `quic/` (kept for stable import paths). |
| `tcp.zig`, `tcp_tls/` | TCP transport and libp2p-TLS-over-TCP (`/tls/1.0.0`). |
| `ws.zig`, `ws_codec.zig`, `ws_handshake.zig` | WebSocket transport (RFC 6455). |
| `yamux/`, `mplex/` | Stream multiplexers for non-QUIC transports. |
| `stream_multistream.zig`, `multistream_negotiate.zig` | Per-stream multistream-select negotiation. |
| `circuit_transport.zig`, `dcutr_punch.zig` | Relay-circuit dialing and DCUtR hole-punch driving. |
| `transport_error.zig`, `over_cap.zig`, `zquic_feed_addr.zig`, `quic_posix_udp.zig` | Shared transport helpers. |

Secure-channel implementations (TLS, Noise) live in
[`../security/`](../security/README.md); muxer/transport selection is driven by
multistream-select from [`../primitives/`](../primitives/README.md).
