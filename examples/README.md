# Examples

Small programs showing how to depend on `zig_libp2p` and call specific surfaces.

| Binary | Source | What it demonstrates |
|--------|--------|----------------------|
| `example-varint` | `varint.zig` | `varint.encodeToScratch` / `decode` |
| `example-addr-list-csv` | `addr_list_csv.zig` | `addr_list.parseCsv` / `freeList` |
| `example-multistream-negotiate` | `multistream_negotiate.zig` | Buffer-only multistream-select for `/quic-v1` |
| `example-gossipsub-mesh` | `gossipsub_mesh.zig` | `Gossipsub.subscribe`, inbound GRAFT, mesh size |
| `example-ping-membuf` | `ping_membuf.zig` | `ping.handleInbound` with fixed `Io.Reader` / `Writer` |
| `example-req-resp-tcp-status` | `req_resp_tcp_status.zig` | `req_resp.wire_tcp` status unary over TCP loopback (no-op single-threaded / WASI; **Darwin skips** when run manually; **`zig build test` compile-only** so CI does not hang) |
| `example-quic-ping-loopback` | `quic_ping_loopback.zig` | `transport.quic_endpoint.loopbackPingOnce`: zquic TLS + multistream + ping (needs `test/fixtures/quic_loopback/*.pem` from repo root) (#15) |

## Build / CI

- `zig build` — installs these into `zig-out/bin/` (or your install prefix).
- `zig build examples` — compile only (no install).
- `zig build test` — runs **library** unit tests, then **executes** each smoke-run example; the TCP status binary is **compiled** but not run (see `build.zig`). Keep `main()` returning success on supported targets so CI stays green.

Register new programs in the `examples` table in `build.zig`.
