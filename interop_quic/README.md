# QUIC interop (Phase B)

QUIC + libp2p interop harness (separate from [`interop/`](../interop/), which targets the libp2p unified-testing matrix on TCP + TLS + Yamux).

## Status

| Scope | handshake | ping | gossipsub | reqresp |
|-------|-----------|------|-----------|---------|
| zig ↔ zig | pass | pass | pass | pass |
| go ↔ go | pass | pass | pass | pass |
| rust ↔ rust | pass | pass | skip* | pass |
| zig ↔ go | **pass** | **pass** | **pass** | pass |
| full 3-corner (cron) | varies | varies | varies | varies |

\* rust gossipsub skipped pending mesh timing.

## Binary

`examples/interop_quic_node.zig` → `zig-out/bin/interop-quic-node`. Role and testcase from environment:

| Variable | Default | Meaning |
|----------|---------|---------|
| `ROLE` | `server` | `server` or `client` |
| `TESTCASE` | `handshake` | `handshake`, `ping`, `gossipsub`, `reqresp` |
| `LISTEN_PORT` / `SERVER_HOST` / `SERVER_PORT` | 4001 / 127.0.0.1 / 4001 | UDP bind / dial |
| `CERT_PATH` / `KEY_PATH` | `/certs/*.pem` | libp2p-extension TLS PEM (zig side) |
| `REMOTE_PEER_ID` | (unset) | Client: base58btc peer id → `dialExtended` + TLS verify |
| `DEADLINE_MS` | `30000` | Overall deadline |
| `GS_*` / `RR_PAYLOAD_LEN` | see source | Gossipsub / reqresp testcase sizes |

Exit codes: `0` ok, `1` failure, `2` bad config.

### Cert generation

`zig-out/bin/gen-libp2p-cert` mints RFC 0001 certs (`SEED_HEX` for deterministic peer ids). Stdout: `gen_libp2p_cert: peer_id=<base58btc>`.

## Run locally

```sh
zig build -Doptimize=ReleaseFast
interop_quic/self_test.sh ping                    # zig ↔ zig
(cd interop_quic/impls/go-libp2p && go build -o interop-quic-node-go .)
interop_quic/run_matrix.sh zig,go-libp2p handshake,ping
zig build interop-matrix                          # shorthand: zig,go-libp2p handshake+ping
```

Output is TAP-like (`ok N - server=… client=…`).

### Docker

```sh
docker build -t zig-libp2p:interop-quic -f interop_quic/Dockerfile .
docker build -t go-libp2p:interop-quic -f interop_quic/impls/go-libp2p/Dockerfile interop_quic/impls/go-libp2p
```

## CI

| Workflow | Trigger | Gate |
|----------|---------|--------|
| [`interop-quic-self.yml`](../.github/workflows/interop-quic-self.yml) | every PR | zig ↔ zig handshake + ping |
| [`interop-quic-cross.yml`](../.github/workflows/interop-quic-cross.yml) | PR / nightly / manual | Same-impl baseline (required); cross-impl **handshake** and **ping** required (zig↔go-libp2p 8/8) |

Impl sources: [`impls/go-libp2p/`](impls/go-libp2p/), [`impls/rust-libp2p/`](impls/rust-libp2p/).
