# QUIC interop (Phase B)

QUIC + libp2p interop harness (separate from [`harness/tcp/`](../tcp/), which targets the libp2p unified-testing matrix on TCP + TLS + Yamux).

## Status

| Scope | handshake | ping | gossipsub | reqresp |
|-------|-----------|------|-----------|---------|
| zig ↔ zig | pass | pass | pass | pass |
| go ↔ go | pass | pass | pass | pass |
| rust ↔ rust | pass | pass | pass¹ | pass |
| zig ↔ go | pass | pass | pass | pass |
| zig ↔ rust | pass | pass | pass | pass |
| full 3-corner (nightly) | pass | pass | pass | pass |

¹ Was skipped pre-#178; now green after the rust interop server waits for `gossipsub::Event::Subscribed` from the remote peer before publishing instead of sleeping a fixed 1.5 s.

All cross-impl pairs in `{handshake, ping, gossipsub, reqresp}` are green on current `main` ([#174](https://github.com/blockblaz/zig-libp2p/issues/174), [#175](https://github.com/blockblaz/zig-libp2p/issues/175), [#177](https://github.com/blockblaz/zig-libp2p/issues/177)). Umbrella tracker [#166](https://github.com/blockblaz/zig-libp2p/issues/166) is closed.

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
harness/quic/self_test.sh ping                    # zig ↔ zig
(cd harness/quic/impls/go-libp2p && go build -o interop-quic-node-go .)
(cd harness/quic/impls/rust-libp2p && cargo build --release --locked)
harness/quic/run_matrix.sh zig,go-libp2p handshake,ping
harness/quic/run_matrix.sh zig,rust-libp2p handshake,ping,gossipsub,reqresp
zig build interop-matrix                          # shorthand: zig,go-libp2p handshake+ping
```

Output is TAP-like (`ok N - server=… client=…`).

### Docker

```sh
docker build -t zig-libp2p:interop-quic -f harness/quic/Dockerfile .
docker build -t go-libp2p:interop-quic -f harness/quic/impls/go-libp2p/Dockerfile harness/quic/impls/go-libp2p
```

## CI

| Workflow | Trigger | Gate |
|----------|---------|--------|
| [`interop-quic-self.yml`](../.github/workflows/interop-quic-self.yml) | every PR | zig ↔ zig handshake + ping |
| [`interop-quic-cross.yml`](../.github/workflows/interop-quic-cross.yml) | PR / nightly / manual | Same-impl baseline (required); cross-impl **zig↔go** and **zig↔rust** handshake + ping required; full 3-impl matrix on nightly/manual |

Impl sources: [`impls/go-libp2p/`](impls/go-libp2p/), [`impls/rust-libp2p/`](impls/rust-libp2p/).
