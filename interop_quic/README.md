# QUIC interop (Phase B)

QUIC + libp2p interop harness, separate from the existing `interop/` directory
(which targets the libp2p `unified-testing` matrix on TCP + TLS + Yamux).

## Phase B layout

| PR | Adds |
|----|------|
| B1 | This dir. `interop-quic-node` binary, Dockerfile, self-test, GH workflow. zig-libp2p ↔ zig-libp2p only. |
| B2 | libp2p TLS cert minter, peer-id wiring, `go-libp2p` impl container, matrix runner, nightly cross-impl workflow. |
| B3 | Gossipsub pub/sub testcase. Go side fully wired; zig side stubbed (skip) pending the `/meshsub/1.1.0` QUIC-stream pipeline. |
| B4 | Req/resp testcase. |
| B5 | `rust-libp2p` impl container. Full matrix expansion. |

## Binary

`examples/interop_quic_node.zig` builds to `zig-out/bin/interop-quic-node`.
Single binary; role and testcase come from environment.

| Variable | Default | Meaning |
|----------|---------|---------|
| `ROLE` | `server` | `server` (listen) or `client` (dial) |
| `TESTCASE` | `handshake` | `handshake` (QUIC handshake only), `ping` (handshake + `/ipfs/ping/1.0.0`), or `gossipsub` (B3 — zig side currently returns exit 3 / TAP skip) |
| `GS_TOPIC` | `/interop/b3` | gossipsub topic both sides subscribe to |
| `GS_COUNT` | `5` | gossipsub: number of messages the server publishes |
| `GS_PAYLOAD_LEN` | `64` | gossipsub: bytes per message; payload is deterministic (`msg-NNNNN:` + 0x2A padding) so multiple impls assert on identical bytes |
| `LISTEN_PORT` | `4001` | server bind port |
| `SERVER_HOST` | `127.0.0.1` | client dial target (IPv4 dotted-decimal) |
| `SERVER_PORT` | `4001` | client dial port |
| `CERT_PATH` | `/certs/cert.pem` | TLS cert (X.509 PEM, **with libp2p extension**, see below) |
| `KEY_PATH` | `/certs/key.pem` | TLS key (SEC1 EC PRIVATE KEY PEM) |
| `REMOTE_PEER_ID` | (unset) | client-only; when set, dialExtended runs the libp2p TLS leaf check against this base58btc peer id |
| `DEADLINE_MS` | `30000` | overall test deadline |

Exit codes: `0` success, `1` failure (timeout / mismatch), `2` bad config, `3` testcase recognized but not yet implemented on this side (B3 zig gossipsub stub).

### Cert generation

`examples/gen_libp2p_cert.zig` builds to `zig-out/bin/gen-libp2p-cert`. It
mints a libp2p-extension cert (RFC 0001) over an ECDSA-P-256 host identity:

| Variable | Default | Meaning |
|----------|---------|---------|
| `CERT_PATH` | `/certs/cert.pem` | output cert path |
| `KEY_PATH` | `/certs/key.pem` | output key path |
| `SEED_HEX` | random | 32-byte hex; deterministic identity when set |
| `PEER_ID_PATH` | (unset) | when set, the base58btc peer id is written here |

Stdout always carries `gen_libp2p_cert: peer_id=<base58btc>` for shell capture.
This replaces the openssl `gen_certs.sh` script that shipped in B1 — the bare
self-signed cert is rejected by every cross-impl libp2p verifier.

## Run

### Local self-test (zig ↔ zig)

```sh
zig build -Doptimize=ReleaseFast
interop_quic/self_test.sh handshake
interop_quic/self_test.sh ping
```

### Local cross-impl matrix (zig ↔ go-libp2p)

```sh
# 1. Build zig binaries.
zig build -Doptimize=ReleaseFast

# 2. Build the go-libp2p side. The binary is dropped next to its source so
#    run_matrix.sh can discover it without an install step.
(cd interop_quic/impls/go-libp2p && go build -o interop-quic-node-go .)

# 3. Run the matrix. First arg is impls (CSV), second is testcases.
interop_quic/run_matrix.sh zig,go-libp2p handshake,ping
```

Output is TAP-like (`ok N - server=… client=… …` per pair, summary at end).
Same-impl pairs (zig↔zig and go↔go) are the green baseline. Cross-impl pairs
currently exercise outstanding zquic ↔ go-libp2p TLS gaps (handshake message
encoding); the runner reports them as `not ok` rather than masking the
mismatch so the regression is visible.

### Docker image (zig impl)

```sh
docker build -t zig-libp2p:interop-quic -f interop_quic/Dockerfile .
docker run --rm --net=host -e ROLE=server -e TESTCASE=ping zig-libp2p:interop-quic
docker run --rm --net=host -e ROLE=client -e TESTCASE=ping -e SERVER_HOST=127.0.0.1 \
           -e REMOTE_PEER_ID=<peer-id-of-server> zig-libp2p:interop-quic
```

### Docker image (go-libp2p impl)

```sh
docker build -t go-libp2p:interop-quic -f interop_quic/impls/go-libp2p/Dockerfile \
             interop_quic/impls/go-libp2p
```

### CI

| Workflow | Trigger | Scope |
|----------|---------|-------|
| `.github/workflows/interop-quic-self.yml` | every PR | zig ↔ zig handshake + ping |
| `.github/workflows/interop-quic-cross.yml` | PR (when matrix-runner files change), nightly cron, manual | zig ↔ zig + go ↔ go (required green) + zig ↔ go (informational, gated behind upstream zquic interop work) |

## Open questions for B3+

- **Cross-impl TLS gaps.** Independent of the libp2p extension, zquic's TLS
  handshake still trips upstream verifiers on a few fronts (post-ALPN /
  post-quic_transport_params extension type fix). Tracked in zquic upstream;
  once green there + a zquic bump here, the cross-impl matrix flips green
  without further changes in this dir.
- **Gossipsub/req-resp testcases.** B3 and B4 add the actual streaming
  protocols. Shared multiaddr discovery is still TBD — probably a Redis pub
  envelope in line with the existing libp2p interop suite.
- **rust-libp2p impl.** B5 adds a third corner of the matrix.
