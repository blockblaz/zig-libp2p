# QUIC interop (Phase B)

QUIC + libp2p interop harness, separate from the existing `interop/` directory
(which targets the libp2p `unified-testing` matrix on TCP + TLS + Yamux).

## Phase B layout

| PR | Adds |
|----|------|
| B1 | This dir. `interop-quic-node` binary, Dockerfile, self-test, GH workflow. zig-libp2p ↔ zig-libp2p only. |
| B2 | `go-libp2p` impl container + matrix runner + nightly cron. First real cross-impl test (handshake + ping). |
| B3 | Gossipsub pub/sub testcase. |
| B4 | Req/resp testcase. |
| B5 | `rust-libp2p` impl container. Full matrix expansion. |

## Binary

`examples/interop_quic_node.zig` builds to `zig-out/bin/interop-quic-node`.
Single binary; role and testcase come from environment.

| Variable | Default | Meaning |
|----------|---------|---------|
| `ROLE` | `server` | `server` (listen) or `client` (dial) |
| `TESTCASE` | `handshake` | `handshake` (QUIC handshake only) or `ping` (handshake + `/ipfs/ping/1.0.0`) |
| `LISTEN_PORT` | `4001` | server bind port |
| `SERVER_HOST` | `127.0.0.1` | client dial target (IPv4 dotted-decimal) |
| `SERVER_PORT` | `4001` | client dial port |
| `CERT_PATH` | `/certs/cert.pem` | TLS cert (X.509 PEM) |
| `KEY_PATH` | `/certs/key.pem` | TLS key (SEC1 EC PRIVATE KEY PEM) |
| `DEADLINE_MS` | `30000` | overall test deadline |

Exit codes: `0` success, `1` failure (timeout / mismatch), `2` bad config.

## Run

### Local self-test

```sh
zig build -Doptimize=ReleaseFast
interop_quic/self_test.sh handshake
interop_quic/self_test.sh ping
```

### Docker image

```sh
docker build -t zig-libp2p:interop-quic -f interop_quic/Dockerfile .

# Server:
docker run --rm --net=host -e ROLE=server -e TESTCASE=ping zig-libp2p:interop-quic

# Client (separate container):
docker run --rm --net=host \
    -e ROLE=client -e TESTCASE=ping -e SERVER_HOST=127.0.0.1 \
    zig-libp2p:interop-quic
```

### CI

`.github/workflows/interop-quic-self.yml` runs the self-test on every PR.
Phase B2 adds `interop-quic-cross.yml` for the nightly cross-impl matrix.

## Cert generation

`gen_certs.sh` produces a P-256 ECDSA self-signed cert via `openssl`. zquic's
vendored TLS parser accepts the SEC1 EC PRIVATE KEY PEM format. Containers
auto-generate a pair on startup if `${CERT_PATH}` is empty.

## Open questions for B2+

- libp2p TLS extension (RFC 0001 v1.0.0) — the self-signed cert here doesn't
  carry the libp2p extension. Cross-impl with go-libp2p needs that. B2 will
  switch to `src/security/libp2p_tls_cert.zig` for cert minting.
- Peer-id verification — current binary doesn't verify the dialed peer's
  identity. Required for proper interop.
- Network simulation — currently no loss/delay. Could wire in `quic-network-simulator`
  later for jitter tolerance testing.
