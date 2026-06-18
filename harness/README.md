# Interop harnesses

Cross-implementation conformance tooling for zig-libp2p. Two matrices live here:

| Harness | Transport stack | Entry point |
|---------|-----------------|-------------|
| [`tcp/`](tcp/) | TCP + TLS 1.3 + Yamux | `zig build interop` → `transport-interop` binary; [libp2p/unified-testing](https://github.com/libp2p/unified-testing) matrix via `harness/tcp/run_unified_testing.sh` |
| [`quic/`](quic/) | QUIC + libp2p TLS 1.3 (native streams) | `examples/interop_quic_node.zig` → `interop-quic-node`; matrix via `harness/quic/run_matrix.sh` |

## Quick start

**QUIC matrix (zig ↔ go-libp2p):**

```sh
zig build -Doptimize=ReleaseFast
(cd harness/quic/impls/go-libp2p && go build -o interop-quic-node-go .)
harness/quic/run_matrix.sh zig,go-libp2p handshake,ping,gossipsub,reqresp
# or: zig build interop-matrix
```

**TCP unified-testing smoke:**

```sh
bash harness/tcp/run_smoke.sh
```

## CI

| Workflow | Harness |
|----------|---------|
| [`interop-quic-self.yml`](../.github/workflows/interop-quic-self.yml) | QUIC zig ↔ zig |
| [`interop-quic-cross.yml`](../.github/workflows/interop-quic-cross.yml) | QUIC cross-impl matrix |
| [`unified-testing-interop.yml`](../.github/workflows/unified-testing-interop.yml) | TCP unified-testing |

## Fixtures

Shared PEM vectors and wire test inputs live in [`fixtures/`](../fixtures/) at the repo root (formerly `test/fixtures/`).

## Layout history

This directory merged the former `interop/` and `interop_quic/` trees. See [`docs/REPO_LAYOUT.md`](../docs/REPO_LAYOUT.md) for the full rationalization plan.
