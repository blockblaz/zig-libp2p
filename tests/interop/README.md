# Cross-implementation interop (#44)

This directory is reserved for **rust-libp2p ↔ zig-libp2p** wire checks. Issue [#44](https://github.com/ch4r10t33r/zig-libp2p/issues/44) calls for a small Rust harness that drives both stacks over real streams.

## Planned coverage (from #44)

- Multistream-select 1.0.0
- Gossipsub v1.1 (minimal RPC exchange, a few messages each direction)
- Req/resp (status, blocks_by_root, blocks_by_range — unary and streaming)
- Ping, identify

## Today

- In-repo **Zig** coverage: deterministic pseudo-random slices plus `std.testing.fuzz` entry points for varint, req/resp frame headers, gossipsub RPC, protobuf length-delimited walks, Snappy framing, and gossipsub `Message` decode ([`src/wire_boundaries.zig`](../../src/wire_boundaries.zig)); explicit max-size frame tests in [`src/req_resp/frame.zig`](../../src/req_resp/frame.zig). CI runs `zig build fuzz` (see root [`README.md`](../../README.md)).
- **Rust** harness: not checked in yet; add a `tests/interop/rust/` (or workspace) crate when someone extends beyond the CI scope in #44 (24 h libFuzzer per parser, full protocol matrix).

## Running Zig parser smoke

`zig build test` runs the full suite; `zig build fuzz` runs only the `wire fuzz …` tests (faster, fuzz-oriented).

## Interop CI (#95)

`.github/workflows/interop.yml` runs nightly and on manual dispatch:

1. **`fuzz-extended`** — extended libFuzzer budget over the wire-conformance
   harness (varint, req/resp frames, gossipsub RPC + control, yamux/mplex
   headers, Snappy, gossipsub `Message`). Catches divergences against
   adversarial inputs before they show up in cross-impl tests.
2. **`rust-libp2p-ping-interop`** — builds the zig-libp2p QUIC ping example
   and sanity-runs the bundled loopback. Currently a single-stack check;
   the workflow has a marked TODO and an explicit skeleton for adding a
   rust-libp2p ping responder Docker container (ghcr.io/libp2p/rust-libp2p-head)
   so a follow-up can extend it without re-litigating workflow shape.

The per-PR CI in `ci.yml` runs the full unit-test + 60s fuzz smoke; only the
nightly job here pulls in cross-impl Docker images and longer fuzz budgets.
