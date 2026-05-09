# Cross-implementation interop (#44)

This directory is reserved for **rust-libp2p ↔ zig-libp2p** wire checks. Issue [#44](https://github.com/ch4r10t33r/zig-libp2p/issues/44) calls for a small Rust harness that drives both stacks over real streams.

## Planned coverage (from #44)

- Multistream-select 1.0.0
- Gossipsub v1.1 (minimal RPC exchange, a few messages each direction)
- Req/resp (status, blocks_by_root, blocks_by_range — unary and streaming)
- Ping, identify

## Today

- In-repo **Zig** coverage: deterministic pseudo-random slices against varint, req/resp frame headers, and gossipsub RPC decoders ([`src/wire_boundaries.zig`](../../src/wire_boundaries.zig)), plus explicit max-size frame tests in [`src/req_resp/frame.zig`](../../src/req_resp/frame.zig).
- **Rust** harness: not checked in yet; add a `tests/interop/rust/` (or workspace) crate when someone picks up the full #44 acceptance criteria.

## Running Zig parser smoke

Same as normal tests: `zig build test` (see root [`README.md`](../../README.md)).
