# zig-libp2p

A minimal pure-Zig libp2p-oriented stack intended as a future drop-in for Zeam’s Rust bridge in [blockblaz/zeam `rust/libp2p-glue`](https://github.com/blockblaz/zeam/tree/main/rust/libp2p-glue).

- Targets **Zig 0.16.0** (`build.zig.zon` `minimum_zig_version`).
- QUIC is planned via [ch4r10t33r/zquic](https://github.com/ch4r10t33r/zquic); that dependency is **not** wired yet — current zquic + vendored TLS hits Zig 0.16 compile errors (`returning address of expired local variable` in `vendor/tls/src/transcript.zig`). Revisit after zquic tracks 0.16.

## Usage

- **Zig module**: depend on this package and `@import("zig_libp2p")` (see `build.zig` module name `zig_libp2p`).
- **Zeam-shaped static library**: `zig build` produces `libzig-libp2p.a` with the same C symbols Zeam expects from the Rust glue (`create_and_run_network`, `publish_msg_to_rust_bridge`, …). Link it **instead of** the Rust `libp2p_glue` when swapping implementations; the Zeam binary must still export the Zig callbacks the bridge calls (`releaseStartNetworkParams`, `handleMsgFromRustBridge`, …).

## Suggested review-sized PRs (this repo)

These map to the git history on `main`:

1. **PR1 — Scaffold** (`build: zig 0.16 scaffold…`): `build.zig`, `build.zig.zon`, `.gitignore`, `src/root.zig`, `src/protocol.zig`, baseline `README.md`.
2. **PR2 — Zeam ABI stub** (`libp2p: zeam C ABI…`): static library root + `zeam_bridge.zig` exports and lifecycle stub.
3. **PR3 — Docs / roadmap** (this commit): expanded `README.md` with status and backlog.

## Completed (to date)

- [x] Zig 0.16 `build.zig` / `build.zig.zon` package layout with `zig build test` and `zig build` (static `libzig-libp2p`).
- [x] Lean consensus req/resp protocol id strings + `LeanSupportedProtocol` enum aligned with `rust/libp2p-glue/src/req_resp/protocol_id.rs` and Zeam `interface.zig` (unit tests for discriminants / `fromInt`).
- [x] Zeam C ABI exports: `CreateNetworkParams`, `create_and_run_network`, `wait_for_network_ready`, `stop_network`, gossip publish/subscribe, RPC send/response helpers, `get_swarm_command_dropped_total`, `get_mesh_peers_total`.
- [x] Lifecycle stub: calls `releaseStartNetworkParams`, sets readiness, blocks until `stop_network` (matches Zeam bridge thread join model; no real P2P yet).

## Next (not started here)

- [ ] Add `build.zig.zon` dependency on zquic once it builds cleanly on Zig 0.16; QUIC `/quic-v1` transport and libp2p security handshake.
- [ ] Multiaddr parsing/dialing, peer identity (secp256k1), Noise (or equivalent) aligned with Lean devnets.
- [ ] Gossipsub v1.1 mesh, topic subscription flow, backpressure compatible with Zeam metrics (`get_swarm_command_dropped_total`, mesh peer counts).
- [ ] Req/resp over streams: varint + snappy-framed frames matching existing Zeam serializers.
- [ ] Zeam `build.zig` integration: link `libzig-libp2p.a` instead of Rust glue behind a feature flag; remove duplicate symbols from `zeam-glue` when cut over.

## Remote

Upstream: [https://github.com/ch4r10t33r/zig-libp2p](https://github.com/ch4r10t33r/zig-libp2p)

```sh
git remote add origin https://github.com/ch4r10t33r/zig-libp2p.git
git push -u origin main
```

(Push when you have rights on that empty repo.)
