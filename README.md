# zig-libp2p

A minimal pure-Zig networking stack aimed at replacing Zeam’s native **FFI networking layer** with a Zig static archive, while keeping the same **C ABI** the host already links against. Reference host sources: [blockblaz/zeam `pkgs/network`](https://github.com/blockblaz/zeam/tree/main/pkgs/network) (today’s `extern fn` surface in `ethlibp2p.zig`).

- Targets **Zig 0.16.0** (`build.zig.zon` `minimum_zig_version`).
- QUIC is planned via [ch4r10t33r/zquic](https://github.com/ch4r10t33r/zquic). **Not integrated yet:** upstream zquic still targets Zig 0.15; a 0.16 build hits std API moves (`std.Io`, TLS helpers, RNG / X25519 entry points). Revisit when zquic tracks 0.16.

## Usage

- **Zig module**: depend on this package and `@import("zig_libp2p")` (`build.zig` module name `zig_libp2p`). Exports include `protocol`, `varint`, `addr_list`, and `req_resp.frame`.
- **Static library for the Zeam host**: `zig build` emits `libzig-libp2p.a` with the **stable C symbols** the host declares (`create_and_run_network`, `publish_msg_to_rust_bridge`, … — link names unchanged). Link this archive **instead of** the previous native networking staticlib when migrating. The host executable must still provide the Zig **callbacks** the archive invokes (`releaseStartNetworkParams`, `handleMsgFromRustBridge`, …).

## Suggested review-sized PRs (this repo)

1. **PR1 — Scaffold** (`build: zig 0.16 scaffold…`): `build.zig`, `build.zig.zon`, `.gitignore`, `src/root.zig`, `src/protocol.zig`, baseline `README.md`.
2. **PR2 — FFI stub** (`libp2p: zeam C ABI…`): static library entry + exported symbols and lifecycle stub.
3. **PR3 — Docs / roadmap** (`docs: readme roadmap…`): expanded `README.md`.
4. **PR4 — Wire helpers** (`libp2p: multiaddr csv and req/resp framing`): `multiaddr-zig`, `addr_list`, `varint`, `req_resp/frame`.

## Completed (to date)

- [x] Zig 0.16 `build.zig` / `build.zig.zon` package layout with `zig build test` and `zig build` (static `libzig-libp2p`).
- [x] Lean req/resp protocol id strings + `LeanSupportedProtocol` enum aligned with Zeam `interface.zig` / historical `protocol_id` table (unit tests for discriminants / `fromInt`).
- [x] Exported C ABI: `CreateNetworkParams`, `create_and_run_network`, `wait_for_network_ready`, `stop_network`, gossip publish/subscribe, RPC helpers, `get_swarm_command_dropped_total`, `get_mesh_peers_total`.
- [x] Lifecycle stub: host buffer release, readiness, block-until-`stop_network` (host thread join model; no real P2P yet).
- [x] **multiaddr-zig** (Zeam pin) and `addr_list.parseCsv` / `freeList`.
- [x] **Unsigned varint** + **req/resp length-prefix** helpers (`req_resp.frame`, 4 MiB cap).

## Next

- [ ] Wire [zquic](https://github.com/ch4r10t33r/zquic) on Zig 0.16; `/quic-v1` transport and libp2p security handshake.
- [ ] Peer identity (secp256k1), Noise (or equivalent) for Lean devnets.
- [ ] Gossipsub v1.1 mesh, subscriptions, backpressure + metrics (`get_swarm_command_dropped_total`, mesh peers).
- [ ] Req/resp streams: snappy-framed payloads on top of `req_resp.frame`; outbound/inbound state machines.
- [ ] Zeam `build.zig`: optional link of `libzig-libp2p.a`, feature flag, no duplicate symbols with the host’s other native archives.

## Remote

[https://github.com/ch4r10t33r/zig-libp2p](https://github.com/ch4r10t33r/zig-libp2p)

```sh
git remote add origin https://github.com/ch4r10t33r/zig-libp2p.git
git push -u origin main
```
