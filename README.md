# zig-libp2p

A minimal **pure-Zig** library you add with `build.zig.zon` + `std.Build.dependency`:

- multiaddr CSV parsing, unsigned varints, Lean req/resp protocol ids
- length-prefixed req/resp **frame** encode/decode
- **streaming** scan/consume over a growable inbound buffer (TCP-style chunking)
- **multistream-select 1.0.0** negotiation line helpers

Transport, security, compression, and gossip are not implemented yet.

- Targets **Zig 0.16.0** (`build.zig.zon` `minimum_zig_version`).
- QUIC is planned via [ch4r10t33r/zquic](https://github.com/ch4r10t33r/zquic). **Not integrated yet:** upstream zquic still targets Zig 0.15; a 0.16 build hits std API moves (`std.Io`, TLS helpers, RNG / X25519 entry points). Revisit when zquic tracks 0.16.

## Usage (Zig dependency)

In your `build.zig.zon`, add this package (path, git URL, or tarball per Zig’s package manager). Then in `build.zig`:

```zig
const zig_libp2p = b.dependency("zig_libp2p", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_libp2p", zig_libp2p.module("zig_libp2p"));
```

In application code:

```zig
const zig_libp2p = @import("zig_libp2p");
// zig_libp2p.protocol, zig_libp2p.varint, zig_libp2p.addr_list,
// zig_libp2p.multistream, zig_libp2p.req_resp.frame, zig_libp2p.req_resp.stream
```

Run this repo’s tests locally: `zig build test`. CI matches [Zeam’s workflow pattern](https://github.com/blockblaz/zeam/blob/main/.github/workflows/ci.yml) for Zig: `mlugg/setup-zig@v2.0.5` at **0.16.0**, `actions/cache` on `~/.cache/zig`, `zig build --fetch` with retries, then `zig fmt --check .`, `zig build test --summary all`, and `zig build` (each with the same retry style where applicable). See `.github/workflows/ci.yml`.

## Suggested review-sized PRs (historical)

1. **PR1 — Scaffold**: `build.zig`, `build.zig.zon`, `src/root.zig`, `src/protocol.zig`.
2. **PR2 — Wire helpers**: `multiaddr-zig`, `addr_list`, `varint`, `req_resp/frame`.
3. **PR3 — Streaming + multistream**: `req_resp/stream`, `multistream`.

## Done so far

- [x] Zig 0.16 package layout; `zig build test` and CI.
- [x] Lean req/resp protocol id strings + `LeanSupportedProtocol` enum (unit tests for discriminants / `fromInt`).
- [x] **multiaddr-zig** pin and `addr_list.parseCsv` / `freeList`.
- [x] **Unsigned varint** + **req/resp length-prefix** helpers (`req_resp.frame`, 4 MiB cap).
- [x] **Incremental framing**: `scanCompleteRequest` / `scanCompleteResponse`, `consumePrefix`, `InboundBuffer` with optional byte cap.
- [x] **Multistream-select**: `/multistream/1.0.0\n`, `writeProtocolLine`, `trimNegotiationLine`.

## Next

- [ ] Wire [zquic](https://github.com/ch4r10t33r/zquic) on Zig 0.16; `/quic-v1` transport and libp2p security handshake.
- [ ] Peer identity and handshake suitable for Lean devnets.
- [ ] Gossipsub v1.1 mesh, subscriptions, backpressure.
- [ ] Snappy (or other) compression on top of `req_resp` payloads.

## Remote

[https://github.com/ch4r10t33r/zig-libp2p](https://github.com/ch4r10t33r/zig-libp2p)

```sh
git remote add origin https://github.com/ch4r10t33r/zig-libp2p.git
git push -u origin main
```
