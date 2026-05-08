# zig-libp2p

A minimal **pure-Zig** library you add with `build.zig.zon` + `std.Build.dependency`: multiaddr CSV parsing, unsigned varints, Lean req/resp protocol ids, and length-prefixed req/resp framing. Transport, security, and gossip are not implemented yet.

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
// zig_libp2p.protocol, zig_libp2p.varint, zig_libp2p.addr_list, zig_libp2p.req_resp.frame
```

Run this repo’s tests locally: `zig build test`. On push and pull request, GitHub Actions runs `zig fmt --check .`, `zig build test`, and `zig build` (see `.github/workflows/ci.yml`).

## Suggested review-sized PRs (historical)

1. **PR1 — Scaffold**: `build.zig`, `build.zig.zon`, `src/root.zig`, `src/protocol.zig`.
2. **PR2 — Wire helpers**: `multiaddr-zig`, `addr_list`, `varint`, `req_resp/frame`.

## Done so far

- [x] Zig 0.16 package layout; `zig build test`.
- [x] Lean req/resp protocol id strings + `LeanSupportedProtocol` enum (unit tests for discriminants / `fromInt`).
- [x] **multiaddr-zig** pin and `addr_list.parseCsv` / `freeList`.
- [x] **Unsigned varint** + **req/resp length-prefix** helpers (`req_resp.frame`, 4 MiB cap).

## Next

- [ ] Wire [zquic](https://github.com/ch4r10t33r/zquic) on Zig 0.16; `/quic-v1` transport and libp2p security handshake.
- [ ] Peer identity, handshake suitable for Lean devnets.
- [ ] Gossipsub v1.1 mesh, subscriptions, backpressure.
- [ ] Req/resp streams: snappy-framed payloads on top of `req_resp.frame`.

## Remote

[https://github.com/ch4r10t33r/zig-libp2p](https://github.com/ch4r10t33r/zig-libp2p)

```sh
git remote add origin https://github.com/ch4r10t33r/zig-libp2p.git
git push -u origin main
```
