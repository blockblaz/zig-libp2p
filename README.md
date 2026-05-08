# zig-libp2p

Minimal **pure-Zig** helpers for libp2p-oriented Lean Ethereum clients: multiaddr CSV and unsigned varints, Lean req/resp protocol ids, length-prefixed req/resp frames, streaming scan/consumption for length-delimited bodies, multistream-select 1.0.0, Snappy stack (`snappyz`, `snappyframesz`, Zeam-aligned pins), `ssz_snappy` unary RPC peek/decode, Lean gossip mesh topics (`gossip.topic`), libp2p ping, peer IDs (`peer_id`, `identity`), protobuf wire, and gossipsub `RPC` plus control (IHAVE, IWANT, graft, prune) and `Message` encode/decode (`gossipsub.rpc`, `gossipsub.control`, `gossipsub.message`).

Full gossipsub mesh behaviour, transports, and security handshakes are not implemented yet.

**Zig 0.16.0** (`build.zig.zon` `minimum_zig_version`). QUIC via [zquic](https://github.com/ch4r10t33r/zquic) is not integrated; upstream still targets Zig 0.15.

## Usage (Zig dependency)

In your `build.zig.zon`, add this package (path, git URL, or tarball per Zig’s package manager). Then in `build.zig`:

```zig
const zig_libp2p = b.dependency("zig_libp2p", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_libp2p", zig_libp2p.module("zig_libp2p"));
```

In application code, `@import("zig_libp2p")` and use the exports from `src/root.zig` (same names as in the paragraph above).

**Tests:** `zig build test`.

**CI:** `zig fmt --check .`, `zig build test --summary all`, and `zig build` on Zig 0.16.0. Details in `.github/workflows/ci.yml`.

## Roadmap

- Wire [zquic](https://github.com/ch4r10t33r/zquic) on Zig 0.16; `/quic-v1` transport and libp2p security handshake (Noise or TLS) for devnets.
- Gossipsub mesh scoring and backpressure; optional **IDONTWANT** / **ControlExtensions** on the wire.

## Repository

https://github.com/ch4r10t33r/zig-libp2p
