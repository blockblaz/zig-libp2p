# zig-libp2p

Pure-Zig building blocks for **libp2p-style** networking: length-prefixed req/resp, gossipsub protobuf, multistream-select, TCP/QUIC transport helpers, Noise and TLS profiles, and re-exports for `peer_id`, `multiaddr`, and Snappy stacks.

**Zeam** integration checklist and CI/release notes: [docs/zeam-parity.md](docs/zeam-parity.md). The [#31](https://github.com/ch4r10t33r/zig-libp2p/issues/31) libp2p-glue replacement checklist is **library-complete**; wire [`host.Host`](./src/host.zig) (alias `zig_libp2p.Node`) plus transport — see [examples/host_quic_node.zig](examples/host_quic_node.zig).

## Security

Lean/Eth2 devnets use gossipsub **StrictNoSign** (signatures on SSZ payloads, not on gossipsub envelopes). Transport auth, Identify signed peer records, and DoS limits: [docs/SECURITY.md](docs/SECURITY.md).

## Requirements

- **Zig** 0.16.0 (`minimum_zig_version` in `build.zig.zon`)
- **zquic** **1.6.13** (pinned in `build.zig.zon`; re-exported as `zig_libp2p.zquic`)

## Usage

Add the dependency in `build.zig.zon`, then in `build.zig`:

```zig
const zig_libp2p = b.dependency("zig_libp2p", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_libp2p", zig_libp2p.module("zig_libp2p"));
```

Application code: `@import("zig_libp2p")` — public API in [`src/root.zig`](./src/root.zig).

Pin this repo by git tag (e.g. `v0.1.11`) in your `build.zig.zon` URL.

## Examples

Programs under [`examples/`](./examples/). `zig build` installs to `zig-out/bin/`; `zig build examples` compiles only. Build/CI details: [examples/README.md](examples/README.md).

| Binary | Source | Description |
|--------|--------|-------------|
| `example-varint` | [varint.zig](examples/varint.zig) | Varint encode/decode round trip |
| `example-addr-list-csv` | [addr_list_csv.zig](examples/addr_list_csv.zig) | Multiaddr CSV parse/free |
| `example-multistream-negotiate` | [multistream_negotiate.zig](examples/multistream_negotiate.zig) | Buffer-only multistream-select |
| `example-gossipsub-mesh` | [gossipsub_mesh.zig](examples/gossipsub_mesh.zig) | Gossipsub subscribe + mesh |
| `example-ping-membuf` | [ping_membuf.zig](examples/ping_membuf.zig) | Ping 1.0.0 over in-memory I/O |
| `example-autonat-membuf` | [autonat_membuf.zig](examples/autonat_membuf.zig) | AutoNAT v1 probe round-trip over in-memory I/O |
| `example-swarm-tick` | [swarm_tick.zig](examples/swarm_tick.zig) | `Swarm.tick` without background threads |
| `example-req-resp-tcp-status` | [req_resp_tcp_status.zig](examples/req_resp_tcp_status.zig) | Req/resp over TCP (compile-only in CI) |
| `example-quic-ping-loopback` | [quic_ping_loopback.zig](examples/quic_ping_loopback.zig) | QUIC loopback ping via `quic_endpoint` |
| `example-host-quic-node` | [host_quic_node.zig](examples/host_quic_node.zig) | `Host` + QUIC lifecycle hooks |
| `interop-quic-node` | [interop_quic_node.zig](examples/interop_quic_node.zig) | QUIC interop endpoint (env-driven; see below) |
| `gen-libp2p-cert` | [gen_libp2p_cert.zig](examples/gen_libp2p_cert.zig) | Mint libp2p TLS cert + peer id for interop |

## QUIC cross-impl interop

[`interop_quic/`](interop_quic/) runs zig ↔ go-libp2p ↔ rust-libp2p matrix tests over QUIC + libp2p TLS (Phase B). Quick start:

```sh
zig build -Doptimize=ReleaseFast
(cd interop_quic/impls/go-libp2p && go build -o interop-quic-node-go .)
interop_quic/run_matrix.sh zig,go-libp2p handshake,ping   # or: zig build interop-matrix
```

**Current matrix (v0.1.11):** all **handshake**, **ping**, and **gossipsub** pairs pass for zig↔zig and zig↔go-libp2p. Full harness docs: [interop_quic/README.md](interop_quic/README.md).

## API overview

Imports use the `zig_libp2p` prefix (e.g. `zig_libp2p.gossipsub.runtime`, `zig_libp2p.transport.quic_runtime`).

| Area | Modules |
|------|---------|
| Core | `host` / `Node`, `swarm`, `connection_manager`, `errors`, `metrics`, `layer_events`, `peer_events` |
| Protocols | `protocol`, `ping`, `identify`, `autonat`, `gossip`, `gossipsub.*`, `req_resp.*` |
| Wire | `varint`, `multistream`, `protobuf.wire`, `addr_list` |
| Transport | `transport.quic_*`, `transport.tcp`, `transport.tcp_tls`, `transport.stream_multistream`, `transport.multistream_negotiate`, `transport.yamux`, `transport.mplex` |
| Security | `security.libp2p_tls`, `security.libp2p_tls_cert`, `security.noise` |
| Identity / codecs | `peer_id`, `identity`, `keypair`, `snappyz`, `snappyframesz` |
| QUIC stack | `zquic` (full re-export) |

Per-module detail lives in source doc comments and [`src/root.zig`](./src/root.zig).

## Development

`zig fmt --check .`, `zig build test`, `zig build fuzz`, CI workflows, and release-please: [docs/zeam-parity.md#development](docs/zeam-parity.md#development).

## Repository

https://github.com/ch4r10t33r/zig-libp2p
