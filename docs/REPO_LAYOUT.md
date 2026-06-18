# zig-libp2p repository layout rationalization

Proposal for reorganizing the repo into a more meaningful structure. Intended as an incremental plan, not a big-bang rename.

**Status:** phases 0–2 implemented; phases 3–5 pending  
**Audience:** maintainers and contributors

---

## Diagnosis (before phases 0–2)

| Area | Problem |
|------|---------|
| `src/*.zig` (~21 flat files) | Core (`host`, `swarm`), primitives (`varint`), and internals (`peer_protocols`, `wire_boundaries`) sit side by side |
| `transport/` | QUIC runtime (~5k lines), relay/DCUtR live glue, muxers, TCP, WS — mixed “stack” and “protocol wiring” |
| `src/vendor/` | Large vendored TLS tree inside the library package |
| `interop/` + `interop_quic/` | Two harnesses, different transports; QUIC node binary lives in `examples/` |
| `test/` vs `tests/` | Fixtures in `test/`; placeholder README in `tests/` |
| `root.zig` | ~100-line force-import `test {}` block — symptom of unclear module graph |
| `build.zig` | Manual example table; examples/interop/bench not all in `build.zig.zon` paths |

The **public API** (`@import("zig_libp2p")`) via `root.zig` works well for consumers (e.g. zeam). Reorganization should be **internal**, with stable facade aliases until the [1.0 API freeze](https://github.com/blockblaz/zig-libp2p/issues/172).

---

## Implemented (phases 0–2)

| Phase | Done |
|-------|------|
| **0** | `harness/tcp/` + `harness/quic/`, `fixtures/`, `harness/README.md`, CI + `build.zig` path updates |
| **1** | `src/protocols/` — autonat, kad_dht, relay, dcutr, gossipsub, req_resp, discovery, identify, ping, gossip |
| **2** | `src/core/`, `src/primitives/`, `src/internal/`; compatibility shims at legacy `src/` paths |

See [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) for the layer diagram.

---

## Target mental model

Organize by **libp2p layers**, matching how contributors and the README already think:

```
primitives → core → protocols → transport → harnesses
```

Not “everything QUIC-related in one folder.”

---

## Current `src/` layout (after phases 0–2)

```
src/
├── core/                    # Node runtime (embedder-facing)
│   ├── host.zig
│   ├── swarm.zig
│   ├── connection_manager.zig
│   ├── peer_events.zig
│   ├── peer_protocols.zig
│   ├── layer_events.zig
│   └── identify_advertisement.zig
│
├── primitives/              # Wire-agnostic building blocks
│   ├── identity.zig
│   ├── keypair.zig
│   ├── protocol.zig
│   ├── multistream.zig
│   ├── varint.zig
│   ├── addr_list.zig
│   ├── protobuf/wire.zig
│   ├── wall_time.zig
│   ├── errors.zig
│   └── metrics.zig
│
├── protocols/               # One folder per libp2p protocol (uniform)
│   ├── ping/
│   ├── identify/
│   ├── gossipsub/
│   ├── req_resp/
│   ├── autonat/
│   ├── kad_dht/
│   ├── relay/
│   ├── dcutr/
│   └── discovery/           # mDNS, (rendezvous when merged)
│
├── transport/               # Transports + muxers (quic_runtime split pending)
├── security/
├── internal/                  # wire_boundaries.zig
├── vendor/
├── root.zig                   # Public facade + legacy shims at src/*.zig
└── *.zig shims                # pub usingnamespace → canonical paths
```

---

## Proposed repo root (non-`src/`)

```
zig-libp2p/
├── src/
├── examples/
├── harness/                   # ✅ merged interop + interop_quic
│   ├── quic/
│   ├── tcp/
│   └── README.md
├── fixtures/                  # ✅ was test/fixtures
├── docs/
├── bench/
├── build/                     # pending phase 4
└── build.zig
```

---

## Remaining work

| Phase | Scope | Status |
|-------|--------|--------|
| **3** | Split `quic_runtime.zig` into `transport/quic/` | pending |
| **4** | `build/` split + `soak-test` step ([#235](https://github.com/blockblaz/zig-libp2p/issues/235)) | pending |
| **5** | `vendor/` to repo root; nested public API polish before 1.0 | pending |

Each phase: **no behavior change**; `zig build test` + interop matrix green.

---

## Related issues

- [#172](https://github.com/blockblaz/zig-libp2p/issues/172) — API 1.0 freeze (drives compatibility shims)
- [#235](https://github.com/blockblaz/zig-libp2p/issues/235) — re-enable 2 skipped unit tests / soak target
- [#57](https://github.com/blockblaz/zig-libp2p/issues/57) — `std.Io` async swarm (tangential to core/ layout)
- [#44](https://github.com/blockblaz/zig-libp2p/issues/44) — fuzz/stress harness (closed; informs `tests/` + `harness/`)
