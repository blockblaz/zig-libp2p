# Examples

Small programs showing how to depend on `zig_libp2p` and call specific surfaces.

The **catalog** (binary names, source links, one-line descriptions) is in the root [README Examples section](../README.md#examples).

## Build / CI

- `zig build` — installs these into `zig-out/bin/` (or your install prefix).
- `zig build examples` — compile only (no install).
- `zig build test` — runs **library** unit tests, then **executes** each smoke-run example; the TCP status binary is **compiled** but not run (see `build.zig`). Keep `main()` returning success on supported targets so CI stays green.

Register new programs in the `examples` table in `build.zig`.
