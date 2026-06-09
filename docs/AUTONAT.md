# AutoNAT (NAT detection)

Implements libp2p AutoNAT wire codecs and client/server logic ([#92](https://github.com/ch4r10t33r/zig-libp2p/issues/92)). Spec: [libp2p/autonat](https://github.com/libp2p/specs/blob/master/autonat/README.md).

## Protocols

| Version | Multistream ID | Role |
|---------|----------------|------|
| v1 | `/libp2p/autonat/1.0.0` | Node-level `NatStatus` (public / private / unknown) |
| v2 | `/libp2p/autonat/2/dial-request` | Per-address reachability probe |
| v2 | `/libp2p/autonat/2/dial-back` | Nonce-echo dial-back with amplification padding |

Prefer **v2** for new integrations (per-address probing, nonce ownership proof, amplification limits).

## Modules

Import via `zig_libp2p.autonat`:

| Module | Purpose |
|--------|---------|
| `wire` | Length-prefixed protobuf encode/decode, v1 + v2 messages |
| `policy` | `NatStatus`, RFC1918 / relay filters, probe aggregation (`>3` successes → public, `>3` failures → private) |
| `client` | `Client.poll` schedules probes; `handleV1Response` / `handleV2DialBack` consume replies |
| `server` | `handleV1Stream` / `handleV2DialRequestStream` — dial-backs via embedder hook |

## Embedder wiring

Transport dial-backs stay **embedder-owned** (same pattern as ping / identify):

1. **Client:** call `Client.poll` when due; open a stream, negotiate the protocol, write `probe.wire_message` (length-prefixed for v1; v2 dial-request is already framed). On inbound response, call `handleV1Response` or `handleV2DialBack`.
2. **Server:** after multistream-select, dispatch to `Server.handleV1Stream` or `handleV2DialRequestStream`. Implement `DialBackFn` to dial the requester's published address from a **fresh source port** and return `.ok` / `.dial_error` / `.dial_back_error`.
3. **Policy:** pass observed remote IP and `is_relayed` into server handlers so relayed connections refuse v1 dial-backs per spec.

```zig
const zl = @import("zig_libp2p");

fn dialBack(ctx: ?*anyopaque, addr: []const u8, nonce: u64) zl.autonat.DialBackResult {
    _ = ctx;
    _ = addr;
    _ = nonce;
    // Open transport to addr, complete v2 nonce echo if applicable.
    return .ok;
}

var server = zl.autonat.Server.init(allocator, .{}, dialBack);
try server.handleV1Stream(&reader, &writer, observed_ip, false);
```

## Example

[`examples/autonat_membuf.zig`](../examples/autonat_membuf.zig) — v1 client probe round-trip through in-memory `std.Io` buffers (smoke-run under `zig build test`).

## Acceptance (issue #92)

- Node behind NAT classifies as **private** after ≥4 failed probes (default thresholds).
- Node with a public listen addr classifies as **public** after sufficient successes.
- v2 dial-back amplification bounded by `ServerConfig.amplification_min_bytes` (default 30 KiB).
