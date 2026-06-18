# Transport interop (unified-testing)

Docker binary for [libp2p unified-testing](https://github.com/libp2p/unified-testing) transport ping tests.

## Stack

- TCP (`TRANSPORT=tcp`)
- TLS 1.3 / `/tls/1.0.0` (`SECURE_CHANNEL=tls`)
- Yamux (`MUXER=yamux`)
- `/ipfs/ping/1.0.0` on a Yamux stream

## Environment (modern)

| Variable | Role |
|----------|------|
| `IS_DIALER` | `true` = dialer, `false` = listener |
| `REDIS_ADDR` | e.g. `transport-redis:6379` |
| `TEST_KEY` | 8-char hex; Redis key `{TEST_KEY}_listener_multiaddr` |
| `LISTENER_IP` | bind address (listener), e.g. `0.0.0.0` |
| `TRANSPORT` | `tcp` |
| `SECURE_CHANNEL` | `tls` |
| `MUXER` | `yamux` |
| `TEST_TIMEOUT_SECS` | default `180` |
| `DEBUG` | `true` for stderr logs |

Legacy lowercase env vars (`is_dialer`, `redis_addr`, `ip`, `security`, `muxer`) and Redis key `listenerAddr` are also accepted.

## Dialer output

YAML on stdout (parsed by unified-testing):

```yaml
latency:
  handshake_plus_one_rtt: <ms>
  ping_rtt: <ms>
  unit: ms
```

## Build

```sh
zig build interop
./zig-out/bin/transport-interop
```

```sh
docker build -f harness/tcp/Dockerfile -t ch4r10t33r/zig-libp2p-interop:dev .
```

## Tracking

See GitHub issue (unified-testing integration plan). Phase 2: PR to `libp2p/unified-testing` `transport/images.yaml`; Phase 3: CI matrix in `.github/workflows/interop.yml`.
