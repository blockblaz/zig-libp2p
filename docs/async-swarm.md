# `std.Io` async Swarm — design note and migration plan (#57)

Today the swarm is built on `std.Io.Threaded`: producers call `submit(cmd)`
to push a command onto a bounded queue and consumers call `nextEvent(timeout)`
to pull events back. A background OS thread loops on `popCommand` →
`dispatchCommand`. This is correct, easy to reason about, and the existing
embedder API (`Swarm.startBackground`, `Swarm.tick`, `Swarm.run`) is stable.

The follow-up tracked in [#57](https://github.com/ch4r10t33r/zig-libp2p/issues/57)
is whether to migrate the swarm onto Zig 0.16's `std.Io` async surface so
that an embedder can host the swarm on its own event loop without a
dedicated OS thread. This document captures the design constraints and
the migration path so the next person who picks it up does not have to
re-derive them.

## Hot spots that block a naive port

These are the places where the current swarm implementation reaches for
OS-thread primitives and would need a `std.Io`-flavoured replacement.

| Site | What it does today | What an async port needs |
|---|---|---|
| `Swarm.startBackground` | `std.Thread.spawn(.{}, runWorkerTrampoline, .{self})` | A task handle obtained from the embedder's `std.Io` runtime |
| `Swarm.run` | Tight loop on `popCommand` → `dispatchCommand` | Cooperative loop that yields on empty command queue and on each command |
| Command channel | `std.Io.Threaded` bounded mutex+condvar | `std.Io` channel + `await`-able receive |
| Event channel | Same | Same — and consumer-side `nextEvent` becomes `try await swarm.events.recv(timeout)` |
| `connection_manager.tick(now_ms)` | Polled by the embedder | Either keep the explicit tick or hide it behind a periodic `std.Io.timer` |
| Transport drivers (`QuicListener.drive`, `QuicOutbound.drive`) | Blocking `posix.poll` + recvfrom loops | Replaced with `std.Io.netSocket.poll`-style yields |
| `ReqResp.tick`, `Gossipsub.heartbeat` | Periodic, called from the embedder | Reused as-is; the runtime just supplies a wake-up tick |

## What stays the same

- The `SwarmCommand` and `Event` union shapes (the wire-format-free public
  contract between producers and the runtime).
- All gossipsub, req/resp, identify, and connection-manager state
  machines. They are deliberately written as pure structures with no
  blocking calls; only the swarm-internal pumps need porting.
- The bounded-queue back-pressure semantics. The threaded swarm drops
  commands with a typed `error.QueueFull`; the async swarm should
  preserve that behaviour so existing producers don't change shape.

## Migration sketch

1. **Move the producer/consumer queues behind an `Io.Channel`-shaped
   abstraction.** Today both ends know they're talking to a
   `std.Io.Threaded` queue. Hide this behind two interfaces:
   `CommandSender.submit(cmd) -> SubmitError!void` and
   `EventReceiver.recv(timeout_ms) -> NextEventError!Event`. The
   threaded implementation stays; the async implementation routes into
   `std.Io` channels.
2. **Add an `AsyncSwarm` type that mirrors `Swarm`'s public API.** The
   two share the same command/event union and the same per-subsystem
   runtimes; what differs is the dispatch loop. `AsyncSwarm.run` is an
   `Io.Task`; the embedder spawns it onto its loop with whatever
   primitive Zig 0.16's `std.Io` ends up settling on.
3. **Keep both for at least one release.** Embedders that already run
   their own thread pool keep `Swarm`; embedders that want to share an
   event loop adopt `AsyncSwarm`. The migration is opt-in; nobody is
   forced to rewrite their main loop.
4. **Port the transport drivers last.** `QuicListener.drive` and
   `QuicOutbound.drive` block on `posix.poll`. The async variant
   `driveAsync` would yield on the same condition. Until the async
   transport landed, an `AsyncSwarm` would still need to spawn one OS
   thread per listener to host `drive`, which removes most of the value.
   So the transport port is the gating step for shipping the async swarm
   as a useful product, not a follow-on.

## Why this is not done in this PR

The threaded swarm is correct and stable, and the only way to make the
async swarm useful is to also port the QUIC/TCP transport drivers off
their blocking `posix.poll` loops. That's a larger change than fits
under "performance / polish" and it needs Zig's `std.Io` async surface
to settle (the API is still moving between 0.16 patch releases). This
note captures the shape so the next attempt does not re-derive it; the
work itself stays parked under #57.

## Stop-gap improvements that *do* fit a small PR

These are the things the *threaded* swarm could do today that would
close some of the gap without committing to the async port:

- **Coalesce command dispatch.** The current loop processes commands one
  at a time with a sleep between empty polls. Batch up to N commands per
  wake-up to amortise the queue lock.
- **Make `Swarm.run`'s idle backoff configurable.** Today it sleeps a
  fixed interval on an empty queue; embedders running latency-sensitive
  workloads might want to spin briefly first.
- **Add `Swarm.handle()` returning an opaque token.** Lets callers later
  swap `Swarm` for `AsyncSwarm` without touching every site that holds a
  `*Swarm`. Pure type-system plumbing, no behaviour change.

None of these are in this PR either; they are listed so the next
follow-up knows what shape they take.
