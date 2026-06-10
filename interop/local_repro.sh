#!/usr/bin/env bash
# Local two-process loopback repro for the interop hang (no docker networking).
set -u

BIN=./zig-out/bin/transport-interop
REDIS_ADDR=127.0.0.1:6399
KEY=deadbeef
TO=${TO:-15}
RUN_SECS=${RUN_SECS:-14}

pkill -9 -f transport-interop 2>/dev/null
docker exec interop-redis redis-cli DEL "${KEY}_listener_multiaddr" >/dev/null 2>&1

IS_DIALER=false REDIS_ADDR=$REDIS_ADDR TEST_KEY=$KEY LISTENER_IP=127.0.0.1 \
  TRANSPORT=tcp SECURE_CHANNEL=tls MUXER=yamux TEST_TIMEOUT_SECS=$TO DEBUG=true \
  "$BIN" > /tmp/listener.log 2>&1 &
LPID=$!

sleep 1

IS_DIALER=true REDIS_ADDR=$REDIS_ADDR TEST_KEY=$KEY \
  TRANSPORT=tcp SECURE_CHANNEL=tls MUXER=yamux TEST_TIMEOUT_SECS=$TO DEBUG=true \
  "$BIN" > /tmp/dialer.log 2>&1 &
DPID=$!

sleep "$RUN_SECS"

kill -9 "$LPID" "$DPID" 2>/dev/null
pkill -9 -f transport-interop 2>/dev/null

echo "----- DIALER LOG -----"
cat /tmp/dialer.log
echo "----- LISTENER LOG -----"
cat /tmp/listener.log
