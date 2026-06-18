#!/usr/bin/env bash
# Build the transport-interop Docker image and run a minimal zig x zig smoke test.
# Compatible with macOS system bash 3.2 (no unified-testing harness required).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE="${ZIG_LIBP2P_INTEROP_IMAGE:-ch4r10t33r/zig-libp2p-interop:local}"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-compose.yaml"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required" >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DOCKER_COMPOSE=(docker-compose)
else
  echo "error: docker compose is required" >&2
  exit 1
fi

echo "→ Building ${IMAGE} from ${REPO_ROOT}"
docker build -f "${SCRIPT_DIR}/Dockerfile" -t "${IMAGE}" "${REPO_ROOT}"

echo "→ Running zig x zig smoke test (tcp, tls, yamux)"
export ZIG_LIBP2P_INTEROP_IMAGE="${IMAGE}"
"${DOCKER_COMPOSE[@]}" -f "${COMPOSE_FILE}" down --volumes --remove-orphans >/dev/null 2>&1 || true

"${DOCKER_COMPOSE[@]}" -f "${COMPOSE_FILE}" up -d redis listener

TEST_KEY="${TEST_KEY:-deadbeef}"
REDIS_CID="$("${DOCKER_COMPOSE[@]}" -f "${COMPOSE_FILE}" ps -q redis)"
deadline=$((SECONDS + 60))
while [ "${SECONDS}" -lt "${deadline}" ]; do
  if [ -n "${REDIS_CID}" ] && docker exec "${REDIS_CID}" redis-cli LLEN "${TEST_KEY}_listener_multiaddr" 2>/dev/null | grep -q '^1$'; then
    break
  fi
  sleep 1
done
if [ "${SECONDS}" -ge "${deadline}" ]; then
  echo "error: listener did not publish multiaddr within 60s" >&2
  "${DOCKER_COMPOSE[@]}" -f "${COMPOSE_FILE}" logs listener >&2 || true
  exit 1
fi

set +e
"${DOCKER_COMPOSE[@]}" -f "${COMPOSE_FILE}" run --rm --no-TTY dialer
status=$?
set -e

"${DOCKER_COMPOSE[@]}" -f "${COMPOSE_FILE}" down --volumes --remove-orphans >/dev/null 2>&1 || true

if [ "${status}" -ne 0 ]; then
  echo "error: interop smoke test failed (exit ${status})" >&2
  exit "${status}"
fi

echo "✓ interop smoke test passed"
