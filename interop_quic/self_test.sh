#!/usr/bin/env bash
# Phase B1 self-test: spawn the interop binary as both server and client in
# the same image, drive a single testcase, assert exit code.
#
# Usage:
#   interop_quic/self_test.sh handshake
#   interop_quic/self_test.sh ping

set -euo pipefail

TESTCASE="${1:-handshake}"
CERT_DIR="${CERT_DIR:-/tmp/zlib2p-interop-certs}"
CERT="${CERT_DIR}/cert.pem"
KEY="${CERT_DIR}/key.pem"
PORT="${PORT:-14242}"
DEADLINE_MS="${DEADLINE_MS:-15000}"

mkdir -p "${CERT_DIR}"

# Pick the interop binary + the cert-mint binary. In the docker image they're
# at /usr/local/bin/*; on a dev host they're at ./zig-out/bin/* relative to
# the repo root.
if command -v interop-quic-node >/dev/null 2>&1; then
    BIN="$(command -v interop-quic-node)"
elif [[ -x "./zig-out/bin/interop-quic-node" ]]; then
    BIN="./zig-out/bin/interop-quic-node"
else
    echo "self_test: cannot find interop-quic-node binary" >&2
    exit 2
fi
if command -v gen-libp2p-cert >/dev/null 2>&1; then
    CERT_BIN="$(command -v gen-libp2p-cert)"
elif [[ -x "./zig-out/bin/gen-libp2p-cert" ]]; then
    CERT_BIN="./zig-out/bin/gen-libp2p-cert"
else
    echo "self_test: cannot find gen-libp2p-cert binary" >&2
    exit 2
fi

if [[ ! -s "${CERT}" || ! -s "${KEY}" ]]; then
    CERT_PATH="${CERT}" KEY_PATH="${KEY}" "${CERT_BIN}"
fi

# Start server in background.
ROLE=server \
TESTCASE="${TESTCASE}" \
LISTEN_PORT="${PORT}" \
CERT_PATH="${CERT}" \
KEY_PATH="${KEY}" \
DEADLINE_MS="${DEADLINE_MS}" \
    "${BIN}" &
SERVER_PID=$!
trap 'kill ${SERVER_PID} 2>/dev/null || true; wait ${SERVER_PID} 2>/dev/null || true' EXIT

# Give the server a moment to bind.
sleep 0.5

# Run the client in foreground.
set +e
ROLE=client \
TESTCASE="${TESTCASE}" \
SERVER_HOST=127.0.0.1 \
SERVER_PORT="${PORT}" \
CERT_PATH="${CERT}" \
KEY_PATH="${KEY}" \
DEADLINE_MS="${DEADLINE_MS}" \
    "${BIN}"
CLIENT_RC=$?
set -e

# Wait for the server to finish its half (it exits after the round-trip).
wait "${SERVER_PID}" 2>/dev/null || true
SERVER_RC=$?

echo "self_test: testcase=${TESTCASE} client_rc=${CLIENT_RC} server_rc=${SERVER_RC}"

if [[ "${CLIENT_RC}" -ne 0 || "${SERVER_RC}" -ne 0 ]]; then
    exit 1
fi
echo "self_test: ${TESTCASE} OK"
