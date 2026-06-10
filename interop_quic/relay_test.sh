#!/usr/bin/env bash
# Circuit Relay v2 + DCUtR self-test (zig interop binary, 2-process).
#
# Usage:
#   interop_quic/relay_test.sh relay
#   interop_quic/relay_test.sh dcutr

set -euo pipefail

TESTCASE="${1:-relay}"
CERT_DIR="${CERT_DIR:-/tmp/zlib2p-interop-certs}"
CERT="${CERT_DIR}/cert.pem"
KEY="${CERT_DIR}/key.pem"
PORT="${PORT:-14243}"
DEADLINE_MS="${DEADLINE_MS:-15000}"
SEED_HEX="$(printf '%08x%056x' "${PORT}" 0)"

mkdir -p "${CERT_DIR}"

if command -v interop-quic-node >/dev/null 2>&1; then
    BIN="$(command -v interop-quic-node)"
elif [[ -x "./zig-out/bin/interop-quic-node" ]]; then
    BIN="./zig-out/bin/interop-quic-node"
else
    echo "relay_test: cannot find interop-quic-node binary" >&2
    exit 2
fi
if command -v gen-libp2p-cert >/dev/null 2>&1; then
    CERT_BIN="$(command -v gen-libp2p-cert)"
elif [[ -x "./zig-out/bin/gen-libp2p-cert" ]]; then
    CERT_BIN="./zig-out/bin/gen-libp2p-cert"
else
    echo "relay_test: cannot find gen-libp2p-cert binary" >&2
    exit 2
fi

if [[ ! -s "${CERT}" || ! -s "${KEY}" ]]; then
    CERT_PATH="${CERT}" KEY_PATH="${KEY}" SEED_HEX="${SEED_HEX}" "${CERT_BIN}"
fi

SERVER_PEER_ID="$(CERT_PATH="${CERT}" KEY_PATH="${KEY}" SEED_HEX="${SEED_HEX}" "${CERT_BIN}" | awk -F= '/peer_id=/{print $2}' | head -1)"

ROLE=server \
TESTCASE="${TESTCASE}" \
LISTEN_PORT="${PORT}" \
CERT_PATH="${CERT}" \
KEY_PATH="${KEY}" \
SEED_HEX="${SEED_HEX}" \
DEADLINE_MS="${DEADLINE_MS}" \
    "${BIN}" &
SERVER_PID=$!
trap 'kill ${SERVER_PID} 2>/dev/null || true; wait ${SERVER_PID} 2>/dev/null || true' EXIT

sleep 0.5

set +e
ROLE=client \
TESTCASE="${TESTCASE}" \
SERVER_HOST=127.0.0.1 \
SERVER_PORT="${PORT}" \
CERT_PATH="${CERT}" \
KEY_PATH="${KEY}" \
SEED_HEX="${SEED_HEX}" \
DEADLINE_MS="${DEADLINE_MS}" \
REMOTE_PEER_ID="${SERVER_PEER_ID}" \
    "${BIN}"
CLIENT_RC=$?
set -e

wait "${SERVER_PID}" 2>/dev/null || true
SERVER_RC=$?

echo "relay_test: testcase=${TESTCASE} client_rc=${CLIENT_RC} server_rc=${SERVER_RC}"

if [[ "${CLIENT_RC}" -ne 0 || "${SERVER_RC}" -ne 0 ]]; then
    exit 1
fi
echo "relay_test: ${TESTCASE} OK"
