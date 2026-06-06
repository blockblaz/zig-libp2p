#!/usr/bin/env bash
# Entry point for the QUIC interop endpoint container.
#
# Reads ROLE / TESTCASE / cert paths from environment, makes sure certs
# exist (generates a self-signed pair if not), then execs the interop
# binary.  Stays minimal — extra orchestration lives in runner scripts.

set -euo pipefail

ROLE="${ROLE:-server}"
TESTCASE="${TESTCASE:-handshake}"
CERT_PATH="${CERT_PATH:-/certs/cert.pem}"
KEY_PATH="${KEY_PATH:-/certs/key.pem}"

if [[ ! -s "${CERT_PATH}" || ! -s "${KEY_PATH}" ]]; then
    echo "run_endpoint: minting libp2p TLS cert at ${CERT_PATH} / ${KEY_PATH}" >&2
    mkdir -p "$(dirname "${CERT_PATH}")"
    CERT_PATH="${CERT_PATH}" KEY_PATH="${KEY_PATH}" \
        /usr/local/bin/gen-libp2p-cert
fi

echo "run_endpoint: ROLE=${ROLE} TESTCASE=${TESTCASE}"
exec /usr/local/bin/interop-quic-node
