#!/usr/bin/env bash
# Generate a self-signed P-256 ECDSA cert pair for the QUIC interop endpoint.
# zquic's vendored TLS parser accepts SEC1 EC PRIVATE KEY PEM and a standard
# X.509 cert PEM.
#
# Usage: gen_certs.sh /certs/cert.pem /certs/key.pem

set -euo pipefail

CERT="${1:-/certs/cert.pem}"
KEY="${2:-/certs/key.pem}"
DAYS="${DAYS:-365}"
CN="${CN:-zig-libp2p-interop}"

mkdir -p "$(dirname "${CERT}")" "$(dirname "${KEY}")"

# `openssl ecparam -name prime256v1 -genkey` produces a SEC1 EC PRIVATE KEY
# block, which is what zquic's vendored TLS parser expects.
openssl ecparam -name prime256v1 -genkey -noout -out "${KEY}"
openssl req -new -x509 -key "${KEY}" -out "${CERT}" -days "${DAYS}" \
    -subj "/CN=${CN}" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "wrote cert: ${CERT}"
echo "wrote key : ${KEY}"
