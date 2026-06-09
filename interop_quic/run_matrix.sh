#!/usr/bin/env bash
# QUIC interop cross-impl matrix runner (Phase B2).
#
# Iterates {server_impl × client_impl × testcase} and spawns the two
# binaries directly (no docker compose) so the script works on dev
# machines and in CI alike. Each impl exposes the same env contract:
#
#   ROLE / TESTCASE / LISTEN_PORT / SERVER_HOST / SERVER_PORT / DEADLINE_MS
#   SEED_HEX (server)       — deterministic peer id
#   REMOTE_PEER_ID (client) — server's libp2p peer id
#   CERT_PATH / KEY_PATH    — zig impl only (go-libp2p derives its TLS
#                             cert from its host key)
#
# Usage:
#   interop_quic/run_matrix.sh [impl_csv] [testcase_csv]
#       impl_csv     = zig,go-libp2p   (default: zig,go-libp2p)
#       testcase_csv = handshake,ping  (default: handshake,ping)
#
# Required binaries on PATH (or under ./zig-out/bin / ./interop_quic/impls):
#   - zig:        interop-quic-node + gen-libp2p-cert
#   - go-libp2p:  interop-quic-node-go (or the prebuilt container's
#                 entry, see interop_quic/impls/go-libp2p)
#
# Exit code: 0 if every (s,c,tc) pair returned 0; 1 otherwise. Per-pair
# pass/fail is printed in TAP-like form so CI logs are grep-friendly.

set -uo pipefail

IMPLS_CSV="${1:-zig,go-libp2p}"
TESTS_CSV="${2:-handshake,ping}"
DEADLINE_MS="${DEADLINE_MS:-20000}"
PORT_START="${PORT_START:-14300}"

IFS=',' read -ra IMPLS <<<"${IMPLS_CSV}"
IFS=',' read -ra TESTS <<<"${TESTS_CSV}"

# --- binary discovery -------------------------------------------------------

# zig
if command -v interop-quic-node >/dev/null 2>&1; then
    ZIG_BIN="$(command -v interop-quic-node)"
elif [[ -x "./zig-out/bin/interop-quic-node" ]]; then
    ZIG_BIN="./zig-out/bin/interop-quic-node"
fi
if command -v gen-libp2p-cert >/dev/null 2>&1; then
    ZIG_CERT_BIN="$(command -v gen-libp2p-cert)"
elif [[ -x "./zig-out/bin/gen-libp2p-cert" ]]; then
    ZIG_CERT_BIN="./zig-out/bin/gen-libp2p-cert"
fi

# go-libp2p
if command -v interop-quic-node-go >/dev/null 2>&1; then
    GO_BIN="$(command -v interop-quic-node-go)"
elif [[ -x "./interop_quic/impls/go-libp2p/interop-quic-node-go" ]]; then
    GO_BIN="./interop_quic/impls/go-libp2p/interop-quic-node-go"
fi

# rust-libp2p
if command -v interop-quic-node-rust >/dev/null 2>&1; then
    RUST_BIN="$(command -v interop-quic-node-rust)"
elif [[ -x "./interop_quic/impls/rust-libp2p/target/release/interop-quic-node-rust" ]]; then
    RUST_BIN="./interop_quic/impls/rust-libp2p/target/release/interop-quic-node-rust"
fi

require_zig() {
    if [[ -z "${ZIG_BIN:-}" || -z "${ZIG_CERT_BIN:-}" ]]; then
        echo "matrix: missing zig binaries (interop-quic-node + gen-libp2p-cert)" >&2
        exit 2
    fi
}
require_go() {
    if [[ -z "${GO_BIN:-}" ]]; then
        echo "matrix: missing go-libp2p binary (interop-quic-node-go)" >&2
        exit 2
    fi
}
require_rust() {
    if [[ -z "${RUST_BIN:-}" ]]; then
        echo "matrix: missing rust-libp2p binary (interop-quic-node-rust)" >&2
        exit 2
    fi
}

# Validate everything we'll need up front so we fail fast rather than
# mid-matrix.
for impl in "${IMPLS[@]}"; do
    case "${impl}" in
        zig) require_zig ;;
        go-libp2p) require_go ;;
        rust-libp2p) require_rust ;;
        *) echo "matrix: unknown impl=${impl}" >&2; exit 2 ;;
    esac
done

# --- helpers ---------------------------------------------------------------

derive_seed() {
    # 32-byte hex derived from the port (deterministic across runs).
    local p="$1"
    printf '%08x%056x' "${p}" 0
}

start_server() {
    # Spawns the server impl in the background and populates the globals
    # SERVER_PID / SERVER_LOG / SERVER_PEER_ID. Does NOT use command
    # substitution — under bash 3.2 (macOS default) that runs in a
    # subshell, so $! lands in the parent of the subshell and the outer
    # SERVER_PID stays at its previous value. If that happened to be 0,
    # a later `kill ${SERVER_PID}` would target the process group and
    # SIGTERM the runner itself.
    local impl="$1" testcase="$2" port="$3" seed="$4"
    SERVER_LOG="$(mktemp -t matrix-srv.XXXXXX)"
    SERVER_PEER_ID=""
    case "${impl}" in
        zig)
            local certdir
            certdir="$(mktemp -d -t matrix-srv-certs.XXXXXX)"
            local cert="${certdir}/cert.pem"
            local key="${certdir}/key.pem"
            CERT_PATH="${cert}" KEY_PATH="${key}" SEED_HEX="${seed}" \
                "${ZIG_CERT_BIN}" > "${SERVER_LOG}.gen" 2>&1
            SERVER_PEER_ID=$(awk -F= '/peer_id=/{print $2}' "${SERVER_LOG}.gen" | head -1)
            ROLE=server TESTCASE="${testcase}" LISTEN_PORT="${port}" \
                CERT_PATH="${cert}" KEY_PATH="${key}" \
                DEADLINE_MS="${DEADLINE_MS}" \
                "${ZIG_BIN}" > "${SERVER_LOG}" 2>&1 &
            SERVER_PID=$!
            ;;
        go-libp2p)
            ROLE=server TESTCASE="${testcase}" LISTEN_PORT="${port}" \
                SEED_HEX="${seed}" DEADLINE_MS="${DEADLINE_MS}" \
                "${GO_BIN}" > "${SERVER_LOG}" 2>&1 &
            SERVER_PID=$!
            # Wait briefly for the peer-id banner.
            local tries=0
            while ! grep -q 'peer_id=' "${SERVER_LOG}" 2>/dev/null; do
                tries=$((tries + 1))
                if [[ ${tries} -gt 60 ]]; then break; fi
                sleep 0.05
            done
            SERVER_PEER_ID=$(awk -F= '/peer_id=/{print $2}' "${SERVER_LOG}" | head -1)
            ;;
        rust-libp2p)
            ROLE=server TESTCASE="${testcase}" LISTEN_PORT="${port}" \
                SEED_HEX="${seed}" DEADLINE_MS="${DEADLINE_MS}" \
                "${RUST_BIN}" > "${SERVER_LOG}" 2>&1 &
            SERVER_PID=$!
            local tries=0
            while ! grep -q 'peer_id=' "${SERVER_LOG}" 2>/dev/null; do
                tries=$((tries + 1))
                if [[ ${tries} -gt 60 ]]; then break; fi
                sleep 0.05
            done
            SERVER_PEER_ID=$(awk -F= '/peer_id=/{print $2}' "${SERVER_LOG}" | head -1)
            ;;
    esac
}

run_client() {
    local impl="$1" testcase="$2" host="$3" port="$4" remote_pid="$5"
    local certdir
    case "${impl}" in
        zig)
            certdir="$(mktemp -d -t matrix-cli-certs.XXXXXX)"
            local cert="${certdir}/cert.pem"
            local key="${certdir}/key.pem"
            CERT_PATH="${cert}" KEY_PATH="${key}" "${ZIG_CERT_BIN}" >/dev/null 2>&1
            ROLE=client TESTCASE="${testcase}" \
                SERVER_HOST="${host}" SERVER_PORT="${port}" \
                CERT_PATH="${cert}" KEY_PATH="${key}" \
                REMOTE_PEER_ID="${remote_pid}" \
                DEADLINE_MS="${DEADLINE_MS}" \
                "${ZIG_BIN}"
            ;;
        go-libp2p)
            ROLE=client TESTCASE="${testcase}" \
                SERVER_HOST="${host}" SERVER_PORT="${port}" \
                REMOTE_PEER_ID="${remote_pid}" \
                DEADLINE_MS="${DEADLINE_MS}" \
                "${GO_BIN}"
            ;;
        rust-libp2p)
            ROLE=client TESTCASE="${testcase}" \
                SERVER_HOST="${host}" SERVER_PORT="${port}" \
                REMOTE_PEER_ID="${remote_pid}" \
                DEADLINE_MS="${DEADLINE_MS}" \
                "${RUST_BIN}"
            ;;
    esac
}

# --- main loop -------------------------------------------------------------

total=0
failed=0
PORT="${PORT_START}"

skipped=0

# Pairs an impl doesn't yet support — TAP "skip" rather than "not ok" so
# a partial impl doesn't fail the matrix. Implemented as a case statement
# instead of an associative array because macOS still ships bash 3.2.
skip_reason_for() {
    case "$1:$2" in
        *) echo "" ;;
    esac
}

# Asymmetric skips (per server×client×testcase). Used for known cross-impl
# protocol-negotiation gaps where one role-pairing fails but the reverse works.
# Reasons should reference an issue.
skip_reason_for_pair() {
    case "$1:$2:$3" in
        zig:rust-libp2p:gossipsub) echo "rust client publishes returns InsufficientPeers — rust-libp2p Strict ValidationMode rejects zig's unsigned SUBSCRIBE RPC; #183" ;;
        zig:rust-libp2p:reqresp) echo "zig server's STREAM frames trigger FINAL_SIZE_ERROR on rust client; #184" ;;
        zig:go-libp2p:reqresp) echo "same zquic STREAM offset issue when zig is the server and the client opens multiple streams concurrently; #184" ;;
        *) echo "" ;;
    esac
}

for server in "${IMPLS[@]}"; do
    for client in "${IMPLS[@]}"; do
        for tc in "${TESTS[@]}"; do
            total=$((total + 1))
            PORT=$((PORT + 1))
            seed="$(derive_seed "${PORT}")"
            echo "--- matrix: server=${server} client=${client} testcase=${tc} port=${PORT} ---"
            skip_reason="$(skip_reason_for "${server}" "${tc}")"
            if [[ -z "${skip_reason}" ]]; then
                skip_reason="$(skip_reason_for "${client}" "${tc}")"
            fi
            if [[ -z "${skip_reason}" ]]; then
                skip_reason="$(skip_reason_for_pair "${server}" "${client}" "${tc}")"
            fi
            if [[ -n "${skip_reason}" ]]; then
                echo "ok ${total} - server=${server} client=${client} ${tc} # skip ${skip_reason}"
                skipped=$((skipped + 1))
                continue
            fi
            SERVER_PID=""
            SERVER_PEER_ID=""
            start_server "${server}" "${tc}" "${PORT}" "${seed}"
            if [[ -z "${SERVER_PEER_ID}" || -z "${SERVER_PID}" ]]; then
                echo "not ok ${total} - server failed to start (server=${server})"
                if [[ -n "${SERVER_PID}" ]]; then
                    kill "${SERVER_PID}" 2>/dev/null || true
                    wait "${SERVER_PID}" 2>/dev/null
                fi
                failed=$((failed + 1))
                continue
            fi
            # Brief grace so the listener is bound before the client dials.
            sleep 0.3

            run_client "${client}" "${tc}" "127.0.0.1" "${PORT}" "${SERVER_PEER_ID}"
            client_rc=$?

            # Reap server. Send SIGTERM only if the process is still
            # running — by handshake-completion time the zig server has
            # usually already exited 0.
            if kill -0 "${SERVER_PID}" 2>/dev/null; then
                kill "${SERVER_PID}" 2>/dev/null || true
            fi
            wait "${SERVER_PID}" 2>/dev/null
            server_rc=$?
            # 143 = SIGTERM from our kill — not a failure.
            if [[ "${server_rc}" -eq 143 ]]; then server_rc=0; fi

            if [[ "${client_rc}" -eq 0 && "${server_rc}" -eq 0 ]]; then
                echo "ok ${total} - server=${server} client=${client} ${tc}"
            else
                echo "not ok ${total} - server=${server} client=${client} ${tc} (client=${client_rc} server=${server_rc})"
                echo "--- server log: ${SERVER_LOG} ---"
                tail -n 30 "${SERVER_LOG}" 2>/dev/null | sed 's/^/    /'
                failed=$((failed + 1))
            fi
        done
    done
done

echo "1..${total}"
if [[ "${failed}" -ne 0 ]]; then
    echo "matrix: ${failed}/${total} pairs FAILED (${skipped} skipped)"
    exit 1
fi
if [[ "${skipped}" -ne 0 ]]; then
    echo "matrix: $((total - skipped))/${total} pairs OK (${skipped} skipped)"
else
    echo "matrix: ${total}/${total} pairs OK"
fi
