# zig-libp2p QUIC interop endpoint image (Phase B1).
#
# Builds the `interop-quic-node` binary (examples/interop_quic_node.zig) and
# packages it into a slim runtime image used by the QUIC interop runner.
#
# Local build:
#   docker build -t zig-libp2p:interop-quic -f interop_quic/Dockerfile .

# ── Stage 1: compile ───────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/*

ARG ZIG_VERSION=0.16.0
RUN arch="$(dpkg --print-architecture)" \
    && case "${arch}" in \
        amd64) zig_arch=x86_64 ;; \
        arm64) zig_arch=aarch64 ;; \
        *) echo "unsupported arch ${arch}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${zig_arch}-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
    && tar -xJf /tmp/zig.tar.xz -C /usr/local \
    && ln -s "/usr/local/zig-linux-${zig_arch}-${ZIG_VERSION}/zig" /usr/local/bin/zig

WORKDIR /build
COPY . .
RUN zig build -Doptimize=ReleaseFast

# ── Stage 2: minimal runtime ────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/zig-out/bin/interop-quic-node /usr/local/bin/interop-quic-node
COPY --from=builder /build/zig-out/bin/gen-libp2p-cert /usr/local/bin/gen-libp2p-cert
COPY interop_quic/run_endpoint.sh /usr/local/bin/run_endpoint.sh
COPY interop_quic/self_test.sh /usr/local/bin/self_test.sh
RUN chmod +x /usr/local/bin/run_endpoint.sh \
              /usr/local/bin/interop-quic-node \
              /usr/local/bin/gen-libp2p-cert \
              /usr/local/bin/self_test.sh

ENTRYPOINT ["/usr/local/bin/run_endpoint.sh"]
