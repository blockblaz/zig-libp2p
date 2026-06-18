# unified-testing transport interop image (TCP + TLS + Yamux + ping).
# Build: docker build -f harness/tcp/Dockerfile -t ch4r10t33r/zig-libp2p-interop:dev .

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils git \
    && rm -rf /var/lib/apt/lists/*

ARG ZIG_VERSION=0.16.0
RUN arch="$(dpkg --print-architecture)" \
    && case "${arch}" in \
        amd64) zig_triple=x86_64-linux ;; \
        arm64) zig_triple=aarch64-linux ;; \
        *) echo "unsupported arch ${arch}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_triple}-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
    && tar -xJf /tmp/zig.tar.xz -C /usr/local \
    && ln -s "/usr/local/zig-${zig_triple}-${ZIG_VERSION}/zig" /usr/local/bin/zig

WORKDIR /app
COPY . .
RUN zig build interop -Doptimize=ReleaseSafe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/zig-out/bin/transport-interop /app/bin/transport-interop
CMD ["/app/bin/transport-interop"]
