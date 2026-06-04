# unified-testing transport interop image (TCP + TLS + Yamux + ping).
# Build: docker build -f interop/Dockerfile -t ch4r10t33r/zig-libp2p-interop:dev .

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils \
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

WORKDIR /app
COPY . .
RUN zig build interop -Doptimize=ReleaseSafe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/zig-out/bin/transport-interop /app/bin/transport-interop
CMD ["/app/bin/transport-interop"]
