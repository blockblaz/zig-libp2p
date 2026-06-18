# rust-libp2p side of the QUIC interop runner (Phase B5).
#
# Local build (from this directory):
#   docker build -t rust-libp2p:interop-quic -f Dockerfile .

# ── Stage 1: compile ───────────────────────────────────────────────────────
FROM rust:1.81-bookworm AS builder

WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
# Cargo.lock isn't strictly required (defaults are fine) but if present
# we honor it for reproducible builds.
COPY Cargo.lock* ./
RUN cargo build --release --locked || cargo build --release
RUN cp target/release/interop-quic-node-rust /out-bin

# ── Stage 2: minimal runtime ───────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out-bin /usr/local/bin/interop-quic-node-rust
RUN chmod +x /usr/local/bin/interop-quic-node-rust

ENTRYPOINT ["/usr/local/bin/interop-quic-node-rust"]
