# go-libp2p side of the QUIC interop runner (Phase B2).
#
# Local build (from repo root):
#   docker build -t go-libp2p:interop-quic \
#                -f interop_quic/impls/go-libp2p/Dockerfile \
#                interop_quic/impls/go-libp2p

# ── Stage 1: compile ───────────────────────────────────────────────────────
FROM golang:1.22-bookworm AS builder

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/interop-quic-node .

# ── Stage 2: minimal runtime ───────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/interop-quic-node /usr/local/bin/interop-quic-node
RUN chmod +x /usr/local/bin/interop-quic-node

ENTRYPOINT ["/usr/local/bin/interop-quic-node"]
