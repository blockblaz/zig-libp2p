# `security/` — secure channels

Authenticated, encrypted channels that bind a connection to a remote `PeerId`.

| Path | Role |
|------|------|
| `libp2p_tls.zig` | libp2p TLS 1.3 (RFC 0001) — the libp2p public-key extension, used over QUIC and TCP. |
| `libp2p_tls_cert.zig` | Self-signed certificate minting + verification carrying the libp2p key/signature. |
| `noise/` | Noise `XX` handshake (`/noise`) — `protocol.zig`, `payload.zig`, `identity.zig`, `libp2p_noise.zig`; supports Ed25519, secp256k1, ECDSA-P256, RSA identities. |

The threat model and wire-size limits are documented in
[`docs/SECURITY.md`](../../docs/SECURITY.md).
