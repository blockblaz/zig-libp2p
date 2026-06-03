# Security model (Lean / Eth2 devnets)

## Transport identity (TLS / QUIC)

Peers are authenticated at the **connection** layer via libp2p TLS 1.3 (`peerIdFromVerifiedCertificate`): self-signed X.509 validity, libp2p extension OID in TBSCertificate `[3] EXPLICIT Extensions`, and SignedKey signature over `libp2p-tls-handshake: || SPKI`.

`QuicOutboundDialOptions` always verifies the server leaf after connect. Do not use `peerIdFromCertificateUnverified` on untrusted certificates.

## Gossipsub: StrictNoSign

Lean and Eth2 consensus use gossipsub **StrictNoSign**: `Message` publishes omit `from`, `seqno`, and `signature`. zig-libp2p:

- Derives `message_id` as truncated SHA-256 over `(domain, topic, data)` (see `gossipsub/message_id.zig`).
- Suppresses duplicates via `duplicate_cache`.
- Does **not** authenticate `data` at the gossipsub layer.

**Application responsibility:** after SSZ-decoding block/attestation payloads, run consensus `state_transition` / signature checks. Wire an optional `GossipsubConfig.topic_validator` to drop invalid blobs early.

TLS peer id ≠ message author under StrictNoSign; only the transport peer is cryptographically bound.

## Identify and address records

`listen_addrs` in Identify are **hints**. When `signed_peer_record` (RFC 0002) is present, `identify.verifySignedPeerRecord` / inbound handlers verify the envelope before invoking callbacks.

Unsigned listen addresses must not be dialed without independent validation.

## Resource limits

| Path | Cap |
|------|-----|
| Req/resp unary (TCP `wire_framing`) | 16 MiB accumulated wire |
| Req/resp unary (QUIC runtime `req_acc`) | same |
| Gossipsub RPC frame | 4 MiB (`wire_limits`) |
| Gossipsub QUIC `gossip_acc` | 4 MiB + varint slack |
| Snappy decompress | bounded to declared uncompressed length |

See issues #119–#127 for the audit that introduced these policies.
