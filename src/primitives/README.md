# `primitives/` — wire-agnostic building blocks

Low-level helpers with no transport or protocol dependencies. Everything else
builds on these.

| Module | Role |
|--------|------|
| `identity.zig` | `PeerId` and `PublicKey` types and conversions. |
| `keypair.zig` | Key generation / encoding (Ed25519, secp256k1, ECDSA-P256, RSA). |
| `protocol.zig` | libp2p protocol-id constants and the supported-protocol table. |
| `multistream.zig` | multistream-select 1.0 negotiation. |
| `varint.zig` | unsigned LEB128 varints (length prefixes). |
| `protobuf/wire.zig` | minimal protobuf wire codec (varints + length-delimited fields) shared by the protocol codecs. |
| `addr_list.zig` | multiaddr list parsing / formatting helpers. |
| `wall_time.zig` | monotonic + unix clock helpers. |
| `errors.zig` | shared error sets. |
| `metrics.zig` | counter/gauge surface consumed across the stack. |
