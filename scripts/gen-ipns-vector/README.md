# gen-ipns-vector

Generates a reference IPNS record using go's [`boxo/ipns`](https://github.com/ipfs/boxo)
— the same library go-ipfs/Kubo uses — so the Zig `kad_dht.ipns_validator` can be
tested for byte-level interop against the reference implementation.

The record is built from a **deterministic** Ed25519 key (seed = `0x42` × 32),
value `/ipfs/bafybeig…`, sequence `7`, and an EOL validity of `2099-12-31`, so the
output is stable and reproducible.

## Run

```sh
cd scripts/gen-ipns-vector
go run .
```

It prints the IPNS name (go's canonical base36 CIDv1 libp2p-key form), the
base58 peer id, the value, the sequence, and the marshaled record as base64.

The base64 record and the name are embedded as the `boxo_ipns_*` test vector in
[`src/kad_dht/ipns_validator.zig`](../../src/kad_dht/ipns_validator.zig)
(`test "ipns validator accepts a go (boxo) reference record"`). Re-run this and
update those constants if the validator's expectations change.
