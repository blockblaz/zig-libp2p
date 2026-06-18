Vendored from [zquic](https://github.com/ch4r10t33r/zquic) v1.6.5 `vendor/tls/src/rsa/` (RFC 8017 PKCS#1).

`der.zig` is patched for Zig 0.16 (no `std.io.fixedBufferStream`). Used by `security/noise/identity.zig` for RSA-SHA256 PKCS#1 v1.5 Noise identity verification ([#87](https://github.com/ch4r10t33r/zig-libp2p/issues/87)).
