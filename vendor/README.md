# Vendored dependencies

See `docs/REPO_LAYOUT.md` phase 5. `zquic_tls` and `zquic_rsa` are vendored outside `src/` to avoid Zig 0.16 duplicate module path errors when both `zquic` and `zig_libp2p` compile the same TLS tree.
