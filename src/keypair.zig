//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./primitives/keypair.zig");

pub const KeyPair = _shim_src.KeyPair;
pub const PeerIdFromKeyPairError = _shim_src.PeerIdFromKeyPairError;
pub const PemError = _shim_src.PemError;
pub const keyPairFromDer = _shim_src.keyPairFromDer;
pub const keyPairFromPem = _shim_src.keyPairFromPem;
pub const peerIdFromKeyPair = _shim_src.peerIdFromKeyPair;
