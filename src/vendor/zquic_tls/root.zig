//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../../../vendor/zquic_tls/root.zig");

pub const Cipher = _shim_src.Cipher;
pub const record = _shim_src.record;
pub const protocol = _shim_src.protocol;
pub const max_ciphertext_record_len = _shim_src.max_ciphertext_record_len;
pub const input_buffer_len = _shim_src.input_buffer_len;
pub const output_buffer_len = _shim_src.output_buffer_len;
pub const config = _shim_src.config;
pub const nonblock = _shim_src.nonblock;
