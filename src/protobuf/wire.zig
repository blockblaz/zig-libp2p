//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("../primitives/protobuf/wire.zig");

pub const Error = _shim_src.Error;
pub const FieldValue = _shim_src.FieldValue;
pub const WireType = _shim_src.WireType;
pub const appendFieldKey = _shim_src.appendFieldKey;
pub const appendLengthDelimited = _shim_src.appendLengthDelimited;
pub const appendVarUInt64 = _shim_src.appendVarUInt64;
pub const decodeFieldKey = _shim_src.decodeFieldKey;
pub const decodeVarUInt64 = _shim_src.decodeVarUInt64;
pub const nextFieldValue = _shim_src.nextFieldValue;
pub const nextFieldValueLimited = _shim_src.nextFieldValueLimited;
