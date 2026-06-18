//! Compatibility shim for legacy import paths (Zig 0.16).
const _shim_src = @import("./protocols/identify/identify.zig");

pub const Error = _shim_src.Error;
pub const Identify = _shim_src.Identify;
pub const Limits = _shim_src.Limits;
pub const MessageOwned = _shim_src.MessageOwned;
pub const MessageView = _shim_src.MessageView;
pub const PeerRecordOwned = _shim_src.PeerRecordOwned;
pub const ReplyParams = _shim_src.ReplyParams;
pub const SignedEnvelopeOwned = _shim_src.SignedEnvelopeOwned;
pub const decodeOwned = _shim_src.decodeOwned;
pub const decodePeerRecord = _shim_src.decodePeerRecord;
pub const decodeSignedEnvelope = _shim_src.decodeSignedEnvelope;
pub const encode = _shim_src.encode;
pub const encodePeerRecordTestWire = _shim_src.encodePeerRecordTestWire;
pub const encodeSignedPeerRecordTestWire = _shim_src.encodeSignedPeerRecordTestWire;
pub const peer_record_payload_type = _shim_src.peer_record_payload_type;
pub const protocol_line = _shim_src.protocol_line;
pub const push_protocol_line = _shim_src.push_protocol_line;
pub const readIdentifyWireAlloc = _shim_src.readIdentifyWireAlloc;
pub const signedEnvelopeVerifyMessage = _shim_src.signedEnvelopeVerifyMessage;
pub const signed_envelope_domain = _shim_src.signed_envelope_domain;
pub const verifySignedPeerRecord = _shim_src.verifySignedPeerRecord;
