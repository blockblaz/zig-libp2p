//! Typed error sets per protocol layer (Zeam / libp2p-glue parity, #45).
//!
//! Rust variants that carried `String` (`IoError`, `InvalidData`, `RawError`) are represented
//! as bare error codes here; embedders attach context in logs or their own wrappers.

/// Observable req/resp failures aligned with zeam `ReqRespError`, plus wire/codec cases.
pub const ReqRespError = error{
    IoError,
    InvalidData,
    IncompleteStream,
    StreamTimedOut,
    Disconnected,
    RawError,
    PayloadTooLarge,
    EmptyFrame,
    IncompleteHeader,
    LengthMismatch,
    BufferCapExceeded,
    VarintOverflow,
};

/// Gossipsub mesh/codec surface (runtime behaviours like `PublishQueueFull` are reserved for #39).
pub const GossipsubError = error{
    TopicNotSubscribed,
    PayloadTooLarge,
    PublishQueueFull,
    InvalidFrame,
};

/// Transport dial/listen/security negotiation (embedders map `std.Io.net` errors where needed).
pub const TransportError = error{
    DialFailed,
    Unreachable,
    SecurityUpgradeFailed,
    ProtocolNegotiationFailed,
};
