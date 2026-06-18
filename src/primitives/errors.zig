//! Typed error sets per protocol layer (Zeam / libp2p-glue parity, #45).
//!
//! Rust variants that carried `String` (`IoError`, `InvalidData`, `RawError`) are represented
//! as bare error codes here. Optional per-thread context: [`setLastErrorMessage`], [`lastErrorMessage`].

const std = @import("std");

threadlocal var last_error_message_buf: [512]u8 = undefined;
threadlocal var last_error_message_len: usize = 0;

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

/// Gossipsub mesh/codec surface (#39); `PublishQueueFull` is returned when the runtime outbox exceeds config.
pub const GossipsubError = error{
    TopicNotSubscribed,
    TopicUnsubscribeBackoff,
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

/// Stores a short UTF-8 diagnostic for the **current thread** (truncated to 512 bytes). Pairs with
/// layered error codes (#45 option 2). Cleared implicitly on each write, not on error return.
pub fn setLastErrorMessage(msg: []const u8) void {
    last_error_message_len = @min(msg.len, last_error_message_buf.len);
    if (last_error_message_len == 0) return;
    @memcpy(last_error_message_buf[0..last_error_message_len], msg[0..last_error_message_len]);
}

/// Slice valid until the next [`setLastErrorMessage`] on this thread. Empty if none was set.
pub fn lastErrorMessage() []const u8 {
    return last_error_message_buf[0..last_error_message_len];
}

pub fn clearLastErrorMessage() void {
    last_error_message_len = 0;
}

test "last error message round trip" {
    clearLastErrorMessage();
    try std.testing.expectEqual(@as(usize, 0), lastErrorMessage().len);
    setLastErrorMessage("hello");
    try std.testing.expectEqualStrings("hello", lastErrorMessage());
    clearLastErrorMessage();
    try std.testing.expectEqual(@as(usize, 0), lastErrorMessage().len);
}
