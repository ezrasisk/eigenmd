//! Errors produced by `muspell-pubsub` operations.

use crate::topic::TopicId;
use muspell_transport::TransportError;
use std::fmt;

/// The unified error type for all pub/sub operations.
///
/// ## Categories
///
/// | Variant        | Cause                                              |
/// |----------------|----------------------------------------------------|
/// | `Encode`       | CBOR serialisation failure                         |
/// | `Decode`       | CBOR deserialisation failure (malformed peer data) |
/// | `ChannelClosed`| The outgoing transport channel has closed          |
/// | `NoSubscribers`| A publish found no local subscribers               |
/// | `TopicClosed`  | The broadcast channel for a topic has been dropped |
/// | `Transport`    | Underlying transport layer error                   |
#[derive(Debug, thiserror::Error)]
pub enum PubSubError {
    /// CBOR serialisation failed when encoding a pub/sub frame.
    #[error("pubsub encode error: {0}")]
    Encode(String),

    /// CBOR deserialisation failed on data received from the network.
    ///
    /// This indicates either a malformed peer or an incompatible protocol
    /// version. The frame should be discarded; the connection can continue.
    #[error("pubsub decode error: {0}")]
    Decode(String),

    /// The outgoing `mpsc` channel to the transport layer is closed.
    ///
    /// The transport task has exited. The `Publisher` and any outgoing
    /// subscribe/unsubscribe requests are no longer functional.
    /// Reconnect at the node layer.
    #[error("pubsub outgoing channel closed — transport has shut down")]
    ChannelClosed,

    /// A publish succeeded locally but there are no local subscribers
    /// for this topic.
    ///
    /// This is informational, not fatal. The message was still forwarded
    /// to the transport for remote subscribers.
    #[error("no local subscribers for topic {topic_id}")]
    NoSubscribers { topic_id: TopicId },

    /// The broadcast channel for a topic has been closed (all receivers
    /// dropped). The topic is no longer active in the local manager.
    #[error("topic {topic_id} channel closed — all subscribers dropped")]
    TopicClosed { topic_id: TopicId },

    /// The underlying transport layer returned an error.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}

impl PubSubError {
    /// Returns `true` if this error is transient and a retry may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport(e) if e.is_transient())
    }

    /// Returns `true` if this error means the pub/sub layer is
    /// permanently broken for this connection (reconnect required).
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::ChannelClosed)
    }
}

/// Short-hand `Result` alias for pub/sub operations.
pub type PubSubResult<T> = Result<T, PubSubError>;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn topic() -> TopicId { TopicId::from_name("test") }

    #[test]
    fn channel_closed_is_fatal() {
        assert!(PubSubError::ChannelClosed.is_fatal());
        assert!(!PubSubError::ChannelClosed.is_retryable());
    }

    #[test]
    fn no_subscribers_is_not_fatal() {
        let e = PubSubError::NoSubscribers { topic_id: topic() };
        assert!(!e.is_fatal());
        assert!(!e.is_retryable());
    }

    #[test]
    fn topic_closed_is_not_fatal() {
        let e = PubSubError::TopicClosed { topic_id: topic() };
        assert!(!e.is_fatal());
        assert!(!e.is_retryable());
    }

    #[test]
    fn error_messages_contain_context() {
        let e = PubSubError::NoSubscribers { topic_id: topic() };
        let s = e.to_string();
        assert!(s.contains("no local subscribers"));
    }
}
