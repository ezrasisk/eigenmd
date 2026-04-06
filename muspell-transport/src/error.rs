//! Errors produced by `muspell-transport` operations.

use muspell_identity::IdentityError;
use muspell_proto::{NodeId, ProtocolVersion};
use std::fmt;

/// The unified error type for all `muspell-transport` operations.
///
/// ## Categories (fail-fast order)
///
/// | Category       | Meaning                                              |
/// |----------------|------------------------------------------------------|
/// | `Codec*`       | Frame encode/decode failure                          |
/// | `Handshake*`   | Hello/HelloAck protocol failure                      |
/// | `Identity*`    | Binding or capability verification failure           |
/// | `Io*`          | QUIC stream read/write failure                       |
/// | `Connection*`  | QUIC connection lifecycle failure                    |
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    // ── Codec ─────────────────────────────────────────────────────────────────

    /// CBOR serialisation of a frame failed.
    #[error("frame encode error: {reason}")]
    EncodeError { reason: String },

    /// CBOR deserialisation of received bytes failed.
    #[error("frame decode error: {reason}")]
    DecodeError { reason: String },

    /// The length-prefix indicates a payload larger than the configured
    /// maximum. Receiving this likely indicates a misbehaving or malicious peer.
    #[error("frame too large: {received} bytes exceeds maximum {maximum}")]
    FrameTooLarge { received: u32, maximum: u32 },

    /// The received bytes produced a valid CBOR value but not a valid `Frame`.
    #[error("frame deserialized but type was unexpected")]
    UnexpectedFrameType,

    // ── Handshake ─────────────────────────────────────────────────────────────

    /// The handshake timed out before `HelloAck` was received.
    #[error("handshake timed out after {secs}s")]
    HandshakeTimeout { secs: u64 },

    /// The peer's protocol version is incompatible with ours.
    #[error(
        "protocol version mismatch: ours is {ours}, peer's is {peer}"
    )]
    VersionMismatch { ours: ProtocolVersion, peer: ProtocolVersion },

    /// The first frame received was not a `Hello` or the `HelloAck`
    /// did not follow a `Hello` correctly.
    #[error("unexpected handshake frame: expected {expected}, got {got}")]
    UnexpectedHandshakeFrame {
        expected: &'static str,
        got:      &'static str,
    },

    /// The `HelloAck` came from a `NodeId` that differs from the one
    /// announced in the `Hello`. Indicates a MITM or protocol bug.
    #[error(
        "hello/ack node_id mismatch: hello said {hello_node_id}, \
         ack said {ack_node_id}"
    )]
    NodeIdMismatch {
        hello_node_id: NodeId,
        ack_node_id:   NodeId,
    },

    /// The peer sent a `Hello` or `HelloAck` with a `Did` but no
    /// `IdentityBinding`. Both must be present or both absent.
    #[error("peer sent a DID in the handshake but no identity binding")]
    MissingIdentityBinding,

    // ── Identity / crypto ─────────────────────────────────────────────────────

    /// Identity verification failed (binding, capability, or frame auth).
    #[error("identity verification failed: {0}")]
    Identity(#[from] IdentityError),

    // ── I/O ───────────────────────────────────────────────────────────────────

    /// An error reading from or writing to a QUIC stream.
    #[error("stream I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The stream was closed by the peer before the expected data arrived.
    #[error("stream closed prematurely")]
    StreamClosed,

    // ── Connection ────────────────────────────────────────────────────────────

    /// The underlying QUIC connection was lost.
    #[error("connection error: {reason}")]
    ConnectionError { reason: String },

    /// An operation was attempted on a connection that is not yet ready
    /// (handshake not complete).
    #[error("connection not ready: handshake has not completed")]
    NotReady,

    /// An operation was attempted on a connection that has already closed.
    #[error("connection already closed")]
    AlreadyClosed,
}

impl TransportError {
    /// Returns `true` if this error is a definite security failure —
    /// the peer may be actively misbehaving or performing a MITM attack.
    ///
    /// A security failure should trigger connection termination and
    /// optionally an event to the application layer for rate-limiting.
    #[must_use]
    pub fn is_security_failure(&self) -> bool {
        match self {
            Self::FrameTooLarge { .. }
            | Self::NodeIdMismatch { .. }
            | Self::MissingIdentityBinding
            | Self::UnexpectedHandshakeFrame { .. } => true,

            Self::Identity(e) => e.is_crypto_failure(),

            _ => false,
        }
    }

    /// Returns `true` if this error is likely transient and retrying
    /// after a backoff may succeed.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::HandshakeTimeout { .. } | Self::ConnectionError { .. }
        )
    }

    /// Convenience constructor for `ConnectionError`.
    #[must_use]
    pub fn connection(reason: impl fmt::Display) -> Self {
        Self::ConnectionError { reason: reason.to_string() }
    }
}

/// Short-hand `Result` alias for transport operations.
pub type TransportResult<T> = Result<T, TransportError>;
