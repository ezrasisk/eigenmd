//! Errors produced by `muspell-node` operations.

use muspell_proto::NodeId;
use muspell_rpc::RpcError;
use muspell_transport::TransportError;
use std::fmt;

/// The unified error type for all node-level operations.
///
/// ## Categories
///
/// | Variant           | Meaning                                             |
/// |-------------------|-----------------------------------------------------|
/// | `Transport`       | QUIC / handshake / codec failure                    |
/// | `Rpc`             | RPC call error (timeout, peer error, etc.)          |
/// | `NotConnected`    | Operation requires a connection that does not exist |
/// | `AlreadyConnected`| Connect attempted to a peer already connected       |
/// | `Shutdown`        | Node is shutting down; operation refused            |
/// | `Internal`        | Unexpected internal inconsistency (bug)             |
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// The underlying transport returned an error.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// An RPC call returned an error.
    #[error("rpc error: {0}")]
    Rpc(#[from] RpcError),

    /// An operation was attempted on a peer that is not connected.
    #[error("not connected to peer {node_id}")]
    NotConnected { node_id: NodeId },

    /// A connection attempt was made to a peer that is already connected.
    #[error("already connected to peer {node_id}")]
    AlreadyConnected { node_id: NodeId },

    /// The node is shutting down and cannot accept new operations.
    #[error("node is shutting down")]
    Shutdown,

    /// An internal inconsistency was detected.
    ///
    /// This indicates a bug in `muspell-node`. Please report it.
    #[error("internal node error: {reason}")]
    Internal { reason: String },
}

impl NodeError {
    /// Returns `true` if this error is likely transient and retrying
    /// after backoff may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(e) => e.is_transient(),
            Self::Rpc(e)       => e.is_retryable(),
            _                  => false,
        }
    }

    /// Convenience constructor for `Internal`.
    #[must_use]
    pub fn internal(reason: impl fmt::Display) -> Self {
        Self::Internal { reason: reason.to_string() }
    }
}

/// Short-hand `Result` alias for node operations.
pub type NodeResult<T> = Result<T, NodeError>;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::NodeId;

    fn nid() -> NodeId { NodeId::from_bytes([1u8; 32]) }

    #[test]
    fn not_connected_is_not_retryable() {
        let e = NodeError::NotConnected { node_id: nid() };
        assert!(!e.is_retryable());
    }

    #[test]
    fn shutdown_is_not_retryable() {
        assert!(!NodeError::Shutdown.is_retryable());
    }

    #[test]
    fn internal_convenience_constructor() {
        let e = NodeError::internal("something broke");
        assert!(e.to_string().contains("something broke"));
    }
}
