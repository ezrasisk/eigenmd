//! Errors produced by `muspell-identity` operations.

use muspell_proto::{CapabilityError, Did, NamespaceId, Timestamp};
use std::fmt;

/// The unified error type for all `muspell-identity` operations.
///
/// ## Categories
///
/// | Variant prefix   | Source                                        |
/// |------------------|-----------------------------------------------|
/// | `Signing*`       | Failure during signature production           |
/// | `Verification*`  | Failure during signature or chain check       |
/// | `Keypair*`       | Invalid or corrupted key material             |
/// | `Capability*`    | Capability chain structural or crypto failure |
/// | `Namespace*`     | Namespace document structural or crypto failure|
/// | `Binding*`       | IdentityBinding structural or crypto failure  |
/// | `FrameAuth*`     | Per-frame auth structural or crypto failure   |
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    // ── Signing ──────────────────────────────────────────────────────────────

    /// The signer's DID does not match the field that requires it.
    ///
    /// For capabilities: the keypair's DID must equal the `issuer` field.
    /// For namespaces: the keypair's DID must equal the `owner` field.
    #[error("signer DID mismatch: expected {expected}, got {got}")]
    SignerMismatch { expected: Did, got: Did },

    // ── Verification — signatures ─────────────────────────────────────────────

    /// The Ed25519 signature is cryptographically invalid.
    ///
    /// This is produced when `ed25519-dalek` rejects the signature bytes,
    /// meaning the signature was not produced by the claimed public key over
    /// the claimed message.
    #[error("invalid Ed25519 signature")]
    InvalidSignature,

    /// A signature field is `None` on a value that requires one.
    #[error("missing signature on {on}")]
    MissingSignature { on: &'static str },

    /// The public key bytes cannot be interpreted as a valid Ed25519 point.
    ///
    /// Caused by a corrupted or maliciously crafted DID or NodeId.
    #[error("invalid Ed25519 public key bytes: {reason}")]
    InvalidPublicKey { reason: String },

    // ── Verification — time bounds ────────────────────────────────────────────

    /// A time-bounded value has expired.
    #[error("{kind} expired at {expiry}; current time is {now}")]
    Expired {
        kind:   &'static str,
        expiry: Timestamp,
        now:    Timestamp,
    },

    /// A time-bounded value is not yet valid.
    #[error("{kind} not valid until {not_before}; current time is {now}")]
    Premature {
        kind:       &'static str,
        not_before: Timestamp,
        now:        Timestamp,
    },

    // ── Verification — capabilities ───────────────────────────────────────────

    /// The capability chain failed structural validation (from `muspell-proto`).
    #[error("capability chain structurally invalid: {0}")]
    CapabilityStructure(#[from] CapabilityError),

    /// The issuer DID in a chain link does not match the subject of its parent.
    #[error(
        "custody break in capability chain at depth {depth}: \
         expected issuer {expected}, got {got}"
    )]
    CustodyBreak {
        depth:    usize,
        expected: Did,
        got:      Did,
    },

    /// A chain link's signature was produced by a key that does not match
    /// the link's `issuer` DID.
    #[error(
        "capability signature at depth {depth} was not produced by \
         the claimed issuer {issuer}"
    )]
    CapabilitySignerMismatch { depth: usize, issuer: Did },

    // ── Verification — namespaces ─────────────────────────────────────────────

    /// The namespace signature was not produced by the `owner` DID.
    #[error("namespace {id} signature not produced by owner {owner}")]
    NamespaceSignerMismatch { id: NamespaceId, owner: Did },

    #[error("Namespace error: {0}")]
    Namespace(#[from] muspell_proto::NamespaceError),
    // ── Verification — identity bindings ──────────────────────────────────────

    /// The binding signature is invalid or was not produced by the bound DID.
    #[error("identity binding signature is invalid")]
    BindingSignatureInvalid,

    // ── Verification — frame auth ─────────────────────────────────────────────

    /// The `FrameAuth::nonce` does not match the enclosing frame's `id`.
    #[error("frame auth nonce mismatch: auth is not bound to this frame")]
    FrameAuthNonceMismatch,

    /// The `FrameAuth::frame_signature` does not match the bearer's key.
    #[error("frame auth bearer signature is invalid")]
    FrameAuthSignatureInvalid,

    // ── Keypair ───────────────────────────────────────────────────────────────

    /// The provided secret key bytes are not a valid Ed25519 scalar.
    #[error("invalid signing key bytes: {reason}")]
    InvalidSigningKey { reason: String },

    /// The provided keypair bytes are the wrong length.
    #[error("keypair bytes must be 32 bytes; got {got}")]
    KeypairWrongLength { got: usize },
}

impl IdentityError {
    /// Convenience: construct `MissingSignature` for a named field.
    #[must_use]
    pub fn missing_signature(on: &'static str) -> Self {
        Self::MissingSignature { on }
    }

    /// Returns `true` if this error indicates a definite cryptographic
    /// failure (as opposed to a structural or time-bound failure).
    ///
    /// A crypto failure means the data was tampered with or forged.
    /// Other errors may simply indicate misconfiguration or clock skew.
    #[must_use]
    pub fn is_crypto_failure(&self) -> bool {
        matches!(
            self,
            Self::InvalidSignature
                | Self::CustodyBreak { .. }
                | Self::CapabilitySignerMismatch { .. }
                | Self::NamespaceSignerMismatch { .. }
                | Self::BindingSignatureInvalid
                | Self::FrameAuthSignatureInvalid
        )
    }
}

/// Short-hand `Result` alias for identity operations.
pub type IdentityResult<T> = Result<T, IdentityError>;

// ── Display for Timestamp (needed in error messages) ─────────────────────────

// Timestamp already implements Display in muspell-proto, so the error
// messages using {expiry}, {now}, etc. will render correctly.

/// Marker so that `IdentityError` is `Send + Sync`, required for
/// use with `tokio::spawn` and `anyhow`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_is_thread_safe() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IdentityError>();
    }
}
