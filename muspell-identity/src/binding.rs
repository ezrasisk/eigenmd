//! Identity bindings — signed assertions that a DID controls a NodeId.
//!
//! During the Muspell handshake, each peer proves that their long-lived
//! [`Did`] currently controls their ephemeral [`NodeId`] by presenting
//! an [`IdentityBinding`]. This prevents an attacker who intercepts a
//! `NodeId` from impersonating the owner's `Did`.
//!
//! ## Lifecycle
//!
//! ```text
//! Owner holds:  DidKeypair (stable)  +  NodeKeypair (ephemeral)
//!
//! 1. Owner signs: binding = sign_binding(&did_kp, &node_kp, now, Some(expiry))
//! 2. Owner sends: HelloFrame { did: Some(owner_did), ... }
//!                 + binding attached to the session
//! 3. Peer verifies: verify_binding(&binding, now)
//!    → proves the DID's private key signed this NodeId
//! ```

use muspell_proto::{Did, NodeId, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A signed, time-bounded assertion that a [`Did`] controls a [`NodeId`].
///
/// ## Signature scope
///
/// The `signature` is produced by the `did`'s private key over the
/// canonical bytes defined in [`crate::canonical::binding_signable_bytes`]:
///
/// ```text
/// DOMAIN_BINDING ‖ did(32) ‖ node_id(32) ‖ valid_from ‖ valid_until
/// ```
///
/// A verifier that holds the `did`'s public key (which equals `did.0`)
/// can verify this without any external state.
///
/// ## Recommended expiry
///
/// Set `valid_until` to at most 24 hours from `valid_from` for daemons
/// that run continuously. Shorter for high-security deployments.
/// The binding should be refreshed before expiry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct IdentityBinding {
    /// The stable DID claiming control.
    pub did: Did,
    /// The ephemeral node identity being claimed.
    pub node_id: NodeId,
    /// The earliest time this binding is valid (inclusive).
    pub valid_from: Timestamp,
    /// The expiry time of this binding (exclusive).
    /// `None` means the binding never expires — strongly discouraged.
    pub valid_until: Option<Timestamp>,
    /// Ed25519 signature by `did` over the canonical binding bytes.
    /// `None` for a draft binding; MUST be `Some` before use.
    pub signature: Option<Signature>,
}

impl IdentityBinding {
    /// Construct an unsigned draft binding.
    ///
    /// Call `muspell_identity::signing::sign_binding` to produce the
    /// signed version ready for transmission.
    #[must_use]
    pub fn draft(
        did:         Did,
        node_id:     NodeId,
        valid_from:  Timestamp,
        valid_until: Option<Timestamp>,
    ) -> Self {
        Self {
            did,
            node_id,
            valid_from,
            valid_until,
            signature: None,
        }
    }

    /// Returns `true` if this binding has been signed.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Returns `true` if this binding is temporally active at `now`.
    ///
    /// A binding with `valid_until: None` is always active (after `valid_from`).
    #[must_use]
    pub fn is_active(&self, now: Timestamp) -> bool {
        if now < self.valid_from {
            return false; // premature
        }
        match self.valid_until {
            None         => true,
            Some(expiry) => now < expiry,
        }
    }

    /// Returns `true` if this binding has expired at `now`.
    #[must_use]
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.valid_until.map_or(false, |exp| now >= exp)
    }

    /// The remaining validity duration in seconds, if a `valid_until` is set.
    ///
    /// Returns `None` if no expiry is set or if the binding has already expired.
    #[must_use]
    pub fn remaining_secs(&self, now: Timestamp) -> Option<i64> {
        let exp = self.valid_until?;
        let remaining = exp.secs - now.secs;
        if remaining > 0 { Some(remaining) } else { None }
    }

    /// Attach a computed signature (used by the signing module).
    #[must_use]
    pub(crate) fn with_signature(mut self, sig: Signature) -> Self {
        self.signature = Some(sig);
        self
    }
}

impl fmt::Display for IdentityBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IdentityBinding({} → {} valid_from={} until={})",
            self.did,
            self.node_id,
            self.valid_from,
            self.valid_until
                .map(|t| t.to_string())
                .unwrap_or_else(|| "∞".into()),
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{Did, NodeId, Timestamp};

    fn did(b: u8) -> Did      { Did::from_bytes([b; 32]) }
    fn nid(b: u8) -> NodeId   { NodeId::from_bytes([b; 32]) }
    fn t(s: i64) -> Timestamp { Timestamp::from_secs(s) }

    #[test]
    fn binding_draft_is_unsigned() {
        let b = IdentityBinding::draft(did(1), nid(2), t(1000), Some(t(2000)));
        assert!(!b.is_signed());
    }

    #[test]
    fn binding_is_active_within_window() {
        let b = IdentityBinding::draft(did(1), nid(2), t(1000), Some(t(2000)));
        assert!(b.is_active(t(1000))); // at valid_from: active
        assert!(b.is_active(t(1500))); // midpoint: active
        assert!(!b.is_active(t(2000))); // at expiry: NOT active (exclusive)
        assert!(!b.is_active(t(2001))); // past expiry: not active
    }

    #[test]
    fn binding_is_premature_before_valid_from() {
        let b = IdentityBinding::draft(did(1), nid(2), t(1000), Some(t(2000)));
        assert!(!b.is_active(t(999)));
    }

    #[test]
    fn binding_no_expiry_is_always_active_after_valid_from() {
        let b = IdentityBinding::draft(did(1), nid(2), t(0), None);
        assert!(b.is_active(t(0)));
        assert!(b.is_active(t(999_999_999)));
        assert!(!b.is_expired(t(999_999_999)));
    }

    #[test]
    fn binding_remaining_secs() {
        let b = IdentityBinding::draft(did(1), nid(2), t(0), Some(t(1000)));
        assert_eq!(b.remaining_secs(t(400)), Some(600));
        assert_eq!(b.remaining_secs(t(1000)), None); // expired
        assert_eq!(b.remaining_secs(t(1001)), None); // expired
    }

    #[test]
    fn binding_remaining_secs_no_expiry() {
        let b = IdentityBinding::draft(did(1), nid(2), t(0), None);
        assert_eq!(b.remaining_secs(t(9999)), None); // no expiry → None
    }

    #[test]
    fn binding_display_shows_key_fields() {
        let b = IdentityBinding::draft(did(1), nid(2), t(1000), Some(t(2000)));
        let s = b.to_string();
        assert!(s.contains("IdentityBinding"));
        assert!(s.contains("valid_from"));
    }
}
