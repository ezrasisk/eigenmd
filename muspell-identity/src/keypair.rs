//! Ed25519 keypair wrappers for DID and Node identities.
//!
//! ## Security model
//!
//! - Secret key bytes are held in `ed25519_dalek::SigningKey`, which
//!   implements `Zeroize` and will clear memory on drop.
//! - Secret key bytes are never logged: `Debug` and `Display` impls
//!   show only the public key.
//! - `to_secret_bytes()` is intentionally named to make call sites
//!   visually obvious in code review — callers of this method should
//!   handle the returned bytes with care (zeroize after use).

use ed25519_dalek::{SigningKey, VerifyingKey};
use muspell_proto::{Did, NodeId};
use zeroize::Zeroize;
use std::fmt;

use crate::error::{IdentityError, IdentityResult};

// ── DidKeypair ────────────────────────────────────────────────────────────────

/// An Ed25519 signing keypair whose public key constitutes a [`Did`].
///
/// The `Did` is stable and long-lived. Treat the secret key as the
/// master credential — it signs capabilities, namespaces, and
/// identity bindings. Store it encrypted; never transmit it.
///
/// ## Zeroization
///
/// The inner `SigningKey` is zeroized on drop (via `ed25519-dalek`'s
/// `zeroize` feature). Cloning a `DidKeypair` creates a second key that
/// is independently zeroized.
pub struct DidKeypair {
    signing_key:   SigningKey,
    verifying_key: VerifyingKey,
    did:           Did,
}

impl DidKeypair {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Generate a new random `DidKeypair` using the OS CSPRNG.
    ///
    /// Available only with the `keygen` feature (default: enabled).
    #[cfg(feature = "keygen")]
    #[must_use]
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let signing_key   = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let did           = Did::from_bytes(verifying_key.to_bytes());
        Self { signing_key, verifying_key, did }
    }

    /// Reconstruct a `DidKeypair` from 32 bytes of secret key material.
    ///
    /// # Errors
    /// Returns `IdentityError::InvalidSigningKey` if the bytes do not
    /// represent a valid Ed25519 scalar.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> IdentityResult<Self> {
        let signing_key = SigningKey::from_bytes(bytes);
        // ed25519-dalek 2.x: from_bytes always succeeds for any 32 bytes
        // (it clamps the scalar internally). We accept this behavior.
        let verifying_key = signing_key.verifying_key();
        let did           = Did::from_bytes(verifying_key.to_bytes());
        Ok(Self { signing_key, verifying_key, did })
    }

    /// Reconstruct from a slice (must be exactly 32 bytes).
    ///
    /// Convenience wrapper around `from_secret_bytes` for callers that
    /// hold an unsized slice (e.g. from a config file or KMS response).
    ///
    /// # Errors
    /// Returns `IdentityError::KeypairWrongLength` if `slice.len() != 32`.
    pub fn from_secret_slice(slice: &[u8]) -> IdentityResult<Self> {
        let arr: [u8; 32] = slice
            .try_into()
            .map_err(|_| IdentityError::KeypairWrongLength { got: slice.len() })?;
        Self::from_secret_bytes(&arr)
    }

    // ── Public accessors ──────────────────────────────────────────────────────

    /// The `Did` derived from this keypair's public key.
    #[must_use]
    pub fn did(&self) -> Did {
        self.did
    }

    /// The raw 32-byte Ed25519 verifying (public) key.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    // ── Secret access — handle with care ─────────────────────────────────────

    /// Return a copy of the secret key bytes.
    ///
    /// **Security:** Zeroize the returned array after use.
    /// This method is named `to_secret_bytes` rather than just `to_bytes`
    /// so it stands out in code review.
    #[must_use]
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    // ── Signing ───────────────────────────────────────────────────────────────

    /// Sign arbitrary bytes, returning a raw 64-byte Ed25519 signature.
    ///
    /// The caller is responsible for constructing the canonical payload
    /// (see `muspell_identity::canonical`). Use the high-level signing
    /// functions in `muspell_identity::signing` for protocol types.
    #[must_use]
    pub(crate) fn sign_raw(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.signing_key.sign(message).to_bytes()
    }
}

impl fmt::Debug for DidKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print secret key bytes.
        write!(f, "DidKeypair({})", self.did)
    }
}

impl fmt::Display for DidKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.did)
    }
}

// Explicit: do not derive Clone — callers should be intentional about
// duplicating key material. If cloning is needed, use `from_secret_bytes`.

// ── NodeKeypair ───────────────────────────────────────────────────────────────

/// An Ed25519 signing keypair whose public key constitutes a [`NodeId`].
///
/// The `NodeId` is ephemeral — it may change each time the daemon restarts
/// or when the node rotates its network key. The stable identity is the
/// `Did`; the `NodeId` is the current network address.
///
/// Used to sign [`IdentityBinding`]s that prove a `Did` controls this node.
///
/// [`IdentityBinding`]: crate::binding::IdentityBinding
pub struct NodeKeypair {
    signing_key:   SigningKey,
    verifying_key: VerifyingKey,
    node_id:       NodeId,
}

impl NodeKeypair {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Generate a new random `NodeKeypair` using the OS CSPRNG.
    #[cfg(feature = "keygen")]
    #[must_use]
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let signing_key   = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let node_id       = NodeId::from_bytes(verifying_key.to_bytes());
        Self { signing_key, verifying_key, node_id }
    }

    /// Reconstruct a `NodeKeypair` from 32 bytes of secret key material.
    ///
    /// # Errors
    /// Returns `IdentityError::KeypairWrongLength` if `slice.len() != 32`.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> IdentityResult<Self> {
        let signing_key   = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        let node_id       = NodeId::from_bytes(verifying_key.to_bytes());
        Ok(Self { signing_key, verifying_key, node_id })
    }

    /// Reconstruct from a slice (must be exactly 32 bytes).
    pub fn from_secret_slice(slice: &[u8]) -> IdentityResult<Self> {
        let arr: [u8; 32] = slice
            .try_into()
            .map_err(|_| IdentityError::KeypairWrongLength { got: slice.len() })?;
        Self::from_secret_bytes(&arr)
    }

    // ── Public accessors ──────────────────────────────────────────────────────

    /// The `NodeId` derived from this keypair's public key.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The raw 32-byte Ed25519 verifying (public) key.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Return a copy of the secret key bytes. Zeroize after use.
    #[must_use]
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    // ── Signing ───────────────────────────────────────────────────────────────

    #[must_use]
    pub(crate) fn sign_raw(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.signing_key.sign(message).to_bytes()
    }
}

impl fmt::Debug for NodeKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeKeypair({})", self.node_id)
    }
}

impl fmt::Display for NodeKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.node_id)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Verify an Ed25519 signature given raw public key bytes, a message, and
/// raw signature bytes.
///
/// This is the single point in `muspell-identity` where cryptographic
/// verification occurs. All `verify_*` functions call this.
///
/// # Errors
/// - `InvalidPublicKey` if the public key bytes are not a valid Ed25519 point.
/// - `InvalidSignature` if the signature does not verify.
pub(crate) fn verify_ed25519(
    public_key_bytes: &[u8; 32],
    message:          &[u8],
    sig_bytes:        &[u8; 64],
) -> IdentityResult<()> {
    use ed25519_dalek::Verifier as _;

    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| IdentityError::InvalidPublicKey { reason: e.to_string() })?;

    let dalek_sig = ed25519_dalek::Signature::from_bytes(sig_bytes);

    verifying_key
        .verify(message, &dalek_sig)
        .map_err(|_| IdentityError::InvalidSignature)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DidKeypair ────────────────────────────────────────────────────────────

    #[cfg(feature = "keygen")]
    #[test]
    fn did_keypair_generate_produces_valid_did() {
        let kp = DidKeypair::generate();
        // The Did should be 32 non-zero bytes (astronomically unlikely to be all zero).
        let did = kp.did();
        assert_ne!(did.as_bytes(), &[0u8; 32]);
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn did_keypair_generate_two_differ() {
        let a = DidKeypair::generate();
        let b = DidKeypair::generate();
        assert_ne!(a.did(), b.did());
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn did_keypair_round_trip_secret() {
        let original = DidKeypair::generate();
        let secret   = original.to_secret_bytes();
        let restored = DidKeypair::from_secret_bytes(&secret).unwrap();
        assert_eq!(original.did(), restored.did());
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn did_keypair_public_bytes_matches_did() {
        let kp  = DidKeypair::generate();
        let did = Did::from_bytes(kp.public_bytes());
        assert_eq!(kp.did(), did);
    }

    #[test]
    fn did_keypair_from_secret_slice_wrong_length() {
        let err = DidKeypair::from_secret_slice(&[0u8; 31]).unwrap_err();
        assert!(matches!(err, IdentityError::KeypairWrongLength { got: 31 }));
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn did_keypair_debug_does_not_contain_secret() {
        let kp     = DidKeypair::generate();
        let debug  = format!("{kp:?}");
        let secret = hex::encode(kp.to_secret_bytes());
        // The debug string must not contain the hex secret key.
        assert!(!debug.contains(&secret), "Debug output leaked secret key");
    }

    // ── NodeKeypair ───────────────────────────────────────────────────────────

    #[cfg(feature = "keygen")]
    #[test]
    fn node_keypair_generate_produces_valid_node_id() {
        let kp = NodeKeypair::generate();
        assert_ne!(kp.node_id().as_bytes(), &[0u8; 32]);
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn node_keypair_round_trip_secret() {
        let original = NodeKeypair::generate();
        let secret   = original.to_secret_bytes();
        let restored = NodeKeypair::from_secret_bytes(&secret).unwrap();
        assert_eq!(original.node_id(), restored.node_id());
    }

    #[test]
    fn node_keypair_from_secret_slice_wrong_length() {
        let err = NodeKeypair::from_secret_slice(&[0u8; 33]).unwrap_err();
        assert!(matches!(err, IdentityError::KeypairWrongLength { got: 33 }));
    }

    // ── verify_ed25519 ────────────────────────────────────────────────────────

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_ed25519_valid_signature() {
        let kp      = DidKeypair::generate();
        let msg     = b"test message";
        let sig     = kp.sign_raw(msg);
        let pub_key = kp.public_bytes();
        assert!(verify_ed25519(&pub_key, msg, &sig).is_ok());
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_ed25519_wrong_message_fails() {
        let kp  = DidKeypair::generate();
        let sig = kp.sign_raw(b"original");
        assert!(verify_ed25519(&kp.public_bytes(), b"tampered", &sig).is_err());
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_ed25519_wrong_key_fails() {
        let kp_a = DidKeypair::generate();
        let kp_b = DidKeypair::generate();
        let sig  = kp_a.sign_raw(b"message");
        // Verify with b's key — should fail.
        assert!(verify_ed25519(&kp_b.public_bytes(), b"message", &sig).is_err());
    }

    #[test]
    fn verify_ed25519_all_zero_sig_fails() {
        let kp  = DidKeypair::from_secret_bytes(&[1u8; 32]).unwrap();
        let sig = [0u8; 64];
        // An all-zero signature is not a valid Ed25519 signature.
        let result = verify_ed25519(&kp.public_bytes(), b"msg", &sig);
        assert!(result.is_err());
    }
}
