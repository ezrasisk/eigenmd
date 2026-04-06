//! Signing functions for Muspell protocol types.
//!
//! ## Signing contract
//!
//! Each `sign_*` function:
//! 1. Verifies the keypair's DID matches the field that requires it.
//! 2. Computes the canonical bytes for the payload.
//! 3. Signs the canonical bytes with the keypair.
//! 4. Writes `id` (where applicable) and `signature` into the payload.
//!
//! After signing, the value is ready to be transmitted and verified by peers.
//!
//! ## Canonical bytes
//!
//! The binary format signed is defined in [`crate::canonical`] and is
//! separate from the CBOR wire encoding. Two nodes with different wire
//! encoding libraries will agree on signatures as long as they implement
//! the canonical format correctly.

use muspell_proto::{
    Capability, CapabilityId, FrameId, Namespace, Signature, Timestamp,
};

use crate::binding::IdentityBinding;
use crate::canonical::{
    binding_signable_bytes, capability_signable_bytes, frame_auth_signable_bytes,
    namespace_signable_bytes,
};
use crate::error::{IdentityError, IdentityResult};
use crate::keypair::{DidKeypair, NodeKeypair};

// ── sign_capability ───────────────────────────────────────────────────────────

/// Sign a [`Capability`], filling in its `id` and `signature` fields.
///
/// The `keypair`'s DID must equal `cap.issuer`. Every link in the
/// delegation chain must be signed by its own issuer — this function
/// signs only the outermost link.
///
/// ## What is signed
///
/// The canonical bytes are defined in
/// [`canonical::capability_signable_bytes`]: all fields except `id`
/// and `signature`, with the proof referenced by hash (not embedded).
///
/// ## CapabilityId
///
/// The `CapabilityId` is the Blake3 hash of the canonical bytes.
/// Two logically identical capabilities always get the same ID.
///
/// # Errors
/// - [`IdentityError::SignerMismatch`] if `keypair.did() != cap.issuer`.
pub fn sign_capability(
    keypair: &DidKeypair,
    cap:     &mut Capability,
) -> IdentityResult<()> {
    if keypair.did() != cap.issuer {
        return Err(IdentityError::SignerMismatch {
            expected: cap.issuer,
            got:      keypair.did(),
        });
    }

    let canonical = capability_signable_bytes(cap);

    // CapabilityId is Blake3 of the canonical bytes.
    let id_hash = blake3::hash(&canonical);
    cap.id = Some(CapabilityId::from_digest(*id_hash.as_bytes()));

    // Sign the canonical bytes.
    let raw_sig = keypair.sign_raw(&canonical);
    cap.signature = Some(Signature::from_bytes(raw_sig));

    Ok(())
}

// ── sign_namespace ────────────────────────────────────────────────────────────

/// Sign a [`Namespace`] document, filling in its `signature` field.
///
/// The `keypair`'s DID must equal `ns.owner`. The namespace's `version`
/// and `updated_at` should be set before signing.
///
/// ## What is signed
///
/// All fields except `name` (petname, display only) and `signature`.
/// Record values are committed by hash. See
/// [`canonical::namespace_signable_bytes`].
///
/// # Errors
/// - [`IdentityError::SignerMismatch`] if `keypair.did() != ns.owner`.
pub fn sign_namespace(
    keypair: &DidKeypair,
    ns:      &mut Namespace,
) -> IdentityResult<()> {
    if keypair.did() != ns.owner {
        return Err(IdentityError::SignerMismatch {
            expected: ns.owner,
            got:      keypair.did(),
        });
    }

    let canonical = namespace_signable_bytes(ns);
    let raw_sig   = keypair.sign_raw(&canonical);
    ns.signature  = Some(Signature::from_bytes(raw_sig));

    Ok(())
}

// ── sign_frame_auth ───────────────────────────────────────────────────────────

/// Sign a `FrameAuth`, filling in its `frame_signature` field.
///
/// The `keypair`'s DID must equal `auth.bearer`. The `frame_id` MUST be the
/// `id` of the frame this auth will be attached to (anti-replay).
/// The `body_hash` is the Blake3 hash of the serialised frame body bytes —
/// the transport layer computes this before calling this function.
///
/// ## What is signed
///
/// ```text
/// DOMAIN_FRAME_AUTH ‖ frame_id(16 bytes LE) ‖ body_hash(32) ‖ bearer(32)
/// ```
///
/// # Errors
/// - [`IdentityError::SignerMismatch`] if `keypair.did() != auth.bearer`.
pub fn sign_frame_auth(
    keypair:   &DidKeypair,
    frame_id:  FrameId,
    body_hash: &[u8; 32],
    auth:      &mut muspell_proto::FrameAuth,
) -> IdentityResult<()> {
    if keypair.did() != auth.bearer {
        return Err(IdentityError::SignerMismatch {
            expected: auth.bearer,
            got:      keypair.did(),
        });
    }

    let canonical = frame_auth_signable_bytes(frame_id.as_u128(), body_hash, &auth.bearer);
    let raw_sig   = keypair.sign_raw(&canonical);
    auth.frame_signature = Some(Signature::from_bytes(raw_sig));

    Ok(())
}

// ── sign_binding ──────────────────────────────────────────────────────────────

/// Produce a signed [`IdentityBinding`] asserting that a DID controls a NodeId.
///
/// The binding is signed by the `did_keypair`. The `node_keypair` provides
/// the `NodeId`; its private key is not used in signing (the DID's private
/// key is the authoritative one — it claims control over the node, not
/// vice versa).
///
/// ## Typical use
///
/// ```rust,ignore
/// let binding = sign_binding(
///     &did_keypair,
///     &node_keypair,
///     Timestamp::now().unwrap(),
///     Some(Timestamp::from_secs(now.secs + 86_400)),  // valid 24 h
/// )?;
/// ```
///
/// # Errors
///
/// This function does not fail in normal operation. The `IdentityResult`
/// wrapper is present for forward-compatibility with future hardware-key
/// implementations that may return errors from the signing operation.
pub fn sign_binding(
    did_keypair:  &DidKeypair,
    node_keypair: &NodeKeypair,
    valid_from:   Timestamp,
    valid_until:  Option<Timestamp>,
) -> IdentityResult<IdentityBinding> {
    let did     = did_keypair.did();
    let node_id = node_keypair.node_id();

    let canonical = binding_signable_bytes(&did, &node_id, valid_from, valid_until);
    let raw_sig   = did_keypair.sign_raw(&canonical);

    let binding = IdentityBinding::draft(did, node_id, valid_from, valid_until)
        .with_signature(Signature::from_bytes(raw_sig));

    Ok(binding)
}

// ── compute_body_hash ─────────────────────────────────────────────────────────

/// Compute the Blake3 hash of serialised frame body bytes.
///
/// Transport layer calls this after CBOR-encoding the frame body, then
/// passes the result to [`sign_frame_auth`] and the peer's
/// [`crate::verify::verify_frame_auth`].
///
/// Using Blake3 here is consistent with all other hash operations in
/// the Muspell stack and is fast enough to run on every frame without
/// measurable overhead.
#[must_use]
pub fn compute_body_hash(body_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(body_bytes).as_bytes()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{
        Action, ActionSet, Capability, Did, FrameAuth, FrameId, NamespaceId,
        NodeId, ResourceId, Timestamp,
    };
    use crate::keypair::{DidKeypair, NodeKeypair};
    use crate::verify::{verify_capability_chain, verify_namespace, verify_frame_auth, verify_binding};

    fn t(s: i64) -> Timestamp { Timestamp::from_secs(s) }

    // ── sign_capability ───────────────────────────────────────────────────────

    #[cfg(feature = "keygen")]
    #[test]
    fn sign_capability_fills_id_and_signature() {
        let kp = DidKeypair::generate();
        let mut cap = Capability::root(
            kp.did(), Did::from_bytes([2u8; 32]),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        sign_capability(&kp, &mut cap).unwrap();
        assert!(cap.id.is_some());
        assert!(cap.signature.is_some());
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn sign_capability_id_is_deterministic() {
        let kp = DidKeypair::generate();
        let base_cap = || Capability::root(
            kp.did(), Did::from_bytes([2u8; 32]),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        let mut cap_a = base_cap();
        let mut cap_b = base_cap();
        sign_capability(&kp, &mut cap_a).unwrap();
        sign_capability(&kp, &mut cap_b).unwrap();
        // Same logical capability → same ID.
        assert_eq!(cap_a.id, cap_b.id);
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn sign_capability_signer_mismatch_fails() {
        let kp_a = DidKeypair::generate();
        let kp_b = DidKeypair::generate();
        let mut cap = Capability::root(
            kp_a.did(), Did::from_bytes([2u8; 32]),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        let err = sign_capability(&kp_b, &mut cap).unwrap_err();
        assert!(matches!(err, IdentityError::SignerMismatch { .. }));
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn sign_and_verify_root_capability() {
        let kp = DidKeypair::generate();
        let mut cap = Capability::root(
            kp.did(), Did::from_bytes([2u8; 32]),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        sign_capability(&kp, &mut cap).unwrap();
        verify_capability_chain(&cap, t(0)).unwrap();
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn sign_and_verify_delegated_capability() {
        let alice_kp = DidKeypair::generate();
        let bob_kp   = DidKeypair::generate();
        let carol    = Did::from_bytes([3u8; 32]);

        // Alice signs the root.
        let mut root = Capability::root(
            alice_kp.did(), bob_kp.did(),
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );
        sign_capability(&alice_kp, &mut root).unwrap();

        // Bob delegates to Carol.
        let mut delegated = Capability::delegate(
            root, bob_kp.did(), carol,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None, None,
        ).unwrap();
        sign_capability(&bob_kp, &mut delegated).unwrap();

        verify_capability_chain(&delegated, t(0)).unwrap();
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn tampered_capability_fails_verification() {
        let kp = DidKeypair::generate();
        let mut cap = Capability::root(
            kp.did(), Did::from_bytes([2u8; 32]),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        sign_capability(&kp, &mut cap).unwrap();

        // Tamper: change the subject after signing.
        cap.subject = Did::from_bytes([9u8; 32]);
        let err = verify_capability_chain(&cap, t(0)).unwrap_err();
        assert!(err.is_crypto_failure(), "expected crypto failure, got: {err}");
    }

    // ── sign_namespace ────────────────────────────────────────────────────────

    #[cfg(feature = "keygen")]
    #[test]
    fn sign_namespace_fills_signature() {
        let kp    = DidKeypair::generate();
        let ns_id = NamespaceId::derive(&kp.did(), "blog");
        let mut ns = Namespace::new(ns_id, kp.did(), t(1000));
        sign_namespace(&kp, &mut ns).unwrap();
        assert!(ns.signature.is_some());
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn sign_namespace_signer_mismatch_fails() {
        let kp_a  = DidKeypair::generate();
        let kp_b  = DidKeypair::generate();
        let ns_id = NamespaceId::derive(&kp_a.did(), "blog");
        let mut ns = Namespace::new(ns_id, kp_a.did(), t(1000));
        let err = sign_namespace(&kp_b, &mut ns).unwrap_err();
        assert!(matches!(err, IdentityError::SignerMismatch { .. }));
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn sign_and_verify_namespace() {
        let kp    = DidKeypair::generate();
        let ns_id = NamespaceId::derive(&kp.did(), "blog");
        let mut ns = Namespace::new(ns_id, kp.did(), t(1000));
        sign_namespace(&kp, &mut ns).unwrap();
        verify_namespace(&ns).unwrap();
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn tampered_namespace_fails_verification() {
        let kp    = DidKeypair::generate();
        let ns_id = NamespaceId::derive(&kp.did(), "blog");
        let mut ns = Namespace::new(ns_id, kp.did(), t(1000));
        sign_namespace(&kp, &mut ns).unwrap();

        // Tamper: bump version after signing.
        ns.version = 99;
        let err = verify_namespace(&ns).unwrap_err();
        assert!(err.is_crypto_failure());
    }

    // ── sign_binding ──────────────────────────────────────────────────────────

    #[cfg(feature = "keygen")]
    #[test]
    fn sign_and_verify_binding() {
        let did_kp  = DidKeypair::generate();
        let node_kp = NodeKeypair::generate();
        let binding = sign_binding(&did_kp, &node_kp, t(0), Some(t(3600))).unwrap();
        assert!(binding.is_signed());
        verify_binding(&binding, t(1000)).unwrap();
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn tampered_binding_fails_verification() {
        let did_kp  = DidKeypair::generate();
        let node_kp = NodeKeypair::generate();
        let mut binding = sign_binding(&did_kp, &node_kp, t(0), Some(t(3600))).unwrap();

        // Tamper: change the node_id after signing.
        binding.node_id = NodeId::from_bytes([0xffu8; 32]);
        let err = verify_binding(&binding, t(1000)).unwrap_err();
        assert!(err.is_crypto_failure());
    }

    // ── sign_frame_auth ───────────────────────────────────────────────────────

    #[cfg(feature = "keygen")]
    #[test]
    fn sign_and_verify_frame_auth() {
        let bearer_kp = DidKeypair::generate();
        let frame_id  = FrameId::from_u128(0xdeadbeef);
        let body_hash = compute_body_hash(b"frame body bytes");

        let mut cap = Capability::root(
            bearer_kp.did(), bearer_kp.did(),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        sign_capability(&bearer_kp, &mut cap).unwrap();

        let mut auth = FrameAuth {
            bearer:          bearer_kp.did(),
            capability:      cap,
            nonce:           frame_id,
            frame_signature: None,
        };
        sign_frame_auth(&bearer_kp, frame_id, &body_hash, &mut auth).unwrap();

        verify_frame_auth(&auth, &frame_id, &body_hash).unwrap();
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn frame_auth_wrong_frame_id_fails_verification() {
        let bearer_kp    = DidKeypair::generate();
        let real_frame   = FrameId::from_u128(1);
        let forged_frame = FrameId::from_u128(2);
        let body_hash    = compute_body_hash(b"body");

        let mut cap = Capability::root(
            bearer_kp.did(), bearer_kp.did(),
            ResourceId::Wildcard, ActionSet::admin(),
        );
        sign_capability(&bearer_kp, &mut cap).unwrap();

        let mut auth = FrameAuth {
            bearer:          bearer_kp.did(),
            capability:      cap,
            nonce:           real_frame,
            frame_signature: None,
        };
        sign_frame_auth(&bearer_kp, real_frame, &body_hash, &mut auth).unwrap();

        // Verify with wrong frame id → nonce mismatch.
        let err = verify_frame_auth(&auth, &forged_frame, &body_hash).unwrap_err();
        assert!(matches!(err, IdentityError::FrameAuthNonceMismatch));
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn compute_body_hash_is_deterministic() {
        let h1 = compute_body_hash(b"same data");
        let h2 = compute_body_hash(b"same data");
        assert_eq!(h1, h2);
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn compute_body_hash_differs_for_different_data() {
        let h1 = compute_body_hash(b"data a");
        let h2 = compute_body_hash(b"data b");
        assert_ne!(h1, h2);
    }
}
