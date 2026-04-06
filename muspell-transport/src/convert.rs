//! Boundary conversions between iroh and `muspell-proto` types.
//!
//! This module is the **only** place in `muspell-transport` that names
//! iroh key types directly. Everything above this layer uses
//! `muspell_proto::{NodeId, Did}` exclusively.
//!
//! ## Why a dedicated module?
//!
//! Both iroh's `PublicKey` and Muspell's `NodeId` are 32-byte Ed25519
//! public keys. The conversion is trivial but putting it in one place
//! means that if iroh ever changes its key representation, there is
//! exactly one file to update.

use iroh::PublicKey;
use muspell_proto::NodeId;

/// Convert an iroh `PublicKey` to a Muspell `NodeId`.
///
/// Both types are 32-byte Ed25519 public keys; this is a zero-copy
/// re-interpretation.
#[must_use]
pub fn public_key_to_node_id(key: &PublicKey) -> NodeId {
    // Dereference the & [u8; 32] to [u8; 32] to satisfy the bound
    NodeId::from_bytes(key.as_bytes().clone())
}

/// Convert a Muspell `NodeId` to an iroh `PublicKey`.
///
/// Returns `None` if the bytes are not a valid Ed25519 public key point.
/// In practice this should never happen for `NodeId`s that were produced
/// by `NodeKeypair::node_id()`.
#[must_use]
pub fn node_id_to_public_key(node_id: &NodeId) -> Option<PublicKey> {
    PublicKey::try_from(node_id.as_bytes().as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_identity::NodeKeypair;

    #[test]
    fn roundtrip_node_id_via_public_key() {
        let kp      = NodeKeypair::generate();
        let node_id = kp.node_id();
        let pk      = node_id_to_public_key(&node_id)
            .expect("valid NodeId should always convert");
        let back    = public_key_to_node_id(&pk);
        assert_eq!(node_id, back);
    }
}
