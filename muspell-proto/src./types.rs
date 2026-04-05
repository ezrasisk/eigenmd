//! Primitive atoms of the Muspell protocol.
//!
//! Every type in this file is a leaf — it depends on nothing else in
//! `muspell-proto`. All higher-level types (`Capability`, `Frame`, …)
//! are built from these atoms.
//!
//! ## Naming discipline
//!
//! | Type            | "Is a …"                                   | Lifecycle     |
//! |-----------------|---------------------------------------------|---------------|
//! | `Did`           | Stable cryptographic identity (public key)  | Long-term     |
//! | `NodeId`        | Ephemeral network address (public key)      | Per-session   |
//! | `NamespaceId`   | Content-addressed namespace root            | Long-term     |
//! | `ContentId`     | Hash of an immutable datum                  | Eternal       |
//! | `Signature`     | 64-byte Ed25519 signature                   | Per-signing   |
//! | `Timestamp`     | Wall-clock instant (secs + nanos)           | Per-event     |
//! | `FrameId`       | Per-connection message correlator (u128)    | Per-frame     |
//! | `ProtocolVersion` | Major.minor version of this wire format  | Per-build     |
//! | `MimeType`      | MIME content type string                    | Per-datum     |
//! | `HumanName`     | Petname (not globally unique)               | Local/display |
//! | `Bytes`         | Opaque byte payload                         | Per-datum     |

use serde_big_array::BigArray;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::fmt;

// ── Did ──────────────────────────────────────────────────────────────────────

/// A Decentralised Identifier — the stable, long-term cryptographic identity
/// of a participant on the Muspell network.
///
/// **Structure:** 32-byte compressed public key of an Ed25519 keypair.
/// **Text form:** `did:muspell:<base58btc-public-key>`
///
/// A DID intentionally outlives any single device, node, or session.
/// Many `NodeId`s may be bound to one DID over time, supporting key
/// rotation and multi-device presence without identity loss.
///
/// Muspell DIDs are compatible with the [W3C DID Core](https://www.w3.org/TR/did-core/)
/// specification; the method name is `muspell`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Did(pub [u8; 32]);

impl Did {
    /// Construct from a raw 32-byte Ed25519 verifying key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "did:muspell:{}", bs58::encode(&self.0).into_string())
    }
}

impl fmt::Debug for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Full key in debug output is intentional — aids diagnostics.
        write!(f, "Did(did:muspell:{})", bs58::encode(&self.0).into_string())
    }
}

// ── NodeId ───────────────────────────────────────────────────────────────────

/// The ephemeral, network-addressable identity of a running daemon instance.
///
/// **Structure:** 32-byte public key underlying an Iroh `EndpointId`.
/// **Text form:** `node:<base58btc-public-key>`
///
/// Unlike a `Did`, a `NodeId` is tied to a specific process and keypair.
/// The same person may run many nodes (different machines, VMs, containers)
/// each with its own `NodeId`, all bound to the same `Did`.
///
/// ## Iroh isolation
///
/// `muspell-proto` holds no iroh dependency. The `muspell-transport` crate
/// is responsible for the `NodeId ↔ iroh::EndpointId` conversion at its
/// boundary, keeping this crate embeddable in any environment.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Construct from a raw 32-byte public key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node:{}", bs58::encode(&self.0).into_string())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", bs58::encode(&self.0).into_string())
    }
}

// ── HashAlg ──────────────────────────────────────────────────────────────────

/// The hash algorithm used to produce a [`ContentId`].
///
/// `#[non_exhaustive]` ensures that nodes receiving an unknown variant
/// treat the `ContentId` as opaque rather than panicking. New algorithms
/// can be added in a minor version bump.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum HashAlg {
    /// Blake3 — primary algorithm. Fast, parallel, streaming, tree-structured.
    /// Preferred for all new content on the Muspell network.
    Blake3,
    /// SHA-256 — interop algorithm. Used when content must be addressable by
    /// the IPFS, Bitcoin, or TLS certificate ecosystems simultaneously.
    Sha2_256,
}

// ── ContentId ────────────────────────────────────────────────────────────────

/// A content-addressed identifier: the address *is* the hash of the data.
///
/// Two nodes holding the same `ContentId` provably hold identical data,
/// without any coordination or trusted third party. This is the replacement
/// for URLs as locators — location-independent, forgery-proof.
///
/// ## Usage
///
/// ```rust
/// use muspell_proto::ContentId;
///
/// let data = b"hello muspell";
/// let cid  = ContentId::blake3(data);
///
/// // The text form is human-readable and copy-pasteable:
/// // cid:b3:<base58-digest>
/// println!("{cid}");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentId {
    /// Algorithm used to produce this digest.
    pub alg: HashAlg,
    /// 32-byte digest of the canonical encoding of the content.
    pub digest: [u8; 32],
}

impl ContentId {
    /// Hash arbitrary bytes with Blake3 (preferred).
    #[must_use]
    pub fn blake3(data: &[u8]) -> Self {
        let digest = blake3::hash(data);
        Self {
            alg: HashAlg::Blake3,
            digest: *digest.as_bytes(),
        }
    }

    /// Hash arbitrary bytes with SHA-256 (ecosystem interop).
    #[must_use]
    pub fn sha2_256(data: &[u8]) -> Self {
        let result = sha2::Sha256::digest(data);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Self {
            alg: HashAlg::Sha2_256,
            digest,
        }
    }

    /// Verify that `data` produces this `ContentId`.
    /// Returns `true` only if both the algorithm and digest match.
    #[must_use]
    pub fn verify(&self, data: &[u8]) -> bool {
        match self.alg {
            HashAlg::Blake3 => {
                let expected = blake3::hash(data);
                self.digest == *expected.as_bytes()
            }
            HashAlg::Sha2_256 => {
                let result = sha2::Sha256::digest(data);
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&result);
                self.digest == digest
            }
            // Future algorithms: treat as unverifiable rather than panic.
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Return the raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match self.alg {
            HashAlg::Blake3   => "b3",
            HashAlg::Sha2_256 => "s2",
            #[allow(unreachable_patterns)]
            _                 => "??",
        };
        write!(f, "cid:{}:{}", prefix, bs58::encode(&self.digest).into_string())
    }
}

impl fmt::Debug for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentId({})", self)
    }
}

// ── Timestamp ────────────────────────────────────────────────────────────────

/// A point in time: seconds + nanoseconds since the Unix epoch (UTC).
///
/// ## Design rationale
///
/// - **64-bit seconds** covers ~584 billion years. No Y2K-style cliffs.
/// - **Nanosecond precision** enables future Hybrid Logical Clock (HLC)
///   use, which is required for causal consistency in distributed systems.
/// - **Not coupled to `std::time`** — callers convert at their boundary.
///   This keeps the type usable in `no_std` / embedded nodes.
/// - **Monotonicity is not guaranteed** — wall clock may jump. Upper layers
///   (consensus, ordering) must not assume monotonicity from `Timestamp` alone.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Timestamp {
    /// Seconds since Unix epoch (UTC). Negative values are representable
    /// but should not appear in practice.
    pub secs: i64,
    /// Sub-second nanoseconds. MUST be in `[0, 999_999_999]`.
    pub nanos: u32,
}

impl Timestamp {
    /// The epoch itself — useful as a sentinel / default.
    pub const ZERO: Self = Self { secs: 0, nanos: 0 };

    /// The theoretical maximum representable instant.
    pub const MAX: Self = Self {
        secs:  i64::MAX,
        nanos: 999_999_999,
    };

    /// Construct from components.
    ///
    /// # Panics (debug builds only)
    /// Panics if `nanos >= 1_000_000_000`.
    #[must_use]
    pub fn new(secs: i64, nanos: u32) -> Self {
        debug_assert!(nanos < 1_000_000_000, "nanos must be < 1_000_000_000");
        Self { secs, nanos }
    }

    /// Construct from whole seconds (nanos = 0).
    #[must_use]
    pub fn from_secs(secs: i64) -> Self {
        Self { secs, nanos: 0 }
    }

    /// Return the total number of nanoseconds since the epoch as `u128`.
    /// Saturates on overflow (not expected in practice).
    #[must_use]
    pub fn as_nanos(&self) -> u128 {
        (self.secs as u128)
            .saturating_mul(1_000_000_000)
            .saturating_add(self.nanos as u128)
    }

    /// Current wall-clock time. Returns `None` if the system clock is
    /// before the Unix epoch (unusual but possible on misconfigured systems).
    ///
    /// Available only with the `clock` feature (default: enabled).
    /// Disable for deterministic test environments or embedded targets.
    #[cfg(feature = "clock")]
    #[must_use]
    pub fn now() -> Option<Self> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let d = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        Some(Self {
            secs:  d.as_secs() as i64,
            nanos: d.subsec_nanos(),
        })
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}", self.secs, self.nanos)
    }
}

// ── Signature ────────────────────────────────────────────────────────────────

/// A 64-byte Ed25519 signature.
///
/// Kept as raw bytes so `muspell-proto` carries no dependency on any
/// particular crypto crate. The `muspell-identity` crate (future) will
/// hold the signing and verification logic and convert to/from this type.
///
/// ## Debug output
///
/// Only the first 4 bytes are shown in `Debug` format to avoid accidentally
/// logging sensitive material in full. Use `Display` for the full base58
/// representation when intentional (e.g. in audit logs).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signature(
  #[serde(with = "BigArray")]
    pub [u8; 64]
);

impl Signature {
    /// Construct from a raw 64-byte Ed25519 signature.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Return the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally truncated — full signatures should not appear in
        // trace logs by default.
        write!(f, "Signature({}…)", hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

// ── FrameId ──────────────────────────────────────────────────────────────────

/// A unique identifier for a single `Frame` within a connection.
///
/// Used for request/response correlation and distributed tracing (causation
/// chains). 128 bits of randomness makes accidental collision negligible
/// even at sustained millions-per-second message rates.
///
/// The sender generates the ID; the responder echoes it back in the
/// `causation` field of the response frame.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FrameId(pub u128);

impl FrameId {
    /// Generate a cryptographically random `FrameId`.
    ///
    /// Available only with the `rand` feature (default: enabled).
    #[cfg(feature = "rand")]
    #[must_use]
    pub fn random() -> Self {
        use rand::RngCore as _;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(u128::from_le_bytes(bytes))
    }

    /// Construct from a raw `u128` — useful in tests or when the ID is
    /// derived externally (e.g. from a transport-layer sequence number).
    #[must_use]
    pub fn from_u128(v: u128) -> Self {
        Self(v)
    }

    /// Return the inner `u128`.
    #[must_use]
    pub fn as_u128(&self) -> u128 {
        self.0
    }
}

impl fmt::Debug for FrameId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FrameId({:032x})", self.0)
    }
}

impl fmt::Display for FrameId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

// ── ProtocolVersion ──────────────────────────────────────────────────────────

/// The Muspell wire-protocol version.
///
/// ## Compatibility rules (MUST be enforced by all nodes)
///
/// | Situation              | Behaviour                                      |
/// |------------------------|------------------------------------------------|
/// | `major` differs        | Reject the connection immediately              |
/// | `minor` of peer > ours | Accept; treat unknown frame variants as `Extension` |
/// | `minor` of peer < ours | Accept; do not send frames the peer can't parse |
///
/// Starting at `0.1` signals that the protocol is pre-stable. The first
/// production release will be `1.0`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct ProtocolVersion {
    /// Breaking changes increment this. Nodes with different `major` MUST
    /// refuse to communicate.
    pub major: u8,
    /// Additive changes (new frame variants, new optional fields) increment
    /// this. Nodes MUST handle unknown minor-version content gracefully.
    pub minor: u8,
}

impl ProtocolVersion {
    /// The version implemented by this build.
    pub const CURRENT: Self = Self { major: 0, minor: 1 };

    /// Returns `true` if `self` and `other` are wire-compatible
    /// (same `major` version).
    #[must_use]
    pub fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ── NamespaceId ──────────────────────────────────────────────────────────────

/// A unique identifier for a [`Namespace`] — the Muspell replacement for
/// domain names.
///
/// Derived from the owner's `Did` and a namespace-specific seed, so
/// ownership is cryptographically verifiable by any node without
/// consulting a central registry.
///
/// Text form: `ns:<base58btc-bytes>`
///
/// [`Namespace`]: crate::namespace::Namespace
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NamespaceId(pub [u8; 32]);

impl NamespaceId {
    /// Derive a `NamespaceId` deterministically from an owner `Did` and
    /// an application-specific label. Same inputs → same ID, always.
    #[must_use]
    pub fn derive(owner: &Did, label: &str) -> Self {
        // Blake3 keyed hash: the key is the owner's DID bytes; the input
        // is the label. This construction binds ownership into the ID.
        let key = owner.0;
        let hash = blake3::keyed_hash(&key, label.as_bytes());
        Self(*hash.as_bytes())
    }

    /// Construct from raw bytes (e.g. deserialised from the network).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ns:{}", bs58::encode(&self.0).into_string())
    }
}

impl fmt::Debug for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NamespaceId({})", self)
    }
}

// ── MimeType ─────────────────────────────────────────────────────────────────

/// A MIME content-type string (e.g. `"application/cbor"`, `"image/webp"`).
///
/// Kept as a validated newtype so future versions can enforce IANA
/// registration or Muspell-specific extensions without breaking callers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MimeType(pub String);

impl MimeType {
    /// `application/octet-stream` — generic binary, no semantic meaning.
    pub const OCTET_STREAM: &'static str = "application/octet-stream";
    /// `application/json`
    pub const JSON: &'static str = "application/json";
    /// `application/cbor` — preferred on-wire encoding for Muspell data.
    pub const CBOR: &'static str = "application/cbor";
    /// `application/dag-cbor` — IPLD DAG-CBOR; deterministic, content-addressable.
    pub const DAG_CBOR: &'static str = "application/dag-cbor";

    /// Construct from any string-like value.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Return the MIME type as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MimeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MimeType({:?})", self.0)
    }
}

impl fmt::Display for MimeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for MimeType {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<String> for MimeType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// ── HumanName ────────────────────────────────────────────────────────────────

/// A human-readable petname for a namespace, identity, or node.
///
/// **Not globally unique** — meaningful only within a local trust context
/// (a contact list, a cluster config, a UI display). Two nodes may assign
/// the same `HumanName` to completely different `Did`s.
///
/// The global uniqueness problem is solved by `NamespaceId` + cryptographic
/// ownership. `HumanName` is purely for human cognition.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct HumanName(pub String);

impl HumanName {
    /// Construct from any string-like value.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Return the name as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HumanName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for HumanName {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

// ── Bytes ────────────────────────────────────────────────────────────────────

/// Opaque byte payload for use in frames and datums.
///
/// A newtype over `Vec<u8>` that makes intent explicit in function
/// signatures and prevents accidental mixing of different byte buffers.
/// The inner `Vec<u8>` is always accessible via `.0` or `AsRef<[u8]>`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    /// Construct from any byte-slice-like value.
    #[must_use]
    pub fn from_slice(s: impl AsRef<[u8]>) -> Self {
        Self(s.as_ref().to_vec())
    }

    /// Return the length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for Bytes {
    fn from(s: &[u8]) -> Self {
        Self(s.to_vec())
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({} bytes)", self.0.len())
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0.len())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Did ──────────────────────────────────────────────────────────────────

    #[test]
    fn did_roundtrip_bytes() {
        let key = [42u8; 32];
        let did = Did::from_bytes(key);
        assert_eq!(did.as_bytes(), &key);
    }

    #[test]
    fn did_display_contains_prefix() {
        let did = Did::from_bytes([1u8; 32]);
        assert!(did.to_string().starts_with("did:muspell:"));
    }

    #[test]
    fn did_two_different_keys_differ() {
        let a = Did::from_bytes([0u8; 32]);
        let b = Did::from_bytes([1u8; 32]);
        assert_ne!(a, b);
        assert_ne!(a.to_string(), b.to_string());
    }

    // ── NodeId ───────────────────────────────────────────────────────────────

    #[test]
    fn node_id_display_contains_prefix() {
        let nid = NodeId::from_bytes([2u8; 32]);
        assert!(nid.to_string().starts_with("node:"));
    }

    // ── ContentId ────────────────────────────────────────────────────────────

    #[test]
    fn content_id_blake3_verify_pass() {
        let data = b"hello muspell";
        let cid = ContentId::blake3(data);
        assert!(cid.verify(data));
    }

    #[test]
    fn content_id_blake3_verify_fail_on_tampered_data() {
        let cid = ContentId::blake3(b"original");
        assert!(!cid.verify(b"tampered"));
    }

    #[test]
    fn content_id_sha256_verify_pass() {
        let data = b"interop content";
        let cid = ContentId::sha2_256(data);
        assert!(cid.verify(data));
    }

    #[test]
    fn content_id_deterministic() {
        // Same data → same CID, always.
        let a = ContentId::blake3(b"deterministic");
        let b = ContentId::blake3(b"deterministic");
        assert_eq!(a, b);
    }

    #[test]
    fn content_id_different_data_differs() {
        let a = ContentId::blake3(b"foo");
        let b = ContentId::blake3(b"bar");
        assert_ne!(a, b);
    }

    #[test]
    fn content_id_display_contains_alg_prefix() {
        let cid = ContentId::blake3(b"test");
        assert!(cid.to_string().starts_with("cid:b3:"));

        let cid2 = ContentId::sha2_256(b"test");
        assert!(cid2.to_string().starts_with("cid:s2:"));
    }

    // ── Timestamp ────────────────────────────────────────────────────────────

    #[test]
    fn timestamp_ordering() {
        let earlier = Timestamp::new(1_000, 0);
        let later   = Timestamp::new(1_001, 0);
        assert!(earlier < later);
    }

    #[test]
    fn timestamp_nanos_ordering() {
        let a = Timestamp::new(1_000, 0);
        let b = Timestamp::new(1_000, 1);
        assert!(a < b);
    }

    #[test]
    fn timestamp_as_nanos_epoch() {
        assert_eq!(Timestamp::ZERO.as_nanos(), 0);
    }

    #[test]
    fn timestamp_as_nanos_one_second() {
        let t = Timestamp::from_secs(1);
        assert_eq!(t.as_nanos(), 1_000_000_000);
    }

    #[cfg(feature = "clock")]
    #[test]
    fn timestamp_now_is_some_and_nonzero() {
        let t = Timestamp::now().expect("system clock should be after epoch");
        assert!(t.secs > 0, "current time should be after Unix epoch");
    }

    // ── ProtocolVersion ──────────────────────────────────────────────────────

    #[test]
    fn protocol_version_compatible_same_major() {
        let a = ProtocolVersion { major: 1, minor: 0 };
        let b = ProtocolVersion { major: 1, minor: 9 };
        assert!(a.is_compatible_with(b));
    }

    #[test]
    fn protocol_version_incompatible_different_major() {
        let a = ProtocolVersion { major: 1, minor: 0 };
        let b = ProtocolVersion { major: 2, minor: 0 };
        assert!(!a.is_compatible_with(b));
    }

    #[test]
    fn protocol_version_display() {
        let v = ProtocolVersion { major: 0, minor: 1 };
        assert_eq!(v.to_string(), "0.1");
    }

    // ── NamespaceId ──────────────────────────────────────────────────────────

    #[test]
    fn namespace_id_derive_is_deterministic() {
        let owner = Did::from_bytes([7u8; 32]);
        let a = NamespaceId::derive(&owner, "blog");
        let b = NamespaceId::derive(&owner, "blog");
        assert_eq!(a, b);
    }

    #[test]
    fn namespace_id_different_labels_differ() {
        let owner = Did::from_bytes([7u8; 32]);
        let a = NamespaceId::derive(&owner, "blog");
        let b = NamespaceId::derive(&owner, "inbox");
        assert_ne!(a, b);
    }

    #[test]
    fn namespace_id_different_owners_differ() {
        let owner_a = Did::from_bytes([1u8; 32]);
        let owner_b = Did::from_bytes([2u8; 32]);
        let a = NamespaceId::derive(&owner_a, "blog");
        let b = NamespaceId::derive(&owner_b, "blog");
        assert_ne!(a, b);
    }

    // ── FrameId ──────────────────────────────────────────────────────────────

    #[cfg(feature = "rand")]
    #[test]
    fn frame_id_random_unique() {
        // Collision probability at 128 bits is negligible; two randoms
        // should never be equal in practice.
        let a = FrameId::random();
        let b = FrameId::random();
        assert_ne!(a, b);
    }

    #[test]
    fn frame_id_roundtrip_u128() {
        let id = FrameId::from_u128(0xdeadbeef_cafebabe_12345678_9abcdef0);
        assert_eq!(id.as_u128(), 0xdeadbeef_cafebabe_12345678_9abcdef0);
    }

    // ── Bytes ────────────────────────────────────────────────────────────────

    #[test]
    fn bytes_len_and_is_empty() {
        let empty = Bytes::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let full = Bytes::from_slice(b"hello");
        assert!(!full.is_empty());
        assert_eq!(full.len(), 5);
    }

    #[test]
    fn bytes_as_ref() {
        let b = Bytes::from_slice(b"test");
        assert_eq!(b.as_ref(), b"test");
    }
}
