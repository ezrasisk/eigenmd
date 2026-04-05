//! Namespace types — the Muspell replacement for DNS and domain names.
//!
//! ## Why namespaces instead of domains?
//!
//! A DNS domain is owned by whoever pays a registrar, resolved by servers
//! you don't control, and can be seized, transferred, or silenced by third
//! parties. A Muspell namespace is:
//!
//! - **Owned by a cryptographic keypair** — no registrar; possession of the
//!   private key is ownership.
//! - **Self-verifying** — any node can check the owner's signature without
//!   consulting a central authority.
//! - **Location-independent** — the address is a hash of the owner's key and
//!   a label; it does not encode where the data lives.
//! - **Content-addressable** — records point to `ContentId`s, `NodeId`s, or
//!   `Did`s rather than IP addresses.
//! - **Updatable without TTL games** — a new signed document with a higher
//!   `version` replaces the old one everywhere simultaneously.
//!
//! ## Mental model
//!
//! Think of a `Namespace` as a signed map:
//!
//! ```text
//! Namespace {
//!     id:    ns:7xKq…          ← hash of (owner, "blog") — the "domain"
//!     owner: did:muspell:4aRp… ← who controls this
//!
//!     records:
//!       "index"       → Content(cid:b3:9f2a…)  ← the front page
//!       "avatar"      → Content(cid:b3:c8d1…)  ← a profile image
//!       "_muspell.inbox" → Node(node:2bXq…)    ← where to send messages
//!       "mirror"      → Namespace(ns:8mYj…)    ← a CNAME-like alias
//! }
//! ```
//!
//! A `NamespacePath` like `ns:7xKq…/blog/post/42` is a URL replacement:
//! globally unique, ownership-verified, resolvable without a central index.
//!
//! ## Atomicity
//!
//! A `Namespace` is an **atomic signed document**. The unit of update is the
//! whole document. A new `version` number (monotonically increasing) replaces
//! the old document everywhere. There is no partial-record update — if you
//! want to change one record, you sign a new version of the whole namespace.
//!
//! This keeps verification simple: one signature check per document.
//! Per-key `sequence` numbers within a document allow an auditor to detect
//! whether a key has been moved backward within a legitimate document lineage.
//!
//! ## Signature scope
//!
//! `Namespace::signature` covers the canonical CBOR encoding of all fields
//! **except** `signature` itself, signed by the `owner` DID's private key.
//! Signing and verification live in `muspell-identity`. This module is
//! pure data.

use crate::capability::Capability;
use crate::types::{Bytes, ContentId, Did, HumanName, NamespaceId, NodeId, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

// ── RecordKey ────────────────────────────────────────────────────────────────

/// A validated record key within a [`Namespace`].
///
/// ## Syntax rules
///
/// | Rule                    | Rationale                                     |
/// |-------------------------|-----------------------------------------------|
/// | Characters: `[a-z0-9._-]` | ASCII only; lowercase only for consistency |
/// | Max length: 253          | DNS label compatibility                       |
/// | No empty string          | Meaningless key                               |
/// | No leading/trailing `.` or `-` | Avoids ambiguity in path parsing      |
/// | No consecutive `..`      | Prevents path traversal                       |
/// | `_muspell.` prefix       | Reserved for protocol-defined well-known keys |
///
/// The `_` prefix convention (e.g. `_muspell.inbox`) signals that a key has
/// a protocol-defined semantics and is NOT application-defined. Application
/// keys MUST NOT begin with `_muspell.`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RecordKey(String);

impl RecordKey {
    /// Maximum allowed key length.
    pub const MAX_LEN: usize = 253;

    /// Validate and construct a `RecordKey` from a string.
    ///
    /// Returns `Err(RecordKeyError)` if any syntax rule is violated.
    pub fn new(s: impl Into<String>) -> Result<Self, RecordKeyError> {
        let s = s.into();

        if s.is_empty() {
            return Err(RecordKeyError::Empty);
        }
        if s.len() > Self::MAX_LEN {
            return Err(RecordKeyError::TooLong(s.len()));
        }

        // Character set: lowercase ASCII alphanumeric, `.`, `_`, `-`
        for (i, ch) in s.chars().enumerate() {
            if !matches!(ch, 'a'..='z' | '0'..='9' | '.' | '_' | '-') {
                return Err(RecordKeyError::InvalidChar { pos: i, ch });
            }
        }

        let first = s.chars().next().unwrap();
        let last  = s.chars().last().unwrap();

        if first == '.' || first == '-' {
            return Err(RecordKeyError::InvalidEdge {
                edge: "start",
                ch:   first,
            });
        }
        if last == '.' || last == '-' {
            return Err(RecordKeyError::InvalidEdge {
                edge: "end",
                ch:   last,
            });
        }

        // No consecutive dots — prevents path traversal ambiguity.
        if s.contains("..") {
            return Err(RecordKeyError::ConsecutiveDots);
        }

        Ok(Self(s))
    }

    /// Construct a `RecordKey` from a static string literal.
    ///
    /// # Panics (debug builds only)
    /// Panics if the literal fails validation. Use this only for
    /// compile-time-known constants. For runtime input, use `RecordKey::new`.
    #[must_use]
    pub fn from_static(s: &'static str) -> Self {
        debug_assert!(
            Self::new(s).is_ok(),
            "RecordKey::from_static called with invalid key: {s:?}"
        );
        Self(s.to_owned())
    }

    /// Return the key as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if this key uses the `_muspell.` reserved prefix.
    #[must_use]
    pub fn is_well_known(&self) -> bool {
        self.0.starts_with("_muspell.")
    }
}

impl fmt::Debug for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordKey({:?})", self.0)
    }
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<&str> for RecordKey {
    type Error = RecordKeyError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<String> for RecordKey {
    type Error = RecordKeyError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

/// Errors produced when validating a [`RecordKey`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RecordKeyError {
    /// The key is an empty string.
    Empty,
    /// The key exceeds the maximum allowed length.
    TooLong(usize),
    /// An invalid character was found at the given position.
    InvalidChar { pos: usize, ch: char },
    /// The key starts or ends with `.` or `-`.
    InvalidEdge { edge: &'static str, ch: char },
    /// The key contains consecutive dots (`..`).
    ConsecutiveDots,
}

impl fmt::Display for RecordKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "record key must not be empty"),
            Self::TooLong(len) => write!(
                f,
                "record key length {len} exceeds maximum {}",
                RecordKey::MAX_LEN
            ),
            Self::InvalidChar { pos, ch } => {
                write!(f, "invalid character {ch:?} at position {pos}")
            }
            Self::InvalidEdge { edge, ch } => {
                write!(f, "key must not {edge} with {ch:?}")
            }
            Self::ConsecutiveDots => write!(f, "key must not contain consecutive dots"),
        }
    }
}

impl std::error::Error for RecordKeyError {}

// ── well_known ────────────────────────────────────────────────────────────────

/// Protocol-reserved record key constants (the `_muspell.` namespace).
///
/// These keys have defined semantics in the Muspell protocol. Applications
/// MUST NOT use these keys for non-protocol purposes.
///
/// ## Conventions for new well-known keys
///
/// - Prefix: `_muspell.<purpose>`
/// - Purpose is lowercase, hyphen-separated
/// - Registered in the Muspell protocol specification before use
pub mod well_known {
    /// The node currently accepting messages for this identity.
    /// Value: `RecordValue::Node(node_id)`
    pub const INBOX: &str = "_muspell.inbox";

    /// The DID document or identity profile for this namespace.
    /// Value: `RecordValue::Content(content_id)` — CBOR-encoded profile
    pub const PROFILE: &str = "_muspell.profile";

    /// An HTTP/S gateway bridging this namespace to the web.
    /// Value: `RecordValue::Node(node_id)` or `RecordValue::Text(url)`
    pub const GATEWAY: &str = "_muspell.gateway";

    /// A public read capability allowing anyone to access this namespace.
    /// Value: `RecordValue::CapabilityGrant(capability)`
    pub const PUBLIC_READ: &str = "_muspell.public-read";

    /// The current public key for this identity (rotation support).
    /// Value: `RecordValue::Did(did)` — the new DID after rotation
    pub const KEY: &str = "_muspell.key";

    /// A delegation record — authority over this namespace transferred
    /// in whole or in part to another DID.
    /// Value: `RecordValue::Delegate { to, namespace }`
    pub const DELEGATE: &str = "_muspell.delegate";

    /// The application endpoint for this namespace.
    /// Value: `RecordValue::Node(node_id)` — the serving node
    pub const APP: &str = "_muspell.app";

    /// A robots-style crawl policy for index nodes.
    /// Value: `RecordValue::Text(policy)` — `"allow"` or `"disallow"`
    pub const CRAWL: &str = "_muspell.crawl";
}

// ── RecordValue ───────────────────────────────────────────────────────────────

/// The typed value stored in a [`NamespaceRecord`].
///
/// ## Choosing the right variant
///
/// | What you want to point at          | Variant to use              |
/// |------------------------------------|-----------------------------|
/// | An immutable blob (image, page, …) | `Content(ContentId)`        |
/// | A running daemon/node              | `Node(NodeId)`              |
/// | A stable identity                  | `Did(Did)`                  |
/// | Another namespace (alias/CNAME)    | `Namespace(NamespaceId)`    |
/// | A short human-readable string      | `Text(String)`              |
/// | A public capability token          | `CapabilityGrant(Capability)`|
/// | Sub-namespace authority delegation | `Delegate { to, namespace }`|
/// | Mark a key as deleted              | `Tombstone`                 |
/// | Application-specific extension     | `Custom { namespace, data }`|
///
/// `#[non_exhaustive]` — new variants may be added in minor version bumps.
/// Receivers of an unknown variant MUST store the record as opaque rather
/// than rejecting the whole namespace document.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum RecordValue {
    /// Points to an immutable, content-addressed blob.
    ///
    /// Analogous to a DNS `A` record, but instead of an IP address, you get
    /// a verifiable hash. Any node holding this content can serve it.
    Content(ContentId),

    /// Points to a currently-live network node.
    ///
    /// The node may come and go; this record is a hint to where the service
    /// was last seen. Use [`well_known::INBOX`] for message routing and
    /// [`well_known::APP`] for application endpoints.
    Node(NodeId),

    /// Points to a stable cryptographic identity.
    ///
    /// Used for identity references, ownership proofs, and key rotation
    /// (via [`well_known::KEY`]). The DID is stable across node changes.
    Did(Did),

    /// Points to another namespace — an alias or sub-namespace reference.
    ///
    /// Analogous to a DNS `CNAME` or `NS` delegation, but ownership of the
    /// target namespace is independently verifiable.
    Namespace(NamespaceId),

    /// A short, human-readable string value.
    ///
    /// Analogous to a DNS `TXT` record. For structured data, prefer
    /// `Content(ContentId)` pointing to a well-typed blob.
    Text(String),

    /// A publicly-visible capability token granting access to this resource.
    ///
    /// Publishing a capability here makes it discoverable: any node that
    /// resolves this namespace record can use the token to authorize requests.
    /// The issuer SHOULD scope it tightly (expiry, specific actions).
    ///
    /// Typical use: [`well_known::PUBLIC_READ`] granting `Action::Read` over
    /// the namespace's content, making the namespace publicly browsable.
    CapabilityGrant(Capability),

    /// Delegates authority over a sub-path to another DID and namespace.
    ///
    /// The `to` DID takes ownership of `namespace`. Any records within
    /// `namespace` are controlled by `to`, not the parent namespace owner.
    /// Analogous to DNS zone delegation (`NS` records).
    Delegate {
        /// The DID receiving authority.
        to: Did,
        /// The namespace the authority is being delegated into.
        namespace: NamespaceId,
    },

    /// Marks a key as intentionally deleted.
    ///
    /// A tombstone carries the `sequence` number at which the deletion
    /// occurred. Recipients that hold a prior record for this key MUST
    /// discard it if the tombstone's `sequence` is higher than the
    /// record's `sequence`.
    ///
    /// Tombstones MUST be retained for at least `ttl_secs` after creation
    /// so that nodes that were offline during the deletion cannot accept
    /// a replayed old record.
    Tombstone,

    /// An application- or deployment-specific record type.
    ///
    /// `namespace` SHOULD be a reverse-domain string: `"io.myapp"`.
    /// `data` is opaque to the Muspell protocol.
    Custom {
        /// Owning application namespace, e.g. `"io.myapp"`.
        namespace: String,
        /// Raw payload. Interpretation is application-defined.
        data: Bytes,
    },
}

impl RecordValue {
    /// Returns `true` if this value is a [`RecordValue::Tombstone`].
    #[must_use]
    pub fn is_tombstone(&self) -> bool {
        matches!(self, RecordValue::Tombstone)
    }

    /// Returns the inner `ContentId` if this is a `Content` variant.
    #[must_use]
    pub fn as_content_id(&self) -> Option<&ContentId> {
        match self {
            RecordValue::Content(cid) => Some(cid),
            _                         => None,
        }
    }

    /// Returns the inner `NodeId` if this is a `Node` variant.
    #[must_use]
    pub fn as_node_id(&self) -> Option<&NodeId> {
        match self {
            RecordValue::Node(nid) => Some(nid),
            _                      => None,
        }
    }

    /// Returns the inner `Did` if this is a `Did` variant.
    #[must_use]
    pub fn as_did(&self) -> Option<&Did> {
        match self {
            RecordValue::Did(did) => Some(did),
            _                     => None,
        }
    }

    /// Returns the inner `NamespaceId` if this is a `Namespace` variant.
    #[must_use]
    pub fn as_namespace_id(&self) -> Option<&NamespaceId> {
        match self {
            RecordValue::Namespace(ns) => Some(ns),
            _                          => None,
        }
    }

    /// A short human-readable type label for logs and diagnostics.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            RecordValue::Content(_)      => "Content",
            RecordValue::Node(_)         => "Node",
            RecordValue::Did(_)          => "Did",
            RecordValue::Namespace(_)    => "Namespace",
            RecordValue::Text(_)         => "Text",
            RecordValue::CapabilityGrant(_) => "CapabilityGrant",
            RecordValue::Delegate { .. } => "Delegate",
            RecordValue::Tombstone       => "Tombstone",
            RecordValue::Custom { .. }   => "Custom",
            #[allow(unreachable_patterns)]
            _                            => "Unknown",
        }
    }
}

impl fmt::Display for RecordValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordValue::Content(cid)   => write!(f, "content:{cid}"),
            RecordValue::Node(nid)      => write!(f, "{nid}"),
            RecordValue::Did(did)       => write!(f, "{did}"),
            RecordValue::Namespace(ns)  => write!(f, "{ns}"),
            RecordValue::Text(s)        => write!(f, "text:{s}"),
            RecordValue::CapabilityGrant(cap) => write!(
                f, "cap-grant:{}",
                cap.id.map(|id| id.to_string())
                   .unwrap_or_else(|| "<unsigned>".into())
            ),
            RecordValue::Delegate { to, namespace } => {
                write!(f, "delegate:{to}@{namespace}")
            }
            RecordValue::Tombstone      => write!(f, "tombstone"),
            RecordValue::Custom { namespace, .. } => {
                write!(f, "custom:{namespace}")
            }
            #[allow(unreachable_patterns)]
            _                           => write!(f, "unknown"),
        }
    }
}

// ── NamespaceRecord ──────────────────────────────────────────────────────────

/// A single key-value entry within a [`Namespace`].
///
/// ## Per-key sequencing
///
/// Each record carries a `sequence` number scoped to its key within a single
/// namespace document lineage. This allows auditors to detect whether a key
/// has been reverted to a previous value across two documents.
///
/// **Example:** a namespace at version 3 has `profile` at sequence 2.
/// A version-4 document that claims `profile` at sequence 1 is suspicious —
/// higher layers should flag it even though version 4 > version 3.
///
/// ## TTL override
///
/// If `ttl_secs` is `Some`, it overrides the namespace-level TTL for this
/// record only. Useful when some records change frequently (e.g. `_muspell.inbox`
/// might point to a node that restarts often) and others are stable.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct NamespaceRecord {
    /// The record key within this namespace.
    pub key: RecordKey,
    /// The typed value for this record.
    pub value: RecordValue,
    /// Monotonically increasing counter for this key within this namespace's
    /// lineage. Starts at 0 for the first entry.
    pub sequence: u64,
    /// Per-record cache TTL in seconds. `None` means use the namespace TTL.
    pub ttl_secs: Option<u32>,
    /// Wall-clock time at which this record was created (set by the owner).
    pub created_at: Timestamp,
}

impl NamespaceRecord {
    /// Construct a new record with `sequence = 0` and no TTL override.
    #[must_use]
    pub fn new(key: RecordKey, value: RecordValue, created_at: Timestamp) -> Self {
        Self {
            key,
            value,
            sequence:  0,
            ttl_secs:  None,
            created_at,
        }
    }

    /// Set a per-record TTL override.
    #[must_use]
    pub fn with_ttl(mut self, ttl_secs: u32) -> Self {
        self.ttl_secs = Some(ttl_secs);
        self
    }

    /// Set the sequence number explicitly (for updates).
    #[must_use]
    pub fn with_sequence(mut self, sequence: u64) -> Self {
        self.sequence = sequence;
        self
    }

    /// Returns `true` if this record is a tombstone (deletion marker).
    #[must_use]
    pub fn is_tombstone(&self) -> bool {
        self.value.is_tombstone()
    }

    /// Returns the effective TTL: the per-record override if set,
    /// otherwise the caller-supplied namespace default.
    #[must_use]
    pub fn effective_ttl(&self, namespace_default: u32) -> u32 {
        self.ttl_secs.unwrap_or(namespace_default)
    }
}

impl fmt::Display for NamespaceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={} (seq={})", self.key, self.value, self.sequence)
    }
}

// ── NamespaceIndex ────────────────────────────────────────────────────────────

/// A lightweight summary of a namespace, used in gossip and announcements.
///
/// Index nodes exchange `NamespaceIndex` structs to propagate knowledge of
/// namespace existence and freshness without transferring full documents.
/// When a peer's index shows a higher `version` than our own, we know to
/// fetch the full [`Namespace`] document.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct NamespaceIndex {
    /// The namespace being described.
    pub id: NamespaceId,
    /// The owner of this namespace.
    pub owner: Did,
    /// The current document version — monotonically increasing.
    pub version: u64,
    /// Wall-clock time of the most recent update.
    pub updated_at: Timestamp,
    /// Number of records in the current version (non-tombstone).
    pub record_count: u32,
}

impl fmt::Display for NamespaceIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NamespaceIndex({} v={} records={} updated={})",
            self.id,
            self.version,
            self.record_count,
            self.updated_at,
        )
    }
}

// ── NamespacePath ─────────────────────────────────────────────────────────────

/// A path addressing a specific record or sub-resource within a namespace.
///
/// `NamespacePath` is the Muspell replacement for URLs. Where a URL says
/// "this resource lives at this IP address under this domain", a path says
/// "this resource is owned by this keypair and reachable at this key path".
///
/// ## Text form
///
/// ```text
/// ns:<base58-namespace-id>[/key[/key...]]
/// ```
///
/// Examples:
/// - `ns:7xKq…/profile`           — the profile record in a namespace
/// - `ns:7xKq…/blog/post-42`      — a post in a blog namespace
/// - `ns:7xKq…/_muspell.inbox`    — the inbox well-known record
/// - `ns:7xKq…`                   — the namespace root (no key path)
///
/// ## Resolution
///
/// A resolver walks the segments left-to-right. If a segment resolves to
/// a `RecordValue::Namespace`, resolution continues into that namespace.
/// If a segment resolves to a `RecordValue::Content`, that content is the
/// final answer. Any other terminal value is returned as-is.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct NamespacePath {
    /// The root namespace.
    pub namespace: NamespaceId,
    /// Path segments within the namespace. May be empty (root path).
    pub segments: Vec<RecordKey>,
}

impl NamespacePath {
    /// Construct a path pointing at the namespace root (no key segments).
    #[must_use]
    pub fn root(namespace: NamespaceId) -> Self {
        Self { namespace, segments: vec![] }
    }

    /// Construct a path with exactly one key segment.
    #[must_use]
    pub fn record(namespace: NamespaceId, key: RecordKey) -> Self {
        Self { namespace, segments: vec![key] }
    }

    /// Extend this path with an additional segment, returning a new path.
    #[must_use]
    pub fn child(&self, key: RecordKey) -> Self {
        let mut segments = self.segments.clone();
        segments.push(key);
        Self { namespace: self.namespace, segments }
    }

    /// Returns `true` if this path points at the namespace root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns the depth of the path (number of segments).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    /// The terminal segment of this path, if any.
    #[must_use]
    pub fn leaf(&self) -> Option<&RecordKey> {
        self.segments.last()
    }

    /// Returns the parent path (all segments except the last).
    /// Returns `None` if this is already a root path.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.segments.is_empty() {
            return None;
        }
        let mut segments = self.segments.clone();
        segments.pop();
        Some(Self { namespace: self.namespace, segments })
    }

    /// Parse a `NamespacePath` from its text representation.
    ///
    /// Expected format: `ns:<base58-id>[/key[/key...]]`
    ///
    /// Returns `Err(NamespacePathError)` if the format is invalid.
    pub fn parse(s: &str) -> Result<Self, NamespacePathError> {
        let s = s.trim();

        let rest = s
            .strip_prefix("ns:")
            .ok_or(NamespacePathError::MissingPrefix)?;

        // Split on the first `/` to separate the namespace ID from the path.
        let (id_str, path_str) = match rest.find('/') {
            Some(pos) => (&rest[..pos], &rest[pos + 1..]),
            None      => (rest, ""),
        };

        if id_str.is_empty() {
            return Err(NamespacePathError::EmptyNamespaceId);
        }

        // Decode base58 → 32 bytes
        let id_bytes = bs58::decode(id_str)
            .into_vec()
            .map_err(|_| NamespacePathError::InvalidNamespaceId)?;

        if id_bytes.len() != 32 {
            return Err(NamespacePathError::InvalidNamespaceId);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id_bytes);
        let namespace = NamespaceId::from_bytes(arr);

        // Parse each `/`-delimited segment as a RecordKey.
        let mut segments = Vec::new();
        if !path_str.is_empty() {
            for segment in path_str.split('/') {
                if segment.is_empty() {
                    return Err(NamespacePathError::EmptySegment);
                }
                let key = RecordKey::new(segment)
                    .map_err(|e| NamespacePathError::InvalidSegment(e))?;
                segments.push(key);
            }
        }

        Ok(Self { namespace, segments })
    }
}

impl fmt::Display for NamespacePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NamespaceId::Display produces "ns:<base58>" — we use that directly.
        write!(f, "{}", self.namespace)?;
        for seg in &self.segments {
            write!(f, "/{seg}")?;
        }
        Ok(())
    }
}

/// Errors produced when parsing a [`NamespacePath`] from a string.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NamespacePathError {
    /// The string did not start with `ns:`.
    MissingPrefix,
    /// The namespace ID portion was absent.
    EmptyNamespaceId,
    /// The base58-encoded namespace ID could not be decoded, or was not 32 bytes.
    InvalidNamespaceId,
    /// A path segment between `/` separators was empty.
    EmptySegment,
    /// A path segment failed `RecordKey` validation.
    InvalidSegment(RecordKeyError),
}

impl fmt::Display for NamespacePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix        => write!(f, "path must start with 'ns:'"),
            Self::EmptyNamespaceId     => write!(f, "namespace ID must not be empty"),
            Self::InvalidNamespaceId   => {
                write!(f, "namespace ID is not valid base58 or not 32 bytes")
            }
            Self::EmptySegment         => write!(f, "path segment must not be empty"),
            Self::InvalidSegment(e)    => write!(f, "invalid path segment: {e}"),
        }
    }
}

impl std::error::Error for NamespacePathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSegment(e) => Some(e),
            _                       => None,
        }
    }
}

// ── Namespace ─────────────────────────────────────────────────────────────────

/// A signed, versioned, content-addressable namespace document.
///
/// The atomic unit of the Muspell naming system. Analogous to a DNS zone
/// file, but owned by a keypair and self-verifying.
///
/// ## Versioning and rollback protection
///
/// The `version` field MUST be strictly increasing across updates. Any node
/// that receives a `Namespace` with `version <= self.version` for the same
/// `NamespaceId` MUST reject it. This prevents an attacker who captures an
/// old signed document from replaying it after a newer version is published.
///
/// ## Record deduplication
///
/// Multiple records with the same `key` are allowed within one document
/// (e.g. several `Node` records for the same `_muspell.inbox` key, for
/// redundancy). [`Namespace::get`] returns the first match; use
/// [`Namespace::get_all`] to retrieve all.
///
/// ## Signing
///
/// The `signature` field MUST be `Some` for any namespace document that
/// is stored or forwarded. A namespace with `signature: None` is a draft
/// and MUST NOT be forwarded.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Namespace {
    /// Stable content-addressed identifier for this namespace.
    pub id: NamespaceId,
    /// The DID that owns and signs this namespace.
    pub owner: Did,
    /// Optional human-readable petname. Not globally unique.
    pub name: Option<HumanName>,
    /// Monotonically increasing document version.
    /// MUST be strictly greater than the previous version to be accepted.
    /// Starts at 1 for a newly created namespace.
    pub version: u64,
    /// Wall-clock time at which this namespace was first created.
    pub created_at: Timestamp,
    /// Wall-clock time at which the current `version` was produced.
    pub updated_at: Timestamp,
    /// Default cache TTL for records, in seconds.
    /// Individual records may override this via `NamespaceRecord::ttl_secs`.
    pub ttl_secs: u32,
    /// The records in this namespace.
    pub records: Vec<NamespaceRecord>,
    /// Ed25519 signature by `owner` over the canonical CBOR encoding of all
    /// fields except `signature`. `None` for draft documents.
    pub signature: Option<Signature>,
}

impl Namespace {
    /// Default TTL — 5 minutes. Conservative for a new protocol.
    pub const DEFAULT_TTL_SECS: u32 = 300;

    /// The minimum valid version number.
    pub const MIN_VERSION: u64 = 1;

    // ── Constructors ─────────────────────────────────────────────────────────

    /// Create a new, unsigned namespace at version 1.
    ///
    /// `id` SHOULD be derived via [`NamespaceId::derive`] from the owner and
    /// a label so that the namespace ID is verifiably owned by `owner`.
    /// `created_at` SHOULD be the current wall-clock time.
    #[must_use]
    pub fn new(id: NamespaceId, owner: Did, created_at: Timestamp) -> Self {
        Self {
            id,
            owner,
            name:       None,
            version:    Self::MIN_VERSION,
            created_at,
            updated_at: created_at,
            ttl_secs:   Self::DEFAULT_TTL_SECS,
            records:    Vec::new(),
            signature:  None,
        }
    }

    // ── Builder methods ───────────────────────────────────────────────────────

    /// Set a human-readable petname for this namespace.
    #[must_use]
    pub fn with_name(mut self, name: HumanName) -> Self {
        self.name = Some(name);
        self
    }

    /// Override the default TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl_secs: u32) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    /// Append a record to this namespace.
    ///
    /// Does not deduplicate — if a record with the same key already exists,
    /// both are kept (intentional: multiple records per key are valid for
    /// redundancy). To update a specific key, remove old records first or use
    /// [`Namespace::upsert_record`].
    #[must_use]
    pub fn with_record(mut self, record: NamespaceRecord) -> Self {
        self.records.push(record);
        self
    }

    // ── Record access ─────────────────────────────────────────────────────────

    /// Look up the first non-tombstone record for `key`.
    ///
    /// Returns `None` if no record exists or only tombstones are present.
    /// For multi-valued keys (redundant nodes, etc.) use [`Namespace::get_all`].
    #[must_use]
    pub fn get(&self, key: &RecordKey) -> Option<&NamespaceRecord> {
        self.records
            .iter()
            .find(|r| &r.key == key && !r.is_tombstone())
    }

    /// Look up all non-tombstone records for `key`.
    #[must_use]
    pub fn get_all(&self, key: &RecordKey) -> Vec<&NamespaceRecord> {
        self.records
            .iter()
            .filter(|r| &r.key == key && !r.is_tombstone())
            .collect()
    }

    /// Returns `true` if this namespace has at least one non-tombstone record
    /// for `key`.
    #[must_use]
    pub fn contains(&self, key: &RecordKey) -> bool {
        self.get(key).is_some()
    }

    /// Insert or update a record for a key.
    ///
    /// If a non-tombstone record with the same key already exists, it is
    /// replaced and the new record's `sequence` is set to `old.sequence + 1`.
    /// If no record exists, `sequence` is left as-is (typically 0).
    ///
    /// This invalidates any existing `signature` — call `with_signature` after
    /// all mutations are complete.
    pub fn upsert_record(&mut self, mut record: NamespaceRecord) {
        let existing_seq = self
            .records
            .iter()
            .filter(|r| r.key == record.key && !r.is_tombstone())
            .map(|r| r.sequence)
            .max();

        if let Some(seq) = existing_seq {
            record.sequence = seq + 1;
            // Remove the old record.
            self.records.retain(|r| r.key != record.key || r.is_tombstone());
        }

        self.records.push(record);
        self.signature = None; // invalidate — must be re-signed
    }

    /// Place a tombstone for `key` at `sequence = current + 1`.
    ///
    /// If no record for `key` exists, this is a no-op.
    /// Invalidates any existing signature.
    pub fn delete_record(&mut self, key: &RecordKey, deleted_at: Timestamp) {
        let max_seq = self
            .records
            .iter()
            .filter(|r| &r.key == key)
            .map(|r| r.sequence)
            .max();

        let Some(seq) = max_seq else { return };

        // Remove the live record(s), keep existing tombstones.
        self.records.retain(|r| &r.key != key || r.is_tombstone());

        // Insert tombstone at seq+1.
        self.records.push(NamespaceRecord {
            key:        key.clone(),
            value:      RecordValue::Tombstone,
            sequence:   seq + 1,
            ttl_secs:   None,
            created_at: deleted_at,
        });

        self.signature = None;
    }

    // ── Iteration helpers ─────────────────────────────────────────────────────

    /// Iterate over all `ContentId`s referenced by non-tombstone records.
    pub fn content_ids(&self) -> impl Iterator<Item = &ContentId> {
        self.records.iter().filter_map(|r| r.value.as_content_id())
    }

    /// Iterate over all `NodeId`s referenced by non-tombstone records.
    pub fn node_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.records.iter().filter_map(|r| r.value.as_node_id())
    }

    /// Iterate over all `Did`s referenced by non-tombstone records.
    pub fn dids(&self) -> impl Iterator<Item = &Did> {
        self.records.iter().filter_map(|r| r.value.as_did())
    }

    /// Iterate over all sub-namespace IDs referenced by non-tombstone records.
    pub fn sub_namespaces(&self) -> impl Iterator<Item = &NamespaceId> {
        self.records.iter().filter_map(|r| r.value.as_namespace_id())
    }

    /// Number of non-tombstone records.
    #[must_use]
    pub fn live_record_count(&self) -> usize {
        self.records.iter().filter(|r| !r.is_tombstone()).count()
    }

    // ── Versioning ────────────────────────────────────────────────────────────

    /// Returns `true` if `self` is strictly newer than `other`.
    ///
    /// "Newer" means a higher `version` number for the same `NamespaceId`.
    /// Returns `false` if the IDs differ — callers must check identity first.
    #[must_use]
    pub fn is_newer_than(&self, other: &Namespace) -> bool {
        self.id == other.id && self.version > other.version
    }

    /// Prepare this namespace for the next version update.
    ///
    /// Increments `version`, updates `updated_at`, and clears `signature`.
    /// The caller must add/modify records and then re-sign.
    pub fn bump_version(&mut self, updated_at: Timestamp) {
        self.version    += 1;
        self.updated_at  = updated_at;
        self.signature   = None;
    }

    // ── Signing helpers ───────────────────────────────────────────────────────

    /// Returns `true` if this namespace has been signed.
    /// Unsigned namespaces MUST NOT be forwarded.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Attach a signature (provided by `muspell-identity` after signing).
    #[must_use]
    pub fn with_signature(mut self, sig: Signature) -> Self {
        self.signature = Some(sig);
        self
    }

    // ── Index ─────────────────────────────────────────────────────────────────

    /// Produce a lightweight [`NamespaceIndex`] summary for gossip.
    #[must_use]
    pub fn index(&self) -> NamespaceIndex {
        NamespaceIndex {
            id:           self.id,
            owner:        self.owner,
            version:      self.version,
            updated_at:   self.updated_at,
            record_count: self.live_record_count() as u32,
        }
    }

    // ── Structural validation ─────────────────────────────────────────────────

    /// Validate the structural integrity of this namespace document.
    ///
    /// Checks:
    /// - `version >= Namespace::MIN_VERSION`
    /// - `signature` is present (no unsigned documents)
    /// - `created_at <= updated_at`
    /// - No two non-tombstone records share the same `(key, sequence)` pair
    /// - `ttl_secs > 0`
    ///
    /// Does **not** verify the cryptographic signature — that is done in
    /// `muspell-identity::verify_namespace`.
    pub fn validate_structure(&self) -> Result<(), NamespaceError> {
        if self.version < Self::MIN_VERSION {
            return Err(NamespaceError::VersionTooLow {
                version: self.version,
                minimum: Self::MIN_VERSION,
            });
        }

        if self.signature.is_none() {
            return Err(NamespaceError::MissingSignature { id: self.id });
        }

        if self.created_at > self.updated_at {
            return Err(NamespaceError::TimestampInversion {
                created_at: self.created_at,
                updated_at: self.updated_at,
            });
        }

        if self.ttl_secs == 0 {
            return Err(NamespaceError::ZeroTtl);
        }

        // Check for (key, sequence) duplicates among live records.
        // Using a simple O(n²) check — namespaces are expected to be small.
        for (i, a) in self.records.iter().enumerate() {
            if a.is_tombstone() {
                continue;
            }
            for b in self.records.iter().skip(i + 1) {
                if b.is_tombstone() {
                    continue;
                }
                if a.key == b.key && a.sequence == b.sequence {
                    return Err(NamespaceError::DuplicateRecord {
                        key:      a.key.clone(),
                        sequence: a.sequence,
                    });
                }
            }
        }

        Ok(())
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self
            .name
            .as_ref()
            .map(|n| format!(" ({n})"))
            .unwrap_or_default();
        write!(
            f,
            "Namespace[{}{} v={} owner={} records={}]",
            self.id,
            name,
            self.version,
            self.owner,
            self.live_record_count(),
        )
    }
}

/// Errors produced during structural validation of a [`Namespace`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NamespaceError {
    /// The `version` is below the minimum.
    VersionTooLow { version: u64, minimum: u64 },
    /// The namespace has no signature and MUST NOT be forwarded.
    MissingSignature { id: NamespaceId },
    /// `created_at` is later than `updated_at`.
    TimestampInversion {
        created_at: Timestamp,
        updated_at: Timestamp,
    },
    /// `ttl_secs` is zero, which would make records non-cacheable.
    ZeroTtl,
    /// Two non-tombstone records share the same `(key, sequence)`.
    DuplicateRecord { key: RecordKey, sequence: u64 },
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionTooLow { version, minimum } => write!(
                f,
                "namespace version {version} is below minimum {minimum}"
            ),
            Self::MissingSignature { id } => {
                write!(f, "namespace {id} has no signature")
            }
            Self::TimestampInversion { created_at, updated_at } => write!(
                f,
                "created_at {created_at} is after updated_at {updated_at}"
            ),
            Self::ZeroTtl => write!(f, "ttl_secs must be > 0"),
            Self::DuplicateRecord { key, sequence } => write!(
                f,
                "duplicate live record for key {key} at sequence {sequence}"
            ),
        }
    }
}

impl std::error::Error for NamespaceError {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContentId, Did, HumanName, NamespaceId, NodeId, Signature, Timestamp};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn did(b: u8) -> Did {
        Did::from_bytes([b; 32])
    }

    fn t(s: i64) -> Timestamp {
        Timestamp::from_secs(s)
    }

    fn ns_id(owner: Did, label: &str) -> NamespaceId {
        NamespaceId::derive(&owner, label)
    }

    fn fake_sig() -> Signature {
        Signature::from_bytes([0xbbu8; 64])
    }

    fn signed_ns(id: NamespaceId, owner: Did) -> Namespace {
        Namespace::new(id, owner, t(1000))
            .with_signature(fake_sig())
    }

    fn key(s: &str) -> RecordKey {
        RecordKey::new(s).unwrap()
    }

    fn content_record(k: &str, data: &[u8]) -> NamespaceRecord {
        NamespaceRecord::new(
            key(k),
            RecordValue::Content(ContentId::blake3(data)),
            t(1000),
        )
    }

    // ── RecordKey validation ──────────────────────────────────────────────────

    #[test]
    fn record_key_valid_simple() {
        assert!(RecordKey::new("profile").is_ok());
        assert!(RecordKey::new("blog-post").is_ok());
        assert!(RecordKey::new("v1.2.3").is_ok());
        assert!(RecordKey::new("_muspell.inbox").is_ok());
        assert!(RecordKey::new("a").is_ok());
        assert!(RecordKey::new("post-42").is_ok());
    }

    #[test]
    fn record_key_empty_is_invalid() {
        assert!(matches!(RecordKey::new(""), Err(RecordKeyError::Empty)));
    }

    #[test]
    fn record_key_too_long_is_invalid() {
        let long = "a".repeat(254);
        assert!(matches!(
            RecordKey::new(long),
            Err(RecordKeyError::TooLong(_))
        ));
    }

    #[test]
    fn record_key_max_length_is_valid() {
        let exactly_max = "a".repeat(253);
        assert!(RecordKey::new(exactly_max).is_ok());
    }

    #[test]
    fn record_key_uppercase_is_invalid() {
        assert!(matches!(
            RecordKey::new("Profile"),
            Err(RecordKeyError::InvalidChar { .. })
        ));
    }

    #[test]
    fn record_key_leading_hyphen_is_invalid() {
        assert!(matches!(
            RecordKey::new("-profile"),
            Err(RecordKeyError::InvalidEdge { .. })
        ));
    }

    #[test]
    fn record_key_trailing_dot_is_invalid() {
        assert!(matches!(
            RecordKey::new("profile."),
            Err(RecordKeyError::InvalidEdge { .. })
        ));
    }

    #[test]
    fn record_key_consecutive_dots_invalid() {
        assert!(matches!(
            RecordKey::new("foo..bar"),
            Err(RecordKeyError::ConsecutiveDots)
        ));
    }

    #[test]
    fn record_key_well_known_detection() {
        assert!(key("_muspell.inbox").is_well_known());
        assert!(!key("profile").is_well_known());
        assert!(!key("_custom.thing").is_well_known());
    }

    #[test]
    fn record_key_try_from_str() {
        let k: Result<RecordKey, _> = "blog".try_into();
        assert!(k.is_ok());
        let k: Result<RecordKey, _> = "BAD".try_into();
        assert!(k.is_err());
    }

    // ── RecordValue helpers ───────────────────────────────────────────────────

    #[test]
    fn record_value_as_content_id() {
        let cid = ContentId::blake3(b"test");
        let v = RecordValue::Content(cid);
        assert_eq!(v.as_content_id(), Some(&cid));
        assert!(RecordValue::Tombstone.as_content_id().is_none());
    }

    #[test]
    fn record_value_as_node_id() {
        let nid = NodeId::from_bytes([3u8; 32]);
        let v = RecordValue::Node(nid);
        assert_eq!(v.as_node_id(), Some(&nid));
    }

    #[test]
    fn record_value_as_did() {
        let d = did(5);
        let v = RecordValue::Did(d);
        assert_eq!(v.as_did(), Some(&d));
    }

    #[test]
    fn record_value_tombstone_detection() {
        assert!(RecordValue::Tombstone.is_tombstone());
        assert!(!RecordValue::Text("hello".into()).is_tombstone());
    }

    #[test]
    fn record_value_type_names() {
        assert_eq!(RecordValue::Content(ContentId::blake3(b"x")).type_name(), "Content");
        assert_eq!(RecordValue::Tombstone.type_name(), "Tombstone");
        assert_eq!(RecordValue::Text("x".into()).type_name(), "Text");
    }

    // ── NamespaceRecord ───────────────────────────────────────────────────────

    #[test]
    fn namespace_record_default_sequence_is_zero() {
        let r = content_record("profile", b"data");
        assert_eq!(r.sequence, 0);
    }

    #[test]
    fn namespace_record_effective_ttl_uses_override() {
        let r = content_record("key", b"x").with_ttl(60);
        assert_eq!(r.effective_ttl(300), 60);
    }

    #[test]
    fn namespace_record_effective_ttl_falls_back_to_default() {
        let r = content_record("key", b"x");
        assert_eq!(r.effective_ttl(300), 300);
    }

    #[test]
    fn namespace_record_is_tombstone() {
        let tomb = NamespaceRecord::new(key("gone"), RecordValue::Tombstone, t(1));
        assert!(tomb.is_tombstone());
        assert!(!content_record("live", b"x").is_tombstone());
    }

    // ── NamespacePath parsing ─────────────────────────────────────────────────

    #[test]
    fn namespace_path_root_roundtrip() {
        let owner = did(1);
        let id    = ns_id(owner, "blog");
        let path  = NamespacePath::root(id);
        let s     = path.to_string();
        let parsed = NamespacePath::parse(&s).expect("parse should succeed");
        assert_eq!(parsed.namespace, id);
        assert!(parsed.is_root());
    }

    #[test]
    fn namespace_path_with_segments_roundtrip() {
        let owner = did(2);
        let id    = ns_id(owner, "docs");
        let path  = NamespacePath::record(id, key("profile"))
            .child(key("avatar"));
        let s      = path.to_string();
        let parsed = NamespacePath::parse(&s).expect("parse should succeed");
        assert_eq!(parsed.namespace, id);
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.segments[0].as_str(), "profile");
        assert_eq!(parsed.segments[1].as_str(), "avatar");
    }

    #[test]
    fn namespace_path_missing_prefix_fails() {
        assert!(matches!(
            NamespacePath::parse("7xKq/profile"),
            Err(NamespacePathError::MissingPrefix)
        ));
    }

    #[test]
    fn namespace_path_invalid_base58_fails() {
        assert!(matches!(
            NamespacePath::parse("ns:not-valid-base58!!!"),
            Err(NamespacePathError::InvalidNamespaceId)
        ));
    }

    #[test]
    fn namespace_path_empty_segment_fails() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let s     = format!("{}/", NamespacePath::root(id));
        assert!(matches!(
            NamespacePath::parse(&s),
            Err(NamespacePathError::EmptySegment)
        ));
    }

    #[test]
    fn namespace_path_invalid_segment_fails() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let s     = format!("{}/UPPERCASE", NamespacePath::root(id));
        assert!(matches!(
            NamespacePath::parse(&s),
            Err(NamespacePathError::InvalidSegment(_))
        ));
    }

    #[test]
    fn namespace_path_depth_and_leaf() {
        let id   = ns_id(did(1), "x");
        let path = NamespacePath::record(id, key("a")).child(key("b"));
        assert_eq!(path.depth(), 2);
        assert_eq!(path.leaf().map(RecordKey::as_str), Some("b"));
    }

    #[test]
    fn namespace_path_parent_of_root_is_none() {
        let id = ns_id(did(1), "x");
        assert!(NamespacePath::root(id).parent().is_none());
    }

    #[test]
    fn namespace_path_parent_of_deep_path() {
        let id   = ns_id(did(1), "x");
        let path = NamespacePath::record(id, key("a")).child(key("b"));
        let parent = path.parent().unwrap();
        assert_eq!(parent.depth(), 1);
        assert_eq!(parent.leaf().map(RecordKey::as_str), Some("a"));
    }

    // ── Namespace construction and record access ──────────────────────────────

    #[test]
    fn namespace_new_is_version_one() {
        let owner = did(1);
        let id    = ns_id(owner, "blog");
        let ns    = Namespace::new(id, owner, t(1000));
        assert_eq!(ns.version, Namespace::MIN_VERSION);
        assert!(ns.records.is_empty());
        assert!(!ns.is_signed());
    }

    #[test]
    fn namespace_get_finds_record() {
        let owner = did(1);
        let id    = ns_id(owner, "blog");
        let ns    = signed_ns(id, owner)
            .with_record(content_record("profile", b"data"));
        assert!(ns.get(&key("profile")).is_some());
        assert!(ns.get(&key("missing")).is_none());
    }

    #[test]
    fn namespace_get_ignores_tombstones() {
        let owner = did(1);
        let id    = ns_id(owner, "blog");
        let tomb  = NamespaceRecord::new(key("gone"), RecordValue::Tombstone, t(1));
        let ns    = signed_ns(id, owner).with_record(tomb);
        assert!(ns.get(&key("gone")).is_none());
    }

    #[test]
    fn namespace_get_all_returns_multiples() {
        let owner = did(1);
        let id    = ns_id(owner, "blog");
        let r1    = content_record("inbox", b"node-a");
        let r2    = NamespaceRecord::new(
            key("inbox"),
            RecordValue::Node(NodeId::from_bytes([7u8; 32])),
            t(1000),
        ).with_sequence(1);
        let ns = signed_ns(id, owner).with_record(r1).with_record(r2);
        assert_eq!(ns.get_all(&key("inbox")).len(), 2);
    }

    #[test]
    fn namespace_contains_key() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let ns    = signed_ns(id, owner)
            .with_record(content_record("avatar", b"img"));
        assert!(ns.contains(&key("avatar")));
        assert!(!ns.contains(&key("missing")));
    }

    // ── Namespace upsert / delete ─────────────────────────────────────────────

    #[test]
    fn namespace_upsert_replaces_existing_and_bumps_sequence() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let mut ns = Namespace::new(id, owner, t(1000))
            .with_record(content_record("profile", b"v1"));

        ns.upsert_record(content_record("profile", b"v2"));

        // Should be only one live record for "profile"
        let all = ns.get_all(&key("profile"));
        assert_eq!(all.len(), 1);
        // Sequence should have been bumped
        assert_eq!(all[0].sequence, 1);
        // Signature cleared
        assert!(!ns.is_signed());
    }

    #[test]
    fn namespace_upsert_new_key_sequence_stays() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let mut ns = Namespace::new(id, owner, t(1000));
        ns.upsert_record(content_record("fresh", b"data"));
        let r = ns.get(&key("fresh")).unwrap();
        assert_eq!(r.sequence, 0);
    }

    #[test]
    fn namespace_delete_record_inserts_tombstone() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let mut ns = Namespace::new(id, owner, t(1000))
            .with_record(content_record("profile", b"data"));

        ns.delete_record(&key("profile"), t(2000));

        assert!(ns.get(&key("profile")).is_none());
        // The tombstone should still be in records
        let all = ns.records.iter().filter(|r| r.key == key("profile")).collect::<Vec<_>>();
        assert_eq!(all.len(), 1);
        assert!(all[0].is_tombstone());
        assert_eq!(all[0].sequence, 1); // was 0, tombstone at 1
    }

    #[test]
    fn namespace_delete_nonexistent_is_noop() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let mut ns = Namespace::new(id, owner, t(1000));
        ns.delete_record(&key("ghost"), t(1000)); // no panic
        assert!(ns.records.is_empty());
    }

    // ── Namespace iteration helpers ───────────────────────────────────────────

    #[test]
    fn namespace_content_ids_iteration() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let cid1  = ContentId::blake3(b"a");
        let cid2  = ContentId::blake3(b"b");
        let ns = Namespace::new(id, owner, t(1000))
            .with_record(NamespaceRecord::new(key("a"), RecordValue::Content(cid1), t(1000)))
            .with_record(NamespaceRecord::new(key("b"), RecordValue::Content(cid2), t(1000)))
            .with_record(NamespaceRecord::new(key("c"), RecordValue::Text("x".into()), t(1000)));
        let cids: Vec<_> = ns.content_ids().collect();
        assert_eq!(cids.len(), 2);
        assert!(cids.contains(&&cid1));
        assert!(cids.contains(&&cid2));
    }

    #[test]
    fn namespace_live_record_count_excludes_tombstones() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let ns = Namespace::new(id, owner, t(1000))
            .with_record(content_record("a", b"a"))
            .with_record(content_record("b", b"b"))
            .with_record(NamespaceRecord::new(key("c"), RecordValue::Tombstone, t(1)));
        assert_eq!(ns.live_record_count(), 2);
    }

    // ── Namespace versioning ──────────────────────────────────────────────────

    #[test]
    fn namespace_is_newer_than() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let old   = signed_ns(id, owner);
        let mut new = signed_ns(id, owner);
        new.version = 2;
        assert!(new.is_newer_than(&old));
        assert!(!old.is_newer_than(&new));
    }

    #[test]
    fn namespace_is_not_newer_than_same_version() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let a     = signed_ns(id, owner);
        let b     = signed_ns(id, owner);
        assert!(!a.is_newer_than(&b));
        assert!(!b.is_newer_than(&a));
    }

    #[test]
    fn namespace_is_not_newer_than_different_id() {
        let owner = did(1);
        let id_a  = ns_id(owner, "a");
        let id_b  = ns_id(owner, "b");
        let a     = signed_ns(id_a, owner);
        let mut b = signed_ns(id_b, owner);
        b.version = 99;
        // Different namespace IDs — is_newer_than is false regardless.
        assert!(!b.is_newer_than(&a));
    }

    #[test]
    fn namespace_bump_version_increments_and_clears_sig() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let mut ns = signed_ns(id, owner);
        assert!(ns.is_signed());
        ns.bump_version(t(2000));
        assert_eq!(ns.version, 2);
        assert!(!ns.is_signed());
        assert_eq!(ns.updated_at, t(2000));
    }

    // ── Namespace::index ─────────────────────────────────────────────────────

    #[test]
    fn namespace_index_fields() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let ns    = signed_ns(id, owner)
            .with_record(content_record("a", b"a"))
            .with_record(content_record("b", b"b"));
        let idx = ns.index();
        assert_eq!(idx.id, id);
        assert_eq!(idx.owner, owner);
        assert_eq!(idx.version, 1);
        assert_eq!(idx.record_count, 2);
    }

    // ── Namespace::validate_structure ────────────────────────────────────────

    #[test]
    fn namespace_validate_passes_for_valid_ns() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let ns    = signed_ns(id, owner);
        assert!(ns.validate_structure().is_ok());
    }

    #[test]
    fn namespace_validate_fails_missing_signature() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let ns    = Namespace::new(id, owner, t(1000));
        assert!(matches!(
            ns.validate_structure(),
            Err(NamespaceError::MissingSignature { .. })
        ));
    }

    #[test]
    fn namespace_validate_fails_version_zero() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let mut ns = Namespace::new(id, owner, t(1000));
        ns.version   = 0;
        ns.signature = Some(fake_sig());
        assert!(matches!(
            ns.validate_structure(),
            Err(NamespaceError::VersionTooLow { .. })
        ));
    }

    #[test]
    fn namespace_validate_fails_timestamp_inversion() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let mut ns = Namespace::new(id, owner, t(2000)); // created_at = 2000
        ns.updated_at = t(1000); // updated_at < created_at
        ns.signature  = Some(fake_sig());
        assert!(matches!(
            ns.validate_structure(),
            Err(NamespaceError::TimestampInversion { .. })
        ));
    }

    #[test]
    fn namespace_validate_fails_zero_ttl() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let mut ns = signed_ns(id, owner);
        ns.ttl_secs = 0;
        assert!(matches!(
            ns.validate_structure(),
            Err(NamespaceError::ZeroTtl)
        ));
    }

    #[test]
    fn namespace_validate_fails_duplicate_key_sequence() {
        let owner = did(1);
        let id    = ns_id(owner, "x");
        // Two live records with the same key AND same sequence — invalid.
        let r1 = content_record("dup", b"a"); // sequence = 0
        let r2 = content_record("dup", b"b"); // sequence = 0
        let mut ns = Namespace::new(id, owner, t(1000))
            .with_record(r1)
            .with_record(r2);
        ns.signature = Some(fake_sig());
        assert!(matches!(
            ns.validate_structure(),
            Err(NamespaceError::DuplicateRecord { .. })
        ));
    }

    #[test]
    fn namespace_validate_allows_same_key_different_sequence() {
        // Same key, different sequence — valid (multi-value record)
        let owner = did(1);
        let id    = ns_id(owner, "x");
        let r1    = content_record("inbox", b"node-a");          // seq 0
        let r2    = content_record("inbox", b"node-b").with_sequence(1); // seq 1
        let mut ns = Namespace::new(id, owner, t(1000))
            .with_record(r1)
            .with_record(r2);
        ns.signature = Some(fake_sig());
        assert!(ns.validate_structure().is_ok());
    }
}
