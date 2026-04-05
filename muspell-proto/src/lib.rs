//! # muspell-proto
//!
//! Canonical wire types for the Muspell decentralised network protocol.
//!
//! ## Design constraints
//!
//! - **Pure data** — no I/O, no async, no runtime. Just types.
//! - **No iroh dependency** — the transport layer converts at its boundary.
//! - **Forward-compatible** — `#[non_exhaustive]` on all open enums;
//!   unknown variants must never cause a hard failure in well-behaved nodes.
//! - **Serialisation-agnostic** — types derive `serde::{Serialize, Deserialize}`;
//!   the encoding (CBOR, JSON, bincode) is the caller's choice.
//!   Production use: CBOR via `ciborium` for DAG-CBOR-compatible canonicalisation.
//!
//! ## Crate layout
//!
//! ```text
//! muspell-proto/
//!   src/
//!     lib.rs      ← you are here; re-exports everything
//!     types.rs    ← primitive atoms (Did, NodeId, ContentId, …)
//!     // future:
//!     // capability.rs  — Capability, ActionSet, ResourceId
//!     // frame.rs       — Frame, FrameBody, sub-frame structs
//!     // namespace.rs   — Namespace, NamespaceRecord
//!     // error.rs       — ProtoError, ErrorCode
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod types;
pub mod capability;
pub mod frame;
pub mod namespace;

// Re-export all public primitives at crate root for ergonomic imports:
//   use muspell_proto::{Did, ContentId, …};
pub use types::{
    Bytes, ContentId, Did, FrameId, HashAlg, HumanName, MimeType, NamespaceId, NodeId,
    ProtocolVersion, Signature, Timestamp,
};

pub use capability::{
    Action, ActionSet, AttenuationError, Capability, CapabilityError, CapabilityId,
    ResourceId, MAX_CHAIN_DEPTH,
};

pub use frame::{
    AnnounceFrame, ByteRange, DeleteAckFrame, DeleteFrame, ErrorCode, ErrorFrame,
    ExtensionFrame, Frame, FrameAuth, FrameBody, GetFrame, GetResponseFrame, GetResult,
    GoodbyeFrame, HelloAckFrame, HelloFrame, MessageAckFrame, MessageFrame, MessageStatus,
    NodeCapabilities, PingFrame, PongFrame, PutFrame, QueryFrame, QueryKind,
    QueryResponseFrame, QueryResult, StreamChannel, StreamCloseFrame, StreamDataFrame,
    StreamKind, StreamOpenFrame,
};

pub use namespace::{
    Namespace, NamespaceError, NamespaceIndex, NamespacePath, NamespacePathError,
    NamespaceRecord, RecordKey, RecordKeyError, RecordValue,
};
/// Protocol-reserved well-known record key constants.
pub use namespace::well_known;
