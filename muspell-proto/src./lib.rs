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

// Re-export all public primitives at crate root for ergonomic imports:
//   use muspell_proto::{Did, ContentId, …};
pub use types::{
    Bytes, ContentId, Did, FrameId, HashAlg, HumanName, MimeType, NamespaceId, NodeId,
    ProtocolVersion, Signature, Timestamp,
};
