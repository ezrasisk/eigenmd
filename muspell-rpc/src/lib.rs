//! # muspell-rpc
//!
//! Request/response abstraction over `muspell-transport`.
//!
//! ## Role in the stack
//!
//! ```text
//! muspell-proto      ← wire types
//! muspell-transport  ← QUIC framing, handshake, raw send/recv
//!        │
//!        ▼
//! muspell-rpc        ← YOU ARE HERE
//!        │              RpcClient:    typed get/put/delete/query/send_message
//!        │              RpcRouter:    RequestHandler trait + dispatch
//!        │              RpcDispatcher: routes incoming frames
//!        │              PendingRequests: in-flight correlation table
//!        ▼
//! muspell-node       ← assembles everything; implements RequestHandler
//! ```
//!
//! ## Layering via channels
//!
//! The RPC layer does not hold a `MuspellConnection` directly. Instead it
//! communicates with the transport task via a pair of `mpsc` channels:
//!
//! ```text
//! ┌──────────────┐   outgoing: mpsc::Sender<Frame>   ┌────────────────┐
//! │  RpcClient   │──────────────────────────────────▶│ transport task │
//! │              │                                   │ (owns conn)    │
//! │  RpcDispatcher│◀─────────────────────────────────│                │
//! └──────────────┘   incoming: mpsc::Receiver<Frame> └────────────────┘
//! ```
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use muspell_rpc::{RpcLayer, RpcConfig, NullHandler};
//! use std::sync::Arc;
//! use tokio::sync::mpsc;
//!
//! // Channels bridge this crate to the transport layer.
//! let (out_tx, out_rx) = mpsc::channel(256);  // RPC → transport
//! let (in_tx, in_rx)   = mpsc::channel(256);  // transport → RPC
//!
//! // Build the RPC layer.
//! let (client, dispatcher) = RpcLayer::new(
//!     out_tx,
//!     Arc::new(NullHandler),
//!     RpcConfig::default(),
//! );
//!
//! // Spawn the dispatch loop.
//! tokio::spawn(dispatcher.run(in_rx));
//!
//! // Wire the transport: forward received frames to in_tx,
//! // and drain out_rx to send frames.
//!
//! // Use the client.
//! let result = client.get(content_id, None).await?;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod client;
pub mod dispatch;
pub mod error;
pub mod pending;
pub mod router;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use client::{RpcClient, RpcConfig};
pub use dispatch::RpcDispatcher;
pub use error::{RpcError, RpcResult};
pub use pending::PendingRequests;
pub use router::{
    NullHandler, RequestHandler, RpcRouter,
    make_delete_ack, make_error_response, make_get_response,
    make_message_ack, make_query_response,
};

// ── RpcLayer — top-level constructor ─────────────────────────────────────────

use std::sync::Arc;
use tokio::sync::mpsc;
use muspell_proto::Frame;

/// Build an `(RpcClient, RpcDispatcher)` pair ready to be wired to the
/// transport layer.
///
/// ## Parameters
///
/// - `outgoing`    — frames to send to the peer (RPC → transport)
/// - `handler`     — handles incoming requests from the peer
/// - `unsolicited` — forwards frames with no known handler
///                   (Announce, StreamOpen, Extension, …)
/// - `config`      — timeouts and limits
///
/// ## Wiring
///
/// ```rust,ignore
/// let (client, dispatcher) = RpcLayer::new(
///     out_tx, Arc::new(MyHandler), unsolicited_tx, RpcConfig::default(),
/// );
/// tokio::spawn(dispatcher.run(in_rx));  // starts routing
/// ```
pub struct RpcLayer;

impl RpcLayer {
    /// Create an `(RpcClient, RpcDispatcher)` pair.
    ///
    /// Call `dispatcher.run(incoming_rx)` in a spawned task to start routing.
    #[must_use]
    pub fn new(
        outgoing:    mpsc::Sender<Frame>,
        handler:     Arc<dyn RequestHandler>,
        unsolicited: mpsc::Sender<Frame>,
        config:      RpcConfig,
    ) -> (RpcClient, RpcDispatcher) {
        let pending  = Arc::new(PendingRequests::new());
        let router   = Arc::new(RpcRouter::new(handler, outgoing.clone(), unsolicited));
        let client   = RpcClient::new(outgoing, pending.clone(), Arc::new(config));
        let dispatch = RpcDispatcher::new(pending, router);
        (client, dispatch)
    }
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use muspell_proto::{
        Bytes, ContentId, Frame, FrameBody, FrameId, GetFrame, MimeType,
        GetResult, DeleteFrame, QueryFrame, QueryKind, Timestamp,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::sync::mpsc;

    fn t(s: i64) -> Timestamp { Timestamp::from_secs(s) }

    // A test handler that returns known responses.
    struct TestStore {
        data: Bytes,
        cid:  ContentId,
    }

    #[async_trait]
    impl RequestHandler for TestStore {
        async fn handle_get(&self, req: GetFrame, id: FrameId) -> Frame {
            if req.content_id == self.cid {
                make_get_response(id, GetResult::Found {
                    content_id: self.cid,
                    mime:       MimeType::new("application/octet-stream"),
                    total_size: self.data.len() as u64,
                    payload:    self.data.clone(),
                    chunked:    false,
                })
            } else {
                make_get_response(id, GetResult::NotFound)
            }
        }

        async fn handle_delete(&self, _req: DeleteFrame, id: FrameId) -> Frame {
            make_delete_ack(id, true)
        }

        async fn handle_query(&self, _req: QueryFrame, id: FrameId) -> Frame {
            make_query_response(id, vec![], false)
        }
    }

    /// Build a connected pair: one client + one server, linked by in-memory
    /// channels in a single-process loopback.
    fn make_loopback() -> (RpcClient, RpcClient) {
        let data = Bytes::from_slice(b"hello muspell");
        let cid  = ContentId::blake3(b"hello muspell");

        // Side A acts as both client and server.
        // Side B is another client connected to A's handler.
        //
        // Channels:
        //   a_out → b_in   (A sends, B receives)
        //   b_out → a_in   (B sends, A receives)

        let (a_out, b_in) = mpsc::channel::<Frame>(64);
        let (b_out, a_in) = mpsc::channel::<Frame>(64);
        let (unsol_a, _)  = mpsc::channel::<Frame>(8);
        let (unsol_b, _)  = mpsc::channel::<Frame>(8);

        let cfg = RpcConfig::new().with_timeout(Duration::from_secs(5));

        let (client_a, dispatch_a) = RpcLayer::new(
            a_out,
            Arc::new(TestStore { data: data.clone(), cid }),
            unsol_a,
            cfg.clone(),
        );
        let (client_b, dispatch_b) = RpcLayer::new(
            b_out,
            Arc::new(TestStore { data, cid }),
            unsol_b,
            cfg,
        );

        // Both dispatchers run concurrently.
        tokio::spawn(dispatch_a.run(a_in));
        tokio::spawn(dispatch_b.run(b_in));

        (client_a, client_b)
    }

    // ── Full round-trip: get ──────────────────────────────────────────────────

    #[tokio::test]
    async fn loopback_get_found() {
        let (client_a, _client_b) = make_loopback();
        let cid = ContentId::blake3(b"hello muspell");

        let result = client_a.get(cid, None).await.unwrap();
        assert!(
            matches!(result, GetResult::Found { .. }),
            "expected Found, got: {result:?}",
        );
    }

    #[tokio::test]
    async fn loopback_get_not_found() {
        let (client_a, _) = make_loopback();
        let missing = ContentId::blake3(b"not there");
        let result  = client_a.get(missing, None).await.unwrap();
        assert!(matches!(result, GetResult::NotFound));
    }

    // ── Full round-trip: delete ───────────────────────────────────────────────

    #[tokio::test]
    async fn loopback_delete_returns_true() {
        let (client_a, _) = make_loopback();
        let cid     = ContentId::blake3(b"to delete");
        let deleted = client_a.delete(cid).await.unwrap();
        assert!(deleted);
    }

    // ── Full round-trip: query ────────────────────────────────────────────────

    #[tokio::test]
    async fn loopback_query_returns_empty() {
        let (client_a, _) = make_loopback();
        let results = client_a
            .query(QueryKind::NodesByCapabilityTag("relay".into()), Some(10))
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    // ── Concurrent requests on the same client ────────────────────────────────

    #[tokio::test]
    async fn concurrent_requests_all_resolve() {
        let (client_a, _) = make_loopback();
        let cid = ContentId::blake3(b"hello muspell");

        let handles: Vec<_> = (0..20)
            .map(|_| {
                let c = client_a.clone();
                tokio::spawn(async move { c.get(cid, None).await })
            })
            .collect();

        for h in handles {
            let result = h.await.unwrap().unwrap();
            assert!(matches!(result, GetResult::Found { .. }));
        }
    }

    // ── Bidirectional: both sides call each other ─────────────────────────────

    #[tokio::test]
    async fn bidirectional_calls() {
        let (client_a, client_b) = make_loopback();
        let cid = ContentId::blake3(b"hello muspell");

        let (ra, rb) = tokio::join!(
            client_a.get(cid, None),
            client_b.get(cid, None),
        );

        assert!(matches!(ra.unwrap(), GetResult::Found { .. }));
        assert!(matches!(rb.unwrap(), GetResult::Found { .. }));
    }
}
