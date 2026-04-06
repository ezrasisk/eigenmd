//! Server-side request dispatch — `RequestHandler` trait and `RpcRouter`.
//!
//! ## Architecture
//!
//! ```text
//! dispatch loop receives a Frame with no causation (= a new request)
//!          │
//!          ▼
//!     RpcRouter::route(frame)
//!          │
//!          ├── FrameBody::Get(req)    → handler.handle_get(req, id)    → response frame
//!          ├── FrameBody::Put(req)    → handler.handle_put(req, id)    → response frame
//!          ├── FrameBody::Delete(req) → handler.handle_delete(req, id) → response frame
//!          ├── FrameBody::Query(req)  → handler.handle_query(req, id)  → response frame
//!          ├── FrameBody::Message(m)  → handler.handle_message(m, id)  → response frame
//!          └── anything else         → NoHandler error frame sent back
//!
//! response frame has causation = request.id so the remote client can correlate.
//! ```
//!
//! ## Implementing a handler
//!
//! ```rust,ignore
//! struct MyStore;
//!
//! #[async_trait]
//! impl RequestHandler for MyStore {
//!     async fn handle_get(&self, req: GetFrame, id: FrameId) -> Frame {
//!         // look up content…
//!         make_get_response(id, GetResult::NotFound)
//!     }
//!     // implement other methods or use default no-op impls
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use muspell_proto::{
    DeleteFrame, ErrorCode, ErrorFrame, Frame, FrameBody, FrameId,
    GetFrame, GetResponseFrame, GetResult, MessageAckFrame, MessageFrame,
    MessageStatus, PutFrame, QueryFrame, QueryResponseFrame, Timestamp,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

// ── Helpers — response frame constructors ─────────────────────────────────────

/// Build a `GetResponse` frame in reply to request `req_id`.
#[must_use]
pub fn make_get_response(req_id: FrameId, result: GetResult) -> Frame {
    Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::GetResponse(GetResponseFrame { request_id: req_id, result }),
    ).with_causation(req_id)
}

/// Build a `DeleteAck` frame in reply to request `req_id`.
#[must_use]
pub fn make_delete_ack(req_id: FrameId, deleted: bool) -> Frame {
    use muspell_proto::DeleteAckFrame;
    Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::DeleteAck(DeleteAckFrame { request_id: req_id, deleted }),
    ).with_causation(req_id)
}

/// Build a `QueryResponse` frame in reply to request `req_id`.
#[must_use]
pub fn make_query_response(
    req_id:   FrameId,
    results:  Vec<muspell_proto::QueryResult>,
    has_more: bool,
) -> Frame {
    Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::QueryResponse(QueryResponseFrame {
            query_id: req_id,
            results,
            has_more,
        }),
    ).with_causation(req_id)
}

/// Build a `MessageAck` frame in reply to a message.
#[must_use]
pub fn make_message_ack(message_id: FrameId, status: MessageStatus) -> Frame {
    Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::MessageAck(MessageAckFrame { message_id, status }),
    ).with_causation(message_id)
}

/// Build a recoverable `ErrorFrame` in reply to request `req_id`.
#[must_use]
pub fn make_error_response(
    req_id:  FrameId,
    code:    ErrorCode,
    message: impl Into<String>,
) -> Frame {
    Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::Error(ErrorFrame {
            code,
            message:       message.into(),
            related_frame: Some(req_id),
            fatal:         false,
        }),
    ).with_causation(req_id)
}

// ── RequestHandler ────────────────────────────────────────────────────────────

/// Trait implemented by anything that handles incoming RPC requests.
///
/// Each method receives the typed request struct and the `FrameId` of the
/// originating request frame (needed to set `causation` on the response).
///
/// ## Default implementations
///
/// Every method has a default implementation that returns an `ErrorFrame`
/// with `ErrorCode::UnknownFrameType`. Implementors only need to override
/// the methods they support.
///
/// ## Async trait
///
/// Uses `#[async_trait]` to allow `async fn` in trait definitions.
/// The macro boxes the returned futures; performance-sensitive code should
/// benchmark and consider manual `Pin<Box<dyn Future>>` if needed.
#[async_trait]
pub trait RequestHandler: Send + Sync {
    /// Handle a `Get` request (fetch content by address).
    async fn handle_get(&self, req: GetFrame, id: FrameId) -> Frame {
        make_error_response(id, ErrorCode::UnknownFrameType, "Get not supported")
    }

    /// Handle a `Put` request (store a content blob).
    async fn handle_put(&self, req: PutFrame, id: FrameId) -> Frame {
        let _ = req;
        make_error_response(id, ErrorCode::UnknownFrameType, "Put not supported")
    }

    /// Handle a `Delete` request (remove a content blob).
    async fn handle_delete(&self, req: DeleteFrame, id: FrameId) -> Frame {
        let _ = req;
        make_error_response(id, ErrorCode::UnknownFrameType, "Delete not supported")
    }

    /// Handle a `Query` request (discover nodes/content/namespaces).
    async fn handle_query(&self, req: QueryFrame, id: FrameId) -> Frame {
        let _ = req;
        make_error_response(id, ErrorCode::UnknownFrameType, "Query not supported")
    }

    /// Handle an incoming `Message` (end-to-end encrypted).
    async fn handle_message(&self, msg: MessageFrame, id: FrameId) -> Frame {
        let _ = msg;
        make_message_ack(id, MessageStatus::Rejected)
    }
}

// ── NullHandler ───────────────────────────────────────────────────────────────

/// A `RequestHandler` that rejects every request.
///
/// Useful as a default or placeholder while building out node functionality.
pub struct NullHandler;

#[async_trait]
impl RequestHandler for NullHandler {}

// ── RpcRouter ─────────────────────────────────────────────────────────────────

/// Routes incoming request frames to the appropriate `RequestHandler` method,
/// then sends the response back via the outgoing channel.
///
/// ## Unsolicited frames
///
/// Frames that are neither requests nor responses (e.g. `Announce`) are
/// forwarded to the `unsolicited` channel for the application layer to handle.
/// If the channel is full or closed, the frame is dropped with a warning.
pub struct RpcRouter {
    handler:     Arc<dyn RequestHandler>,
    outgoing:    mpsc::Sender<Frame>,
    unsolicited: mpsc::Sender<Frame>,
}

impl RpcRouter {
    /// Create a new router.
    ///
    /// - `handler`     — handles Get / Put / Delete / Query / Message
    /// - `outgoing`    — frames to send to the peer
    /// - `unsolicited` — frames with no causation and no known handler
    ///                   (Announce, StreamOpen, Extension, etc.)
    #[must_use]
    pub fn new(
        handler:     Arc<dyn RequestHandler>,
        outgoing:    mpsc::Sender<Frame>,
        unsolicited: mpsc::Sender<Frame>,
    ) -> Self {
        Self { handler, outgoing, unsolicited }
    }

    /// Route one incoming frame.
    ///
    /// - Response frames (causation is set) are NOT handled here — they go to
    ///   the pending table in the dispatch loop.
    /// - Request frames are dispatched to the handler.
    /// - Everything else is forwarded to the unsolicited channel.
    pub async fn route(&self, frame: Frame) {
        let req_id = frame.id;

        let response = match frame.body {
            FrameBody::Get(req) => {
                debug!("router: Get id={:032x}", req_id.as_u128());
                self.handler.handle_get(req, req_id).await
            }
            FrameBody::Put(req) => {
                debug!("router: Put id={:032x}", req_id.as_u128());
                self.handler.handle_put(req, req_id).await
            }
            FrameBody::Delete(req) => {
                debug!("router: Delete id={:032x}", req_id.as_u128());
                self.handler.handle_delete(req, req_id).await
            }
            FrameBody::Query(req) => {
                debug!("router: Query id={:032x}", req_id.as_u128());
                self.handler.handle_query(req, req_id).await
            }
            FrameBody::Message(msg) => {
                debug!("router: Message id={:032x}", req_id.as_u128());
                self.handler.handle_message(msg, req_id).await
            }
            // Unknown or unsolicited frame types.
            other => {
                let name = other.variant_name();
                debug!("router: unsolicited {} id={:032x}", name, req_id.as_u128());
                let unsolicited_frame = Frame::new(req_id, Timestamp::ZERO, other);
                if let Err(e) = self.unsolicited.try_send(unsolicited_frame) {
                    warn!("router: unsolicited channel full/closed, dropping {name}: {e}");
                }
                return;
            }
        };

        // Send the response back to the peer.
        if let Err(e) = self.outgoing.send(response).await {
            warn!("router: outgoing channel closed, could not send response: {e}");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{
        Bytes, ContentId, Frame, FrameBody, FrameId, GetFrame, MimeType,
        PutFrame, Timestamp,
    };
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn fid(v: u128) -> FrameId { FrameId::from_u128(v) }
    fn t(s: i64)   -> Timestamp { Timestamp::from_secs(s) }

    // ── NullHandler ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn null_handler_get_returns_error() {
        let h  = NullHandler;
        let id = fid(1);
        let resp = h.handle_get(
            GetFrame { content_id: ContentId::blake3(b"x"), byte_range: None },
            id,
        ).await;
        assert!(matches!(resp.body, FrameBody::Error(_)));
        assert_eq!(resp.causation, Some(id));
    }

    // ── Custom handler ────────────────────────────────────────────────────────

    struct EchoStore;

    #[async_trait]
    impl RequestHandler for EchoStore {
        async fn handle_get(&self, req: GetFrame, id: FrameId) -> Frame {
            make_get_response(id, GetResult::NotFound)
        }

        async fn handle_delete(&self, req: DeleteFrame, id: FrameId) -> Frame {
            let _ = req;
            make_delete_ack(id, false)
        }

        async fn handle_query(&self, req: QueryFrame, id: FrameId) -> Frame {
            let _ = req;
            make_query_response(id, vec![], false)
        }
    }

    fn make_router() -> (RpcRouter, mpsc::Receiver<Frame>, mpsc::Receiver<Frame>) {
        let (out_tx, out_rx)   = mpsc::channel(32);
        let (unsol_tx, unsol_rx) = mpsc::channel(32);
        let router = RpcRouter::new(Arc::new(EchoStore), out_tx, unsol_tx);
        (router, out_rx, unsol_rx)
    }

    #[tokio::test]
    async fn router_dispatches_get_to_handler() {
        let (router, mut out, _unsol) = make_router();
        let id = fid(10);
        let frame = Frame::new(id, t(0), FrameBody::Get(GetFrame {
            content_id: ContentId::blake3(b"x"),
            byte_range: None,
        }));
        router.route(frame).await;
        let response = out.recv().await.expect("response sent");
        assert!(matches!(response.body, FrameBody::GetResponse(_)));
        assert_eq!(response.causation, Some(id));
    }

    #[tokio::test]
    async fn router_dispatches_delete_to_handler() {
        let (router, mut out, _unsol) = make_router();
        let id = fid(20);
        let frame = Frame::new(id, t(0), FrameBody::Delete(DeleteFrame {
            content_id: ContentId::blake3(b"del"),
        }));
        router.route(frame).await;
        let response = out.recv().await.unwrap();
        assert!(matches!(response.body, FrameBody::DeleteAck(_)));
        assert_eq!(response.causation, Some(id));
    }

    #[tokio::test]
    async fn router_forwards_unknown_to_unsolicited() {
        let (router, _out, mut unsol) = make_router();
        let id = fid(30);
        // Announce has no response — goes to unsolicited.
        let frame = Frame::new(id, t(0), FrameBody::Announce(muspell_proto::AnnounceFrame {
            node_id:        muspell_proto::NodeId::from_bytes([1u8; 32]),
            did:            None,
            namespaces:     vec![],
            content_sample: vec![],
            ttl_secs:       300,
        }));
        router.route(frame).await;
        let unsol_frame = unsol.recv().await.expect("unsolicited frame forwarded");
        assert!(matches!(unsol_frame.body, FrameBody::Announce(_)));
    }

    #[tokio::test]
    async fn router_get_response_has_correct_causation() {
        let (router, mut out, _unsol) = make_router();
        let id = fid(77);
        router.route(Frame::new(id, t(0), FrameBody::Get(GetFrame {
            content_id: ContentId::blake3(b"y"),
            byte_range: None,
        }))).await;
        let resp = out.recv().await.unwrap();
        // causation must equal the request id
        assert_eq!(resp.causation, Some(id));
    }

    // ── Response helpers ──────────────────────────────────────────────────────

    #[test]
    fn make_get_response_sets_causation() {
        let id   = fid(1);
        let resp = make_get_response(id, GetResult::NotFound);
        assert_eq!(resp.causation, Some(id));
        assert!(matches!(resp.body, FrameBody::GetResponse(_)));
    }

    #[test]
    fn make_delete_ack_sets_causation() {
        let id   = fid(2);
        let resp = make_delete_ack(id, true);
        assert_eq!(resp.causation, Some(id));
        if let FrameBody::DeleteAck(a) = resp.body {
            assert!(a.deleted);
        } else {
            panic!("expected DeleteAck");
        }
    }

    #[test]
    fn make_error_response_is_non_fatal() {
        let id   = fid(3);
        let resp = make_error_response(id, ErrorCode::NotFound, "missing");
        assert_eq!(resp.causation, Some(id));
        if let FrameBody::Error(e) = resp.body {
            assert!(!e.fatal);
            assert_eq!(e.code, ErrorCode::NotFound);
        } else {
            panic!("expected Error");
        }
    }

    #[test]
    fn make_message_ack_sets_causation() {
        let id   = fid(4);
        let resp = make_message_ack(id, MessageStatus::Delivered);
        assert_eq!(resp.causation, Some(id));
        if let FrameBody::MessageAck(a) = resp.body {
            assert!(matches!(a.status, MessageStatus::Delivered));
        } else {
            panic!("expected MessageAck");
        }
    }
}
