//! `RpcClient` — typed, async request/response calls over a Muspell connection.
//!
//! ## Usage pattern
//!
//! ```rust,ignore
//! let (client, dispatcher) = RpcLayer::new(outgoing_tx, handler, RpcConfig::default());
//! tokio::spawn(dispatcher.run(incoming_rx));
//! let result = client.get(content_id, None).await?;
//! ```
//!
//! ## Request correlation
//!
//! Every request gets a unique `FrameId`. The dispatch loop matches responses
//! to waiting futures via `response.causation == request.id`.
//!
//! ## Timeouts
//!
//! Every call is wrapped in `tokio::time::timeout`. On expiry the in-flight
//! entry is cleaned up and `RpcError::Timeout` is returned.

use std::{sync::Arc, time::Duration};
use muspell_proto::{
    Bytes, ContentId, DeleteFrame, Frame, FrameBody, FrameId,
    GetFrame, MessageFrame, MimeType, PutFrame, QueryFrame, QueryKind,
    QueryResult, GetResult, MessageStatus, Timestamp, ByteRange, Did,
};
use tokio::{sync::mpsc, time::timeout};
use tracing::debug;

use crate::error::{RpcError, RpcResult};
use crate::pending::{PendingGuard, PendingRequests};

// ── RpcConfig ─────────────────────────────────────────────────────────────────

/// Configuration for the RPC layer.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// Timeout for each individual call. Default: 30 seconds.
    pub call_timeout: Duration,
    /// Maximum number of in-flight requests at once. Default: 512.
    pub max_in_flight: usize,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            call_timeout:  Duration::from_secs(30),
            max_in_flight: 512,
        }
    }
}

impl RpcConfig {
    /// Create with default values.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Override the per-call timeout.
    #[must_use]
    pub fn with_timeout(mut self, d: Duration) -> Self {
        self.call_timeout = d; self
    }

    /// Override the maximum in-flight request count.
    #[must_use]
    pub fn with_max_in_flight(mut self, n: usize) -> Self {
        self.max_in_flight = n; self
    }
}

// ── RpcClient ─────────────────────────────────────────────────────────────────

/// A typed, `Clone`-able RPC client.
///
/// `RpcClient` is `Clone + Send + Sync` — share it freely across tasks.
#[derive(Clone)]
pub struct RpcClient {
    outgoing: mpsc::Sender<Frame>,
    pending:  Arc<PendingRequests>,
    config:   Arc<RpcConfig>,
}

impl RpcClient {
    /// Construct. Prefer `RpcLayer::new`.
    #[must_use]
    pub(crate) fn new(
        outgoing: mpsc::Sender<Frame>,
        pending:  Arc<PendingRequests>,
        config:   Arc<RpcConfig>,
    ) -> Self {
        Self { outgoing, pending, config }
    }

    // ── Generic call ──────────────────────────────────────────────────────────

    /// Send a request frame and await the matching response.
    ///
    /// The response is matched by `response.causation == frame.id`.
    ///
    /// # Errors
    /// - `RpcError::ChannelClosed` if the transport task has exited.
    /// - `RpcError::Timeout` if no response arrives within the configured window.
    /// - `RpcError::PeerError` if the peer responds with an `ErrorFrame`.
    pub async fn call(&self, frame: Frame) -> RpcResult<Frame> {
        let id          = frame.id;
        let timeout_dur = self.config.call_timeout;
        let name        = frame.variant_name();

        // Register *before* sending to eliminate the race where the response
        // arrives before we register.
        let rx    = self.pending.register(id).await;
        let guard = PendingGuard::new(id, self.pending.clone(), rx);

        self.outgoing.send(frame).await
            .map_err(|_| RpcError::ChannelClosed)?;

        debug!("rpc: sent {} id={:032x}", name, id.as_u128());

        match timeout(timeout_dur, guard.await_response()).await {
            Ok(Ok(response)) => {
                // Peer error frames are converted here so typed callers
                // never see a raw ErrorFrame.
                if let FrameBody::Error(e) = response.body {
                    return Err(RpcError::peer(e.code, e.message, e.fatal));
                }
                Ok(response)
            }
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => Err(RpcError::Timeout {
                request: name,
                after:   timeout_dur,
            }),
        }
    }

    // ── Typed calls ───────────────────────────────────────────────────────────

    /// Request a content blob by address.
    ///
    /// Returns the typed `GetResult` — `NotFound`, `Denied`, and `Unavailable`
    /// are application-level outcomes, not `RpcError`s.
    pub async fn get(
        &self,
        content_id: ContentId,
        byte_range: Option<ByteRange>,
    ) -> RpcResult<GetResult> {
        let frame = self.make_frame(FrameBody::Get(GetFrame { content_id, byte_range }));
        let response = self.call(frame).await?;
        match response.body {
            FrameBody::GetResponse(r) => Ok(r.result),
            other => Err(unexpected_response("GetResponse", other.variant_name())),
        }
    }

    /// Push a content blob to the peer and await confirmation.
    ///
    /// The peer MUST verify `content_id` against the received `data`.
    /// A hash mismatch will come back as `RpcError::PeerError { code: HashMismatch }`.
    pub async fn put(
        &self,
        content_id: ContentId,
        mime:       MimeType,
        data:       Bytes,
    ) -> RpcResult<()> {
        let total = data.len() as u64;
        let frame = self.make_frame(FrameBody::Put(PutFrame {
            content_id,
            mime,
            total_size: total,
            payload:    data,
            chunked:    false,
        }));
        let response = self.call(frame).await?;
        // The node layer responds to Put with a GetResponse(Found) on success.
        match response.body {
            FrameBody::GetResponse(_) => Ok(()),
            other => Err(unexpected_response("GetResponse", other.variant_name())),
        }
    }

    /// Request deletion of a content blob.
    ///
    /// Returns `true` if the peer found and deleted the content,
    /// `false` if it was not present.
    pub async fn delete(&self, content_id: ContentId) -> RpcResult<bool> {
        let frame = self.make_frame(FrameBody::Delete(DeleteFrame { content_id }));
        let response = self.call(frame).await?;
        match response.body {
            FrameBody::DeleteAck(a) => Ok(a.deleted),
            other => Err(unexpected_response("DeleteAck", other.variant_name())),
        }
    }

    /// Query the peer for nodes, content, or namespaces.
    ///
    /// Returns the matching results. An empty `Vec` means no matches were found.
    pub async fn query(
        &self,
        kind:  QueryKind,
        limit: Option<u32>,
    ) -> RpcResult<Vec<QueryResult>> {
        let frame = self.make_frame(FrameBody::Query(QueryFrame { kind, limit }));
        let response = self.call(frame).await?;
        match response.body {
            FrameBody::QueryResponse(r) => Ok(r.results),
            other => Err(unexpected_response("QueryResponse", other.variant_name())),
        }
    }

    /// Send an end-to-end encrypted message to a `Did`.
    ///
    /// The `encrypted_payload` must be encrypted by the caller using the
    /// recipient's public key — this layer is transport only.
    ///
    /// Returns the delivery status reported by the relay or destination node.
    pub async fn send_message(
        &self,
        to:                Did,
        from:              Did,
        encrypted_payload: Bytes,
    ) -> RpcResult<MessageStatus> {
        let message_id = FrameId::random();
        let now        = Timestamp::now().unwrap_or(Timestamp::ZERO);
        let frame = self.make_frame(FrameBody::Message(MessageFrame {
            to,
            from,
            encrypted_payload,
            sent_at:    now,
            message_id,
        }));
        let response = self.call(frame).await?;
        match response.body {
            FrameBody::MessageAck(a) => Ok(a.status),
            other => Err(unexpected_response("MessageAck", other.variant_name())),
        }
    }

    // ── Pending table introspection ───────────────────────────────────────────

    /// Number of currently in-flight requests.
    pub async fn in_flight(&self) -> usize {
        self.pending.len().await
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Build a new frame with a random ID and current timestamp.
    fn make_frame(&self, body: FrameBody) -> Frame {
        Frame::new(
            FrameId::random(),
            Timestamp::now().unwrap_or(Timestamp::ZERO),
            body,
        )
    }
}

/// Construct a `PeerError` for when the response body is the wrong type.
///
/// This should be extremely rare in production — it indicates a protocol
/// mismatch between peers (different proto versions with breaking changes).
fn unexpected_response(expected: &str, got: &'static str) -> RpcError {
    use muspell_proto::ErrorCode;
    RpcError::peer(
        ErrorCode::UnknownFrameType,
        format!("expected {expected}, got {got}"),
        false,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{
        ContentId, DeleteAckFrame, Frame, FrameBody, FrameId,
        GetResponseFrame, GetResult, MimeType, PongFrame, QueryResponseFrame,
        Timestamp,
    };
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn t(s: i64) -> Timestamp { Timestamp::from_secs(s) }
    fn fid(v: u128) -> FrameId { FrameId::from_u128(v) }

    /// Simulate the dispatch loop: wait for a request on `incoming`, inspect it,
    /// and send back a response with `causation = request.id`.
    async fn respond_with<F>(
        incoming: &mut mpsc::Receiver<Frame>,
        pending:  &Arc<PendingRequests>,
        make_response: F,
    ) where
        F: FnOnce(FrameId) -> FrameBody,
    {
        let req = incoming.recv().await.expect("request frame");
        let response = Frame::new(
            FrameId::random(),
            Timestamp::ZERO,
            make_response(req.id),
        ).with_causation(req.id);
        pending.resolve(req.id, response).await;
    }

    fn make_client() -> (RpcClient, mpsc::Receiver<Frame>, Arc<PendingRequests>) {
        let (tx, rx) = mpsc::channel(32);
        let pending  = Arc::new(PendingRequests::new());
        let config   = Arc::new(RpcConfig::new().with_timeout(Duration::from_secs(5)));
        let client   = RpcClient::new(tx, pending.clone(), config);
        (client, rx, pending)
    }

    // ── get ───────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_returns_found() {
        let (client, mut rx, pending) = make_client();
        let cid  = ContentId::blake3(b"hello");
        let data = Bytes::from_slice(b"hello");

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.get(cid, None).await }
        });

        respond_with(&mut rx, &pending, |req_id| {
            FrameBody::GetResponse(GetResponseFrame {
                request_id: req_id,
                result: GetResult::Found {
                    content_id: cid,
                    mime:       MimeType::new("application/octet-stream"),
                    total_size: 5,
                    payload:    data.clone(),
                    chunked:    false,
                },
            })
        }).await;

        let result = call.await.unwrap().unwrap();
        assert!(matches!(result, GetResult::Found { .. }));
    }

    #[tokio::test]
    async fn get_returns_not_found() {
        let (client, mut rx, pending) = make_client();
        let cid = ContentId::blake3(b"missing");

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.get(cid, None).await }
        });

        respond_with(&mut rx, &pending, |req_id| {
            FrameBody::GetResponse(GetResponseFrame {
                request_id: req_id,
                result:     GetResult::NotFound,
            })
        }).await;

        let result = call.await.unwrap().unwrap();
        assert!(matches!(result, GetResult::NotFound));
    }

    // ── delete ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_returns_true_when_found() {
        let (client, mut rx, pending) = make_client();
        let cid = ContentId::blake3(b"data");

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.delete(cid).await }
        });

        respond_with(&mut rx, &pending, |req_id| {
            FrameBody::DeleteAck(DeleteAckFrame { request_id: req_id, deleted: true })
        }).await;

        assert_eq!(call.await.unwrap().unwrap(), true);
    }

    #[tokio::test]
    async fn delete_returns_false_when_not_found() {
        let (client, mut rx, pending) = make_client();
        let cid = ContentId::blake3(b"ghost");

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.delete(cid).await }
        });

        respond_with(&mut rx, &pending, |req_id| {
            FrameBody::DeleteAck(DeleteAckFrame { request_id: req_id, deleted: false })
        }).await;

        assert_eq!(call.await.unwrap().unwrap(), false);
    }

    // ── query ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn query_returns_results() {
        let (client, mut rx, pending) = make_client();

        let call = tokio::spawn({
            let client = client.clone();
            async move {
                client.query(
                    QueryKind::NodesByCapabilityTag("relay".into()),
                    Some(10),
                ).await
            }
        });

        respond_with(&mut rx, &pending, |req_id| {
            FrameBody::QueryResponse(QueryResponseFrame {
                query_id: req_id,
                results:  vec![],
                has_more: false,
            })
        }).await;

        let results = call.await.unwrap().unwrap();
        assert!(results.is_empty());
    }

    // ── peer error propagation ────────────────────────────────────────────────

    #[tokio::test]
    async fn call_converts_error_frame_to_peer_error() {
        use muspell_proto::{ErrorCode, ErrorFrame};
        let (client, mut rx, pending) = make_client();
        let cid = ContentId::blake3(b"x");

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.get(cid, None).await }
        });

        respond_with(&mut rx, &pending, |req_id| {
            FrameBody::Error(ErrorFrame {
                code:          ErrorCode::NotFound,
                message:       "not here".into(),
                related_frame: Some(req_id),
                fatal:         false,
            })
        }).await;

        let err = call.await.unwrap().unwrap_err();
        assert!(matches!(err, RpcError::PeerError { .. }));
    }

    // ── timeout ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn call_times_out_when_no_response() {
        let (tx, _rx) = mpsc::channel::<Frame>(32);
        let pending   = Arc::new(PendingRequests::new());
        let config    = Arc::new(
            RpcConfig::new().with_timeout(Duration::from_millis(50))
        );
        let client = RpcClient::new(tx, pending, config);
        let cid    = ContentId::blake3(b"slow");

        let err = client.get(cid, None).await.unwrap_err();
        assert!(
            matches!(err, RpcError::Timeout { .. }),
            "expected Timeout, got: {err:?}"
        );
    }

    // ── channel closed ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn call_returns_channel_closed_when_sender_dropped() {
        let (tx, rx) = mpsc::channel::<Frame>(1);
        drop(rx); // simulate transport task dying
        let pending = Arc::new(PendingRequests::new());
        let config  = Arc::new(RpcConfig::new());
        let client  = RpcClient::new(tx, pending, config);
        let cid     = ContentId::blake3(b"x");

        let err = client.get(cid, None).await.unwrap_err();
        assert!(matches!(err, RpcError::ChannelClosed));
    }

    // ── config ────────────────────────────────────────────────────────────────

    #[test]
    fn rpc_config_builder() {
        let cfg = RpcConfig::new()
            .with_timeout(Duration::from_secs(10))
            .with_max_in_flight(100);
        assert_eq!(cfg.call_timeout, Duration::from_secs(10));
        assert_eq!(cfg.max_in_flight, 100);
    }

    // ── in_flight counter ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn in_flight_increments_while_pending() {
        let (client, _rx, pending) = make_client();

        assert_eq!(client.in_flight().await, 0);

        // Register manually to simulate an in-flight call.
        let _dummy_rx = pending.register(fid(99)).await;
        assert_eq!(client.in_flight().await, 1);

        pending.cancel(fid(99)).await;
        assert_eq!(client.in_flight().await, 0);
    }
}
