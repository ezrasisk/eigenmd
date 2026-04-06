//! In-flight request correlation table.
//!
//! ## Lifecycle of a pending request
//!
//! ```text
//! RpcClient::call(request)
//!   │
//!   ├─ pending.register(request.id) → oneshot::Receiver<Frame>
//!   │
//!   ├─ send request frame to transport
//!   │
//!   │    ┌── (on the wire) ──────────────────────────────┐
//!   │    │  peer receives request                        │
//!   │    │  peer sends response with causation = req.id  │
//!   │    └───────────────────────────────────────────────┘
//!   │
//!   ├─ dispatch_loop receives response
//!   │   └─ pending.resolve(causation_id, response_frame)
//!   │       └─ oneshot::Sender::send(frame) → wakes caller
//!   │
//!   └─ caller .awaits the Receiver, gets the Frame
//!
//! If the future is dropped before resolution:
//!   └─ PendingGuard::drop() → pending.cancel(id)
//!       └─ removes the sender from the table (prevents leak)
//! ```
//!
//! ## Concurrency
//!
//! The table uses a `tokio::sync::Mutex` rather than `std::sync::Mutex`
//! because `register` and `resolve` are called from async contexts. The
//! lock is only held for the duration of a `HashMap` insert/remove — no
//! awaiting while locked.

use muspell_proto::FrameId;
use muspell_proto::Frame;
use std::collections::HashMap;
use tokio::sync::{oneshot, Mutex};
use tracing::warn;

// ── PendingRequests ───────────────────────────────────────────────────────────

/// Thread-safe in-flight request table.
///
/// Maps request `FrameId` → oneshot channel sender. When a response arrives
/// with a matching `causation`, the frame is delivered to the waiting caller.
#[derive(Default)]
pub struct PendingRequests {
    map: Mutex<HashMap<u128, oneshot::Sender<Frame>>>,
}

impl PendingRequests {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new in-flight request and return the receiver half.
    ///
    /// The caller `.await`s the returned `Receiver` to get the response.
    /// When the response arrives, `resolve` sends the frame through the channel.
    ///
    /// Storing the `FrameId` as `u128` avoids needing `Hash` on `FrameId`.
    pub async fn register(&self, id: FrameId) -> oneshot::Receiver<Frame> {
        let (tx, rx) = oneshot::channel();
        let mut guard = self.map.lock().await;
        guard.insert(id.as_u128(), tx);
        rx
    }

    /// Deliver a response frame to the caller waiting on `id`.
    ///
    /// Returns `true` if a caller was waiting and the frame was delivered.
    /// Returns `false` if no caller was registered (e.g. already cancelled).
    ///
    /// Called by the dispatch loop when a response frame arrives.
    pub async fn resolve(&self, id: FrameId, frame: Frame) -> bool {
        let tx = {
            let mut guard = self.map.lock().await;
            guard.remove(&id.as_u128())
        };
        match tx {
            None => {
                warn!(
                    "pending: received response for unknown request id={:032x}",
                    id.as_u128()
                );
                false
            }
            Some(sender) => {
                // If the receiver was dropped (cancelled), send() returns Err.
                // That's fine — we just discard the frame.
                sender.send(frame).is_ok()
            }
        }
    }

    /// Remove the entry for `id` without delivering a response.
    ///
    /// Called when a pending future is cancelled (dropped). Prevents
    /// the table from growing unboundedly when callers bail out early.
    pub async fn cancel(&self, id: FrameId) {
        let mut guard = self.map.lock().await;
        guard.remove(&id.as_u128());
    }

    /// Number of currently in-flight requests.
    pub async fn len(&self) -> usize {
        self.map.lock().await.len()
    }

    /// Returns `true` if no requests are currently in-flight.
    pub async fn is_empty(&self) -> bool {
        self.map.lock().await.is_empty()
    }
}

// ── PendingGuard ──────────────────────────────────────────────────────────────

/// An RAII guard that cancels a pending request when dropped.
///
/// Wrap the `oneshot::Receiver` in this guard so that if the calling
/// future is dropped before the response arrives, the pending table is
/// cleaned up and the memory is freed.
///
/// ## Usage
///
/// ```rust,ignore
/// let rx = pending.register(frame_id).await;
/// let guard = PendingGuard::new(frame_id, pending.clone(), rx);
/// // Await the guard — it transparently awaits the receiver.
/// let response = guard.await?;
/// ```
pub struct PendingGuard {
    id:      FrameId,
    pending: std::sync::Arc<PendingRequests>,
    rx:      Option<oneshot::Receiver<Frame>>,
}

impl PendingGuard {
    /// Wrap a registered receiver in a cancellation guard.
    #[must_use]
    pub fn new(
        id:      FrameId,
        pending: std::sync::Arc<PendingRequests>,
        rx:      oneshot::Receiver<Frame>,
    ) -> Self {
        Self { id, pending, rx: Some(rx) }
    }

    /// Await the response, returning the `Frame` or an error.
    ///
    /// Consumes `self` — once awaited, the guard is done regardless of outcome.
    pub async fn await_response(mut self) -> Result<Frame, crate::error::RpcError> {
        let rx = self.rx.take().expect("rx is always Some before await_response");
        match rx.await {
            Ok(frame) => Ok(frame),
            Err(_)    => Err(crate::error::RpcError::ChannelClosed),
        }
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        // If rx is still Some, the guard was dropped without being awaited —
        // that means the future was cancelled. Clean up the pending table.
        if self.rx.is_some() {
            let pending = self.pending.clone();
            let id      = self.id;
            // Spawn a cleanup task. This is a best-effort fire-and-forget;
            // the map will also be cleaned up on the next resolve() miss.
            tokio::spawn(async move {
                pending.cancel(id).await;
            });
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{
        Frame, FrameBody, FrameId, PingFrame, Timestamp,
    };
    use std::sync::Arc;

    fn fid(v: u128) -> FrameId { FrameId::from_u128(v) }
    fn t(s: i64) -> Timestamp  { Timestamp::from_secs(s) }

    fn ping_frame(id: u128) -> Frame {
        Frame::new(
            fid(id), t(0),
            FrameBody::Ping(PingFrame { nonce: 1, sent_at: t(0) }),
        )
    }

    // ── Basic register / resolve ──────────────────────────────────────────────

    #[tokio::test]
    async fn register_then_resolve_delivers_frame() {
        let pending = PendingRequests::new();
        let id      = fid(42);
        let frame   = ping_frame(42);

        let rx      = pending.register(id).await;
        let resolved = pending.resolve(id, frame.clone()).await;

        assert!(resolved, "resolve should return true when a caller is waiting");
        let received = rx.await.expect("receiver should get the frame");
        assert_eq!(received, frame);
    }

    #[tokio::test]
    async fn resolve_with_no_caller_returns_false() {
        let pending = PendingRequests::new();
        let frame   = ping_frame(99);
        let resolved = pending.resolve(fid(99), frame).await;
        assert!(!resolved);
    }

    #[tokio::test]
    async fn cancel_removes_entry() {
        let pending = Arc::new(PendingRequests::new());
        let id      = fid(7);
        let _rx     = pending.register(id).await;

        assert_eq!(pending.len().await, 1);
        pending.cancel(id).await;
        assert_eq!(pending.len().await, 0);
    }

    #[tokio::test]
    async fn multiple_requests_independent() {
        let pending = PendingRequests::new();

        let id_a  = fid(1);
        let id_b  = fid(2);
        let frame_a = ping_frame(1);
        let frame_b = ping_frame(2);

        let rx_a = pending.register(id_a).await;
        let rx_b = pending.register(id_b).await;

        assert_eq!(pending.len().await, 2);

        pending.resolve(id_b, frame_b.clone()).await;
        pending.resolve(id_a, frame_a.clone()).await;

        assert_eq!(rx_a.await.unwrap(), frame_a);
        assert_eq!(rx_b.await.unwrap(), frame_b);
        assert!(pending.is_empty().await);
    }

    // ── PendingGuard ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn guard_await_response_delivers_frame() {
        let pending = Arc::new(PendingRequests::new());
        let id      = fid(10);
        let frame   = ping_frame(10);

        let rx    = pending.register(id).await;
        let guard = PendingGuard::new(id, pending.clone(), rx);

        pending.resolve(id, frame.clone()).await;
        let result = guard.await_response().await.unwrap();
        assert_eq!(result, frame);
    }

    #[tokio::test]
    async fn guard_drop_cancels_pending() {
        let pending = Arc::new(PendingRequests::new());
        let id      = fid(20);

        let rx    = pending.register(id).await;
        let guard = PendingGuard::new(id, pending.clone(), rx);

        assert_eq!(pending.len().await, 1);

        // Drop the guard without awaiting it — should trigger cancellation.
        drop(guard);

        // Give the spawned cleanup task a moment to run.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(pending.len().await, 0);
    }

    #[tokio::test]
    async fn guard_channel_closed_returns_error() {
        let pending = Arc::new(PendingRequests::new());
        let id      = fid(30);

        let rx    = pending.register(id).await;
        let guard = PendingGuard::new(id, pending.clone(), rx);

        // Cancel the pending entry, which drops the sender.
        pending.cancel(id).await;

        // Now the channel is closed — guard should return ChannelClosed.
        let err = guard.await_response().await.unwrap_err();
        assert!(matches!(err, crate::error::RpcError::ChannelClosed));
    }
}
