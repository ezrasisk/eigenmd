//! `PubSubRouter` — routes incoming frames into the local manager.
//!
//! ## Responsibility
//!
//! The router sits between the transport layer and the `SubscriptionManager`.
//! It receives raw `Frame`s from the transport's incoming channel and:
//!
//! 1. Tries to decode each frame as a pub/sub frame.
//! 2. Routes decoded frames:
//!    - `Message`     → `manager.deliver()`
//!    - `Subscribe`   → records that the remote peer wants this topic
//!    - `Unsubscribe` → removes the remote peer's interest
//! 3. Ignores frames that are not pub/sub frames (passes them to the
//!    `unsolicited` channel for the node layer).
//!
//! ## Remote subscription tracking
//!
//! When a remote peer sends a `Subscribe` frame, the router records their
//! `NodeId` as interested in that topic. When a local `Publisher` publishes,
//! the node layer can call `router.remote_subscribers(topic_id)` to find
//! which peers should receive the message — and forward it over their
//! connections.
//!
//! This router tracks interests; it does NOT open connections. Forwarding
//! is the node layer's responsibility.

use dashmap::DashMap;
use muspell_proto::{Frame, NodeId};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::error::PubSubResult;
use crate::manager::SubscriptionManager;
use crate::message::{try_decode_pubsub_frame, DecodedPubSubFrame};
use crate::topic::TopicId;

// ── RemoteInterestTable ───────────────────────────────────────────────────────

/// Tracks which remote peers have subscribed to which topics.
///
/// Key:   `[u8; 32]` (TopicId bytes)
/// Value: set of `NodeId`s that have sent a `Subscribe` for this topic.
#[derive(Default)]
struct RemoteInterestTable {
    map: DashMap<[u8; 32], HashSet<[u8; 32]>>,
}

impl RemoteInterestTable {
    fn add(&self, topic_id: TopicId, node_id: NodeId) {
        self.map
            .entry(*topic_id.as_bytes())
            .or_default()
            .insert(*node_id.as_bytes());
    }

    fn remove(&self, topic_id: TopicId, node_id: NodeId) {
        if let Some(mut set) = self.map.get_mut(topic_id.as_bytes()) {
            set.remove(node_id.as_bytes());
        }
    }

    fn remove_all_for_node(&self, node_id: NodeId) {
        let key = *node_id.as_bytes();
        for mut entry in self.map.iter_mut() {
            entry.value_mut().remove(&key);
        }
    }

    fn subscribers(&self, topic_id: TopicId) -> Vec<NodeId> {
        self.map
            .get(topic_id.as_bytes())
            .map(|set| {
                set.iter()
                    .map(|bytes| NodeId::from_bytes(*bytes))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn subscriber_count(&self, topic_id: TopicId) -> usize {
        self.map
            .get(topic_id.as_bytes())
            .map(|s| s.len())
            .unwrap_or(0)
    }
}

// ── PubSubRouter ──────────────────────────────────────────────────────────────

/// Routes incoming frames for the pub/sub layer.
///
/// `Clone`-able and `Send + Sync` — share freely across tasks.
#[derive(Clone)]
pub struct PubSubRouter {
    inner: Arc<RouterInner>,
}

struct RouterInner {
    manager:     SubscriptionManager,
    /// Remote nodes that have subscribed to topics on this node.
    interests:   RemoteInterestTable,
    /// Non-pubsub frames are forwarded here for the node layer.
    unsolicited: mpsc::Sender<Frame>,
}

impl PubSubRouter {
    /// Construct. Prefer `PubSubLayer::new`.
    #[must_use]
    pub(crate) fn new(
        manager:     SubscriptionManager,
        unsolicited: mpsc::Sender<Frame>,
    ) -> Self {
        Self {
            inner: Arc::new(RouterInner {
                manager,
                interests:   RemoteInterestTable::default(),
                unsolicited,
            }),
        }
    }

    // ── Frame routing ─────────────────────────────────────────────────────────

    /// Route a single incoming frame.
    ///
    /// - Pub/sub frames are processed directly.
    /// - Non-pub/sub frames are forwarded to the `unsolicited` channel.
    pub async fn route(&self, frame: Frame, from: NodeId) {
        match try_decode_pubsub_frame(&frame) {
            Ok(Some(decoded)) => self.handle_decoded(decoded, from).await,
            Ok(None)          => self.forward_unsolicited(frame).await,
            Err(e)            => {
                warn!(
                    "pubsub: failed to decode frame from {}: {}",
                    from, e
                );
                // Malformed pub/sub frame — discard, do not forward.
            }
        }
    }

    /// Run the routing loop until `incoming` closes.
    ///
    /// `from` is the `NodeId` of the peer whose frames arrive on `incoming`.
    /// Spawn one of these tasks per connected peer.
    pub async fn run(
        self,
        mut incoming: mpsc::Receiver<Frame>,
        from: NodeId,
    ) {
        debug!("pubsub router: loop started for {}", from);
        while let Some(frame) = incoming.recv().await {
            self.route(frame, from).await;
        }
        // Peer disconnected — clean up their remote subscriptions.
        self.inner.interests.remove_all_for_node(from);
        debug!("pubsub router: loop ended for {} (cleaned up interests)", from);
    }

    // ── Remote interest queries ───────────────────────────────────────────────

    /// Returns the `NodeId`s of remote peers that have subscribed to `topic_id`.
    ///
    /// The node layer uses this to forward published messages to interested peers.
    #[must_use]
    pub fn remote_subscribers(&self, topic_id: TopicId) -> Vec<NodeId> {
        self.inner.interests.subscribers(topic_id)
    }

    /// Number of remote subscribers for `topic_id`.
    #[must_use]
    pub fn remote_subscriber_count(&self, topic_id: TopicId) -> usize {
        self.inner.interests.subscriber_count(topic_id)
    }

    /// Remove all remote subscriptions from `node_id`.
    ///
    /// Called when a peer disconnects. Also called automatically by `run()`
    /// when the incoming channel closes.
    pub fn peer_disconnected(&self, node_id: NodeId) {
        self.inner.interests.remove_all_for_node(node_id);
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    async fn handle_decoded(&self, decoded: DecodedPubSubFrame, from: NodeId) {
        match decoded {
            DecodedPubSubFrame::Message(recv) => {
                debug!(
                    "pubsub router: message on {} from {} seq={}",
                    recv.topic(), from, recv.seq()
                );
                match self.inner.manager.deliver(recv) {
                    Ok(n) => debug!("pubsub router: delivered to {} local subscriber(s)", n),
                    Err(e) => debug!("pubsub router: local delivery note: {}", e),
                }
            }
            DecodedPubSubFrame::Subscribe(topic_id) => {
                debug!("pubsub router: {} subscribed to {}", from, topic_id);
                self.inner.interests.add(topic_id, from);
            }
            DecodedPubSubFrame::Unsubscribe(topic_id) => {
                debug!("pubsub router: {} unsubscribed from {}", from, topic_id);
                self.inner.interests.remove(topic_id, from);
            }
        }
    }

    async fn forward_unsolicited(&self, frame: Frame) {
        if let Err(e) = self.inner.unsolicited.try_send(frame) {
            warn!("pubsub router: unsolicited channel full/closed: {}", e);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::SubscriptionManager;
    use crate::message::{encode_message, encode_subscribe, encode_unsubscribe, PubSubMessage};
    use muspell_proto::{Bytes, FrameBody, FrameId, NodeId, PingFrame, Timestamp};

    fn peer(b: u8) -> NodeId    { NodeId::from_bytes([b; 32]) }
    fn topic(name: &str) -> TopicId { TopicId::from_name(name) }

    fn make_router() -> (PubSubRouter, mpsc::Receiver<Frame>) {
        let (unsol_tx, unsol_rx) = mpsc::channel(16);
        let manager = SubscriptionManager::with_defaults();
        let router  = PubSubRouter::new(manager, unsol_tx);
        (router, unsol_rx)
    }

    fn make_router_with_manager() -> (PubSubRouter, SubscriptionManager, mpsc::Receiver<Frame>) {
        let (unsol_tx, unsol_rx) = mpsc::channel(16);
        let manager = SubscriptionManager::with_defaults();
        let router  = PubSubRouter::new(manager.clone(), unsol_tx);
        (router, manager, unsol_rx)
    }

    // ── Message routing to local subscribers ─────────────────────────────────

    #[tokio::test]
    async fn message_frame_delivered_to_local_subscriber() {
        let (router, manager, _unsol) = make_router_with_manager();
        let t   = topic("router/deliver");
        let mut sub = manager.subscribe(t);

        let msg = PubSubMessage::new(t, 0, peer(1), Bytes::from_slice(b"test"));
        let frame = encode_message(&msg).unwrap();
        router.route(frame, peer(1)).await;

        let received = sub.recv().await.unwrap();
        assert_eq!(received.seq(), 0);
        assert_eq!(received.topic(), t);
    }

    #[tokio::test]
    async fn message_with_no_local_subscriber_does_not_error() {
        let (router, _unsol) = make_router();
        let t   = topic("router/no-sub");
        let msg = PubSubMessage::new(t, 0, peer(1), Bytes::from_slice(b"x"));
        let frame = encode_message(&msg).unwrap();
        // Should not panic or return an error — just logs a debug message.
        router.route(frame, peer(1)).await;
    }

    // ── Subscribe / Unsubscribe interest tracking ─────────────────────────────

    #[tokio::test]
    async fn subscribe_frame_registers_interest() {
        let (router, _unsol) = make_router();
        let t = topic("router/subscribe");

        let frame = encode_subscribe(t).unwrap();
        router.route(frame, peer(2)).await;

        let subs = router.remote_subscribers(t);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0], peer(2));
    }

    #[tokio::test]
    async fn unsubscribe_frame_removes_interest() {
        let (router, _unsol) = make_router();
        let t = topic("router/unsub");

        router.route(encode_subscribe(t).unwrap(), peer(3)).await;
        assert_eq!(router.remote_subscriber_count(t), 1);

        router.route(encode_unsubscribe(t).unwrap(), peer(3)).await;
        assert_eq!(router.remote_subscriber_count(t), 0);
    }

    #[tokio::test]
    async fn multiple_peers_subscribe_independently() {
        let (router, _unsol) = make_router();
        let t = topic("router/multi");

        router.route(encode_subscribe(t).unwrap(), peer(10)).await;
        router.route(encode_subscribe(t).unwrap(), peer(11)).await;
        router.route(encode_subscribe(t).unwrap(), peer(12)).await;

        assert_eq!(router.remote_subscriber_count(t), 3);
    }

    // ── peer_disconnected ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn peer_disconnected_removes_all_subscriptions() {
        let (router, _unsol) = make_router();
        let t1 = topic("router/dc/a");
        let t2 = topic("router/dc/b");

        router.route(encode_subscribe(t1).unwrap(), peer(5)).await;
        router.route(encode_subscribe(t2).unwrap(), peer(5)).await;

        assert_eq!(router.remote_subscriber_count(t1), 1);
        assert_eq!(router.remote_subscriber_count(t2), 1);

        router.peer_disconnected(peer(5));

        assert_eq!(router.remote_subscriber_count(t1), 0);
        assert_eq!(router.remote_subscriber_count(t2), 0);
    }

    // ── Non-pubsub frames forwarded to unsolicited ────────────────────────────

    #[tokio::test]
    async fn non_pubsub_frame_forwarded_to_unsolicited() {
        let (router, mut unsol) = make_router();

        let ping_frame = Frame::new(
            FrameId::from_u128(1),
            Timestamp::ZERO,
            FrameBody::Ping(PingFrame { nonce: 7, sent_at: Timestamp::ZERO }),
        );
        router.route(ping_frame, peer(1)).await;

        let forwarded = unsol.recv().await.expect("non-pubsub frame forwarded");
        assert!(matches!(forwarded.body, FrameBody::Ping(_)));
    }

    // ── run loop ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn run_loop_processes_and_cleans_up() {
        let (router, manager, _unsol) = make_router_with_manager();
        let t   = topic("router/run");
        let mut sub = manager.subscribe(t);

        let (in_tx, in_rx) = mpsc::channel::<Frame>(16);
        let from = peer(99);

        // Subscribe from the remote peer.
        let clone = router.clone();
        tokio::spawn(clone.run(in_rx, from));

        // Send a subscribe frame.
        in_tx.send(encode_subscribe(t).unwrap()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(router.remote_subscriber_count(t), 1);

        // Send a message.
        let msg = PubSubMessage::new(t, 0, from, Bytes::from_slice(b"via-run"));
        in_tx.send(encode_message(&msg).unwrap()).await.unwrap();
        let received = sub.recv().await.unwrap();
        assert_eq!(received.payload().as_ref(), b"via-run");

        // Close channel — run loop should clean up.
        drop(in_tx);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(router.remote_subscriber_count(t), 0);
    }
}
