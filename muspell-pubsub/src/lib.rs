//! # muspell-pubsub
//!
//! Topic publish/subscribe over the Muspell network protocol.
//!
//! ## Role in the stack
//!
//! ```text
//! muspell-proto       ← wire types (Frame, ExtensionFrame, …)
//! muspell-transport   ← QUIC framing, handshake, raw send/recv
//! muspell-rpc         ← request/response
//!        │
//!        ▼
//! muspell-pubsub      ← YOU ARE HERE
//!        │              TopicId:            blake3-addressed topic identifier
//!        │              PubSubMessage:      CBOR envelope over ExtensionFrame
//!        │              Publisher:          publish to a topic (outgoing)
//!        │              Subscriber:         receive from a topic (incoming)
//!        │              SubscriptionManager:local broadcast fan-out per topic
//!        │              PubSubRouter:       incoming frame → manager + interest table
//!        │              PubSubLayer:        top-level constructor; wires it all together
//!        ▼
//! muspell-node        ← assembles RPC + pubsub + transport into a running node
//! ```
//!
//! ## Design principles
//!
//! - **Zero transport changes** — pub/sub rides `ExtensionFrame` with
//!   `namespace = "muspell/pubsub"`. No new frame types are needed.
//! - **Channel-based wiring** — identical to `muspell-rpc`. An `mpsc::Sender<Frame>`
//!   bridges this crate to the transport task; the node layer owns the plumbing.
//! - **Local delivery is free** — publishing a message delivers it to local
//!   subscribers immediately, without a network round-trip.
//! - **Remote interest tracking** — `PubSubRouter` records which remote peers
//!   have subscribed to which topics. The node layer uses this to forward
//!   published messages to interested peers.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use muspell_pubsub::{PubSubLayer, TopicName};
//! use muspell_proto::{Bytes, NodeId};
//! use tokio::sync::mpsc;
//!
//! // Channels bridge this crate to the transport layer.
//! let (out_tx, out_rx)   = mpsc::channel(256); // PubSub → transport
//! let (in_tx,  in_rx)    = mpsc::channel(256); // transport → PubSub
//! let (unsol_tx, unsol_rx) = mpsc::channel(64);  // non-pubsub frames
//!
//! let local_node_id = NodeId::from_bytes([1u8; 32]);
//!
//! let layer = PubSubLayer::new(out_tx, unsol_tx, local_node_id);
//!
//! // Spawn the receive loop for each connected peer.
//! // `from` is the NodeId of the peer whose frames arrive on `in_rx`.
//! let from = NodeId::from_bytes([2u8; 32]);
//! tokio::spawn(layer.router().run(in_rx, from));
//!
//! // Subscribe to a topic.
//! let topic = TopicName::new("muspell/events");
//! let mut sub = layer.subscribe(topic.id());
//!
//! // Publish a message.
//! let pub_ = layer.publisher(topic.id());
//! pub_.publish(Bytes::from_slice(b"hello network")).await?;
//!
//! // Receive a message.
//! let msg = sub.recv().await?;
//! println!("received: {:?}", msg.payload());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod manager;
pub mod message;
pub mod publisher;
pub mod router;
pub mod topic;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use error::{PubSubError, PubSubResult};
pub use manager::{SubscriptionManager, Subscriber};
pub use message::{
    DecodedPubSubFrame, PubSubMessage, ReceivedMessage,
    encode_message, encode_subscribe, encode_unsubscribe,
    try_decode_pubsub_frame,
    KIND_MESSAGE, KIND_SUBSCRIBE, KIND_UNSUBSCRIBE, PUBSUB_NS,
};
pub use publisher::Publisher;
pub use router::PubSubRouter;
pub use topic::{TopicId, TopicName};

// ── PubSubLayer ───────────────────────────────────────────────────────────────

use muspell_proto::{Frame, NodeId};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Top-level pub/sub layer — wires `Publisher`, `Subscriber`,
/// `SubscriptionManager`, and `PubSubRouter` together.
///
/// ## Construction
///
/// ```rust,ignore
/// let layer = PubSubLayer::new(outgoing_tx, unsolicited_tx, local_node_id);
/// ```
///
/// ## Wiring
///
/// ```text
/// PubSubLayer
///   ├── .router()    → PubSubRouter (run with: router.run(incoming_rx, peer_id))
///   ├── .publisher() → Publisher   (publish messages)
///   └── .subscribe() → Subscriber  (receive messages)
/// ```
#[derive(Clone)]
pub struct PubSubLayer {
    outgoing: mpsc::Sender<Frame>,
    manager:  SubscriptionManager,
    router:   PubSubRouter,
    node_id:  NodeId,
}

impl PubSubLayer {
    /// Create a new `PubSubLayer`.
    ///
    /// ## Parameters
    ///
    /// - `outgoing`    — frames to send to the transport (PubSub → wire)
    /// - `unsolicited` — non-pubsub frames forwarded here for the node layer
    /// - `node_id`     — this node's identity, embedded in outgoing messages
    #[must_use]
    pub fn new(
        outgoing:    mpsc::Sender<Frame>,
        unsolicited: mpsc::Sender<Frame>,
        node_id:     NodeId,
    ) -> Self {
        let manager = SubscriptionManager::with_defaults();
        let router  = PubSubRouter::new(manager.clone(), unsolicited);
        Self { outgoing, manager, router, node_id }
    }

    /// Create a new `PubSubLayer` with a custom channel capacity.
    #[must_use]
    pub fn with_capacity(
        outgoing:         mpsc::Sender<Frame>,
        unsolicited:      mpsc::Sender<Frame>,
        node_id:          NodeId,
        channel_capacity: usize,
    ) -> Self {
        let manager = SubscriptionManager::new(channel_capacity);
        let router  = PubSubRouter::new(manager.clone(), unsolicited);
        Self { outgoing, manager, router, node_id }
    }

    // ── Handles ───────────────────────────────────────────────────────────────

    /// The `PubSubRouter` for this layer.
    ///
    /// Spawn `router.run(incoming_rx, peer_node_id)` for each connected peer.
    #[must_use]
    pub fn router(&self) -> &PubSubRouter {
        &self.router
    }

    /// Create a `Publisher` for `topic_id`.
    ///
    /// The publisher shares the layer's outgoing channel and
    /// `SubscriptionManager`. Multiple publishers on the same topic share
    /// a single atomic sequence counter.
    #[must_use]
    pub fn publisher(&self, topic_id: TopicId) -> Publisher {
        Publisher::new(
            topic_id,
            self.node_id,
            self.outgoing.clone(),
            self.manager.clone(),
        )
    }

    /// Subscribe to `topic_id`.
    ///
    /// Returns a `Subscriber` that yields `ReceivedMessage`s as they arrive
    /// from either local publishers or the network.
    #[must_use]
    pub fn subscribe(&self, topic_id: TopicId) -> Subscriber {
        self.manager.subscribe(topic_id)
    }

    /// Access the `SubscriptionManager` directly.
    ///
    /// Useful for inspection (subscriber counts, active topics, etc.)
    /// and for delivering messages from sources outside the normal
    /// routing flow.
    #[must_use]
    pub fn manager(&self) -> &SubscriptionManager {
        &self.manager
    }

    /// The local `NodeId` this layer is configured with.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{Bytes, NodeId};
    use tokio::sync::mpsc;

    fn node(b: u8) -> NodeId { NodeId::from_bytes([b; 32]) }

    fn make_layer(node_id: NodeId) -> (PubSubLayer, mpsc::Receiver<Frame>) {
        let (out_tx, out_rx) = mpsc::channel(64);
        let (unsol_tx, _)    = mpsc::channel(8);
        let layer = PubSubLayer::new(out_tx, unsol_tx, node_id);
        (layer, out_rx)
    }

    // ── Local publish → local subscribe ──────────────────────────────────────

    #[tokio::test]
    async fn local_publish_reaches_local_subscriber() {
        let (layer, mut _rx) = make_layer(node(1));
        let topic = TopicName::new("integration/local");

        let mut sub = layer.subscribe(topic.id());
        let pub_    = layer.publisher(topic.id());

        pub_.publish(Bytes::from_slice(b"hello local")).await.unwrap();

        let msg = sub.recv().await.unwrap();
        assert_eq!(msg.payload().as_ref(), b"hello local");
        assert_eq!(msg.topic(), topic.id());
        assert_eq!(msg.sender(), node(1));
    }

    // ── Remote publish → local subscriber via router ──────────────────────────

    #[tokio::test]
    async fn remote_publish_routed_to_local_subscriber() {
        let (layer, _out_rx) = make_layer(node(1));
        let remote = node(2);
        let topic  = TopicName::new("integration/remote");

        let mut sub = layer.subscribe(topic.id());

        // Simulate remote publish: create a PubSubMessage from node(2),
        // encode it as an Extension frame, and route it through the router.
        let msg = PubSubMessage::new(
            topic.id(), 0, remote,
            Bytes::from_slice(b"from remote"),
        );
        let frame = encode_message(&msg).unwrap();
        layer.router().route(frame, remote).await;

        let received = sub.recv().await.unwrap();
        assert_eq!(received.payload().as_ref(), b"from remote");
        assert_eq!(received.sender(), remote);
    }

    // ── Remote subscribe tracking ─────────────────────────────────────────────

    #[tokio::test]
    async fn remote_subscribe_frame_registers_interest() {
        let (layer, _rx) = make_layer(node(1));
        let remote = node(3);
        let topic  = TopicName::new("integration/interest");

        let sub_frame = encode_subscribe(topic.id()).unwrap();
        layer.router().route(sub_frame, remote).await;

        let subs = layer.router().remote_subscribers(topic.id());
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0], remote);
    }

    // ── Multiple topics independent ───────────────────────────────────────────

    #[tokio::test]
    async fn multiple_topics_are_independent() {
        let (layer, _rx) = make_layer(node(1));
        let t1 = TopicName::new("integration/t1");
        let t2 = TopicName::new("integration/t2");

        let mut sub1 = layer.subscribe(t1.id());
        let mut sub2 = layer.subscribe(t2.id());
        let pub1     = layer.publisher(t1.id());
        let pub2     = layer.publisher(t2.id());

        pub1.publish(Bytes::from_slice(b"on-t1")).await.unwrap();
        pub2.publish(Bytes::from_slice(b"on-t2")).await.unwrap();

        let msg1 = sub1.recv().await.unwrap();
        let msg2 = sub2.recv().await.unwrap();

        assert_eq!(msg1.payload().as_ref(), b"on-t1");
        assert_eq!(msg2.payload().as_ref(), b"on-t2");
        assert_eq!(msg1.topic(), t1.id());
        assert_eq!(msg2.topic(), t2.id());
    }

    // ── Two layers loopback: A publishes, B receives ──────────────────────────

    #[tokio::test]
    async fn two_layer_loopback() {
        // Node A → sends frames → Node B's incoming channel.
        let node_a = node(10);
        let node_b = node(11);

        // A's outgoing is B's incoming.
        let (a_out, b_in) = mpsc::channel::<Frame>(64);
        let (unsol_a, _)  = mpsc::channel::<Frame>(8);
        let (unsol_b, _)  = mpsc::channel::<Frame>(8);

        // B's outgoing goes nowhere (not used in this test).
        let (b_out, _b_out_rx) = mpsc::channel::<Frame>(64);

        let layer_a = PubSubLayer::new(a_out,  unsol_a, node_a);
        let layer_b = PubSubLayer::new(b_out,  unsol_b, node_b);

        let topic = TopicName::new("loopback/test");

        // B subscribes locally.
        let mut sub_b = layer_b.subscribe(topic.id());

        // Spawn B's router to process frames from A.
        let router_b = layer_b.router().clone();
        tokio::spawn(router_b.run(b_in, node_a));

        // Give the router task a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        // A publishes.
        let pub_a = layer_a.publisher(topic.id());
        pub_a.publish(Bytes::from_slice(b"a-to-b")).await.unwrap();

        // B receives.
        let msg = sub_b.recv().await.unwrap();
        assert_eq!(msg.payload().as_ref(), b"a-to-b");
        assert_eq!(msg.sender(), node_a);
    }

    // ── subscriber count reporting ────────────────────────────────────────────

    #[tokio::test]
    async fn subscriber_count_accurate() {
        let (layer, _rx) = make_layer(node(1));
        let topic = TopicName::new("integration/count");

        assert_eq!(layer.manager().total_subscriber_count(), 0);

        let _s1 = layer.subscribe(topic.id());
        let _s2 = layer.subscribe(topic.id());
        assert_eq!(layer.manager().total_subscriber_count(), 2);
        assert_eq!(layer.manager().active_topic_count(), 1);
    }

    // ── PubSubLayer::node_id ──────────────────────────────────────────────────

    #[test]
    fn layer_node_id_matches() {
        let n = node(42);
        let (out_tx, _) = mpsc::channel::<Frame>(1);
        let (uns_tx, _) = mpsc::channel::<Frame>(1);
        let layer = PubSubLayer::new(out_tx, uns_tx, n);
        assert_eq!(layer.node_id(), n);
    }
}
