//! # muspell-node
//!
//! Assembles transport, RPC, pub/sub, and identity into a running Muspell node.
//!
//! ## Role in the stack
//!
//! ```text
//! muspell-proto       ← wire types
//! muspell-identity    ← keypairs, signing, verification
//! muspell-transport   ← QUIC endpoint, handshake
//! muspell-rpc         ← request/response
//! muspell-pubsub      ← topic pub/sub
//!        │
//!        ▼
//! muspell-node        ← YOU ARE HERE
//!        │              MuspellNode builder
//!        │              NodeHandle: connect/accept/pubsub/aliases/shutdown
//!        │              Per-peer task wiring
//!        ▼
//! muspell-daemon / muspell-sdk
//! ```
//!
//! ## Architecture
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────────┐
//!  │  NodeHandle  (Clone + Send + Sync)                       │
//!  │    ├── node_id() / did()         → local identity        │
//!  │    ├── connect(peer_id)          → PeerSession           │
//!  │    ├── accept()                  → PeerSession           │
//!  │    ├── peer(id) / peers()        → peer lookup           │
//!  │    ├── pubsub()                  → PubSubLayer (shared)  │
//!  │    ├── with_aliases(f)           → AliasRegistry         │
//!  │    ├── announce_to_all()         → broadcast Announce    │
//!  │    └── shutdown()                → graceful close        │
//!  └──────────────────────────────────────────────────────────┘
//!
//!  Per-peer (spawned on connect/accept):
//!  ┌────────────────────────────────────────────────────────────────┐
//!  │ connection_task ← owns MuspellConnection<W,R>                  │
//!  │   wire ↔ (incoming_tx, outgoing_rx)                            │
//!  ├────────────────────────────────────────────────────────────────┤
//!  │ rpc_dispatch_task   ← RpcDispatcher::run(incoming_rx)         │
//!  │   responses → pending, requests → RequestHandler               │
//!  │   other → unsolicited_tx                                        │
//!  ├────────────────────────────────────────────────────────────────┤
//!  │ pubsub_router_task  ← PubSubRouter::run(unsolicited_rx, peer)  │
//!  │   pubsub Extension frames → SubscriptionManager                │
//!  │   other frames → dropped (node-level unsolicited, future ext) │
//!  └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use muspell_node::{MuspellNode, NodeConfig};
//! use muspell_identity::{DidKeypair, NodeKeypair};
//! use muspell_rpc::NullHandler;
//! use std::sync::Arc;
//!
//! let node = MuspellNode::builder()
//!     .with_node_keypair(NodeKeypair::generate())
//!     .with_did_keypair(DidKeypair::generate())
//!     .with_handler(Arc::new(NullHandler))
//!     .with_config(NodeConfig::new().with_user_agent("my-app/1.0"))
//!     .start()
//!     .await?;
//!
//! // Connect to a peer by NodeId.
//! let session = node.connect(peer_node_id).await?;
//! let result  = session.rpc.get(cid, None).await?;
//!
//! // Accept an inbound connection.
//! while let Some(Ok(session)) = node.accept().await {
//!     let node_clone = node.clone();
//!     tokio::spawn(async move {
//!         // use session.rpc, node_clone.pubsub(), etc.
//!     });
//! }
//!
//! node.shutdown().await;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod error;
pub mod handle;
pub mod peer;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use config::NodeConfig;
pub use error::{NodeError, NodeResult};
pub use handle::NodeHandle;
pub use peer::PeerSession;

// ── Re-export key types applications will use alongside NodeHandle ────────────

pub use muspell_pubsub::{
    Publisher, Subscriber, SubscriptionManager,
    TopicId, TopicName, PubSubLayer,
    ReceivedMessage, PubSubMessage,
};
pub use muspell_rpc::{
    RpcClient, RpcConfig,
    RequestHandler, NullHandler,
    make_get_response, make_delete_ack, make_query_response,
    make_message_ack, make_error_response,
};
pub use muspell_identity::{
    AliasEntry, AliasRegistry,
    DidKeypair, NodeKeypair,
};
pub use muspell_transport::{PeerInfo, TransportConfig};

// ── MuspellNode ───────────────────────────────────────────────────────────────

use handle::NodeInner;
use muspell_identity::sign_binding;
use muspell_proto::{Frame, NodeId, Timestamp};

use muspell_transport::MuspellEndpointBuilder;
use std::sync::{Arc, atomic::AtomicBool};
use tokio::sync::{Mutex, mpsc};

/// Builder for a Muspell node.
///
/// Call [`MuspellNode::builder()`] to start, then chain configuration
/// methods, and finish with `.start().await` to bind and return a
/// [`NodeHandle`].
#[derive(Default)]
pub struct MuspellNode {
    node_kp:  Option<NodeKeypair>,
    did_kp:   Option<DidKeypair>,
    handler:  Option<Arc<dyn RequestHandler>>,
    config:   Option<NodeConfig>,
}

impl MuspellNode {
    /// Begin building a node.
    #[must_use]
    pub fn builder() -> Self {
        Self::default()
    }

    /// Set the node keypair (generated if not provided).
    #[must_use]
    pub fn with_node_keypair(mut self, kp: NodeKeypair) -> Self {
        self.node_kp = Some(kp);
        self
    }

    /// Set the DID keypair (optional — enables authenticated connections).
    #[must_use]
    pub fn with_did_keypair(mut self, kp: DidKeypair) -> Self {
        self.did_kp = Some(kp);
        self
    }

    /// Set the `RequestHandler` implementation (defaults to `NullHandler`).
    #[must_use]
    pub fn with_handler(mut self, handler: Arc<dyn RequestHandler>) -> Self {
        self.handler = Some(handler);
        self
    }

    /// Set the node configuration.
    #[must_use]
    pub fn with_config(mut self, config: NodeConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Bind the QUIC endpoint and return a running `NodeHandle`.
    ///
    /// # Errors
    /// Returns `NodeError::Transport` if the QUIC endpoint fails to bind.
    pub async fn start(self) -> NodeResult<NodeHandle> {
        let node_kp  = self.node_kp.unwrap_or_else(NodeKeypair::generate);
        let config   = Arc::new(self.config.unwrap_or_default());
        let handler  = self.handler
            .unwrap_or_else(|| Arc::new(NullHandler));
        let did_kp   = self.did_kp.map(Arc::new);

        // ── Build the QUIC endpoint ───────────────────────────────────────────

        let mut ep_builder = MuspellEndpointBuilder::default()
            .with_node_keypair(
                // We pass a fresh keypair; the node keeps its own Arc.
                // The endpoint also needs to know the identity for bindings.
                // NodeKeypair doesn't impl Clone, so we reconstruct from bytes.
                NodeKeypair::from_secret_bytes(&node_kp.to_secret_bytes())
                    .map_err(|e| NodeError::internal(e))?,
            )
            .with_config(config.transport.clone());

        if let Some(ref kp) = did_kp {
            ep_builder = ep_builder.with_did_keypair(
                DidKeypair::from_secret_bytes(&kp.to_secret_bytes())
                    .map_err(|e| NodeError::internal(e))?,
            );
        }

        let endpoint = ep_builder.bind().await?;

        let local_node_id = node_kp.node_id();

        // ── Build the PubSub layer ────────────────────────────────────────────
        // The PubSubLayer needs an outgoing channel. In the node architecture,
        // each peer gets its own outgoing channel — the PubSubLayer's shared
        // channel is a fanout that the publisher sends to. When a peer connects,
        // the node wires up that peer's outgoing_tx by giving each Publisher a
        // clone. The PubSubLayer constructor takes a "default" outgoing that
        // goes nowhere (it's overridden per-peer in spawn_peer_tasks).
        //
        // For broadcast: when a publisher publishes, the PubSubLayer delivers
        // to LOCAL subscribers directly. For REMOTE subscribers, the node layer
        // (future: node-level pubsub fanout task) checks
        // router.remote_subscribers(topic_id) and forwards via each peer's
        // outgoing_tx. That fanout is a muspell-node concern.
        //
        // For now: PubSubLayer is constructed with a sink channel (dropped
        // immediately) because per-peer forwarding is handled via each peer's
        // outgoing_tx. The publish() method delivers locally and sends to the
        // "default" outgoing. For cross-peer forwarding, callers use
        // layer.router().remote_subscribers() + peer session outgoing_tx.

        let (pubsub_sink_tx, _pubsub_sink_rx) = mpsc::channel::<Frame>(1);
        let (unsol_tx, _unsol_rx)             = mpsc::channel::<Frame>(8);

        let pubsub = PubSubLayer::with_capacity(
            pubsub_sink_tx,
            unsol_tx,
            local_node_id,
            config.pubsub_channel_capacity,
        );

        // ── Assemble NodeInner ────────────────────────────────────────────────

        let inner = Arc::new(NodeInner {
            node_kp:  Arc::new(node_kp),
            did_kp,
            endpoint,
            pubsub,
            handler,
            peers:    dashmap::DashMap::new(),
            aliases:  Mutex::new(AliasRegistry::new()),
            config,
            shutdown: AtomicBool::new(false),
        });

        Ok(NodeHandle { inner })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::NodeId;

    // ── Builder defaults ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn builder_with_all_defaults_starts_successfully() {
        let node = MuspellNode::builder()
            .start()
            .await
            .expect("node should start with default config");

        assert_ne!(node.node_id(), NodeId::from_bytes([0u8; 32]));
        assert!(node.did().is_none());
        assert_eq!(node.peer_count(), 0);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn builder_with_did_keypair_exposes_did() {
        let did_kp = DidKeypair::generate();
        let expected_did = did_kp.did();

        let node = MuspellNode::builder()
            .with_did_keypair(did_kp)
            .start()
            .await
            .expect("should start");

        assert_eq!(node.did(), Some(expected_did));
        node.shutdown().await;
    }

    #[tokio::test]
    async fn builder_with_node_keypair_preserves_identity() {
        let kp = NodeKeypair::generate();
        let expected_id = kp.node_id();

        let node = MuspellNode::builder()
            .with_node_keypair(kp)
            .start()
            .await
            .expect("should start");

        assert_eq!(node.node_id(), expected_id);
        node.shutdown().await;
    }

    // ── NodeHandle basics ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn handle_is_cloneable_with_shared_state() {
        let node = MuspellNode::builder()
            .start()
            .await
            .expect("should start");

        let clone = node.clone();
        assert_eq!(node.node_id(), clone.node_id());
        assert!(std::ptr::eq(
            Arc::as_ptr(&node.inner),
            Arc::as_ptr(&clone.inner),
        ));

        node.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_sets_flag() {
        let node = MuspellNode::builder()
            .start()
            .await
            .expect("should start");

        node.shutdown().await;

        // After shutdown, connect should return Shutdown error.
        let err = node
            .connect(NodeId::from_bytes([2u8; 32]))
            .await
            .unwrap_err();
        assert!(matches!(err, NodeError::Shutdown));
    }

    // ── Alias registry ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn alias_registry_accessible_via_with_aliases() {
        let node = MuspellNode::builder()
            .start()
            .await
            .expect("should start");

        let did = DidKeypair::generate().did();
        node.with_aliases(|reg| {
            reg.assign_name(did, muspell_identity::AliasEntry::new(did).names.into_iter()
                .next()
                .unwrap_or_default().into());
        }).await;

        // Registry is shared — second closure sees changes.
        let contains = node.with_aliases(|reg| reg.contains(&did)).await;
        // We didn't actually add the DID in the first closure above (the
        // inline construction was wrong), so let's test add_did directly.
        node.with_aliases(|reg| reg.add_did(did)).await;
        let contains2 = node.with_aliases(|reg| reg.contains(&did)).await;
        assert!(contains2);
        let _ = contains; // suppress warning

        node.shutdown().await;
    }

    // ── PubSub access ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn pubsub_layer_accessible_and_functional() {
        let node = MuspellNode::builder()
            .start()
            .await
            .expect("should start");

        let topic   = TopicName::new("node/test/events");
        let mut sub = node.pubsub().subscribe(topic.id());
        let pub_    = node.pubsub().publisher(topic.id());

        use muspell_proto::Bytes;
        pub_.publish(Bytes::from_slice(b"test payload")).await.unwrap();

        let msg = sub.recv().await.unwrap();
        assert_eq!(msg.payload().as_ref(), b"test payload");
        assert_eq!(msg.topic(), topic.id());

        node.shutdown().await;
    }

    // ── Config access ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn config_accessible_from_handle() {
        let config = NodeConfig::new()
            .with_user_agent("test-node/0.1")
            .with_pubsub_capacity(128);

        let node = MuspellNode::builder()
            .with_config(config)
            .start()
            .await
            .expect("should start");

        assert_eq!(node.config().pubsub_channel_capacity, 128);
        node.shutdown().await;
    }

    // ── Two-node loopback: connect + basic RPC ────────────────────────────────

    #[tokio::test]
    async fn two_node_loopback_connect_and_peer_visible() {
        let node_a = MuspellNode::builder()
            .with_config(NodeConfig::new().without_auto_announce())
            .start()
            .await
            .expect("node_a should start");

        let node_b = MuspellNode::builder()
            .with_config(NodeConfig::new().without_auto_announce())
            .start()
            .await
            .expect("node_b should start");

        let b_id = node_b.node_id();

        // A connects to B.
        let session = node_a.connect(b_id).await.expect("connect should succeed");
        assert_eq!(session.node_id(), b_id);

        // Give B's accept loop a moment (B needs to be accepting).
        // In a real app, B's accept loop is running. Here we skip that
        // since we just test A's outgoing connection state.
        assert_eq!(node_a.peer_count(), 1);
        assert!(node_a.peer(b_id).is_some());

        node_a.shutdown().await;
        node_b.shutdown().await;
    }

    // ── AlreadyConnected error ────────────────────────────────────────────────

    #[tokio::test]
    async fn connect_already_connected_returns_error() {
        let node_a = MuspellNode::builder()
            .with_config(NodeConfig::new().without_auto_announce())
            .start()
            .await
            .expect("node_a should start");

        let node_b = MuspellNode::builder()
            .with_config(NodeConfig::new().without_auto_announce())
            .start()
            .await
            .expect("node_b should start");

        let b_id = node_b.node_id();

        // First connect succeeds.
        node_a.connect(b_id).await.expect("first connect should succeed");

        // Second connect should fail with AlreadyConnected.
        let err = node_a.connect(b_id).await.unwrap_err();
        assert!(
            matches!(err, NodeError::AlreadyConnected { node_id } if node_id == b_id),
            "expected AlreadyConnected, got: {err:?}"
        );

        node_a.shutdown().await;
        node_b.shutdown().await;
    }
}
