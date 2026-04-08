//! `NodeHandle` — the public API for a running Muspell node.
//!
//! `NodeHandle` is `Clone + Send + Sync`. Every clone refers to the same
//! underlying node. Pass handles freely to async tasks; there is no
//! performance cost beyond an `Arc` clone.
//!
//! ## Typical usage
//!
//! ```rust,ignore
//! use muspell_node::{MuspellNode, NodeConfig};
//! use muspell_identity::{DidKeypair, NodeKeypair};
//!
//! let node = MuspellNode::builder()
//!     .with_node_keypair(NodeKeypair::generate())
//!     .with_did_keypair(DidKeypair::generate())
//!     .with_config(NodeConfig::new().with_user_agent("my-app/1.0"))
//!     .start()
//!     .await?;
//!
//! // Connect to a peer.
//! let peer = node.connect(peer_node_id).await?;
//!
//! // Make an RPC call.
//! let result = peer.rpc.get(content_id, None).await?;
//!
//! // Publish on a topic.
//! let pub_ = node.pubsub().publisher(topic_id);
//! pub_.publish(Bytes::from_slice(b"hello")).await?;
//!
//! // Graceful shutdown.
//! node.shutdown().await;
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use muspell_identity::{AliasRegistry, DidKeypair, NodeKeypair};
use muspell_proto::{
    AnnounceFrame, Did, Frame, FrameBody, NodeCapabilities, NodeId, Timestamp,
};
use muspell_pubsub::PubSubLayer;
use muspell_rpc::RequestHandler;
use muspell_transport::{MuspellEndpoint, MuspellEndpointBuilder};
use tokio::sync::{Mutex, oneshot};
use tracing::{info, warn};

use crate::config::NodeConfig;
use crate::error::{NodeError, NodeResult};
use crate::peer::{PeerSession, spawn_peer_tasks};

// ── NodeInner ─────────────────────────────────────────────────────────────────

/// The shared state behind all `NodeHandle` clones.
pub(crate) struct NodeInner {
    /// The local node's transport keypair and identity.
    pub node_kp:  Arc<NodeKeypair>,
    /// The local DID keypair, if this node has a stable identity.
    pub did_kp:   Option<Arc<DidKeypair>>,
    /// The QUIC endpoint — accepts and initiates connections.
    pub endpoint: MuspellEndpoint,
    /// The pub/sub layer — shared across all peer connections.
    pub pubsub:   PubSubLayer,
    /// The request handler for incoming RPC calls.
    pub handler:  Arc<dyn RequestHandler>,
    /// Active peer sessions, keyed by raw `NodeId` bytes.
    pub peers:    DashMap<[u8; 32], PeerSession>,
    /// Local alias registry (contact book).
    pub aliases:  Mutex<AliasRegistry>,
    /// Node configuration.
    pub config:   Arc<NodeConfig>,
    /// `true` once `shutdown()` has been called.
    pub shutdown: AtomicBool,
}

impl NodeInner {
    fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

// ── NodeHandle ────────────────────────────────────────────────────────────────

/// A handle to a running Muspell node.
///
/// `Clone + Send + Sync` — share freely across tasks.
#[derive(Clone)]
pub struct NodeHandle {
    pub(crate) inner: Arc<NodeInner>,
}

impl NodeHandle {
    // ── Identity ──────────────────────────────────────────────────────────────

    /// The local node's ephemeral `NodeId`.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.inner.node_kp.node_id()
    }

    /// The local node's stable `Did`, if configured.
    #[must_use]
    pub fn did(&self) -> Option<Did> {
        self.inner.did_kp.as_ref().map(|kp| kp.did())
    }

    // ── Connections ───────────────────────────────────────────────────────────

    /// Connect to a remote node and return its `PeerSession`.
    ///
    /// If a session already exists for `peer_node_id`, returns
    /// `NodeError::AlreadyConnected`.
    ///
    /// The connection runs in background tasks; the returned `PeerSession`
    /// is the application's handle to interact with the peer.
    ///
    /// # Errors
    /// - `NodeError::Shutdown` if the node is shutting down.
    /// - `NodeError::AlreadyConnected` if already connected.
    /// - `NodeError::Transport` if the QUIC connection or handshake fails.
    pub async fn connect(&self, peer_node_id: NodeId) -> NodeResult<PeerSession> {
        if self.inner.is_shutdown() {
            return Err(NodeError::Shutdown);
        }
        if self.inner.peers.contains_key(peer_node_id.as_bytes()) {
            return Err(NodeError::AlreadyConnected { node_id: peer_node_id });
        }

        // Clone the Arc *before* the await so the borrow of &self ends here.
        // attach_connection is a free function that takes Arc<NodeInner>
        // directly — it carries no lifetime derived from &self.
        let inner = Arc::clone(&self.inner);
        let conn  = self.inner.endpoint.connect(peer_node_id).await?;
        let session = attach_connection(inner, conn).await;
        Ok(session)
    }

    /// Return the `PeerSession` for an already-connected peer, or `None`.
    #[must_use]
    pub fn peer(&self, node_id: NodeId) -> Option<PeerSession> {
        self.inner.peers
            .get(node_id.as_bytes())
            .map(|e| e.value().clone())
    }

    /// Return sessions for all currently connected peers.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerSession> {
        self.inner.peers
            .iter()
            .map(|e| e.value().clone())
            .collect()
    }

    /// Return the `NodeId`s of all currently connected peers.
    #[must_use]
    pub fn peer_ids(&self) -> Vec<NodeId> {
        self.inner.peers
            .iter()
            .map(|e| NodeId::from_bytes(*e.key()))
            .collect()
    }

    /// Number of currently connected peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.inner.peers.len()
    }

    // ── Pub/sub ───────────────────────────────────────────────────────────────

    /// Access the shared `PubSubLayer`.
    ///
    /// Use this to create publishers and subscribers that work across all
    /// peer connections simultaneously.
    #[must_use]
    pub fn pubsub(&self) -> &PubSubLayer {
        &self.inner.pubsub
    }

    // ── Alias registry ────────────────────────────────────────────────────────

    /// Run a closure with access to the `AliasRegistry`.
    ///
    /// The registry is behind a `Mutex`; this method acquires it, calls
    /// `f`, and releases it.
    pub async fn with_aliases<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut AliasRegistry) -> T,
    {
        let mut guard = self.inner.aliases.lock().await;
        f(&mut *guard)
    }

    // ── Announce ──────────────────────────────────────────────────────────────

    /// Send an `Announce` frame to all connected peers.
    ///
    /// Used to inform peers of this node's capabilities, served namespaces,
    /// and content sample. Called automatically after each connection if
    /// `NodeConfig::auto_announce` is `true`.
    pub async fn announce_to_all(&self) {
        let frame = self.build_announce_frame();
        for session in self.peers() {
            if let Err(e) = session.outgoing_tx.send(frame.clone()).await {
                warn!("announce: failed to send to {}: {e}", session.node_id());
            }
        }
    }

    /// Send an `Announce` frame to a specific peer.
    pub async fn announce_to(&self, peer_node_id: NodeId) -> NodeResult<()> {
        let session = self
            .inner
            .peers
            .get(peer_node_id.as_bytes())
            .ok_or(NodeError::NotConnected { node_id: peer_node_id })?;

        let frame = self.build_announce_frame();
        session
            .outgoing_tx
            .send(frame)
            .await
            .map_err(|_| NodeError::NotConnected { node_id: peer_node_id })
    }

    // ── Config ────────────────────────────────────────────────────────────────

    /// The node's configuration.
    #[must_use]
    pub fn config(&self) -> &NodeConfig {
        &self.inner.config
    }

    // ── Accept loop ───────────────────────────────────────────────────────────

    /// Accept the next inbound connection and return its `PeerSession`.
    ///
    /// Returns `None` when the node is shutting down.
    ///
    /// Typically called in a loop:
    ///
    /// ```rust,ignore
    /// while let Some(session) = node.accept().await {
    ///     // session is ready — spawn a task to use it
    /// }
    /// ```
    pub async fn accept(&self) -> Option<NodeResult<PeerSession>> {
        if self.inner.is_shutdown() {
            return None;
        }
        // Clone the Arc before the await — same reasoning as connect().
        let inner  = Arc::clone(&self.inner);
        let result = self.inner.endpoint.accept().await?;
        match result {
            Ok(conn)  => {
                let inner = Arc::clone(&self.inner);
                let session = attach_connection(inner, conn).await;
                Some(Ok(session))
            }
            Err(e) => Some(Err(NodeError::Transport(e))),
        }
    }

    // ── Shutdown ──────────────────────────────────────────────────────────────

    /// Initiate a graceful shutdown.
    ///
    /// 1. Sets the shutdown flag so new connections are refused.
    /// 2. Sends `Goodbye` to all connected peers.
    /// 3. Closes the QUIC endpoint.
    ///
    /// After this returns, the node is fully stopped. All `NodeHandle` clones
    /// will return `NodeError::Shutdown` on any operation.
    pub async fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::Relaxed);
        info!("node: shutting down ({} peers)", self.peer_count());

        // Send Goodbye to all peers and drain their outgoing channels.
        let peers: Vec<_> = self.inner.peers
            .iter()
            .map(|e| (NodeId::from_bytes(*e.key()), e.value().outgoing_tx.clone()))
            .collect();

        let goodbye = Frame::new(
            muspell_proto::FrameId::from_u128(0),
            Timestamp::now().unwrap_or(Timestamp::ZERO),
            FrameBody::Goodbye(muspell_proto::GoodbyeFrame {
                reason:               "node shutdown".into(),
                reconnect_after_secs: None,
            }),
        );

        for (nid, tx) in peers {
            if let Err(e) = tx.send(goodbye.clone()).await {
                warn!("shutdown: could not send Goodbye to {nid}: {e}");
            }
        }

        // Give tasks a moment to drain, then force close.
        tokio::time::sleep(
            self.inner.config.shutdown_timeout.min(std::time::Duration::from_secs(5))
        ).await;

        self.inner.endpoint.close().await;
        info!("node: shutdown complete");
    }

    fn build_announce_frame(&self) -> Frame {
        Frame::new(
            muspell_proto::FrameId::random(),
            Timestamp::now().unwrap_or(Timestamp::ZERO),
            FrameBody::Announce(AnnounceFrame {
                node_id:        self.node_id(),
                did:            self.did(),
                namespaces:     vec![],
                content_sample: vec![],
                ttl_secs:       300,
            }),
        )
    }
}

// ── attach_connection — free function, not a method ───────────────────────────
//
// This MUST be a free function, not a method on `NodeHandle`.
//
// If it were `NodeHandle::attach_connection(&self, ...)` or even
// `NodeHandle::attach_connection(self, ...)`, callers inside `&self` methods
// (`connect`, `accept`) would produce a future that the compiler treats as
// derived from `&'1 self`, which cannot satisfy `tokio::spawn`'s `'static`
// requirement.
//
// By taking `Arc<NodeInner>` directly, all state is `'static`-owned;
// the borrow of `&self` in the calling method ends before this function
// is invoked.
pub(crate) async fn attach_connection<W, R>(
    inner: Arc<NodeInner>,
    conn:  muspell_transport::MuspellConnection<W, R>,
) -> PeerSession
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    R: tokio::io::AsyncRead  + Unpin + Send + 'static,
{
    let peer_id = conn.peer_node_id();
    let (disc_tx, disc_rx) = oneshot::channel::<NodeId>();

    let session = spawn_peer_tasks(
        conn,
        inner.handler.clone(),
        inner.pubsub.clone(),
        inner.config.clone(),
        disc_tx,
    );

    // Register session.
    inner.peers.insert(*peer_id.as_bytes(), session.clone());
    info!(
        "node: peer {} connected (total: {})",
        peer_id,
        inner.peers.len()
    );

    // Cleanup task: remove peer when it disconnects.
    // Both captures are 'static Arcs — no lifetime from a method receiver.
    let inner_ref = Arc::clone(&inner);
    tokio::spawn(async move {
        if let Ok(disconnected_id) = disc_rx.await {
            inner_ref.peers.remove(disconnected_id.as_bytes());
            inner_ref.pubsub.router().peer_disconnected(disconnected_id);
            info!(
                "node: peer {} disconnected (remaining: {})",
                disconnected_id,
                inner_ref.peers.len()
            );
        }
    });

    // Auto-announce.
    if inner.config.auto_announce {
        let node_id = inner.node_kp.node_id();
        let did     = inner.did_kp.as_ref().map(|kp| kp.did());
        let frame   = Frame::new(
            muspell_proto::FrameId::random(),
            Timestamp::now().unwrap_or(Timestamp::ZERO),
            FrameBody::Announce(AnnounceFrame {
                node_id:        node_id,
                did,
                namespaces:     vec![],
                content_sample: vec![],
                ttl_secs:       300,
            }),
        );
        if let Err(e) = session.outgoing_tx.send(frame).await {
            warn!("node: auto-announce to {peer_id} failed: {e}");
        }
    }

    session
}
