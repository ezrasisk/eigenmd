//! Per-peer session management.
//!
//! ## Architecture
//!
//! Each connected peer gets a `PeerSession` stored in the node's peer table,
//! plus a set of spawned tasks that own the `MuspellConnection` and drive
//! the RPC and pub/sub layers for that peer.
//!
//! ```text
//!
//!  ┌─────────────────────────────────────────────────────────────┐
//!  │  connection_task  (owns MuspellConnection<W, R>)            │
//!  │                                                             │
//!  │  recv side:  conn.recv_loop → incoming_tx                  │
//!  │  send side:  outgoing_rx    → conn.send_frame()            │
//!  └─────────────────────────────────────────────────────────────┘
//!           │incoming_tx                  ▲ outgoing_rx
//!           ▼                             │
//!  ┌─────────────────────────┐   ┌────────────────────────────────┐
//!  │  rpc_dispatch_task       │   │  RpcClient / PubSubLayer       │
//!  │  dispatcher.run(in_rx)   │   │  both hold outgoing_tx clone   │
//!  │                          │   │                                │
//!  │  responses → pending     │   │  rpc_client.get(cid).await    │
//!  │  requests  → handler     │   │  pubsub_layer.publish(…)      │
//!  │  other     → unsol_tx    │   └────────────────────────────────┘
//!  └─────────────────────────┘
//!           │unsol_tx
//!           ▼
//!  ┌─────────────────────────┐
//!  │  pubsub_router_task      │
//!  │  router.run(unsol_rx,   │
//!  │             peer_id)    │
//!  └─────────────────────────┘
//! ```
//!
//! ## `PeerSession`
//!
//! The node's peer table stores one `PeerSession` per connected peer.
//! It provides:
//! - `rpc_client` — send typed RPC calls to this peer
//! - `outgoing_tx` — send raw frames directly (used by pub/sub layer)
//! - `info` — handshake-verified peer metadata
//!
//! ## Task lifecycle
//!
//! All tasks are spawned when the connection is established and run until:
//! - The peer disconnects (stream closed / Goodbye received)
//! - The node shuts down (outgoing channel closed)
//!
//! When the connection task exits, it notifies the node to remove the peer
//! from the peer table via a `disconnect_tx` oneshot.

use std::sync::Arc;

use muspell_proto::{
    AnnounceFrame, Frame, FrameBody, FrameId, NodeId, PongFrame, Timestamp,
};
use muspell_transport::codec::encode_frame;
use muspell_pubsub::PubSubLayer;
use muspell_rpc::{RpcClient, RpcConfig, RpcDispatcher, RpcLayer, RequestHandler};
use muspell_transport::{PeerInfo, TransportError};
use tokio::sync::{mpsc, oneshot};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use crate::config::NodeConfig;

// ── PeerSession ───────────────────────────────────────────────────────────────

/// Everything the node needs to interact with one connected peer.
///
/// Stored in the node's peer table after a successful connection/handshake.
#[derive(Clone)]
pub struct PeerSession {
    /// Verified metadata from the handshake.
    pub info: PeerInfo,
    /// Typed RPC client for this peer.
    ///
    /// Call `rpc.get(cid, None).await` etc. to make typed requests.
    pub rpc: RpcClient,
    /// Raw frame sender — shared by the RPC and pub/sub layers.
    ///
    /// The node's `PubSubLayer` uses this to send pub/sub frames to this peer.
    pub outgoing_tx: mpsc::Sender<Frame>,
}

impl PeerSession {
    /// The peer's `NodeId`.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.info.node_id
    }
}

// ── spawn_peer_tasks ──────────────────────────────────────────────────────────

/// Spawn all tasks for a newly established peer connection and return a
/// `PeerSession` for the node's peer table.
///
/// ## Generic parameters
///
/// `W` and `R` are the write/read halves of the QUIC stream. They are
/// generic because `MuspellConnection<W,R>` is generic — this function is
/// the only place where those concrete types are named.
///
/// ## Spawned tasks
///
/// 1. **connection_task** — owns the `MuspellConnection`. Bridges the wire to
///    the channel pair. Exits on peer disconnect or outgoing channel close.
/// 2. **rpc_dispatch_task** — drives `RpcDispatcher::run`. Routes responses to
///    pending callers and requests to the `RequestHandler`.
/// 3. **pubsub_router_task** — drives `PubSubRouter::run` for this peer. Routes
///    pub/sub extension frames to the local `SubscriptionManager`.
///
/// ## Cleanup
///
/// When the connection_task exits (peer disconnected), it sends on
/// `disconnect_tx` so the node can remove the peer from its table.
pub fn spawn_peer_tasks<W, R>(
    conn:          muspell_transport::MuspellConnection<W, R>,
    handler:       Arc<dyn RequestHandler>,
    pubsub:        PubSubLayer,
    config:        Arc<NodeConfig>,
    disconnect_tx: oneshot::Sender<NodeId>,
) -> PeerSession
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead  + Unpin + Send + 'static,
{
    let peer_info  = conn.peer_info().clone();
    let peer_id    = peer_info.node_id;
    let cap        = config.peer_channel_capacity;
    let unsol_cap  = config.unsolicited_channel_capacity;

    // ── Channels ─────────────────────────────────────────────────────────────

    // Outgoing: RpcClient + PubSubLayer → connection_task → wire
    let (outgoing_tx, outgoing_rx) = mpsc::channel::<Frame>(cap);

    // Incoming: connection_task → rpc_dispatcher
    let (incoming_tx, incoming_rx) = mpsc::channel::<Frame>(cap);

    // Unsolicited: rpc_dispatcher → pubsub_router
    let (unsol_tx, unsol_rx) = mpsc::channel::<Frame>(unsol_cap);

    // ── RPC layer ────────────────────────────────────────────────────────────

    let (rpc_client, rpc_dispatcher) = RpcLayer::new(
        outgoing_tx.clone(),
        handler,
        unsol_tx,
        config.rpc.clone(),
    );

    // ── Spawn: rpc_dispatch_task ──────────────────────────────────────────────

    tokio::spawn({
        async move {
            rpc_dispatcher.run(incoming_rx).await;
            debug!("rpc_dispatch_task: exited for {peer_id}");
        }
    });

    // ── Spawn: pubsub_router_task ─────────────────────────────────────────────

    let router = pubsub.router().clone();
    tokio::spawn(async move {
        router.run(unsol_rx, peer_id).await;
        debug!("pubsub_router_task: exited for {peer_id}");
    });

    // ── Spawn: connection_task ────────────────────────────────────────────────

    tokio::spawn(async move {
        run_connection_task(
            conn,
            incoming_tx,
            outgoing_rx,
            peer_id,
            disconnect_tx,
        ).await;
    });

    // ── Auto-announce ─────────────────────────────────────────────────────────
    // Sending an Announce frame immediately after connection is handled by the
    // caller (NodeHandle::do_connect) after this function returns.

    PeerSession {
        info: peer_info,
        rpc:  rpc_client,
        outgoing_tx,
    }
}

/// The connection task: bridges `MuspellConnection` ↔ channel pair.
///
/// ## Why `clone_send_arc` instead of `conn.send_frame()`
///
/// `conn.send_frame()` takes `&self` and contains an `.await`. Holding a
/// `&MuspellConnection<W,R>` across an `.await` inside `tokio::spawn`
/// requires `MuspellConnection<W,R>: Sync`, which needs `R: Sync`. Typical
/// async read halves (e.g. `tokio::io::ReadHalf`) are NOT `Sync`.
///
/// The fix: extract `Arc<Mutex<W>>` once up-front, then all sends go through
/// that directly using `encode_frame`. Only `conn.recv_frame()` (takes
/// `&mut self`) is called on the connection itself, which only needs `Send`.
async fn run_connection_task<W, R>(
    mut conn:        muspell_transport::MuspellConnection<W, R>,
    incoming_tx:     mpsc::Sender<Frame>,
    mut outgoing_rx: mpsc::Receiver<Frame>,
    peer_id:         NodeId,
    disconnect_tx:   oneshot::Sender<NodeId>,
)
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead  + Unpin + Send + 'static,
{
    debug!("connection_task: started for {peer_id}");

    // Extract the writer so we can send frames without borrowing &conn.
    // Arc<Mutex<W>> is always Send+Sync when W: Send, regardless of R.
    let send_arc = conn.clone_send_arc();

    loop {
        tokio::select! {
            // Receive from wire, forward to rpc_dispatcher.
            result = conn.recv_frame() => {
                match result {
                    Ok(frame) => {
                        match &frame.body {
                            FrameBody::Goodbye(g) => {
                                info!("connection_task: Goodbye from {peer_id}: {}", g.reason);
                                break;
                            }
                            FrameBody::Ping(ping) => {
                                // Build Pong without borrowing &conn.
                                let now = Timestamp::now().unwrap_or(Timestamp::ZERO);
                                let pong = Frame::new(
                                    FrameId::random(),
                                    now,
                                    FrameBody::Pong(PongFrame {
                                        nonce:        ping.nonce,
                                        ping_sent_at: ping.sent_at,
                                        pong_sent_at: now,
                                    }),
                                );
                                let mut guard = send_arc.lock().await;
                                if let Err(e) = encode_frame(&mut *guard, &pong).await {
                                    warn!("connection_task: pong failed for {peer_id}: {e}");
                                }
                            }
                            _ => {
                                if incoming_tx.send(frame).await.is_err() {
                                    debug!("connection_task: incoming_tx closed for {peer_id}");
                                    break;
                                }
                            }
                        }
                    }
                    Err(TransportError::StreamClosed) => {
                        debug!("connection_task: stream closed by {peer_id}");
                        break;
                    }
                    Err(e) => {
                        warn!("connection_task: recv error from {peer_id}: {e}");
                        break;
                    }
                }
            }

            // Drain outgoing channel, encode and send to wire.
            Some(frame) = outgoing_rx.recv() => {
                let mut guard = send_arc.lock().await;
                if let Err(e) = encode_frame(&mut *guard, &frame).await {
                    warn!("connection_task: send error to {peer_id}: {e}");
                    break;
                }
            }

            // Outgoing channel closed (node shut down).
            else => {
                debug!("connection_task: outgoing channel closed for {peer_id}");
                break;
            }
        }
    }

    // Send Goodbye on clean disconnect — again via send_arc, not &conn.
    let goodbye = Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::Goodbye(muspell_proto::GoodbyeFrame {
            reason:               "disconnecting".into(),
            reconnect_after_secs: None,
        }),
    );
    let mut guard = send_arc.lock().await;
    let _ = encode_frame(&mut *guard, &goodbye).await;
    drop(guard);

    // Notify node to remove peer from table.
    let _ = disconnect_tx.send(peer_id);

    debug!("connection_task: exited for {peer_id}");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_identity::NodeKeypair;
    use muspell_proto::{NodeId, NodeCapabilities, ProtocolVersion};
    use muspell_rpc::NullHandler;
    use muspell_transport::{MuspellConnection, TransportConfig};
    use std::sync::Arc;
    use tokio::io::duplex;
    use tokio::sync::oneshot;

    fn make_peer_info(node_id: NodeId) -> PeerInfo {
        PeerInfo {
            node_id,
            did:                None,
            capabilities:       NodeCapabilities::none(),
            user_agent:         None,
            binding:            None,
            negotiated_version: ProtocolVersion::CURRENT,
        }
    }

    // Helper: build a MuspellConnection over a duplex stream for testing.
    fn make_test_connection(
        node_id: NodeId,
    ) -> (
        MuspellConnection<
            tokio::io::WriteHalf<tokio::io::DuplexStream>,
            tokio::io::ReadHalf<tokio::io::DuplexStream>,
        >,
        tokio::io::DuplexStream, // the other half for test assertions
    ) {
        let (a, b) = duplex(65_536);
        let (w, r) = tokio::io::split(a);
        let config = Arc::new(TransportConfig::default());
        let peer   = make_peer_info(node_id);
        let conn   = MuspellConnection::new(w, r, peer, config);
        (conn, b)
    }

    #[tokio::test]
    async fn spawn_peer_tasks_returns_session_with_correct_node_id() {
        let peer_id = NodeId::from_bytes([7u8; 32]);
        let (conn, _other) = make_test_connection(peer_id);

        let (disc_tx, _disc_rx) = oneshot::channel();
        let (unsol_tx, _unsol_rx) = mpsc::channel::<Frame>(8);
        let (out_tx, _out_rx) = mpsc::channel::<Frame>(8);
        let node_id = NodeKeypair::generate().node_id();
        let pubsub  = PubSubLayer::new(out_tx, unsol_tx, node_id);
        let config  = Arc::new(NodeConfig::default());

        let session = spawn_peer_tasks(
            conn,
            Arc::new(NullHandler),
            pubsub,
            config,
            disc_tx,
        );

        assert_eq!(session.node_id(), peer_id);
        assert!(session.info.did.is_none());
    }

    #[tokio::test]
    async fn peer_session_rpc_client_is_cloneable() {
        let peer_id = NodeId::from_bytes([8u8; 32]);
        let (conn, _other) = make_test_connection(peer_id);

        let (disc_tx, _disc_rx) = oneshot::channel();
        let (unsol_tx, _unsol_rx) = mpsc::channel::<Frame>(8);
        let (out_tx, _out_rx) = mpsc::channel::<Frame>(8);
        let node_id = NodeKeypair::generate().node_id();
        let pubsub  = PubSubLayer::new(out_tx, unsol_tx, node_id);

        let session = spawn_peer_tasks(
            conn,
            Arc::new(NullHandler),
            pubsub,
            Arc::new(NodeConfig::default()),
            disc_tx,
        );

        // RpcClient must be Clone.
        let _clone = session.rpc.clone();
    }
}
