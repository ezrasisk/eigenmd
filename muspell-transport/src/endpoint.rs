//! `MuspellEndpoint` — the iroh QUIC endpoint with Muspell handshakes.
//!
//! ## Responsibilities
//!
//! - Registers the `muspell/0.1` ALPN with the iroh endpoint builder.
//! - Converts `iroh::endpoint::Connection` into `MuspellConnection` by
//!   running the Muspell handshake over the first bidi QUIC stream.
//! - Converts `muspell_proto::NodeId ↔ iroh::PublicKey` at the boundary.
//! - Holds the local keypairs (`DidKeypair`, `NodeKeypair`) and produces
//!   `IdentityBinding`s for outgoing connections.
//!
//! ## Thread safety
//!
//! `MuspellEndpoint` is `Clone + Send + Sync`. The inner `iroh::Endpoint`
//! is `Arc`-wrapped internally by iroh.

use std::sync::Arc;
use std::time::Duration;

use iroh::{endpoint::presets, Endpoint, EndpointAddr};
use muspell_identity::{
    sign_binding, DidKeypair, IdentityBinding, NodeKeypair,
};
use muspell_proto::{Did, NodeId, Timestamp};
use tokio::io::split;
use tracing::{debug, info, warn};

use crate::config::{TransportConfig, ALPN};
use crate::conn::MuspellConnection;
use crate::convert::{node_id_to_public_key, public_key_to_node_id};
use crate::error::{TransportError, TransportResult};
use crate::handshake::{perform_handshake_acceptor, perform_handshake_initiator};

// ── MuspellEndpoint ───────────────────────────────────────────────────────────

/// A Muspell-protocol QUIC endpoint.
///
/// Wraps `iroh::Endpoint` and adds the Muspell handshake, keypair
/// management, and type conversions.
///
/// ## Construction
///
/// ```rust,ignore
/// let endpoint = MuspellEndpoint::builder()
///     .with_node_keypair(node_kp)
///     .with_did_keypair(did_kp)
///     .with_config(config)
///     .bind()
///     .await?;
/// ```
#[derive(Clone)]
pub struct MuspellEndpoint {
    inner:      Endpoint,
    node_kp:    Arc<NodeKeypair>,
    did_kp:     Option<Arc<DidKeypair>>,
    config:     Arc<TransportConfig>,
}

impl MuspellEndpoint {
    // ── Builder ───────────────────────────────────────────────────────────────

    /// Begin constructing a `MuspellEndpoint`.
    #[must_use]
    pub fn builder() -> MuspellEndpointBuilder {
        MuspellEndpointBuilder::default()
    }

    // ── Local identity ────────────────────────────────────────────────────────

    /// The local `NodeId` (ephemeral, derived from the node keypair).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node_kp.node_id()
    }

    /// The local `Did`, if this endpoint was configured with a DID keypair.
    #[must_use]
    pub fn did(&self) -> Option<Did> {
        self.did_kp.as_ref().map(|kp| kp.did())
    }

    // ── Outgoing connections ──────────────────────────────────────────────────

    /// Connect to a remote Muspell node by its `NodeId`.
    ///
    /// Resolves the `NodeId` to an iroh `NodeAddr` and performs the
    /// Muspell handshake after QUIC connection establishment.
    ///
    /// # Errors
    /// - `TransportError::ConnectionError` if the QUIC connection fails.
    /// - `TransportError::HandshakeTimeout` if the handshake stalls.
    /// - Any other `TransportError` from the handshake protocol.
    pub async fn connect(
        &self,
        peer_node_id: NodeId,
    ) -> TransportResult<MuspellConnection<
        impl tokio::io::AsyncWrite + Unpin + Send,
        impl tokio::io::AsyncRead  + Unpin + Send,
    >> {
        let pk = node_id_to_public_key(&peer_node_id)
            .ok_or_else(|| TransportError::connection(
                "peer NodeId is not a valid Ed25519 public key"
            ))?;

        let node_addr: iroh::EndpointAddr = iroh::EndpointAddr::new(pk);

        debug!("connecting to {peer_node_id}");

        let conn: iroh::endpoint::Connection = self
            .inner
            .connect(node_addr, ALPN)
            .await
            .map_err(|e| TransportError::connection(e))?;

        debug!("QUIC connection established to {peer_node_id}; opening control stream");

        // Open the single bidi control stream.
        let (send, recv): (iroh::endpoint::SendStream, iroh::endpoint::RecvStream) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::connection(e))?;

        // Combine into a single AsyncRead + AsyncWrite for the handshake.
        // We use `tokio::io::join` conceptually but the handshake function
        // takes a single `AsyncRead + AsyncWrite` — use a `tokio::io::DuplexStream`
        // adapter. Since iroh streams are already separate, we use the
        // `tokio::io::ReadHalf`/`WriteHalf` approach via a joined stream.
        //
        // For simplicity, we pass send and recv directly through a small shim.
        let local_did_pair = self.make_binding_for_connect().await?;

        let mut combined = JoinedStream::new(send, recv);
        let peer_info = perform_handshake_initiator(
            &mut combined,
            &self.config,
            self.node_id(),
            local_did_pair,
        ).await?;

        info!("connected to {} (did={:?})", peer_info.node_id, peer_info.did);

        let (send_half, recv_half) = combined.into_halves();
        Ok(MuspellConnection::new(
            send_half,
            recv_half,
            peer_info,
            self.config.clone(),
        ))
    }

    // ── Incoming connections ───────────────────────────────────────────────────

    /// Accept the next incoming Muspell connection.
    ///
    /// Blocks until a connection arrives, then performs the Muspell
    /// handshake over the first accepted bidi stream.
    ///
    /// Returns `None` when the endpoint is shutting down.
    ///
    /// # Errors
    /// - `TransportError::ConnectionError` if the QUIC handshake fails.
    /// - `TransportError::HandshakeTimeout` if the Muspell handshake stalls.
    pub async fn accept(&self) -> Option<TransportResult<MuspellConnection<
        impl tokio::io::AsyncWrite + Unpin + Send,
        impl tokio::io::AsyncRead  + Unpin + Send,
    >>> {
        let incoming = self.inner.accept().await?;

        let connecting = match incoming.accept() {
            Ok(c)  => c,
            Err(e) => {
                warn!("accept: TLS handshake failed: {e}");
                return Some(Err(TransportError::connection(e)));
            }
        };

        let conn = match connecting.await {
            Ok(c)  => c,
            Err(e) => {
                warn!("accept: QUIC connection failed: {e}");
                return Some(Err(TransportError::connection(e)));
            }
        };

        let remote_pk  = conn.remote_id();
        let remote_nid = public_key_to_node_id(&remote_pk);
        debug!("incoming QUIC connection from {remote_nid}; waiting for control stream");

        let (send, recv) = match conn.accept_bi().await {
            Ok(s)  => s,
            Err(e) => {
                warn!("accept: failed to accept bidi stream: {e}");
                return Some(Err(TransportError::connection(e)));
            }
        };

        let local_did_pair = match self.make_binding_for_connect().await {
            Ok(p)  => p,
            Err(e) => return Some(Err(e)),
        };

        let mut combined = JoinedStream::new(send, recv);
        let peer_info = match perform_handshake_acceptor(
            &mut combined,
            &self.config,
            self.node_id(),
            local_did_pair,
        ).await {
            Ok(p)  => p,
            Err(e) => {
                warn!("accept: Muspell handshake failed: {e}");
                return Some(Err(e));
            }
        };

        info!("accepted connection from {} (did={:?})", peer_info.node_id, peer_info.did);

        let (send_half, recv_half) = combined.into_halves();
        Some(Ok(MuspellConnection::new(
            send_half,
            recv_half,
            peer_info,
            self.config.clone(),
        )))
    }

    /// Return the local `NodeAddr` that peers can use to connect to us.
    ///
    /// This is the iroh-native address, usable in `iroh::NodeAddr`.
    pub fn node_addr(&self) -> TransportResult<iroh::EndpointAddr> {
        Ok(self.inner.addr())
    }

    /// Close the endpoint and all active connections.
    pub async fn close(&self) {
        self.inner.close().await;
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Produce the `(Did, IdentityBinding)` pair to send during the handshake,
    /// if this endpoint has a `DidKeypair` configured.
    async fn make_binding_for_connect(
        &self,
    ) -> TransportResult<Option<(Did, IdentityBinding)>> {
        let did_kp = match &self.did_kp {
            Some(kp) => kp,
            None     => return Ok(None),
        };

        let now = Timestamp::now()
            .ok_or_else(|| TransportError::connection("system clock before epoch"))?;
        let valid_until = Timestamp::from_secs(
            now.secs + self.config.binding_validity.as_secs() as i64,
        );

        let binding = sign_binding(did_kp, &self.node_kp, now, Some(valid_until))
            .map_err(TransportError::Identity)?;

        Ok(Some((did_kp.did(), binding)))
    }
}

// ── MuspellEndpointBuilder ────────────────────────────────────────────────────

/// Builder for [`MuspellEndpoint`].
#[derive(Default)]
pub struct MuspellEndpointBuilder {
    node_kp: Option<NodeKeypair>,
    did_kp:  Option<DidKeypair>,
    config:  Option<TransportConfig>,
}

impl MuspellEndpointBuilder {
    /// Set the node keypair (required).
    #[must_use]
    pub fn with_node_keypair(mut self, kp: NodeKeypair) -> Self {
        self.node_kp = Some(kp);
        self
    }

    /// Set the DID keypair (optional; enables authenticated connections).
    #[must_use]
    pub fn with_did_keypair(mut self, kp: DidKeypair) -> Self {
        self.did_kp = Some(kp);
        self
    }

    /// Override the default transport configuration.
    #[must_use]
    pub fn with_config(mut self, config: TransportConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Bind the endpoint and begin listening.
    ///
    /// # Errors
    /// - `TransportError::ConnectionError` if iroh fails to bind.
    pub async fn bind(self) -> TransportResult<MuspellEndpoint> {
        let node_kp = self.node_kp.unwrap_or_else(NodeKeypair::generate);
        let config  = self.config.unwrap_or_default();

        let iroh_endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| TransportError::connection(e))?;

        Ok(MuspellEndpoint {
            inner:   iroh_endpoint,
            node_kp: Arc::new(node_kp),
            did_kp:  self.did_kp.map(Arc::new),
            config:  Arc::new(config),
        })
    }
}

// ── JoinedStream ─────────────────────────────────────────────────────────────

/// Combines an iroh `SendStream` and `RecvStream` into a single type
/// that implements both `AsyncRead` and `AsyncWrite`.
///
/// The handshake functions require `AsyncRead + AsyncWrite + Unpin` on a
/// single value; this shim provides that without copying data.
pub(crate) struct JoinedStream<W, R> {
    send: W,
    recv: R,
}

impl<W, R> JoinedStream<W, R> {
    pub(crate) fn new(send: W, recv: R) -> Self {
        Self { send, recv }
    }

    /// Decompose back into send/recv halves (e.g. for passing to `MuspellConnection`).
    pub(crate) fn into_halves(self) -> (W, R) {
        (self.send, self.recv)
    }
}

impl<W, R> tokio::io::AsyncWrite for JoinedStream<W, R>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx:       &mut std::task::Context<'_>,
        buf:      &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx:       &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx:       &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

impl<W, R> tokio::io::AsyncRead for JoinedStream<W, R>
where
    W: Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self:  std::pin::Pin<&mut Self>,
        cx:        &mut std::task::Context<'_>,
        buf:       &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

// `JoinedStream` is `Unpin` when both halves are `Unpin`.
impl<W: Unpin, R: Unpin> Unpin for JoinedStream<W, R> {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    // ── JoinedStream ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn joined_stream_write_and_read() {
        // Use two duplex pairs to simulate independent W and R.
        let (mut wire_w, mut wire_r) = duplex(1024);

        // JoinedStream: writes go to wire_w, reads come from wire_r.
        // We need the inverse pair for the other side.
        let (mut other_r, mut other_w) = duplex(1024);

        // For simplicity: just test that AsyncWrite on JoinedStream works.
        let (send_side, recv_side) = duplex(1024);
        let (write_half, read_half) = tokio::io::split(send_side);
        let (write_half2, read_half2) = tokio::io::split(recv_side);

        let mut joined_a = JoinedStream::new(write_half,  read_half2);
        let mut joined_b = JoinedStream::new(write_half2, read_half);

        // A writes, B reads.
        joined_a.write_all(b"hello muspell").await.unwrap();
        let mut buf = vec![0u8; 13];
        joined_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello muspell");

        // Suppress unused warnings.
        let _ = (wire_w, wire_r, other_r, other_w);
    }

    #[tokio::test]
    async fn joined_stream_into_halves() {
        let (send, recv) = duplex(1024);
        let (w, r) = tokio::io::split(send);
        let (w2, r2) = tokio::io::split(recv);
        let joined = JoinedStream::new(w, r2);
        let (_, _) = joined.into_halves(); // just tests the decomposition compiles
        let _ = (w2, r);
    }
}
