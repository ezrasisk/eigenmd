//! Muspell connection handshake — `Hello` / `HelloAck` exchange.
//!
//! ## Protocol sequence
//!
//! ```text
//!   Initiator                         Acceptor
//!       │                                │
//!       │──── Hello ────────────────────▶│  (initiator sends first)
//!       │◀─── HelloAck ─────────────────│  (acceptor replies)
//!       │──── HelloAck ─────────────────▶│  (initiator confirms)
//!       │                                │
//!       │           ← Ready →            │
//! ```
//!
//! Both sides exchange `Hello` + `HelloAck`. The initiator sends `Hello`
//! first. The acceptor sends `HelloAck` in response and then waits for
//! the initiator's `HelloAck`. Both sides are `Ready` once they have
//! received the other's `HelloAck`.
//!
//! ## Identity bindings
//!
//! If a node has a `Did` (stable identity), it MUST include an
//! `IdentityBinding` alongside its `Hello`. The binding proves
//! the DID's private key signed this `NodeId`. The peer verifies
//! the binding before accepting the `Hello`. Nodes without a `Did`
//! connect anonymously.
//!
//! ## Frame encoding
//!
//! Handshake frames use the same length-prefixed CBOR codec as all
//! other frames. No special pre-handshake binary format.

use std::sync::Arc;
use std::time::Duration;

use muspell_identity::{IdentityBinding, verify_binding};
use muspell_proto::{
    Did, Frame, FrameBody, FrameId, HelloAckFrame, HelloFrame,
    NodeCapabilities, NodeId, ProtocolVersion, Timestamp,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::codec::{decode_frame, encode_frame};
use crate::config::TransportConfig;
use crate::error::{TransportError, TransportResult};

// ── PeerInfo ──────────────────────────────────────────────────────────────────

/// Information about a remote peer, established during the handshake.
///
/// Available on a connection after `HandshakeOutcome::Ready` is returned.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// The peer's ephemeral `NodeId` (their iroh public key).
    pub node_id: NodeId,
    /// The peer's stable `Did`, if they authenticated with one.
    pub did: Option<Did>,
    /// The capabilities the peer advertised.
    pub capabilities: NodeCapabilities,
    /// The peer's user-agent string, if provided.
    pub user_agent: Option<String>,
    /// The identity binding the peer provided, if any.
    ///
    /// Present and verified if `did` is `Some`. `None` for anonymous peers.
    pub binding: Option<IdentityBinding>,
    /// The protocol version agreed for this connection.
    pub negotiated_version: ProtocolVersion,
}

// ── perform_handshake_initiator ───────────────────────────────────────────────

/// Execute the initiator side of the Muspell handshake.
///
/// The initiator:
/// 1. Sends `Hello` (with optional `IdentityBinding`).
/// 2. Receives and validates peer's `HelloAck`.
/// 3. Sends its own `HelloAck` to complete the exchange.
///
/// Returns the verified `PeerInfo` on success.
///
/// # Errors
/// - `HandshakeTimeout` if the peer does not respond within the configured window.
/// - `UnexpectedHandshakeFrame` if the peer violates the sequence.
/// - `VersionMismatch` if the peers cannot agree on a protocol version.
/// - `Identity(...)` if the peer's binding fails verification.
pub async fn perform_handshake_initiator<S>(
    stream:    &mut S,
    config:    &Arc<TransportConfig>,
    local_node_id: NodeId,
    local_did: Option<(Did, IdentityBinding)>,
) -> TransportResult<PeerInfo>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let now = Timestamp::now()
        .ok_or_else(|| TransportError::connection("system clock before epoch"))?;

    // ── Step 1: send Hello ────────────────────────────────────────────────────

    let (local_did_opt, local_binding_opt) = match local_did {
        Some((did, binding)) => (Some(did), Some(binding)),
        None                 => (None, None),
    };

    let hello = build_hello_frame(
        local_node_id,
        local_did_opt,
        config,
    );
    encode_frame(stream, &hello).await?;
    debug!("initiator: Hello sent (node_id={})", local_node_id);

    // ── If we have a binding, send it right after Hello ───────────────────────
    // The binding is sent as an Extension frame immediately after Hello so
    // we don't need to change the HelloFrame struct.
    // Actually — we embed binding data differently. Let's carry it in the
    // handshake context; the acceptor sends binding after HelloAck.
    // For simplicity: we encode the binding inline in a custom Extension frame
    // following Hello. If no binding, nothing is sent.

    if let Some(ref binding) = local_binding_opt {
        let ext = build_binding_frame(binding, FrameId::from_u128(1));
        encode_frame(stream, &ext).await?;
    }

    // ── Step 2: receive peer HelloAck ─────────────────────────────────────────

    let (peer_hello_ack, peer_binding) = timeout(
        config.handshake_timeout,
        receive_hello_ack_and_binding(stream, config.max_frame_size),
    )
    .await
    .map_err(|_| TransportError::HandshakeTimeout {
        secs: config.handshake_timeout.as_secs(),
    })??;

    debug!("initiator: HelloAck received from {}", peer_hello_ack.node_id);

    // ── Validate version ──────────────────────────────────────────────────────

    let negotiated = peer_hello_ack.negotiated_version;
    if !ProtocolVersion::CURRENT.is_compatible_with(negotiated) {
        return Err(TransportError::VersionMismatch {
            ours: ProtocolVersion::CURRENT,
            peer: negotiated,
        });
    }

    // ── Validate peer binding if they have a DID ──────────────────────────────

    validate_peer_binding(peer_hello_ack.did, &peer_binding, now)?;

    // ── Step 3: send our HelloAck ─────────────────────────────────────────────

    let our_ack = build_hello_ack_frame(
        local_node_id,
        local_did_opt,
        negotiated,
        &peer_hello_ack.accepted_capabilities,
    );
    encode_frame(stream, &our_ack).await?;
    debug!("initiator: HelloAck sent, handshake complete");

    // ── If we have a binding, send it after our HelloAck ─────────────────────

    if let Some(ref binding) = local_binding_opt {
        let ext = build_binding_frame(binding, FrameId::from_u128(2));
        encode_frame(stream, &ext).await?;
    }

    Ok(PeerInfo {
        node_id:            peer_hello_ack.node_id,
        did:                peer_hello_ack.did,
        capabilities:       peer_hello_ack.accepted_capabilities,
        user_agent:         None, // HelloAck doesn't carry user_agent
        binding:            peer_binding,
        negotiated_version: negotiated,
    })
}

// ── perform_handshake_acceptor ────────────────────────────────────────────────

/// Execute the acceptor side of the Muspell handshake.
///
/// The acceptor:
/// 1. Receives the initiator's `Hello`.
/// 2. Validates version and optional binding.
/// 3. Sends its `HelloAck` (with optional binding).
/// 4. Receives the initiator's `HelloAck`.
///
/// Returns the verified `PeerInfo` on success.
pub async fn perform_handshake_acceptor<S>(
    stream:        &mut S,
    config:        &Arc<TransportConfig>,
    local_node_id: NodeId,
    local_did:     Option<(Did, IdentityBinding)>,
) -> TransportResult<PeerInfo>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let now = Timestamp::now()
        .ok_or_else(|| TransportError::connection("system clock before epoch"))?;

    // ── Step 1: receive peer Hello ────────────────────────────────────────────

    let (peer_hello, peer_binding) = timeout(
        config.handshake_timeout,
        receive_hello_and_binding(stream, config.max_frame_size),
    )
    .await
    .map_err(|_| TransportError::HandshakeTimeout {
        secs: config.handshake_timeout.as_secs(),
    })??;

    debug!("acceptor: Hello received from {}", peer_hello.node_id);

    // ── Version check ─────────────────────────────────────────────────────────

    let peer_version = ProtocolVersion::CURRENT; // will be sent in HelloAck
    if !ProtocolVersion::CURRENT.is_compatible_with(peer_version) {
        return Err(TransportError::VersionMismatch {
            ours: ProtocolVersion::CURRENT,
            peer: peer_version,
        });
    }

    // ── Validate peer binding ─────────────────────────────────────────────────

    validate_peer_binding(peer_hello.did, &peer_binding, now)?;

    // ── Step 2: send HelloAck ─────────────────────────────────────────────────

    let (local_did_opt, local_binding_opt) = match local_did {
        Some((did, binding)) => (Some(did), Some(binding)),
        None                 => (None, None),
    };

    let ack = build_hello_ack_frame(
        local_node_id,
        local_did_opt,
        ProtocolVersion::CURRENT,
        &peer_hello.capabilities,
    );
    encode_frame(stream, &ack).await?;
    debug!("acceptor: HelloAck sent");

    if let Some(ref binding) = local_binding_opt {
        let ext = build_binding_frame(binding, FrameId::from_u128(10));
        encode_frame(stream, &ext).await?;
    }

    // ── Step 3: receive initiator's HelloAck ──────────────────────────────────

    let (init_ack, _init_binding) = timeout(
        config.handshake_timeout,
        receive_hello_ack_and_binding(stream, config.max_frame_size),
    )
    .await
    .map_err(|_| TransportError::HandshakeTimeout {
        secs: config.handshake_timeout.as_secs(),
    })??;

    // The initiator's HelloAck node_id must match what they said in Hello.
    if init_ack.node_id != peer_hello.node_id {
        return Err(TransportError::NodeIdMismatch {
            hello_node_id: peer_hello.node_id,
            ack_node_id:   init_ack.node_id,
        });
    }

    debug!("acceptor: initiator HelloAck received, handshake complete");

    Ok(PeerInfo {
        node_id:            peer_hello.node_id,
        did:                peer_hello.did,
        capabilities:       peer_hello.capabilities,
        user_agent:         peer_hello.user_agent,
        binding:            peer_binding,
        negotiated_version: ProtocolVersion::CURRENT,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Read one frame and expect it to be `Hello`.
/// Then peek at the next frame; if it is a binding extension, read it too.
async fn receive_hello_and_binding<S>(
    stream:    &mut S,
    max_bytes: u32,
) -> TransportResult<(HelloFrame, Option<IdentityBinding>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = decode_frame(stream, max_bytes).await?;
    let hello = match frame.body {
        FrameBody::Hello(h) => h,
        other => return Err(TransportError::UnexpectedHandshakeFrame {
            expected: "Hello",
            got:      other.variant_name_static(),
        }),
    };

    // The binding follows as an Extension frame tagged with the binding namespace.
    // We try to read one more frame; if it's not a binding extension we've
    // overread. In practice the stream is sequential so this is safe.
    // For a real implementation, use a buffered reader; for now we rely on
    // the protocol being followed correctly.
    //
    // If the peer has a DID, they MUST send a binding; if not, we stop here.
    let binding = if hello.did.is_some() {
        Some(read_binding_frame(stream, max_bytes).await?)
    } else {
        None
    };

    Ok((hello, binding))
}

/// Read one frame and expect it to be `HelloAck`.
/// Then optionally read a following binding extension.
async fn receive_hello_ack_and_binding<S>(
    stream:    &mut S,
    max_bytes: u32,
) -> TransportResult<(HelloAckFrame, Option<IdentityBinding>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = decode_frame(stream, max_bytes).await?;
    let ack = match frame.body {
        FrameBody::HelloAck(a) => a,
        other => return Err(TransportError::UnexpectedHandshakeFrame {
            expected: "HelloAck",
            got:      other.variant_name_static(),
        }),
    };

    let binding = if ack.did.is_some() {
        Some(read_binding_frame(stream, max_bytes).await?)
    } else {
        None
    };

    Ok((ack, binding))
}

/// Read one frame and expect it to be a binding extension.
async fn read_binding_frame<S>(
    stream:    &mut S,
    max_bytes: u32,
) -> TransportResult<IdentityBinding>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = decode_frame(stream, max_bytes).await?;
    match frame.body {
        FrameBody::Extension(ext) if ext.namespace == BINDING_EXTENSION_NS => {
            decode_binding_from_cbor(&ext.payload.0)
        }
        other => Err(TransportError::UnexpectedHandshakeFrame {
            expected: "IdentityBinding extension",
            got:      other.variant_name_static(),
        }),
    }
}

/// Namespace string for the binding extension frame.
const BINDING_EXTENSION_NS: &str = "muspell/identity-binding";

/// Encode a binding into an `Extension` frame.
fn build_binding_frame(binding: &IdentityBinding, id: FrameId) -> Frame {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(binding, &mut payload)
        .expect("IdentityBinding CBOR serialisation is infallible");
    Frame::new(
        id,
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::Extension(muspell_proto::ExtensionFrame {
            namespace: BINDING_EXTENSION_NS.into(),
            kind:      "binding".into(),
            payload:   muspell_proto::Bytes::from_slice(&payload),
        }),
    )
}

/// Deserialize an `IdentityBinding` from CBOR bytes.
fn decode_binding_from_cbor(bytes: &[u8]) -> TransportResult<IdentityBinding> {
    ciborium::de::from_reader(std::io::Cursor::new(bytes))
        .map_err(|e| TransportError::DecodeError { reason: e.to_string() })
}

/// Validate that `peer_binding` is consistent with `peer_did` and
/// cryptographically sound at `now`.
fn validate_peer_binding(
    peer_did:     Option<Did>,
    peer_binding: &Option<IdentityBinding>,
    now:          Timestamp,
) -> TransportResult<()> {
    match (peer_did, peer_binding) {
        (Some(_), None) => {
            // Peer claimed a DID but sent no binding.
            Err(TransportError::MissingIdentityBinding)
        }
        (None, Some(_)) => {
            // Peer sent a binding but claimed no DID. Unusual but not
            // harmful — we accept it and treat the connection as anonymous.
            warn!("peer sent a binding without a DID; treating as anonymous");
            Ok(())
        }
        (Some(did), Some(binding)) => {
            // The binding's DID must match the one in the Hello.
            if binding.did != did {
                return Err(TransportError::Identity(
                    muspell_identity::IdentityError::BindingSignatureInvalid,
                ));
            }
            verify_binding(binding, now).map_err(TransportError::Identity)
        }
        (None, None) => Ok(()), // anonymous node, no verification needed
    }
}

/// Construct a `Hello` frame from local state.
fn build_hello_frame(
    node_id: NodeId,
    did:     Option<Did>,
    config:  &TransportConfig,
) -> Frame {
    Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::Hello(HelloFrame {
            node_id,
            did,
            capabilities: config.local_capabilities.clone(),
            user_agent:   config.user_agent.clone(),
        }),
    )
}

/// Construct a `HelloAck` frame from local state.
fn build_hello_ack_frame(
    node_id:              NodeId,
    did:                  Option<Did>,
    negotiated_version:   ProtocolVersion,
    accepted_capabilities: &NodeCapabilities,
) -> Frame {
    Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::HelloAck(HelloAckFrame {
            node_id,
            did,
            negotiated_version,
            accepted_capabilities: accepted_capabilities.clone(),
            motd: None,
        }),
    )
}

// ── FrameBody variant name helper ─────────────────────────────────────────────

trait FrameBodyExt {
    fn variant_name_static(&self) -> &'static str;
}

impl FrameBodyExt for FrameBody {
    fn variant_name_static(&self) -> &'static str {
        self.variant_name()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_identity::{DidKeypair, NodeKeypair, sign_binding};
    use std::sync::Arc;
    use tokio::io::duplex;

    fn make_config() -> Arc<TransportConfig> {
        Arc::new(
            TransportConfig::new()
                .with_handshake_timeout(Duration::from_secs(5))
                .with_user_agent("muspell-test/0.1"),
        )
    }

    // ── Anonymous handshake (no DID on either side) ───────────────────────────

    #[tokio::test]
    async fn anonymous_handshake_succeeds() {
        let (mut initiator_stream, mut acceptor_stream) = duplex(65536);
        let config = make_config();

        let initiator_node = NodeKeypair::generate();
        let acceptor_node  = NodeKeypair::generate();

        let init_cfg = config.clone();
        let init_nid = initiator_node.node_id();
        let init_task = tokio::spawn(async move {
            perform_handshake_initiator(
                &mut initiator_stream,
                &init_cfg,
                init_nid,
                None,
            ).await
        });

        let acc_cfg  = config.clone();
        let acc_nid  = acceptor_node.node_id();
        let acc_task = tokio::spawn(async move {
            perform_handshake_acceptor(
                &mut acceptor_stream,
                &acc_cfg,
                acc_nid,
                None,
            ).await
        });

        let (init_result, acc_result) = tokio::join!(init_task, acc_task);
        let init_peer = init_result.unwrap().unwrap();
        let acc_peer  = acc_result.unwrap().unwrap();

        // Each side should see the other's node_id.
        assert_eq!(init_peer.node_id, acceptor_node.node_id());
        assert_eq!(acc_peer.node_id,  initiator_node.node_id());

        // No DIDs on either side.
        assert!(init_peer.did.is_none());
        assert!(acc_peer.did.is_none());
    }

    // ── Authenticated handshake (both sides have DIDs) ────────────────────────

    #[tokio::test]
    async fn authenticated_handshake_succeeds() {
        let (mut init_stream, mut acc_stream) = duplex(65536);
        let config = make_config();

        let init_did_kp  = DidKeypair::generate();
        let init_node_kp = NodeKeypair::generate();
        let acc_did_kp   = DidKeypair::generate();
        let acc_node_kp  = NodeKeypair::generate();

        let now    = Timestamp::now().unwrap();
        let expiry = Timestamp::from_secs(now.secs + 3600);

        let init_binding = sign_binding(
            &init_did_kp, &init_node_kp, now, Some(expiry),
        ).unwrap();
        let acc_binding = sign_binding(
            &acc_did_kp, &acc_node_kp, now, Some(expiry),
        ).unwrap();

        let init_did  = init_did_kp.did();
        let init_nid  = init_node_kp.node_id();
        let acc_did   = acc_did_kp.did();
        let acc_nid   = acc_node_kp.node_id();
        let cfg_i     = config.clone();
        let cfg_a     = config.clone();

        let init_task = tokio::spawn(async move {
            perform_handshake_initiator(
                &mut init_stream,
                &cfg_i,
                init_nid,
                Some((init_did, init_binding)),
            ).await
        });

        let acc_task = tokio::spawn(async move {
            perform_handshake_acceptor(
                &mut acc_stream,
                &cfg_a,
                acc_nid,
                Some((acc_did, acc_binding)),
            ).await
        });

        let (ir, ar) = tokio::join!(init_task, acc_task);
        let init_peer = ir.unwrap().expect("initiator handshake should succeed");
        let acc_peer  = ar.unwrap().expect("acceptor handshake should succeed");

        assert_eq!(init_peer.node_id, acc_nid);
        assert_eq!(init_peer.did,     Some(acc_did));
        assert!(init_peer.binding.is_some());

        assert_eq!(acc_peer.node_id, init_nid);
        assert_eq!(acc_peer.did,     Some(init_did));
        assert!(acc_peer.binding.is_some());
    }

    // ── DID without binding is rejected ──────────────────────────────────────

    #[tokio::test]
    async fn handshake_fails_did_without_binding() {
        use muspell_proto::{FrameBody, HelloFrame, NodeCapabilities};
        // Manually craft a Hello that claims a DID but sends no binding.
        let (mut init_stream, mut acc_stream) = duplex(65536);
        let config = make_config();
        let acc_node = NodeKeypair::generate();
        let fake_did = DidKeypair::generate().did();

        // Acceptor task — should fail with MissingIdentityBinding.
        let cfg_a   = config.clone();
        let acc_nid = acc_node.node_id();
        let acc_task = tokio::spawn(async move {
            perform_handshake_acceptor(
                &mut acc_stream,
                &cfg_a,
                acc_nid,
                None,
            ).await
        });

        // Manually send a Hello with a DID but no binding.
        let bad_hello = Frame::new(
            FrameId::from_u128(99),
            Timestamp::ZERO,
            FrameBody::Hello(HelloFrame {
                node_id:      NodeKeypair::generate().node_id(),
                did:          Some(fake_did),
                capabilities: NodeCapabilities::none(),
                user_agent:   None,
            }),
        );
        encode_frame(&mut init_stream, &bad_hello).await.unwrap();
        // Do NOT send the binding — this should trigger the error.

        let result = acc_task.await.unwrap();
        assert!(
            matches!(result, Err(TransportError::MissingIdentityBinding)),
            "expected MissingIdentityBinding, got: {result:?}",
        );
    }
}
