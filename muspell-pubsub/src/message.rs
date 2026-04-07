//! `PubSubMessage` — the pub/sub wire envelope and its codec.
//!
//! ## Wire encoding
//!
//! Pub/sub messages ride inside the existing `ExtensionFrame` to avoid
//! requiring changes to the transport or proto layers.
//!
//! ```text
//! Frame {
//!   body: ExtensionFrame {
//!     namespace: "muspell/pubsub",
//!     kind:      "message",
//!     payload:   <CBOR-encoded PubSubMessage>,
//!   }
//! }
//! ```
//!
//! The outer `Frame` envelope carries the timestamp and `FrameId`. The inner
//! `PubSubMessage` carries the `TopicId`, the opaque payload, and the sender's
//! `NodeId`. This two-level structure keeps pubsub entirely self-contained
//! without touching any existing frame definitions.
//!
//! ## Subscribe / Unsubscribe handshake
//!
//! Subscribe and Unsubscribe are also carried as `ExtensionFrame`s with
//! `kind = "subscribe"` / `kind = "unsubscribe"`. Their payload is a single
//! CBOR-encoded `TopicId`.
//!
//! | kind          | payload               | meaning                        |
//! |---------------|-----------------------|--------------------------------|
//! | `"subscribe"` | CBOR `[u8; 32]`       | sender wants messages on topic |
//! | `"unsubscribe"`| CBOR `[u8; 32]`      | sender no longer wants them    |
//! | `"message"`   | CBOR `PubSubMessage`  | a message on a topic           |

use muspell_proto::{
    Bytes, ExtensionFrame, Frame, FrameBody, FrameId, NodeId, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::topic::TopicId;
use crate::error::{PubSubError, PubSubResult};

// ── Extension namespace constant ──────────────────────────────────────────────

/// The `ExtensionFrame::namespace` value for all pub/sub frames.
pub const PUBSUB_NS: &str = "muspell/pubsub";

/// `ExtensionFrame::kind` for a published message.
pub const KIND_MESSAGE: &str = "message";
/// `ExtensionFrame::kind` for a subscribe request.
pub const KIND_SUBSCRIBE: &str = "subscribe";
/// `ExtensionFrame::kind` for an unsubscribe request.
pub const KIND_UNSUBSCRIBE: &str = "unsubscribe";

// ── PubSubMessage ─────────────────────────────────────────────────────────────

/// The inner envelope of a published message.
///
/// Serialised as CBOR and placed in the `payload` of an `ExtensionFrame`.
///
/// ## Fields
///
/// - `topic`   — which topic this message belongs to
/// - `seq`     — per-publisher monotonic sequence number; receivers may
///               use this to detect gaps or deduplicate retransmissions
/// - `sender`  — the publishing node's `NodeId`
/// - `payload` — opaque application-defined bytes
///
/// The outer `Frame` envelope already carries a `Timestamp`, so no
/// separate timestamp is stored here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PubSubMessage {
    /// The topic this message was published to.
    pub topic: TopicId,
    /// Monotonically increasing per-publisher sequence number.
    ///
    /// Starts at 0. Incremented by 1 for each message published on this
    /// topic by this sender. Used for gap detection; NOT a global ordering.
    pub seq: u64,
    /// The publishing node's identity.
    pub sender: NodeId,
    /// The application payload. Opaque to the pub/sub layer.
    pub payload: Bytes,
}

impl PubSubMessage {
    /// Construct a new message. `seq` is the caller's responsibility.
    #[must_use]
    pub fn new(topic: TopicId, seq: u64, sender: NodeId, payload: Bytes) -> Self {
        Self { topic, seq, sender, payload }
    }

    /// The size of the payload in bytes.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

impl fmt::Display for PubSubMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PubSubMessage(topic={} seq={} from={} payload={}B)",
            self.topic,
            self.seq,
            self.sender,
            self.payload_len(),
        )
    }
}

// ── Received message — includes outer envelope metadata ───────────────────────

/// A message as received by a subscriber, including outer envelope metadata.
///
/// The `Frame` envelope fields (timestamp, id) are extracted and surfaced
/// alongside the `PubSubMessage` so subscribers have full context without
/// needing to interact with the raw frame.
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// The inner pub/sub message.
    pub message:    PubSubMessage,
    /// Wall-clock time from the outer `Frame` envelope.
    pub received_at: Timestamp,
    /// The `FrameId` of the outer frame (for deduplication / tracing).
    pub frame_id:   FrameId,
}

impl ReceivedMessage {
    /// Convenience accessor for the topic.
    #[must_use]
    pub fn topic(&self) -> TopicId {
        self.message.topic
    }

    /// Convenience accessor for the sender.
    #[must_use]
    pub fn sender(&self) -> NodeId {
        self.message.sender
    }

    /// Convenience accessor for the payload.
    #[must_use]
    pub fn payload(&self) -> &Bytes {
        &self.message.payload
    }

    /// Convenience accessor for the sequence number.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.message.seq
    }
}

// ── Frame encoding ────────────────────────────────────────────────────────────

/// Encode a `PubSubMessage` into an `ExtensionFrame`-bearing `Frame`.
///
/// The outer `Frame` gets a fresh random `FrameId` and the current timestamp.
///
/// # Errors
/// Returns `PubSubError::Encode` if CBOR serialisation fails.
pub fn encode_message(msg: &PubSubMessage) -> PubSubResult<Frame> {
    let payload_bytes = cbor_encode(msg)?;
    Ok(Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::Extension(ExtensionFrame {
            namespace: PUBSUB_NS.into(),
            kind:      KIND_MESSAGE.into(),
            payload:   Bytes::from_slice(&payload_bytes),
        }),
    ))
}

/// Encode a subscribe request for `topic_id` into a `Frame`.
///
/// # Errors
/// Returns `PubSubError::Encode` if CBOR serialisation fails.
pub fn encode_subscribe(topic_id: TopicId) -> PubSubResult<Frame> {
    let payload_bytes = cbor_encode(&topic_id.as_bytes().as_slice())?;
    Ok(Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::Extension(ExtensionFrame {
            namespace: PUBSUB_NS.into(),
            kind:      KIND_SUBSCRIBE.into(),
            payload:   Bytes::from_slice(&payload_bytes),
        }),
    ))
}

/// Encode an unsubscribe request for `topic_id` into a `Frame`.
///
/// # Errors
/// Returns `PubSubError::Encode` if CBOR serialisation fails.
pub fn encode_unsubscribe(topic_id: TopicId) -> PubSubResult<Frame> {
    let payload_bytes = cbor_encode(&topic_id.as_bytes().as_slice())?;
    Ok(Frame::new(
        FrameId::random(),
        Timestamp::now().unwrap_or(Timestamp::ZERO),
        FrameBody::Extension(ExtensionFrame {
            namespace: PUBSUB_NS.into(),
            kind:      KIND_UNSUBSCRIBE.into(),
            payload:   Bytes::from_slice(&payload_bytes),
        }),
    ))
}

// ── Frame decoding ────────────────────────────────────────────────────────────

/// The three recognised pub/sub frame kinds, after decoding.
#[derive(Debug)]
pub enum DecodedPubSubFrame {
    /// A published message.
    Message(ReceivedMessage),
    /// A subscribe request for the given topic.
    Subscribe(TopicId),
    /// An unsubscribe request for the given topic.
    Unsubscribe(TopicId),
}

/// Try to decode a `Frame` as a pub/sub extension frame.
///
/// Returns `None` if the frame is not a pub/sub frame (different namespace
/// or not an `ExtensionFrame`). Returns `Err` if it IS a pub/sub frame but
/// the payload is malformed.
///
/// This is the central parse point: all incoming frames pass through here
/// in the `PubSubRouter`.
pub fn try_decode_pubsub_frame(frame: &Frame) -> PubSubResult<Option<DecodedPubSubFrame>> {
    let ext = match &frame.body {
        FrameBody::Extension(e) if e.namespace == PUBSUB_NS => e,
        _ => return Ok(None),
    };

    match ext.kind.as_str() {
        KIND_MESSAGE => {
            let msg: PubSubMessage = cbor_decode(ext.payload.as_ref())?;
            Ok(Some(DecodedPubSubFrame::Message(ReceivedMessage {
                message:     msg,
                received_at: frame.timestamp,
                frame_id:    frame.id,
            })))
        }
        KIND_SUBSCRIBE => {
            let bytes: Vec<u8> = cbor_decode(ext.payload.as_ref())?;
            let arr: [u8; 32] = bytes.try_into()
                .map_err(|_| PubSubError::Decode(
                    "subscribe payload: expected 32 bytes".into()
                ))?;
            Ok(Some(DecodedPubSubFrame::Subscribe(TopicId::from_bytes(arr))))
        }
        KIND_UNSUBSCRIBE => {
            let bytes: Vec<u8> = cbor_decode(ext.payload.as_ref())?;
            let arr: [u8; 32] = bytes.try_into()
                .map_err(|_| PubSubError::Decode(
                    "unsubscribe payload: expected 32 bytes".into()
                ))?;
            Ok(Some(DecodedPubSubFrame::Unsubscribe(TopicId::from_bytes(arr))))
        }
        unknown => {
            // Unknown kind in our namespace — log and discard.
            tracing::warn!("pubsub: unknown kind {:?} in {}", unknown, PUBSUB_NS);
            Ok(None)
        }
    }
}

// ── CBOR helpers ──────────────────────────────────────────────────────────────

fn cbor_encode<T: Serialize>(value: &T) -> PubSubResult<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e: ciborium::ser::Error<std::io::Error>|{
            PubSubError::Encode(e.to_string())
        })?;
    Ok(buf)
}

fn cbor_decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> PubSubResult<T> {
    ciborium::de::from_reader(std::io::Cursor::new(bytes))
        .map_err(|e: ciborium::de::Error<std::io::Error>| {
            PubSubError::Decode(e.to_string())
        })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{Bytes, NodeId, Timestamp};

    fn sender() -> NodeId   { NodeId::from_bytes([1u8; 32]) }
    fn topic()  -> TopicId  { TopicId::from_name("test/topic") }

    fn sample_message() -> PubSubMessage {
        PubSubMessage::new(
            topic(),
            0,
            sender(),
            Bytes::from_slice(b"hello pubsub"),
        )
    }

    // ── encode_message / decode ───────────────────────────────────────────────

    #[test]
    fn encode_message_produces_extension_frame() {
        let msg   = sample_message();
        let frame = encode_message(&msg).unwrap();
        assert!(matches!(frame.body, FrameBody::Extension(_)));
        if let FrameBody::Extension(ext) = &frame.body {
            assert_eq!(ext.namespace, PUBSUB_NS);
            assert_eq!(ext.kind, KIND_MESSAGE);
        }
    }

    #[test]
    fn message_roundtrip_via_try_decode() {
        let msg      = sample_message();
        let frame    = encode_message(&msg).unwrap();
        let decoded  = try_decode_pubsub_frame(&frame).unwrap().unwrap();
        if let DecodedPubSubFrame::Message(recv) = decoded {
            assert_eq!(recv.message.topic,  msg.topic);
            assert_eq!(recv.message.seq,    msg.seq);
            assert_eq!(recv.message.sender, msg.sender);
            assert_eq!(recv.payload(),      msg.payload());
        } else {
            panic!("expected Message, got something else");
        }
    }

    // ── encode_subscribe / decode ─────────────────────────────────────────────

    #[test]
    fn subscribe_roundtrip() {
        let topic_id = topic();
        let frame    = encode_subscribe(topic_id).unwrap();
        let decoded  = try_decode_pubsub_frame(&frame).unwrap().unwrap();
        if let DecodedPubSubFrame::Subscribe(tid) = decoded {
            assert_eq!(tid, topic_id);
        } else {
            panic!("expected Subscribe");
        }
    }

    // ── encode_unsubscribe / decode ───────────────────────────────────────────

    #[test]
    fn unsubscribe_roundtrip() {
        let topic_id = topic();
        let frame    = encode_unsubscribe(topic_id).unwrap();
        let decoded  = try_decode_pubsub_frame(&frame).unwrap().unwrap();
        if let DecodedPubSubFrame::Unsubscribe(tid) = decoded {
            assert_eq!(tid, topic_id);
        } else {
            panic!("expected Unsubscribe");
        }
    }

    // ── non-pubsub frames return None ─────────────────────────────────────────

    #[test]
    fn non_pubsub_frame_returns_none() {
        let frame = Frame::new(
            FrameId::from_u128(1),
            Timestamp::ZERO,
            FrameBody::Extension(ExtensionFrame {
                namespace: "io.other/app".into(),
                kind:      "thing".into(),
                payload:   Bytes::default(),
            }),
        );
        let result = try_decode_pubsub_frame(&frame).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn non_extension_frame_returns_none() {
        use muspell_proto::{PingFrame};
        let frame = Frame::new(
            FrameId::from_u128(2),
            Timestamp::ZERO,
            FrameBody::Ping(PingFrame { nonce: 1, sent_at: Timestamp::ZERO }),
        );
        assert!(try_decode_pubsub_frame(&frame).unwrap().is_none());
    }

    // ── ReceivedMessage convenience accessors ─────────────────────────────────

    #[test]
    fn received_message_accessors() {
        let msg   = sample_message();
        let frame = encode_message(&msg).unwrap();
        let decoded = try_decode_pubsub_frame(&frame).unwrap().unwrap();
        if let DecodedPubSubFrame::Message(recv) = decoded {
            assert_eq!(recv.topic(),   msg.topic);
            assert_eq!(recv.sender(),  msg.sender);
            assert_eq!(recv.payload(), &msg.payload);
            assert_eq!(recv.seq(),     0);
        }
    }

    // ── payload_len ───────────────────────────────────────────────────────────

    #[test]
    fn payload_len_matches_data() {
        let msg = PubSubMessage::new(
            topic(), 0, sender(),
            Bytes::from_slice(b"12345"),
        );
        assert_eq!(msg.payload_len(), 5);
    }
}
