//! `Publisher` — publish messages to a topic.
//!
//! ## Responsibility
//!
//! A `Publisher` is the send-side handle for a single topic. It:
//! 1. Increments a per-topic sequence number.
//! 2. Wraps the payload in a `PubSubMessage`.
//! 3. Encodes it as an `ExtensionFrame`.
//! 4. Forwards it to the outgoing `mpsc` channel (→ transport → wire).
//! 5. Delivers it to local subscribers via the `SubscriptionManager`.
//!
//! Step 5 (local delivery) is done unconditionally so that local subscribers
//! receive messages published by the same process without a network round-trip.
//! This is the correct behaviour: local and remote subscribers are treated
//! identically from the application's perspective.
//!
//! ## Cloning
//!
//! `Publisher` is `Clone`. All clones share the same atomic sequence counter,
//! so the sequence numbers across all clones of the same publisher are globally
//! ordered (no per-clone sub-sequences).

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use muspell_proto::{Bytes, NodeId};
use tokio::sync::mpsc;
use tracing::debug;

use crate::error::{PubSubError, PubSubResult};
use crate::manager::SubscriptionManager;
use crate::message::{encode_message, PubSubMessage, ReceivedMessage};
use crate::topic::TopicId;
use muspell_proto::{Frame, FrameId, Timestamp};

// ── Publisher ─────────────────────────────────────────────────────────────────

/// A handle for publishing messages to a specific topic.
///
/// Construct via [`PubSubLayer::publisher`].
///
/// [`PubSubLayer::publisher`]: crate::PubSubLayer::publisher
#[derive(Clone)]
pub struct Publisher {
    topic:    TopicId,
    sender:   NodeId,
    outgoing: mpsc::Sender<Frame>,
    manager:  SubscriptionManager,
    seq:      Arc<AtomicU64>,
}

impl Publisher {
    /// Construct. Prefer `PubSubLayer::publisher`.
    #[must_use]
    pub(crate) fn new(
        topic:    TopicId,
        sender:   NodeId,
        outgoing: mpsc::Sender<Frame>,
        manager:  SubscriptionManager,
    ) -> Self {
        Self {
            topic,
            sender,
            outgoing,
            manager,
            seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The topic this publisher publishes to.
    #[must_use]
    pub fn topic(&self) -> TopicId {
        self.topic
    }

    /// The current (next to be assigned) sequence number.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    // ── Publishing ────────────────────────────────────────────────────────────

    /// Publish a message to this topic.
    ///
    /// The message is:
    /// 1. Assigned the next sequence number (atomically incremented).
    /// 2. Sent to the transport layer via the outgoing channel.
    /// 3. Delivered to local subscribers in the `SubscriptionManager`.
    ///
    /// Local delivery failures (`NoSubscribers`, `TopicClosed`) are silently
    /// ignored — having no local subscribers is not an error for a publisher.
    ///
    /// # Errors
    /// - `PubSubError::Encode` if CBOR serialisation fails (very rare).
    /// - `PubSubError::ChannelClosed` if the transport channel is closed.
    pub async fn publish(&self, payload: Bytes) -> PubSubResult<()> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);

        let msg = PubSubMessage::new(self.topic, seq, self.sender, payload);

        debug!(
            "pubsub: publishing seq={} on {} ({} bytes)",
            seq, self.topic, msg.payload_len()
        );

        // Encode into a wire frame.
        let frame = encode_message(&msg)?;
        let frame_id    = frame.id;
        let received_at = frame.timestamp;

        // Send to transport (and thus to remote subscribers).
        self.outgoing
            .send(frame)
            .await
            .map_err(|_| PubSubError::ChannelClosed)?;

        // Deliver to local subscribers — best effort.
        let received = ReceivedMessage {
            message: msg,
            received_at,
            frame_id,
        };
        // Ignore NoSubscribers / TopicClosed — local delivery is opportunistic.
        let _ = self.manager.deliver(received);

        Ok(())
    }

    /// Publish raw bytes, returning the assigned sequence number on success.
    ///
    /// Identical to `publish()` but returns the sequence number so callers
    /// can implement at-least-once delivery acknowledgement.
    pub async fn publish_seq(&self, payload: Bytes) -> PubSubResult<u64> {
        let seq = self.seq.load(Ordering::Relaxed);
        self.publish(payload).await?;
        Ok(seq)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::SubscriptionManager;
    use crate::message::try_decode_pubsub_frame;
    use muspell_proto::{Bytes, FrameBody, NodeId};
    use tokio::sync::mpsc;

    fn node() -> NodeId  { NodeId::from_bytes([5u8; 32]) }
    fn topic() -> TopicId { TopicId::from_name("test/publish") }

    fn make_publisher() -> (Publisher, mpsc::Receiver<Frame>, SubscriptionManager) {
        let (tx, rx)  = mpsc::channel(32);
        let manager   = SubscriptionManager::with_defaults();
        let publisher = Publisher::new(topic(), node(), tx, manager.clone());
        (publisher, rx, manager)
    }

    // ── publish sends a frame ─────────────────────────────────────────────────

    #[tokio::test]
    async fn publish_sends_extension_frame() {
        let (publisher, mut rx, _mgr) = make_publisher();

        publisher.publish(Bytes::from_slice(b"hello")).await.unwrap();

        let frame = rx.recv().await.expect("frame should arrive");
        assert!(matches!(frame.body, FrameBody::Extension(_)));
    }

    #[tokio::test]
    async fn publish_encodes_correct_topic() {
        let (publisher, mut rx, _mgr) = make_publisher();

        publisher.publish(Bytes::from_slice(b"data")).await.unwrap();

        let frame = rx.recv().await.unwrap();
        let decoded = try_decode_pubsub_frame(&frame).unwrap().unwrap();
        if let crate::message::DecodedPubSubFrame::Message(recv) = decoded {
            assert_eq!(recv.topic(), topic());
        } else {
            panic!("expected Message");
        }
    }

    // ── sequence numbering ────────────────────────────────────────────────────

    #[tokio::test]
    async fn sequence_numbers_increment() {
        let (publisher, mut rx, _mgr) = make_publisher();

        publisher.publish(Bytes::from_slice(b"a")).await.unwrap();
        publisher.publish(Bytes::from_slice(b"b")).await.unwrap();
        publisher.publish(Bytes::from_slice(b"c")).await.unwrap();

        let seqs: Vec<u64> = {
            let mut s = vec![];
            for _ in 0..3 {
                let frame = rx.recv().await.unwrap();
                if let Some(crate::message::DecodedPubSubFrame::Message(recv)) =
                    try_decode_pubsub_frame(&frame).unwrap()
                {
                    s.push(recv.seq());
                }
            }
            s
        };

        assert_eq!(seqs, vec![0, 1, 2]);
    }

    #[tokio::test]
    async fn publish_seq_returns_sequence_number() {
        let (publisher, mut _rx, _mgr) = make_publisher();
        let s0 = publisher.publish_seq(Bytes::from_slice(b"x")).await.unwrap();
        let s1 = publisher.publish_seq(Bytes::from_slice(b"y")).await.unwrap();
        assert_eq!(s0, 0);
        assert_eq!(s1, 1);
    }

    #[tokio::test]
    async fn clone_shares_sequence_counter() {
        let (publisher, mut rx, _mgr) = make_publisher();
        let clone = publisher.clone();

        publisher.publish(Bytes::from_slice(b"p")).await.unwrap();
        clone.publish(Bytes::from_slice(b"c")).await.unwrap();

        let mut seqs = vec![];
        for _ in 0..2 {
            let f = rx.recv().await.unwrap();
            if let Some(crate::message::DecodedPubSubFrame::Message(recv)) =
                try_decode_pubsub_frame(&f).unwrap()
            {
                seqs.push(recv.seq());
            }
        }
        // Both clones share the same counter: seq 0 and seq 1.
        assert_eq!(seqs, vec![0, 1]);
    }

    // ── local delivery ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn publish_delivers_to_local_subscriber() {
        let (publisher, mut _tx, manager) = make_publisher();
        let mut sub = manager.subscribe(topic());

        publisher.publish(Bytes::from_slice(b"local")).await.unwrap();

        let msg = sub.recv().await.unwrap();
        assert_eq!(msg.payload().as_ref(), b"local");
        assert_eq!(msg.seq(), 0);
    }

    #[tokio::test]
    async fn publish_without_local_subscriber_does_not_error() {
        let (publisher, mut _rx, _mgr) = make_publisher();
        // No subscriber — should not return an error.
        let result = publisher.publish(Bytes::from_slice(b"no-sub")).await;
        assert!(result.is_ok());
    }

    // ── channel closed ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn publish_fails_when_channel_closed() {
        let (tx, rx)  = mpsc::channel(1);
        drop(rx);       // close the receiver
        let mgr = SubscriptionManager::with_defaults();
        let pub_ = Publisher::new(topic(), node(), tx, mgr);
        let err = pub_.publish(Bytes::from_slice(b"x")).await.unwrap_err();
        assert!(matches!(err, PubSubError::ChannelClosed));
    }
}
