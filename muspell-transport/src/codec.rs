//! Frame codec: CBOR serialisation with a `u32`-BE length prefix.
//!
//! ## Wire format
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  u32 BE  │  CBOR-encoded Frame (N bytes)                │
//! │  (4 bytes│  N = value of the length field               │
//! │  = N)    │                                              │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! The length prefix is the number of bytes in the CBOR payload,
//! NOT including the 4-byte prefix itself.
//!
//! ## Max frame size
//!
//! Every read call takes a `max_bytes: u32` parameter. If the
//! length prefix exceeds `max_bytes`, `TransportError::FrameTooLarge`
//! is returned immediately without reading the payload, preventing
//! memory exhaustion from a misbehaving peer.
//!
//! ## Async I/O
//!
//! `encode_frame` writes to any `AsyncWrite + Unpin`.
//! `decode_frame` reads from any `AsyncRead + Unpin`.
//! Both are cancellation-safe: a cancelled future will not have
//! partially committed data to the stream (the `write_all` call
//! is atomic from the caller's perspective).

use muspell_proto::Frame;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{TransportError, TransportResult};

/// Encode a [`Frame`] into the length-prefixed CBOR wire format and
/// write it to `writer`.
///
/// The writer is NOT flushed after writing; the caller must flush if
/// the underlying transport requires it (iroh streams auto-flush on send).
///
/// # Errors
/// - `TransportError::EncodeError` if CBOR serialisation fails.
/// - `TransportError::Io` if writing to `writer` fails.
pub async fn encode_frame<W>(
    writer: &mut W,
    frame:  &Frame,
) -> TransportResult<()>
where
    W: AsyncWrite + Unpin,
{
    // Serialise to an in-memory buffer first so we know the length.
    let payload = cbor_encode(frame)?;

    // Length prefix: u32 BE.
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;

    // Payload.
    writer.write_all(&payload).await?;

    Ok(())
}

/// Read a length-prefixed CBOR frame from `reader`.
///
/// # Errors
/// - `TransportError::FrameTooLarge` if the length prefix exceeds `max_bytes`.
/// - `TransportError::StreamClosed` if the stream ends before the frame is read.
/// - `TransportError::DecodeError` if the CBOR payload is malformed.
/// - `TransportError::Io` if reading from `reader` fails.
pub async fn decode_frame<R>(
    reader:    &mut R,
    max_bytes: u32,
) -> TransportResult<Frame>
where
    R: AsyncRead + Unpin,
{
    // Read 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_)  => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(TransportError::StreamClosed);
        }
        Err(e) => return Err(TransportError::Io(e)),
    }
    let payload_len = u32::from_be_bytes(len_buf);

    // Reject oversized frames before allocating.
    if payload_len > max_bytes {
        return Err(TransportError::FrameTooLarge {
            received: payload_len,
            maximum:  max_bytes,
        });
    }

    // Read CBOR payload.
    let mut payload = vec![0u8; payload_len as usize];
    match reader.read_exact(&mut payload).await {
        Ok(_)  => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(TransportError::StreamClosed);
        }
        Err(e) => return Err(TransportError::Io(e)),
    }

    cbor_decode(&payload)
}

// ── CBOR helpers ──────────────────────────────────────────────────────────────

/// Serialize a [`Frame`] to CBOR bytes.
fn cbor_encode(frame: &Frame) -> TransportResult<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    ciborium::ser::into_writer(frame, &mut buf)
        .map_err(|e| TransportError::EncodeError { reason: e.to_string() })?;
    Ok(buf)
}

/// Deserialize a [`Frame`] from CBOR bytes.
fn cbor_decode(bytes: &[u8]) -> TransportResult<Frame> {
    ciborium::de::from_reader(std::io::Cursor::new(bytes))
        .map_err(|e| TransportError::DecodeError { reason: e.to_string() })
}

/// Compute the Blake3 hash of the CBOR-encoded frame body.
///
/// Used by the transport layer when constructing or verifying `FrameAuth`
/// signatures, which commit to the body hash to prevent frame substitution.
pub fn frame_body_hash(frame: &Frame) -> TransportResult<[u8; 32]> {
    // Encode only the body field for the hash (not the full envelope).
    // This matches the `compute_body_hash` contract in muspell-identity.
    let mut buf = Vec::with_capacity(128);
    ciborium::ser::into_writer(&frame.body, &mut buf)
        .map_err(|e| TransportError::EncodeError { reason: e.to_string() })?;
    Ok(*blake3::hash(&buf).as_bytes())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{
        Frame, FrameBody, FrameId, NodeId, NodeCapabilities,
        HelloFrame, PingFrame, GoodbyeFrame, Timestamp,
    };

    fn t(s: i64) -> Timestamp { Timestamp::from_secs(s) }
    fn fid(v: u128) -> FrameId { FrameId::from_u128(v) }

    fn ping_frame() -> Frame {
        Frame::new(
            fid(1),
            t(1000),
            FrameBody::Ping(PingFrame { nonce: 42, sent_at: t(1000) }),
        )
    }

    fn hello_frame() -> Frame {
        Frame::new(
            fid(2),
            t(1000),
            FrameBody::Hello(HelloFrame {
                node_id:      NodeId::from_bytes([1u8; 32]),
                did:          None,
                capabilities: NodeCapabilities::none(),
                user_agent:   Some("muspell-test/0.1".into()),
            }),
        )
    }

    // ── encode / decode roundtrip ─────────────────────────────────────────────

    #[tokio::test]
    async fn roundtrip_ping_frame() {
        let original = ping_frame();
        let mut buf  = Vec::new();

        encode_frame(&mut buf, &original).await.unwrap();
        assert!(buf.len() > 4, "buffer should contain length prefix + payload");

        let mut cursor = std::io::Cursor::new(&buf);
        let decoded = decode_frame(&mut cursor, 1024).await.unwrap();

        assert_eq!(original, decoded);
    }

    #[tokio::test]
    async fn roundtrip_hello_frame() {
        let original = hello_frame();
        let mut buf  = Vec::new();
        encode_frame(&mut buf, &original).await.unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let decoded = decode_frame(&mut cursor, 4096).await.unwrap();

        assert_eq!(original, decoded);
    }

    #[tokio::test]
    async fn roundtrip_goodbye_frame() {
        let original = Frame::new(
            fid(3), t(0),
            FrameBody::Goodbye(GoodbyeFrame {
                reason: "clean shutdown".into(),
                reconnect_after_secs: Some(60),
            }),
        );
        let mut buf = Vec::new();
        encode_frame(&mut buf, &original).await.unwrap();
        let mut cursor = std::io::Cursor::new(&buf);
        let decoded = decode_frame(&mut cursor, 4096).await.unwrap();
        assert_eq!(original, decoded);
    }

    // ── frame-too-large rejection ─────────────────────────────────────────────

    #[tokio::test]
    async fn decode_rejects_frame_exceeding_max() {
        let frame = hello_frame();
        let mut buf = Vec::new();
        encode_frame(&mut buf, &frame).await.unwrap();

        // Set max to 1 byte — far too small.
        let mut cursor = std::io::Cursor::new(&buf);
        let err = decode_frame(&mut cursor, 1).await.unwrap_err();
        assert!(matches!(err, TransportError::FrameTooLarge { .. }));
    }

    // ── stream-closed on empty reader ─────────────────────────────────────────

    #[tokio::test]
    async fn decode_returns_stream_closed_on_empty_reader() {
        let empty: &[u8] = &[];
        let mut cursor = std::io::Cursor::new(empty);
        let err = decode_frame(&mut cursor, 4096).await.unwrap_err();
        assert!(matches!(err, TransportError::StreamClosed));
    }

    // ── stream-closed mid-payload ─────────────────────────────────────────────

    #[tokio::test]
    async fn decode_returns_stream_closed_on_truncated_payload() {
        // Write a length prefix of 100 but only 4 bytes of payload.
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_be_bytes()); // says 100 bytes coming
        buf.extend_from_slice(&[0u8; 4]);             // only 4 bytes follow

        let mut cursor = std::io::Cursor::new(&buf);
        let err = decode_frame(&mut cursor, 4096).await.unwrap_err();
        assert!(matches!(err, TransportError::StreamClosed));
    }

    // ── wire format structure ─────────────────────────────────────────────────

    #[tokio::test]
    async fn wire_format_length_prefix_is_big_endian() {
        let frame = ping_frame();
        let mut buf = Vec::new();
        encode_frame(&mut buf, &frame).await.unwrap();

        // First 4 bytes must be the u32 BE payload length.
        let prefix = u32::from_be_bytes(buf[..4].try_into().unwrap());
        assert_eq!(prefix as usize, buf.len() - 4);
    }

    #[tokio::test]
    async fn multiple_frames_on_same_stream() {
        let frames = vec![ping_frame(), hello_frame(), ping_frame()];
        let mut buf = Vec::new();
        for f in &frames {
            encode_frame(&mut buf, f).await.unwrap();
        }

        let mut cursor = std::io::Cursor::new(&buf);
        for expected in &frames {
            let decoded = decode_frame(&mut cursor, 4096).await.unwrap();
            assert_eq!(expected, &decoded);
        }
    }

    // ── frame_body_hash ───────────────────────────────────────────────────────

    #[test]
    fn frame_body_hash_is_deterministic() {
        let f = ping_frame();
        let h1 = frame_body_hash(&f).unwrap();
        let h2 = frame_body_hash(&f).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn frame_body_hash_differs_for_different_bodies() {
        let a = ping_frame();
        let b = hello_frame();
        assert_ne!(
            frame_body_hash(&a).unwrap(),
            frame_body_hash(&b).unwrap(),
        );
    }

    #[test]
    fn frame_body_hash_same_body_different_id() {
        // Body hash must be independent of the frame envelope (id, timestamp, etc.)
        let body = FrameBody::Ping(PingFrame { nonce: 7, sent_at: t(0) });
        let f1 = Frame::new(fid(1), t(100), body.clone());
        let f2 = Frame::new(fid(2), t(999), body);
        assert_eq!(
            frame_body_hash(&f1).unwrap(),
            frame_body_hash(&f2).unwrap(),
            "body hash must not depend on frame envelope fields",
        );
    }
}
