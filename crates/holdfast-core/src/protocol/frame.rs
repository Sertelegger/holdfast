//! Length-prefixed CBOR framing for `control.sock` (spec §7.4).
//!
//! Wire format, normative: a 4-byte **big-endian** unsigned length,
//! followed by exactly that many bytes of CBOR. The length is exclusive
//! of the four prefix bytes. A frame body larger than
//! [`MAX_FRAME_BYTES`] is refused at the codec boundary and the caller
//! must close the connection (§7.4) — nothing in this module closes
//! anything, and which codes close is [`super::method::ErrorCode::closes_connection`]'s
//! answer, not this one's.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bytes of length prefix that precede every frame body.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// Hard cap on a single frame body (spec §7.4).
///
/// **Which side of the redactor: this measures the encoded body as
/// sent, which is *after* redaction, and it **rejects** rather than
/// truncating — [`FrameError::TooLarge`], never a short read — so it
/// cannot split a secret at its boundary.** Stated because the obvious
/// justification is on the wrong side: "`read_output` is bounded by the
/// 1 MiB buffer cap" bounds this frame's *input*, not the frame.
/// Redaction can make a body **grow**, and the shipped rules reach it:
/// `database-connection-password` captures only the password inside
/// `postgres://svc:<pw>@host` and replaces it with the 28-byte
/// `[REDACTED:connection-string]`, so a one-byte password grows 28x
/// (`output::redact`'s
/// `a_connection_string_keeps_its_host_and_loses_its_password`). A
/// post-redaction container sized by a pre-redaction argument is
/// therefore unsound reasoning even where, as here, the 16x headroom
/// makes it unreachable. Do not restore the shorter comment — and do
/// not reach for an `AKIA…` example, which is the trap this comment
/// fell into once: a marker names the rule's **`kind`**, never its
/// `name`, so `aws-access-key-id` yields `[REDACTED:aws]` and the
/// twenty bytes of `AKIAIOSFODNN7EXAMPLE` *shrink* to fourteen.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too large: {len} bytes exceeds the {MAX_FRAME_BYTES}-byte limit")]
    TooLarge { len: usize },
    #[error("malformed cbor: {0}")]
    Cbor(String),
    #[error("peer closed the connection")]
    Eof,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Serialise `value` into a complete frame (prefix + CBOR body).
///
/// Exposed separately from [`write_frame`] so tests can assert on the
/// exact bytes that go on the wire.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let mut body = Vec::new();
    ciborium::into_writer(value, &mut body).map_err(|e| FrameError::Cbor(e.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { len: body.len() });
    }
    let mut out = Vec::with_capacity(LENGTH_PREFIX_BYTES + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a frame body (CBOR only, no length prefix).
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    ciborium::from_reader(body).map_err(|e| FrameError::Cbor(e.to_string()))
}

/// Write one frame and flush it.
pub async fn write_frame<W, T>(w: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = encode(value)?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read one frame.
///
/// A close between frames yields [`FrameError::Eof`]. An over-limit
/// declared length yields [`FrameError::TooLarge`] *without* reading or
/// allocating the body — the caller must close the connection, which is
/// what §7.4 requires anyway.
///
/// An *in*-limit declared length is allocated up front, so four
/// attacker-chosen bytes buy up to 16 MiB of zeroed buffer per
/// connection before a body byte arrives. Accepted rather than
/// mitigated: `SO_PEERCRED` has already established that the peer is
/// this same uid (`daemon::peer`), so the attacker is the owner. A
/// chunked read with a growing buffer is the fix if that ever changes.
pub async fn read_frame<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    decode(&read_frame_body(r).await?)
}

/// [`read_frame`] stopping one step short: the body bytes, undecoded.
///
/// **This is [`read_frame`]'s own body, extracted, not a second codec.**
/// §7.5's attach wire needs to tell *"a `type` this build does not
/// know"* from *"these bytes are not a frame"*, and answer the first
/// with the unknown name echoed back in `ProtocolError.frame_kind` —
/// which is impossible once `decode` has consumed the bytes and
/// returned a `serde` message. `read_frame` is now a `decode` of this,
/// so the length prefix, the cap and the EOF mapping stay in exactly
/// one place; a caller that wants the raw body reads it through the
/// same function the typed reader does.
pub async fn read_frame_body<R>(r: &mut R) -> Result<Vec<u8>, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
    match r.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Eof),
        Err(e) => return Err(FrameError::Io(e)),
    }
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { len });
    }
    let mut body = vec![0u8; len];
    match r.read_exact(&mut body).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Eof),
        Err(e) => return Err(FrameError::Io(e)),
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value as Cbor;

    #[test]
    fn length_prefix_is_four_byte_big_endian() {
        // A 300-byte CBOR byte string encodes as 0x59 0x01 0x2C followed
        // by 300 bytes = 303 body bytes. Big-endian 303 is [0, 0, 1, 47];
        // little-endian would be [47, 1, 0, 0]. Asserting the literal
        // prefix bytes is the only formulation that fails against a
        // codec that picked the other byte order.
        let frame = encode(&Cbor::Bytes(vec![0u8; 300])).unwrap();
        assert_eq!(&frame[..4], &[0, 0, 1, 47]);
        assert_eq!(frame.len(), 4 + 303);
        assert_eq!(frame[4], 0x59, "CBOR major type 2 with a 2-byte length");
    }

    #[tokio::test]
    async fn round_trips_every_byte_value() {
        // CBOR was chosen over JSON because PTY output is arbitrary bytes
        // (§7.4). A codec that lost the 8-bit range — or that widened
        // bytes into an array of integers — fails the variant assertion.
        //
        // The variant assertion comes **first** on purpose. Behind
        // `assert_eq!(back, payload)` it is a tautology — anything that
        // widened bytes into an array has already reddened the equality
        // — so it could not fail and read as coverage it did not add.
        let payload = Cbor::Bytes((0u8..=255).collect());
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload).await.unwrap();
        let back: Cbor = read_frame(&mut buf.as_slice()).await.unwrap();
        // No `{back:?}` in the message: a widened array prints 256
        // entries and buries the one word that matters.
        assert!(
            matches!(back, Cbor::Bytes(ref b) if b.len() == 256),
            "still a 256-byte bstr, not an array of integers"
        );
        assert_eq!(back, payload);
    }

    #[tokio::test]
    async fn reads_two_frames_from_one_stream() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Cbor::Text("first".into()))
            .await
            .unwrap();
        write_frame(&mut buf, &Cbor::Text("second".into()))
            .await
            .unwrap();
        let mut r = buf.as_slice();
        let a: Cbor = read_frame(&mut r).await.unwrap();
        let b: Cbor = read_frame(&mut r).await.unwrap();
        assert_eq!(a, Cbor::Text("first".into()));
        assert_eq!(b, Cbor::Text("second".into()));
    }

    #[tokio::test]
    async fn close_between_frames_is_eof_not_an_error() {
        let empty: &[u8] = &[];
        let r: Result<Cbor, _> = read_frame(&mut &empty[..]).await;
        assert!(matches!(r, Err(FrameError::Eof)), "got {r:?}");
    }

    #[tokio::test]
    async fn truncated_body_is_eof_not_a_bogus_value() {
        let mut frame = encode(&Cbor::Text("hello".into())).unwrap();
        frame.truncate(frame.len() - 2);
        let r: Result<Cbor, _> = read_frame(&mut frame.as_slice()).await;
        assert!(matches!(r, Err(FrameError::Eof)), "got {r:?}");
    }

    #[tokio::test]
    async fn oversized_declared_length_is_refused_before_allocating() {
        // Only the 4-byte prefix is on the wire. An implementation that
        // allocated `len` bytes and then read would return Eof here, not
        // TooLarge — which is exactly the bug this guards.
        let prefix = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        let r: Result<Cbor, _> = read_frame(&mut &prefix[..]).await;
        assert!(
            matches!(r, Err(FrameError::TooLarge { len }) if len == MAX_FRAME_BYTES + 1),
            "got {r:?}"
        );
    }

    /// A CBOR byte string longer than 65535 encodes as `0x5a` plus a
    /// four-byte length, so its body is the payload plus five. Named
    /// because both cap tests below size a payload to land the *body*
    /// on an exact boundary, and a wrong constant here would silently
    /// test the wrong size rather than fail.
    const BSTR_HEADER_BYTES: usize = 5;

    #[test]
    fn oversized_body_is_refused_on_encode() {
        let big = Cbor::Bytes(vec![0u8; MAX_FRAME_BYTES + 1]);
        // The `len` pin matches the read-side twin above: without it a
        // mutation that reports the wrong length on the encode path
        // survives. The body is the payload plus the bstr header.
        let r = encode(&big);
        assert!(
            matches!(r, Err(FrameError::TooLarge { len })
                if len == MAX_FRAME_BYTES + 1 + BSTR_HEADER_BYTES),
            "got {:?}",
            r.err()
        );
    }

    #[test]
    fn a_body_of_exactly_the_cap_is_encoded_not_refused() {
        // §7.4's bound is **exclusive**: `length > 16 MiB` is refused,
        // `length == 16 MiB` is not, and both peers must agree to the
        // byte. Every other size test here uses `MAX_FRAME_BYTES + 1`,
        // which is green under `>` and under `>=` alike; this is the
        // assertion that separates them on the encode path.
        let payload = MAX_FRAME_BYTES - BSTR_HEADER_BYTES;
        let frame = encode(&Cbor::Bytes(vec![0u8; payload]))
            .expect("a body of exactly the cap is legal, not TooLarge");
        assert_eq!(
            frame.len() - LENGTH_PREFIX_BYTES,
            MAX_FRAME_BYTES,
            "the fixture must land on the cap exactly, or the expect above proves nothing"
        );
        assert_eq!(frame[LENGTH_PREFIX_BYTES], 0x5a, "bstr, 4-byte length");
    }

    #[tokio::test]
    async fn a_declared_length_of_exactly_the_cap_is_not_refused() {
        // The read-side twin of the test above, and the same mutant:
        // `len > MAX_FRAME_BYTES` versus `len >= MAX_FRAME_BYTES`. Only
        // the prefix is on the wire, so the body read runs out and
        // yields Eof — the point is that it is *not* TooLarge.
        let prefix = (MAX_FRAME_BYTES as u32).to_be_bytes();
        let r: Result<Cbor, _> = read_frame(&mut &prefix[..]).await;
        assert!(matches!(r, Err(FrameError::Eof)), "got {r:?}");
    }

    #[tokio::test]
    async fn malformed_cbor_body_is_a_cbor_error() {
        // The prefix declares 3 bytes; the body is not valid CBOR.
        let wire = [0u8, 0, 0, 3, 0xff, 0xff, 0xff];
        let r: Result<Cbor, _> = read_frame(&mut &wire[..]).await;
        assert!(matches!(r, Err(FrameError::Cbor(_))), "got {r:?}");
    }
}
