//! Length-prefixed framing over one QUIC bidirectional stream.
//!
//! A frame is `u32_be(len) || payload`. The announced length is validated
//! against the configured limit **before** a buffer of that size is allocated,
//! so a hostile peer cannot make the agent allocate arbitrary memory with a
//! four byte header.
//!
//! No custom encryption is layered on top: the iroh/QUIC connection already
//! provides confidentiality, integrity and endpoint authentication.

use iroh::endpoint::{RecvStream, SendStream};

use crate::error::ProtocolError;

/// Size of the frame length prefix, in bytes.
pub const LENGTH_PREFIX_LEN: usize = 4;

/// Writes one frame.
pub async fn write_frame(
    stream: &mut SendStream,
    payload: &[u8],
    max_frame_len: usize,
) -> Result<(), ProtocolError> {
    if payload.len() > max_frame_len {
        return Err(ProtocolError::FrameTooLarge {
            announced: payload.len() as u64,
            limit: max_frame_len,
        });
    }
    let len = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
        announced: payload.len() as u64,
        limit: max_frame_len,
    })?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|err| ProtocolError::Stream(err.to_string()))?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| ProtocolError::Stream(err.to_string()))?;
    Ok(())
}

/// Reads one frame, rejecting oversized headers before allocating.
pub async fn read_frame(
    stream: &mut RecvStream,
    max_frame_len: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let mut header = [0u8; LENGTH_PREFIX_LEN];
    match stream.read_exact(&mut header).await {
        Ok(()) => {}
        Err(err) => return Err(classify_read_error(err)),
    }

    let announced = u32::from_be_bytes(header) as u64;
    if announced > max_frame_len as u64 {
        return Err(ProtocolError::FrameTooLarge {
            announced,
            limit: max_frame_len,
        });
    }

    // Safe: `announced` was just bounded by `max_frame_len`, a usize.
    let mut payload = vec![0u8; announced as usize];
    if !payload.is_empty() {
        match stream.read_exact(&mut payload).await {
            Ok(()) => {}
            Err(err) => return Err(classify_read_error(err)),
        }
    }
    Ok(payload)
}

fn classify_read_error(err: iroh::endpoint::ReadExactError) -> ProtocolError {
    match err {
        iroh::endpoint::ReadExactError::FinishedEarly(_) => ProtocolError::StreamClosed,
        other => ProtocolError::Stream(other.to_string()),
    }
}
