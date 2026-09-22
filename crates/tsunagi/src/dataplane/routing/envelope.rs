//! Fixed header. Transit changes one byte in an owned receive buffer.
use super::{FlowId, PeerId};
use crate::config::{MAX_DATA_DATAGRAM, ROUTING_HOP_LIMIT};
use bytes::{BufMut, Bytes, BytesMut};

pub(crate) const HEADER: usize = 2 + 32 + 32 + 8;
const VERSION: u8 = 1;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub source: PeerId,
    pub destination: PeerId,
    pub remaining: u8,
    pub flow: FlowId,
}

pub(crate) fn decode(bytes: &[u8]) -> Option<Header> {
    if bytes.len() < HEADER
        || bytes.len() > MAX_DATA_DATAGRAM
        || bytes[0] != VERSION
        || bytes[1] == 0
        || bytes[1] > ROUTING_HOP_LIMIT
    {
        return None;
    }
    Some(Header {
        source: bytes[2..34].try_into().ok()?,
        destination: bytes[34..66].try_into().ok()?,
        remaining: bytes[1],
        flow: u64::from_be_bytes(bytes[66..74].try_into().ok()?),
    })
}

pub(crate) fn encode(source: PeerId, destination: PeerId, flow: FlowId, payload: &[u8]) -> Bytes {
    let mut bytes = BytesMut::with_capacity(HEADER + payload.len());
    bytes.put_u8(VERSION);
    bytes.put_u8(ROUTING_HOP_LIMIT);
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&destination);
    bytes.put_u64(flow);
    bytes.extend_from_slice(payload);
    bytes.freeze()
}

pub(crate) fn decrement(bytes: Bytes) -> Bytes {
    let mut bytes = match bytes.try_into_mut() {
        Ok(bytes) => bytes,
        Err(bytes) => BytesMut::from(bytes.as_ref()),
    };
    // Called only after decode and after excluding remaining <= 1.
    bytes[1] -= 1;
    bytes.freeze()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn transit_reuses_the_buffer_and_rejects_invalid_headers() {
        let frame = encode([1; 32], [2; 32], 17, &[42; 1280]);
        let address = frame.as_ptr();
        let frame = decrement(frame);
        assert_eq!(
            frame.as_ptr(),
            address,
            "no payload copy for an owned buffer"
        );
        assert_eq!(decode(&frame).unwrap().remaining, ROUTING_HOP_LIMIT - 1);
        assert_eq!(&frame[HEADER..], &[42; 1280]);
        for length in 0..HEADER {
            assert!(decode(&frame[..length]).is_none());
        }
        for ttl in [0, ROUTING_HOP_LIMIT + 1] {
            let mut bad = frame.to_vec();
            bad[1] = ttl;
            assert!(decode(&bad).is_none());
        }
        let mut bad = frame.to_vec();
        bad[0] = 99;
        assert!(decode(&bad).is_none());
        assert!(decode(&vec![1; MAX_DATA_DATAGRAM + 1]).is_none());
    }
}
