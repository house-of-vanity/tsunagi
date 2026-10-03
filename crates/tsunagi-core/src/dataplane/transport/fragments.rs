//! Bounded fragmentation of opaque transport payloads, below peer relaying.
//!
//! Data ALPN v3: u64 packet ID, u32 total length, u32 byte offset (big endian),
//! followed by payload. Each QUIC connection owns its IDs and reassembly state.
//! There is no retransmission: one missing fragment loses one datagram only.

use std::collections::{HashMap, VecDeque};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::time::Instant;

use crate::config::{
    DATA_REASSEMBLY_TTL, DATA_RECENT_IDS, MAX_DATA_ASSEMBLIES, MAX_DATA_DATAGRAM,
    MAX_DATA_FRAGMENTS, MAX_DATA_REASSEMBLY_BYTES,
};

pub(super) const HEADER: usize = 16;

pub(super) fn encode(id: u64, total: usize, offset: usize, payload: &[u8]) -> Bytes {
    let mut frame = BytesMut::with_capacity(HEADER + payload.len());
    frame.put_u64(id);
    frame.put_u32(total as u32);
    frame.put_u32(offset as u32);
    frame.extend_from_slice(payload);
    frame.freeze()
}

#[derive(Debug)]
struct Assembly {
    started: Instant,
    bytes: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    received: usize,
}

#[derive(Debug, Default)]
pub(super) struct Reassembler {
    packets: HashMap<u64, Assembly>,
    buffered: usize,
    recent: VecDeque<u64>,
}

impl Reassembler {
    fn remember(&mut self, id: u64) {
        if self.recent.len() == DATA_RECENT_IDS {
            self.recent.pop_front();
        }
        self.recent.push_back(id);
    }

    fn remove(&mut self, id: u64) -> Option<Assembly> {
        let packet = self.packets.remove(&id)?;
        self.buffered -= packet.bytes.len();
        self.remember(id);
        Some(packet)
    }

    pub(super) fn expire(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .packets
            .iter()
            .filter(|(_, p)| now.duration_since(p.started) >= DATA_REASSEMBLY_TTL)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.remove(id);
        }
    }

    pub(super) fn push(&mut self, frame: Bytes, now: Instant) -> Option<Bytes> {
        self.expire(now);
        let id = u64::from_be_bytes(frame.get(..8)?.try_into().ok()?);
        let total = u32::from_be_bytes(frame.get(8..12)?.try_into().ok()?) as usize;
        let offset = u32::from_be_bytes(frame.get(12..HEADER)?.try_into().ok()?) as usize;
        let payload = frame.get(HEADER..)?;
        let end = offset.checked_add(payload.len())?;
        if total > MAX_DATA_DATAGRAM
            || end > total
            || (payload.is_empty() && total != 0)
            || self.recent.contains(&id)
        {
            return None;
        }
        if !self.packets.contains_key(&id) {
            if offset == 0 && end == total {
                self.remember(id);
                return Some(frame.slice(HEADER..));
            }
            // The length is validated before allocating. Drop the oldest
            // incomplete packet when the per-link byte or entry budget is full.
            while self.packets.len() >= MAX_DATA_ASSEMBLIES
                || self.buffered + total > MAX_DATA_REASSEMBLY_BYTES
            {
                let oldest = self
                    .packets
                    .iter()
                    .min_by_key(|(_, p)| p.started)
                    .map(|(id, _)| *id)?;
                self.remove(oldest);
            }
            self.packets.insert(
                id,
                Assembly {
                    started: now,
                    bytes: vec![0; total],
                    ranges: Vec::new(),
                    received: 0,
                },
            );
            self.buffered += total;
        }
        let packet = self.packets.get_mut(&id)?;
        if packet.bytes.len() != total {
            self.remove(id);
            return None;
        }
        for &(start, stop) in &packet.ranges {
            if start == offset && stop == end && packet.bytes[offset..end] == *payload {
                return None; // a duplicate does not reset the expiry time
            }
            if offset < stop && end > start {
                self.remove(id); // conflicting or overlapping fragments
                return None;
            }
        }
        if packet.ranges.len() == MAX_DATA_FRAGMENTS {
            self.remove(id);
            return None;
        }
        packet.bytes[offset..end].copy_from_slice(payload);
        packet.ranges.push((offset, end));
        packet.received += payload.len();
        if packet.received == total {
            return self.remove(id).map(|p| Bytes::from(p.bytes));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn reordered_duplicates_and_changing_fragment_sizes_reassemble_once() {
        let mut rx = Reassembler::default();
        let now = Instant::now();
        let packet: Vec<u8> = (0..9000).map(|i| (i % 251) as u8).collect();
        let mut parts = Vec::new();
        let mut offset = 0;
        for size in [1100, 700, 1100, 1100, 700, 1100, 1100, 1100, 1000] {
            parts.push(encode(
                7,
                packet.len(),
                offset,
                &packet[offset..offset + size],
            ));
            offset += size;
        }
        assert_eq!(offset, packet.len());
        for part in parts[1..].iter().rev() {
            assert!(rx.push(part.clone(), now).is_none());
            assert!(rx.push(part.clone(), now).is_none());
        }
        assert_eq!(rx.push(parts[0].clone(), now).unwrap().as_ref(), packet);
        assert!(rx.push(parts[0].clone(), now).is_none());
        assert_eq!(rx.buffered, 0);
        assert!(rx.packets.is_empty());
    }

    #[test]
    fn a_missing_fragment_never_blocks_the_next_packet_and_expires() {
        let mut rx = Reassembler::default();
        let now = Instant::now();
        assert!(rx.push(encode(1, 1280, 0, &[1; 800]), now).is_none());
        assert_eq!(
            rx.push(encode(2, 4, 0, b"next"), now).unwrap(),
            &b"next"[..]
        );
        rx.expire(now + DATA_REASSEMBLY_TTL);
        assert!(rx.packets.is_empty());
        assert_eq!(rx.buffered, 0);
        assert!(
            rx.push(encode(1, 1280, 800, &[1; 480]), now + DATA_REASSEMBLY_TTL)
                .is_none()
        );
    }

    #[test]
    fn malformed_conflicting_and_oversized_fragments_are_bounded() {
        let now = Instant::now();
        let mut rx = Reassembler::default();
        for len in 0..HEADER {
            assert!(rx.push(Bytes::from(vec![0xff; len]), now).is_none());
        }
        assert!(
            rx.push(encode(1, MAX_DATA_DATAGRAM + 1, 0, b"x"), now)
                .is_none()
        );
        assert!(rx.push(encode(2, 100, 100, b"x"), now).is_none());
        assert!(rx.push(encode(3, 100, 0, b""), now).is_none());
        assert_eq!(rx.buffered, 0);
        for (id, bad) in [
            (4, encode(4, 100, 0, b"different")),
            (5, encode(5, 100, 3, b"overlap")),
            (6, encode(6, 101, 9, b"changed total")),
        ] {
            assert!(rx.push(encode(id, 100, 0, b"123456789"), now).is_none());
            assert!(rx.push(bad, now).is_none());
            assert_eq!(rx.buffered, 0);
        }
        for id in 100..400 {
            assert!(
                rx.push(encode(id, MAX_DATA_DATAGRAM, 0, b"x"), now)
                    .is_none()
            );
            assert!(rx.buffered <= MAX_DATA_REASSEMBLY_BYTES);
            assert!(rx.packets.len() <= MAX_DATA_ASSEMBLIES);
            assert!(rx.recent.len() <= DATA_RECENT_IDS);
        }
    }

    #[test]
    fn excessive_fragment_counts_are_discarded() {
        let mut rx = Reassembler::default();
        let now = Instant::now();
        for offset in 0..=MAX_DATA_FRAGMENTS {
            assert!(rx.push(encode(1, 1000, offset, b"x"), now).is_none());
        }
        assert!(rx.packets.is_empty());
        assert_eq!(rx.buffered, 0);
    }
}
