use crate::Direction;
use bytes::{Bytes, BytesMut};
use std::net::Ipv4Addr;

pub(crate) const MIN_MTU: u16 = 576;
pub(crate) const MAX_MTU: u16 = 1500;
pub(crate) const HEADER: u16 = 46;
const MAGIC: &[u8; 8] = b"TSNGSP01";
const IP_PROTOCOL: u8 = 253; // RFC 3692 local experiment, disambiguated by MAGIC.

/// Fields from a validated version-one diagnostic IPv4 packet. Probes carry no arbitrary stream data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram {
    /// Measurement identifier from the authenticated control exchange.
    pub id: u64,
    /// Source address of the inner IPv4 datagram.
    pub source: Ipv4Addr,
    /// Destination address of the inner IPv4 datagram.
    pub destination: Ipv4Addr,
    pub(crate) direction: Direction,
    pub(crate) stage: u8,
    pub(crate) sequence: u32,
    pub(crate) sent_us: u32,
    pub(crate) size: u16,
}

impl Datagram {
    /// Number of delivered diagnostic payload bytes, excluding both headers.
    pub fn payload_len(self) -> u16 {
        self.size - HEADER
    }
}

/// Identify this crate's reserved IPv4 payload, including malformed records that should be dropped.
pub fn is_test_packet(bytes: &[u8]) -> bool {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 || bytes[9] != IP_PROTOCOL {
        return false;
    }
    let offset = usize::from(bytes[0] & 0x0f) * 4;
    offset >= 20 && bytes.get(offset..offset + MAGIC.len()) == Some(MAGIC)
}

/// Validate an entire diagnostic datagram before handing its fixed-size metadata to the receiver.
pub fn decode_packet(bytes: &[u8]) -> Option<Datagram> {
    let size = u16::try_from(bytes.len()).ok()?;
    if !(MIN_MTU..=MAX_MTU).contains(&size)
        || bytes[0] != 0x45
        || bytes[9] != IP_PROTOCOL
        || bytes[20..28] != *MAGIC
        || u16::from_be_bytes([bytes[2], bytes[3]]) != size
        || u16::from_be_bytes([bytes[6], bytes[7]]) & !0x4000 != 0
        || checksum(&bytes[..20]) != 0
    {
        return None;
    }
    let direction = match bytes[36] {
        0 => Direction::Download,
        1 => Direction::Upload,
        _ => return None,
    };
    let sent_us = u32::from_be_bytes(bytes[42..46].try_into().ok()?);
    if sent_us > 5_000_000 {
        return None;
    }
    Some(Datagram {
        source: Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).ok()?),
        destination: Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).ok()?),
        id: u64::from_be_bytes(bytes[28..36].try_into().ok()?),
        direction,
        stage: bytes[37],
        sequence: u32::from_be_bytes(bytes[38..42].try_into().ok()?),
        sent_us,
        size,
    })
}

// Build the immutable header and deterministic padding once per direction. The
// underlying data tunnel encrypts the packet before it goes on the wire.
pub(crate) struct PacketBuilder(Bytes);

impl PacketBuilder {
    pub(crate) fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        id: u64,
        direction: Direction,
        mtu: u16,
    ) -> Self {
        let mut bytes = BytesMut::zeroed(usize::from(mtu));
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&mtu.to_be_bytes());
        bytes[6] = 0x40;
        bytes[8] = 64;
        bytes[9] = IP_PROTOCOL;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&destination.octets());
        let check = checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&check.to_be_bytes());
        bytes[20..28].copy_from_slice(MAGIC);
        bytes[28..36].copy_from_slice(&id.to_be_bytes());
        bytes[36] = match direction {
            Direction::Download => 0,
            Direction::Upload => 1,
        };
        Self(bytes.freeze())
    }

    pub(crate) fn packet(&self, stage: u8, sequence: u32, sent_us: u32) -> Bytes {
        let mut bytes = BytesMut::from(self.0.as_ref());
        bytes[37] = stage;
        bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
        bytes[42..46].copy_from_slice(&sent_us.to_be_bytes());
        bytes.freeze()
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&word| u32::from(u16::from_be_bytes(word)))
        .sum();
    while sum > u32::from(u16::MAX) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn probe() -> Bytes {
        PacketBuilder::new(
            Ipv4Addr::new(10, 1, 10, 1),
            Ipv4Addr::new(10, 1, 10, 2),
            42,
            Direction::Upload,
            1280,
        )
        .packet(3, 908, 12_000)
    }

    #[test]
    fn routeable_ip_header_and_test_metadata_round_trip() {
        let bytes = probe();
        assert!(is_test_packet(&bytes));
        let data = decode_packet(&bytes).unwrap();
        assert_eq!(data.source, Ipv4Addr::new(10, 1, 10, 1));
        assert_eq!(data.destination, Ipv4Addr::new(10, 1, 10, 2));
        assert_eq!(
            (
                data.id,
                data.direction,
                data.stage,
                data.sequence,
                data.sent_us
            ),
            (42, Direction::Upload, 3, 908, 12_000)
        );
        assert_eq!(data.payload_len(), 1280 - HEADER);
        for n in [0, 1, 19, 27, 45, 100, 1279] {
            assert!(decode_packet(&bytes[..n]).is_none());
        }
        for (byte, value) in [
            (0, 0x65),
            (2, 0x04),
            (6, 0x20),
            (9, 17),
            (10, 0),
            (20, b'z'),
            (36, 3),
            (42, 255),
        ] {
            let mut bad = bytes.to_vec();
            bad[byte] = value;
            assert!(decode_packet(&bad).is_none(), "corrupted {byte}");
        }
        let mut broken = bytes.to_vec();
        broken[36] = 123;
        assert!(is_test_packet(&broken));
        broken[20] = 0;
        assert!(!is_test_packet(&broken));
    }
}
