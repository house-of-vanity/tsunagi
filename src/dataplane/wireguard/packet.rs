//! The little bit of IP parsing the data plane needs.
//!
//! Two questions only: which peer should carry this packet, and did the packet
//! that came back really come from that peer? Everything is bounds checked and
//! nothing here can panic on a hostile packet.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The addresses of an IP packet, as far as routing cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpHeader {
    /// An IPv4 packet.
    V4 {
        /// Source address.
        source: Ipv4Addr,
        /// Destination address.
        destination: Ipv4Addr,
    },
    /// An IPv6 packet.
    V6 {
        /// Source address.
        source: Ipv6Addr,
        /// Destination address.
        destination: Ipv6Addr,
    },
}

impl IpHeader {
    /// Reads the addresses out of a packet, or `None` if it is not one.
    pub fn parse(packet: &[u8]) -> Option<Self> {
        let version = packet.first()? >> 4;
        match version {
            4 => {
                let source: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
                let destination: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
                Some(IpHeader::V4 {
                    source: Ipv4Addr::from(source),
                    destination: Ipv4Addr::from(destination),
                })
            }
            6 => {
                let source: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
                let destination: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
                Some(IpHeader::V6 {
                    source: Ipv6Addr::from(source),
                    destination: Ipv6Addr::from(destination),
                })
            }
            _ => None,
        }
    }

    /// The destination, when the packet is IPv6.
    pub fn v6_destination(&self) -> Option<Ipv6Addr> {
        match self {
            IpHeader::V6 { destination, .. } => Some(*destination),
            IpHeader::V4 { .. } => None,
        }
    }

    /// The source, when the packet is IPv6.
    pub fn v6_source(&self) -> Option<Ipv6Addr> {
        match self {
            IpHeader::V6 { source, .. } => Some(*source),
            IpHeader::V4 { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn ipv6_packet(source: Ipv6Addr, destination: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 6 << 4;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet
    }

    #[test]
    fn ipv6_addresses_are_read_correctly() {
        let source: Ipv6Addr = "fd00::1".parse().unwrap();
        let destination: Ipv6Addr = "fd00::2".parse().unwrap();
        let header = IpHeader::parse(&ipv6_packet(source, destination)).unwrap();
        assert_eq!(header.v6_source(), Some(source));
        assert_eq!(header.v6_destination(), Some(destination));
    }

    #[test]
    fn ipv4_addresses_are_read_correctly() {
        let mut packet = vec![0u8; 20];
        packet[0] = 4 << 4;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let header = IpHeader::parse(&packet).unwrap();
        assert_eq!(
            header,
            IpHeader::V4 {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
            }
        );
        // The overlay is IPv6, so the v6 accessors correctly report nothing.
        assert_eq!(header.v6_destination(), None);
    }

    #[test]
    fn truncated_and_nonsense_packets_are_rejected_without_panicking() {
        assert!(IpHeader::parse(&[]).is_none());
        assert!(IpHeader::parse(&[0x60]).is_none());
        assert!(IpHeader::parse(&[0x40; 19]).is_none(), "short IPv4");
        assert!(IpHeader::parse(&[0x60; 39]).is_none(), "short IPv6");
        assert!(IpHeader::parse(&[0x00; 64]).is_none(), "version 0");
        assert!(IpHeader::parse(&[0xf0; 64]).is_none(), "version 15");
        // Every possible first byte is safe to feed in.
        for byte in 0..=u8::MAX {
            let _ = IpHeader::parse(&[byte; 64]);
            let _ = IpHeader::parse(&[byte]);
        }
    }
}
