//! Translate errors on existing flows, including truncated RFC 792 quotations.
use super::update_checksum;
use bytes::Bytes;
use smoltcp::wire::{Icmpv4Packet, IpProtocol, Ipv4Packet};
use std::net::Ipv4Addr;

pub(super) fn rewrite_error(
    packet: Bytes,
    header_len: usize,
    inbound: bool,
    mut lookup: impl FnMut(&[u8], bool) -> Option<(Ipv4Addr, Ipv4Addr)>,
) -> Option<Bytes> {
    let outer = Ipv4Packet::new_checked(&packet[..]).ok()?;
    if outer.version() != 4
        || header_len < 20
        || header_len != usize::from(outer.header_len())
        || usize::from(outer.total_len()) != packet.len()
        || outer.next_header() != IpProtocol::Icmp
        || outer.more_frags()
        || outer.frag_offset() != 0
        || !outer.verify_checksum()
    {
        return None;
    }
    let icmp = outer.payload();
    if !Icmpv4Packet::new_checked(icmp).ok()?.verify_checksum() || !matches!(icmp[0], 3 | 11 | 12) {
        return None;
    }
    let payload = &icmp[8..];
    // RFC 4884 records the padded quotation length in words when extensions follow.
    let quote = match icmp[5] {
        0 => payload,
        words => payload.get(..usize::from(words) * 4)?,
    };
    quote.get(..20)?;
    // The original total length may exceed the bytes the router chose to quote.
    let inner = Ipv4Packet::new_unchecked(quote);
    let inner_header = usize::from(inner.header_len());
    let quote_len = quote.len().min(usize::from(inner.total_len()));
    if inner.version() != 4
        || inner_header < 20
        || quote_len < inner_header + 8
        || inner.frag_offset() != 0
        || !inner.verify_checksum()
    {
        return None;
    }
    let (outer_local, inner_local) = if inbound {
        (outer.dst_addr(), inner.src_addr())
    } else {
        (outer.src_addr(), inner.dst_addr())
    };
    if outer_local != inner_local {
        return None;
    }
    let (old, new) = lookup(&quote[..quote_len], inbound)?;
    if old != inner_local {
        return None;
    }
    if old == new {
        return Some(packet);
    }
    let transport = inner.next_header();
    let mut result = packet.to_vec();
    let quote_start = header_len + 8;
    let mut inner = Ipv4Packet::new_unchecked(&mut result[quote_start..quote_start + quote_len]);
    if inbound {
        inner.set_src_addr(new);
    } else {
        inner.set_dst_addr(new);
    }
    inner.fill_checksum();
    let transport_bytes = &mut inner.into_inner()[inner_header..];
    // A minimum TCP quote includes ports and sequence number, but not its checksum.
    let field = match transport {
        IpProtocol::Tcp => transport_bytes.get_mut(16..18),
        IpProtocol::Udp => transport_bytes.get_mut(6..8),
        _ => None,
    };
    if let Some(field) = field {
        let previous = u16::from_be_bytes([field[0], field[1]]);
        if previous != 0 || transport == IpProtocol::Tcp {
            let adjusted = update_checksum(previous, old, new);
            let value = if adjusted == 0 && transport == IpProtocol::Udp {
                u16::MAX
            } else {
                adjusted
            };
            field.copy_from_slice(&value.to_be_bytes());
        }
    }
    Icmpv4Packet::new_unchecked(&mut result[header_len..]).fill_checksum();
    let mut outer = Ipv4Packet::new_unchecked(&mut result);
    if inbound {
        outer.set_dst_addr(new);
    } else {
        outer.set_src_addr(new);
    }
    outer.fill_checksum();
    Some(result.into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use smoltcp::wire::{TcpPacket, UdpPacket};

    const APP: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 1);
    const WIRE: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 1);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 2);
    const ROUTER: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 3);

    fn ipv4(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0; 20 + payload.len()];
        let total = p.len() as u16;
        p[0] = 0x45;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[8] = 64;
        p[9] = protocol;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..].copy_from_slice(payload);
        Ipv4Packet::new_unchecked(&mut p).fill_checksum();
        p
    }

    fn error(src: Ipv4Addr, dst: Ipv4Addr, quote: &[u8]) -> Bytes {
        let mut icmp = vec![3, 4, 0, 0, 0, 0, 5, 0];
        icmp.extend_from_slice(quote);
        Icmpv4Packet::new_unchecked(&mut icmp).fill_checksum();
        ipv4(1, src, dst, &icmp).into()
    }

    #[test]
    fn inbound_pmtu_restores_a_truncated_udp_quote_and_preserves_the_reporting_router() {
        use crate::plan::VpnPlan;
        use crate::source::SourceFlows;
        use tsunagi::overlay::Cidr;

        let mut flows = SourceFlows::new(&VpnPlan {
            addresses: vec![
                Cidr::new(APP.into(), 24).unwrap(),
                Cidr::new(WIRE.into(), 24).unwrap(),
            ],
            mtu: 1280,
            ..Default::default()
        });
        let mut udp = [0x71; 16];
        udp[4..6].copy_from_slice(&16u16.to_be_bytes());
        UdpPacket::new_unchecked(&mut udp[..]).fill_checksum(&APP.into(), &PEER.into());
        let original = ipv4(17, APP, PEER, &udp);
        let wire = flows.outbound(original.clone().into()).pop().unwrap();
        let p = error(ROUTER, WIRE, &wire[..28]);
        let restored = flows.inbound(p).pop().unwrap();
        let outer = Ipv4Packet::new_checked(&restored[..]).unwrap();
        assert!(outer.verify_checksum());
        assert_eq!(outer.src_addr(), ROUTER);
        assert_eq!(outer.dst_addr(), APP);
        assert!(
            Icmpv4Packet::new_checked(outer.payload())
                .unwrap()
                .verify_checksum()
        );
        assert_eq!(outer.payload()[6..8], 1280u16.to_be_bytes());
        assert_eq!(outer.payload()[8..], original[..28]);
    }

    #[test]
    fn outbound_error_restores_tcp_quotes_with_or_without_a_transport_checksum() {
        let mut tcp = [0x41; 48];
        tcp[12] = 0x50;
        TcpPacket::new_unchecked(&mut tcp[..]).fill_checksum(&PEER.into(), &APP.into());
        let original = ipv4(6, PEER, APP, &tcp);
        TcpPacket::new_unchecked(&mut tcp[..]).fill_checksum(&PEER.into(), &WIRE.into());
        let wire = ipv4(6, PEER, WIRE, &tcp);
        for length in [28, original.len()] {
            let p = error(APP, PEER, &original[..length]);
            let rewritten = rewrite_error(p, 20, false, |_, outbound| {
                assert!(!outbound);
                Some((APP, WIRE))
            })
            .unwrap();
            assert_eq!(rewritten, error(WIRE, PEER, &wire[..length]));
        }
    }

    #[test]
    fn malformed_quotes_unknown_flows_and_unrelated_outer_addresses_are_rejected() {
        let original = ipv4(17, WIRE, PEER, &[0; 8]);
        let p = error(ROUTER, WIRE, &original);
        assert_eq!(
            rewrite_error(p.clone(), 20, true, |_, _| Some((WIRE, WIRE))),
            Some(p.clone())
        );
        assert!(rewrite_error(p, 20, true, |_, _| None).is_none());
        for invalid in [
            error(ROUTER, APP, &original),
            error(ROUTER, WIRE, &original[..26]),
            {
                let mut fragment = original.clone();
                fragment[7] = 1;
                Ipv4Packet::new_unchecked(&mut fragment).fill_checksum();
                error(ROUTER, WIRE, &fragment)
            },
            {
                let mut damaged = error(ROUTER, WIRE, &original).to_vec();
                damaged[22] ^= 1;
                damaged.into()
            },
        ] {
            assert!(
                rewrite_error(invalid, 20, true, |_, _| panic!(
                    "invalid quote reached lookup"
                ))
                .is_none()
            );
        }
        // IPv4 UDP allows a zero checksum; translation may not enable it.
        let restored = rewrite_error(error(ROUTER, WIRE, &original), 20, true, |_, _| {
            Some((WIRE, APP))
        })
        .unwrap();
        assert_eq!(restored[54..56], [0, 0]);
    }
}
