//! Optional IP flow classifier for IP plugins, called before encryption.
//! The router itself treats this identifier and the payload as opaque.

use super::FlowId;

fn hash(parts: &[&[u8]]) -> FlowId {
    let mut value = 0xcbf29ce484222325u64;
    for part in parts {
        for byte in *part {
            value = (value ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
    }
    value
}

/// Stable directional IP flow hash, independent of TCP sequence numbers,
/// checksums and packet contents. Fragmented traffic uses addresses/protocol
/// instead of ports: even non-initial fragments and subsequent fragmented
/// datagrams stay together. This deliberately coalesces fragmented flows.
/// Malformed packets get a coarse hash; parsing is bounded and never allocates.
pub fn ip_flow(packet: &[u8]) -> FlowId {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let addresses = &packet[12..20];
            let protocol = &packet[9..10];
            let offset = usize::from(packet[0] & 15) * 4;
            if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
                return hash(&[addresses, protocol]);
            }
            if offset >= 20
                && matches!(packet[9], 6 | 17)
                && let Some(ports) = packet.get(offset..offset + 4)
            {
                return hash(&[addresses, protocol, ports]);
            }
            hash(&[addresses, protocol])
        }
        Some(6) if packet.len() >= 40 => {
            let addresses = &packet[8..40];
            let mut protocol = packet[6];
            let mut offset = 40;
            for _ in 0..8 {
                match protocol {
                    44 => {
                        if let Some(fragment) = packet.get(offset..offset + 8) {
                            return hash(&[addresses, &fragment[..1]]);
                        }
                        break;
                    }
                    0 | 43 | 60 | 51 => {
                        let Some(header) = packet.get(offset..offset + 2) else {
                            break;
                        };
                        let size = if protocol == 51 {
                            (usize::from(header[1]) + 2) * 4
                        } else {
                            (usize::from(header[1]) + 1) * 8
                        };
                        protocol = header[0];
                        offset += size;
                    }
                    6 | 17 => {
                        if let Some(ports) = packet.get(offset..offset + 4) {
                            return hash(&[addresses, &[protocol], ports]);
                        }
                        break;
                    }
                    _ => break,
                }
            }
            hash(&[addresses, &[protocol]])
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_flow_ignores_packet_contents_but_distinguishes_ports() {
        let mut packet = [0u8; 80];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..24].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2, 0, 22, 1, 2]);
        let flow = ip_flow(&packet);
        packet[4] = 123; // IP id changes for each unfragmented packet.
        packet[24..].fill(47);
        assert_eq!(flow, ip_flow(&packet));
        packet[23] = 3;
        assert_ne!(flow, ip_flow(&packet));
        packet[6] = 0x20;
        let fragment_flow = ip_flow(&packet);
        packet[6] = 0;
        packet[7] = 1;
        packet[20..].fill(99);
        assert_eq!(fragment_flow, ip_flow(&packet));
        packet[4] = 97;
        assert_eq!(fragment_flow, ip_flow(&packet));
    }

    #[test]
    fn ipv6_extensions_and_fragments_are_bounded_and_stable() {
        let mut packet = [0u8; 80];
        packet[0] = 0x60;
        packet[6] = 0;
        packet[40] = 17;
        packet[48..52].copy_from_slice(&[1, 2, 3, 4]);
        let flow = ip_flow(&packet);
        packet[52..].fill(5);
        assert_eq!(flow, ip_flow(&packet));
        packet[50] = 9;
        assert_ne!(flow, ip_flow(&packet));
        packet[6] = 44;
        packet[40] = 6;
        let flow = ip_flow(&packet);
        packet[42] = 32;
        packet[48..].fill(3);
        assert_eq!(flow, ip_flow(&packet));
        for len in 0..packet.len() {
            let _ = ip_flow(&packet[..len]);
        }
    }
}
