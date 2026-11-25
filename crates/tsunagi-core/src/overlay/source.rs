//! Translate host-selected IPv4 aliases at the local packet interface.
use super::Cidr;
use super::packet::{Ipv4Reassembly, fragment_ipv4};
use bytes::Bytes;
use smoltcp::wire::{Ipv4Cidr, Ipv4Packet};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

mod icmp;

#[cfg(any(all(windows, feature = "tun-device"), test))]
pub(crate) mod windows;

// No mappings are persisted, and a new flow cannot evict a live socket.
const MAX_FLOWS: usize = 4096;
const MAX_FRAGMENTED: usize = 16;
const UDP_IDLE: Duration = Duration::from_secs(120);
const TCP_IDLE: Duration = Duration::from_secs(2 * 60 * 60);
const ECHO_IDLE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct WireFlow {
    local: Ipv4Addr,
    remote: Ipv4Addr,
    protocol: u8,
    local_port: u16,
    remote_port: u16,
}

impl WireFlow {
    // ICMP errors quote as few as eight transport bytes; the caller validates
    // the outer packet separately. Echo requests in opposite directions can
    // have the same identifier without sharing a flow.
    fn parse(packet: &[u8], outbound: bool) -> Option<Self> {
        let h = usize::from(*packet.first()? & 15) * 4;
        if packet[0] >> 4 != 4
            || h < 20
            || packet.len() < h + 8
            || u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0
        {
            return None;
        }
        let src = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?);
        let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?);
        let (local, remote) = if outbound { (src, dst) } else { (dst, src) };
        let protocol = packet[9];
        let data = &packet[h..];
        let (local_port, remote_port) = match protocol {
            6 | 17 => {
                let src = u16::from_be_bytes([data[0], data[1]]);
                let dst = u16::from_be_bytes([data[2], data[3]]);
                if outbound { (src, dst) } else { (dst, src) }
            }
            1 if matches!(data[0], 0 | 8) && data[1] == 0 => {
                let id = u16::from_be_bytes([data[4], data[5]]);
                (id, u16::from(outbound != (data[0] == 8)))
            }
            _ => return None,
        };
        Some(Self {
            local,
            remote,
            protocol,
            local_port,
            remote_port,
        })
    }
}

#[derive(Clone, Copy)]
struct Binding {
    host: Ipv4Addr,
    // A response from an unbound UDP listener can leave Android with the
    // primary address even though its request targeted a different alias.
    remote_initiated: bool,
    expires: Instant,
}

/// How the host chooses a source at the TUN boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceMode {
    /// Android can choose the primary VPN address even for another mesh.
    Primary,
    /// Windows chooses the matching subnet for mesh traffic, but may select
    /// any local alias for a default route.
    ExitOnly,
}

#[derive(Debug, PartialEq, Eq)]
struct Domains {
    aliases: Vec<Ipv4Cidr>,
    exit: Option<Ipv4Addr>,
    mode: SourceMode,
}

impl Domains {
    fn new(addresses: &[Cidr], exit: Option<Ipv4Addr>, mode: SourceMode) -> Self {
        let aliases = addresses
            .iter()
            .filter_map(|cidr| match cidr.addr {
                IpAddr::V4(addr) if cidr.prefix_len <= 32 => {
                    Some(Ipv4Cidr::new(addr, cidr.prefix_len))
                }
                _ => None,
            })
            .collect();
        Self {
            aliases,
            exit,
            mode,
        }
    }

    fn primary(&self) -> Option<Ipv4Addr> {
        match self.mode {
            SourceMode::Primary => self.aliases.first().map(Ipv4Cidr::address),
            SourceMode::ExitOnly => None,
        }
    }
    fn has(&self, addr: Ipv4Addr) -> bool {
        self.aliases.iter().any(|alias| alias.address() == addr)
    }
    fn owner(&self, remote: Ipv4Addr) -> Option<Ipv4Addr> {
        if remote.is_broadcast()
            || remote.is_multicast()
            || remote.is_unspecified()
            || remote.is_loopback()
            || self.has(remote)
        {
            return None;
        }
        if let Some(prefix) = self.aliases.iter().find(|p| p.contains_addr(&remote)) {
            return (self.mode == SourceMode::Primary && prefix.broadcast() != Some(remote))
                .then(|| prefix.address());
        }
        self.exit
    }
}

/// Bounded flow bindings restore replies to the socket that opened each flow.
pub struct SourceFlows {
    domains: Domains,
    mtu: u32,
    flows: HashMap<Ipv4Addr, HashMap<WireFlow, Binding>>,
    primary_has_translations: bool,
    last_sweep: Instant,
    outgoing_parts: HashMap<Ipv4Addr, Ipv4Reassembly>,
    incoming_parts: HashMap<Ipv4Addr, Ipv4Reassembly>,
}

impl SourceFlows {
    /// Addresses are in the same order as on the device, primary first where applicable.
    pub fn new(addresses: &[Cidr], exit: Option<Ipv4Addr>, mtu: u32, mode: SourceMode) -> Self {
        Self {
            domains: Domains::new(addresses, exit, mode),
            mtu,
            flows: HashMap::new(),
            primary_has_translations: false,
            last_sweep: Instant::now(),
            outgoing_parts: HashMap::new(),
            incoming_parts: HashMap::new(),
        }
    }

    /// Keep live bindings whose host and wire addresses still belong to the same domains.
    pub fn reconfigure(&mut self, addresses: &[Cidr], exit: Option<Ipv4Addr>, mtu: u32) {
        self.domains = Domains::new(addresses, exit, self.domains.mode);
        self.mtu = mtu;
        self.flows.retain(|_, table| {
            table.retain(|wire, entry| {
                self.domains.has(entry.host) && self.domains.owner(wire.remote) == Some(wire.local)
            });
            !table.is_empty()
        });
        self.refresh_primary();
        // Outstanding fragments belong to the previous VPN attachment.
        self.outgoing_parts.clear();
        self.incoming_parts.clear();
    }

    fn refresh_primary(&mut self) {
        if let Some(primary) = self.domains.primary() {
            self.primary_has_translations = self
                .flows
                .get(&primary)
                .is_some_and(|table| table.values().any(|entry| entry.host != primary));
            if !self.primary_has_translations {
                self.flows.remove(&primary);
            }
        }
    }

    /// Packets read from the host.
    pub fn outbound(&mut self, packet: Bytes) -> Vec<Bytes> {
        self.process(packet, true)
    }

    /// Packets admitted by the mesh and destined for the host.
    pub fn inbound(&mut self, packet: Bytes) -> Vec<Bytes> {
        self.process(packet, false)
    }

    fn process(&mut self, packet: Bytes, outbound: bool) -> Vec<Bytes> {
        if self.domains.aliases.len() < 2 || packet.first().is_none_or(|byte| byte >> 4 != 4) {
            return vec![packet];
        }
        let Ok(ip) = Ipv4Packet::new_checked(&packet[..]) else {
            return vec![];
        };
        let h = usize::from(ip.header_len());
        if h < 20 || usize::from(ip.total_len()) != packet.len() {
            return vec![];
        }
        let (local, remote) = if outbound {
            (ip.src_addr(), ip.dst_addr())
        } else {
            (ip.dst_addr(), ip.src_addr())
        };
        // ICMP errors can come from a router other than the original peer.
        let is_icmp = packet[9] == 1;
        let owner = self.domains.owner(remote);
        let fragmented = ip.more_frags() || ip.frag_offset() != 0;
        if self.domains.mode == SourceMode::ExitOnly {
            // A mesh router can report PMTU for an internet flow whose source
            // we translated. All other native mesh and forwarded packets pass
            // directly, including fragments and packets headed to the gateway.
            let exit_error = !outbound
                && Some(local) == self.domains.exit
                && is_icmp
                && (fragmented || matches!(packet.get(h), Some(3 | 11 | 12)));
            if !self.domains.has(local) || (owner.is_none() && !exit_error) {
                return vec![packet];
            }
        }
        if !ip.verify_checksum() {
            return vec![];
        }
        let primary = self.domains.primary();
        // The kernel already uses the primary address for its own subnet. A
        // primary change can leave earlier translated sockets draining there.
        if Some(local) == primary
            && (!outbound || owner == primary)
            && !self.primary_has_translations
        {
            return vec![packet];
        }
        if owner.is_none() && !(is_icmp && self.domains.has(local)) {
            return vec![packet];
        }
        if !self.domains.has(local) {
            // Never translate addresses outside the local host's assignments.
            return if outbound { vec![] } else { vec![packet] };
        }

        let now = Instant::now();
        if now.duration_since(self.last_sweep) >= Duration::from_secs(5) {
            self.flows.retain(|_, table| {
                table.retain(|_, entry| now < entry.expires);
                !table.is_empty()
            });
            self.refresh_primary();
            self.last_sweep = now;
        }
        let packet = if fragmented {
            let parts = if outbound {
                &mut self.outgoing_parts
            } else {
                &mut self.incoming_parts
            };
            let key = if outbound {
                owner.unwrap_or(local)
            } else {
                local
            };
            let Some(packet) = parts
                .entry(key)
                .or_default()
                .accept(packet, MAX_FRAGMENTED, None)
            else {
                return vec![];
            };
            packet
        } else {
            packet
        };
        let h = usize::from(packet[0] & 15) * 4;
        let output = if is_icmp
            && packet
                .get(h)
                .is_some_and(|kind| matches!(kind, 3 | 11 | 12))
        {
            icmp::rewrite_error(packet, h, !outbound, |quote, quote_outbound| {
                let binding = WireFlow::parse(quote, quote_outbound)
                    .and_then(|flow| self.domains.owner(flow.remote).map(|alias| (flow, alias)));
                let Some((flow, alias)) = binding else {
                    // The quote passed validation but never required exit translation,
                    // for example a native socket talking to a peer inside the mesh.
                    return (self.domains.mode == SourceMode::ExitOnly).then_some((local, local));
                };
                let wire = WireFlow {
                    local: alias,
                    ..flow
                };
                let entry = self
                    .flows
                    .get(&wire.local)
                    .and_then(|table| table.get(&wire))
                    .filter(|entry| now < entry.expires);
                let Some(entry) = entry else {
                    return (wire.local == flow.local
                        && (Some(wire.local) == primary
                            || self.domains.mode == SourceMode::ExitOnly))
                        .then_some((wire.local, wire.local));
                };
                if quote_outbound {
                    (flow.local == wire.local).then_some((wire.local, entry.host))
                } else {
                    (flow.local == entry.host).then_some((entry.host, wire.local))
                }
            })
        } else {
            self.translate(packet, h, local, remote, outbound, now)
        };
        match output {
            Some(packet) if fragmented => fragment_ipv4(packet, self.mtu),
            Some(packet) => vec![packet],
            None => vec![],
        }
    }

    fn translate(
        &mut self,
        packet: Bytes,
        h: usize,
        local: Ipv4Addr,
        remote: Ipv4Addr,
        outbound: bool,
        now: Instant,
    ) -> Option<Bytes> {
        let Some(alias) = self.domains.owner(remote) else {
            return Some(packet);
        };
        // VIP/exit replies and any other special delivery already admitted by
        // core may have a source outside the addressed subnet.
        if !outbound && local != alias {
            return Some(packet);
        }
        let Some(flow) = WireFlow::parse(&packet, outbound) else {
            return (local == alias).then_some(packet);
        };
        let data = &packet[h..];
        let idle = match flow.protocol {
            6 => {
                let n = usize::from(*data.get(12)? >> 4) * 4;
                if n < 20 || n > data.len() {
                    return None;
                }
                if data[13] & 5 != 0 {
                    UDP_IDLE
                } else {
                    TCP_IDLE
                }
            }
            17 => {
                if usize::from(u16::from_be_bytes([data[4], data[5]])) != data.len() {
                    return None;
                }
                UDP_IDLE
            }
            _ => ECHO_IDLE,
        };
        let wire = WireFlow {
            local: alias,
            ..flow
        };
        let table = self.flows.entry(alias).or_default();
        if table.get(&wire).is_some_and(|entry| entry.expires <= now) {
            table.remove(&wire);
        }
        if !table.contains_key(&wire) {
            if Some(alias) == self.domains.primary() && local == alias {
                return Some(packet);
            }
            if table.len() >= MAX_FLOWS {
                return None;
            }
            if outbound
                && local != alias
                && (self
                    .domains
                    .primary()
                    .is_some_and(|primary| primary != local)
                    || flow.protocol == 6 && data[13] & 0x12 != 2)
            {
                return None;
            }
        }
        let entry = table.entry(wire).or_insert(Binding {
            host: local,
            remote_initiated: !outbound,
            expires: now + idle,
        });
        let target = if outbound {
            if local != entry.host {
                let wildcard_reply = entry.remote_initiated
                    && entry.host == alias
                    && flow.protocol == 17
                    && self.domains.primary() == Some(local);
                if !wildcard_reply {
                    return None;
                }
            }
            alias
        } else {
            if entry.host != alias && flow.protocol == 6 && data[13] & 0x12 == 2 {
                return None;
            }
            entry.host
        };
        entry.expires = now + idle;
        if target == local {
            return Some(packet);
        }
        let mut out = packet.to_vec();
        let address = if outbound { 12 } else { 16 };
        out[address..address + 4].copy_from_slice(&target.octets());
        let check = u16::from_be_bytes([out[10], out[11]]);
        out[10..12].copy_from_slice(&update_checksum(check, local, target).to_be_bytes());
        if matches!(flow.protocol, 6 | 17) {
            let off = h + if flow.protocol == 6 { 16 } else { 6 };
            let check = u16::from_be_bytes([out[off], out[off + 1]]);
            if flow.protocol == 6 || check != 0 {
                let new = update_checksum(check, local, target);
                let new = if new == 0 && flow.protocol == 17 {
                    u16::MAX
                } else {
                    new
                };
                out[off..off + 2].copy_from_slice(&new.to_be_bytes());
            }
        }
        Some(out.into())
    }
}

/// RFC 1624 one's-complement adjustment for replacing an IPv4 address.
fn update_checksum(checksum: u16, old: Ipv4Addr, new: Ipv4Addr) -> u16 {
    let mut sum = u32::from(!checksum);
    for (old, new) in old
        .octets()
        .as_chunks::<2>()
        .0
        .iter()
        .zip(new.octets().as_chunks::<2>().0)
    {
        sum += u32::from(!u16::from_be_bytes(*old)) + u32::from(u16::from_be_bytes(*new));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const FIRST: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 1);
    const SECOND: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 1);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 8);

    fn aliases() -> Vec<Cidr> {
        vec![
            Cidr::new(FIRST.into(), 24).unwrap(),
            Cidr::new(SECOND.into(), 24).unwrap(),
        ]
    }

    fn udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Bytes {
        use smoltcp::wire::{IpAddress, Ipv4Packet, UdpPacket};
        let mut bytes = vec![0; 28 + payload.len()];
        bytes[0] = 0x45;
        let size = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&size.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&src.octets());
        bytes[16..20].copy_from_slice(&dst.octets());
        Ipv4Packet::new_unchecked(&mut bytes[..]).fill_checksum();
        let mut udp = UdpPacket::new_unchecked(&mut bytes[20..]);
        udp.set_src_port(sport);
        udp.set_dst_port(dport);
        udp.set_len(size - 20);
        udp.payload_mut().copy_from_slice(payload);
        udp.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
        bytes.into()
    }

    #[test]
    fn connected_udp_keeps_its_kernel_address_while_the_peer_sees_the_right_alias() {
        let mut flows = SourceFlows::new(&aliases(), None, 1280, SourceMode::Primary);
        let request = udp(FIRST, PEER, 4123, 1234, b"request");
        assert_eq!(
            flows.outbound(request),
            vec![udp(SECOND, PEER, 4123, 1234, b"request")]
        );
        assert_eq!(
            flows.inbound(udp(PEER, SECOND, 1234, 4123, b"reply")),
            vec![udp(PEER, FIRST, 1234, 4123, b"reply")]
        );
        assert!(
            flows
                .outbound(udp(SECOND, PEER, 4123, 1234, b"bound collision"))
                .is_empty()
        );
        assert_eq!(
            flows.inbound(udp(PEER, SECOND, 1234, 4124, b"to a listener")),
            vec![udp(PEER, SECOND, 1234, 4124, b"to a listener")]
        );
        assert_eq!(
            flows.outbound(udp(FIRST, PEER, 4124, 1234, b"wildcard listener reply")),
            vec![udp(SECOND, PEER, 4124, 1234, b"wildcard listener reply")]
        );
        assert_eq!(
            flows.inbound(udp(PEER, SECOND, 1234, 4124, b"again")),
            vec![udp(PEER, SECOND, 1234, 4124, b"again")]
        );
    }

    #[test]
    fn windows_exit_accepts_any_local_alias_and_restores_external_replies() {
        let mut flows = SourceFlows::new(&aliases(), Some(FIRST), 1280, SourceMode::ExitOnly);
        let internet = Ipv4Addr::new(203, 0, 113, 2);
        let request = udp(SECOND, internet, 4123, 443, b"external");
        assert_eq!(
            flows.outbound(request),
            [udp(FIRST, internet, 4123, 443, b"external")]
        );
        assert_eq!(
            flows.inbound(udp(internet, FIRST, 443, 4123, b"reply")),
            [udp(internet, SECOND, 443, 4123, b"reply")]
        );
        // An explicitly bound socket cannot take replies from this flow.
        assert!(
            flows
                .outbound(udp(FIRST, internet, 4123, 443, b"collision"))
                .is_empty()
        );
        // An address in either overlay, including the gateway itself, stays native.
        let mesh = udp(SECOND, PEER, 4123, 443, b"mesh");
        assert_eq!(flows.outbound(mesh.clone()), [mesh]);
    }

    #[tokio::test]
    async fn wintun_normalizes_only_external_flows_while_an_exit_is_selected() {
        use super::windows::ExitSourceTun;
        use crate::overlay::{MemoryTun, TunDevice};

        let device = MemoryTun::new("test", 1280);
        let tun = ExitSourceTun::new(device.clone());
        let internet = Ipv4Addr::new(203, 0, 113, 2);
        let request = udp(FIRST, internet, 4000, 80, &[1; 1600]);
        let on_wire = udp(SECOND, internet, 4000, 80, &[1; 1600]);
        tun.set_exit_source(&aliases(), Some(SECOND));
        for part in fragment_ipv4(request.clone(), 1280) {
            device.push_from_os(part);
        }
        for expected in fragment_ipv4(on_wire, 1280) {
            assert_eq!(tun.recv().await, Some(expected));
        }
        // Periodic exit rule refreshes must preserve the original socket.
        tun.set_exit_source(&aliases(), Some(SECOND));
        tun.send(udp(internet, SECOND, 80, 4000, b"reply"))
            .await
            .unwrap();
        assert_eq!(
            device.pop_to_os().await,
            Some(udp(internet, FIRST, 80, 4000, b"reply"))
        );
        let forwarded = udp(PEER, internet, 4000, 80, b"forwarded");
        device.push_from_os(forwarded.clone());
        assert_eq!(tun.recv().await, Some(forwarded));

        tun.set_exit_source(&aliases(), None);
        device.push_from_os(request.clone());
        assert_eq!(tun.recv().await, Some(request));
    }

    #[test]
    fn proper_bound_flows_and_limited_broadcast_keep_their_identity() {
        let mut flows = SourceFlows::new(&aliases(), None, 1280, SourceMode::Primary);
        let native = udp(SECOND, PEER, 3000, 3001, b"bound");
        assert_eq!(flows.outbound(native.clone()), vec![native]);
        assert!(
            flows
                .outbound(udp(FIRST, PEER, 3000, 3001, b"collision"))
                .is_empty()
        );
        let reply = udp(PEER, SECOND, 3001, 3000, b"native");
        assert_eq!(flows.inbound(reply.clone()), vec![reply]);
        let broadcast = udp(FIRST, Ipv4Addr::BROADCAST, 3000, 3001, b"lan");
        assert_eq!(flows.outbound(broadcast.clone()), vec![broadcast]);
        assert!(
            flows
                .outbound(udp(PEER, PEER, 3100, 3100, b"forged source"))
                .is_empty()
        );
    }

    fn packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, data: &[u8]) -> Bytes {
        let mut out = vec![0; 20 + data.len()];
        let size = out.len() as u16;
        out[0] = 0x45;
        out[2..4].copy_from_slice(&size.to_be_bytes());
        out[8] = 64;
        out[9] = protocol;
        out[12..16].copy_from_slice(&src.octets());
        out[16..20].copy_from_slice(&dst.octets());
        out[20..].copy_from_slice(data);
        Ipv4Packet::new_unchecked(&mut out).fill_checksum();
        out.into()
    }

    fn tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> Bytes {
        use smoltcp::wire::{IpAddress, TcpPacket};
        let mut data = [0; 20];
        data[..2].copy_from_slice(&sport.to_be_bytes());
        data[2..4].copy_from_slice(&dport.to_be_bytes());
        data[12] = 0x50;
        data[13] = flags;
        TcpPacket::new_unchecked(&mut data[..])
            .fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
        packet(src, dst, 6, &data)
    }

    #[test]
    fn tcp_keeps_direction_and_bindings_survive_unrelated_plans() {
        let mut aliases = aliases();
        let mut flows = SourceFlows::new(&aliases, None, 1280, SourceMode::Primary);
        assert!(flows.outbound(tcp(FIRST, PEER, 333, 443, 16)).is_empty());
        assert_eq!(
            flows.outbound(tcp(FIRST, PEER, 333, 443, 2)),
            [tcp(SECOND, PEER, 333, 443, 2)]
        );
        flows.reconfigure(&aliases, None, 1280);
        assert_eq!(
            flows.inbound(tcp(PEER, SECOND, 443, 333, 18)),
            [tcp(PEER, FIRST, 443, 333, 18)]
        );
        // An inbound connection cannot replace a client's active translation.
        assert!(flows.inbound(tcp(PEER, SECOND, 443, 333, 2)).is_empty());
        let inbound = tcp(PEER, SECOND, 12345, 80, 2);
        assert_eq!(flows.inbound(inbound.clone()), [inbound]);
        let syn_ack = tcp(SECOND, PEER, 80, 12345, 18);
        assert_eq!(flows.outbound(syn_ack.clone()), [syn_ack]);
        aliases.remove(0);
        flows.reconfigure(&aliases, None, 1280);
        assert!(
            !flows
                .flows
                .values()
                .any(|table| table.values().any(|e| e.host == FIRST))
        );
    }

    #[test]
    fn a_new_primary_drains_earlier_translations_and_passes_its_own_packets() {
        let mut aliases = aliases();
        let mut flows = SourceFlows::new(&aliases, None, 1280, SourceMode::Primary);
        assert_eq!(flows.outbound(udp(FIRST, PEER, 2222, 53, b"q")).len(), 1);
        aliases.swap(0, 1);
        flows.reconfigure(&aliases, Some(SECOND), 1280);
        assert_eq!(
            flows.inbound(udp(PEER, SECOND, 53, 2222, b"a")),
            [udp(PEER, FIRST, 53, 2222, b"a")]
        );
        let bound = udp(SECOND, PEER, 4444, 443, b"native");
        assert_eq!(flows.outbound(bound.clone()), [bound]);
        let native_reply = udp(PEER, SECOND, 443, 4444, b"r");
        assert_eq!(flows.inbound(native_reply.clone()), [native_reply]);
        assert_eq!(flows.flows[&SECOND].len(), 1);
    }

    #[test]
    fn untracked_primary_errors_and_point_to_point_destinations_are_preserved() {
        let mut aliases = aliases();
        let mut flows = SourceFlows::new(&aliases, None, 1280, SourceMode::Primary);
        let router = Ipv4Addr::new(10, 1, 0, 7);
        let mut unreachable = vec![3, 1, 0, 0, 0, 0, 0, 0];
        unreachable.extend_from_slice(&udp(FIRST, router, 50_000, 7, b"probe")[..28]);
        smoltcp::wire::Icmpv4Packet::new_unchecked(&mut unreachable).fill_checksum();
        let error = packet(router, FIRST, 1, &unreachable);
        assert_eq!(flows.inbound(error.clone()), [error]);
        let directed = udp(FIRST, Ipv4Addr::new(10, 2, 0, 255), 5, 6, b"broadcast");
        assert_eq!(flows.outbound(directed.clone()), [directed]);
        let point = Ipv4Addr::new(10, 2, 0, 0);
        aliases[1] = Cidr::new(point.into(), 31).unwrap();
        flows.reconfigure(&aliases, None, 1280);
        assert_eq!(
            flows.outbound(udp(FIRST, SECOND, 5, 6, b"p2p")),
            [udp(point, SECOND, 5, 6, b"p2p")]
        );
    }

    #[test]
    fn echo_ids_can_match_in_both_directions() {
        let mut flows = SourceFlows::new(&aliases(), None, 1280, SourceMode::Primary);
        let message = |src, dst, kind| {
            use smoltcp::wire::Icmpv4Packet;
            let mut data = [kind, 0, 0, 0, 0x12, 0x34, 0, 2];
            Icmpv4Packet::new_unchecked(&mut data[..]).fill_checksum();
            packet(src, dst, 1, &data)
        };
        assert_eq!(
            flows.outbound(message(FIRST, PEER, 8)),
            [message(SECOND, PEER, 8)]
        );
        assert_eq!(
            flows.inbound(message(PEER, SECOND, 8)),
            [message(PEER, SECOND, 8)]
        );
        assert_eq!(
            flows.outbound(message(SECOND, PEER, 0)),
            [message(SECOND, PEER, 0)]
        );
        assert_eq!(
            flows.inbound(message(PEER, SECOND, 0)),
            [message(PEER, FIRST, 0)]
        );
    }

    #[test]
    fn saturated_network_does_not_take_another_networks_capacity() {
        let mut flows = SourceFlows::new(&aliases(), None, 1280, SourceMode::Primary);
        for port in 0..MAX_FLOWS {
            assert_eq!(
                flows
                    .outbound(udp(FIRST, PEER, port as u16, 53, b"q"))
                    .len(),
                1
            );
        }
        assert!(
            flows
                .outbound(udp(FIRST, PEER, 60000, 53, b"full"))
                .is_empty()
        );
        let primary_peer = Ipv4Addr::new(10, 1, 0, 20);
        let own = udp(FIRST, primary_peer, 60000, 53, b"first");
        assert_eq!(flows.outbound(own.clone()), [own]);
        for entry in flows.flows.get_mut(&SECOND).unwrap().values_mut() {
            entry.expires = Instant::now();
        }
        flows.last_sweep -= Duration::from_secs(6);
        assert_eq!(
            flows.outbound(udp(FIRST, PEER, 60000, 53, b"free")).len(),
            1
        );
        assert_eq!(flows.flows[&SECOND].len(), 1);
    }

    #[test]
    fn fragmented_udp_translates_after_assembly_in_both_directions() {
        let mut flows = SourceFlows::new(&aliases(), None, 1280, SourceMode::Primary);
        let mut original = udp(FIRST, PEER, 3333, 4444, &[7; 1900]);
        let parts = fragment_ipv4(original.clone(), 1280);
        let mut output = Vec::new();
        for part in parts.into_iter().rev() {
            output.extend(flows.outbound(part));
        }
        assert_eq!(
            output,
            fragment_ipv4(udp(SECOND, PEER, 3333, 4444, &[7; 1900]), 1280)
        );
        original = udp(PEER, SECOND, 4444, 3333, &[8; 1900]);
        let mut output = Vec::new();
        for part in fragment_ipv4(original, 1280) {
            output.extend(flows.inbound(part));
        }
        assert_eq!(
            output,
            fragment_ipv4(udp(PEER, FIRST, 4444, 3333, &[8; 1900]), 1280)
        );
    }
}
