//! Bounded IPv4 parsing, NAT checksums and fragment reassembly at local ingress.
use super::Protocol;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Tuple {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub protocol: Protocol,
}
impl Tuple {
    pub fn reverse(self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            sport: self.dport,
            dport: self.sport,
            protocol: self.protocol,
        }
    }
}
pub(crate) fn header(p: &[u8]) -> Option<usize> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let n = usize::from(p[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
    (n >= 20 && n <= p.len() && total == p.len() && checksum(&p[..n]) == 0).then_some(n)
}
pub(crate) fn addresses(p: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    header(p)?;
    Some((
        Ipv4Addr::new(p[12], p[13], p[14], p[15]),
        Ipv4Addr::new(p[16], p[17], p[18], p[19]),
    ))
}
pub(crate) fn tuple(p: &[u8]) -> Option<Tuple> {
    let n = header(p)?;
    if u16::from_be_bytes([p[6], p[7]]) & 0x3fff != 0 {
        return None;
    }
    let protocol = match p[9] {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };
    let min = if protocol == Protocol::Tcp { 20 } else { 8 };
    if p.len() < n + min {
        return None;
    }
    if protocol == Protocol::Tcp {
        let h = usize::from(p[n + 12] >> 4) * 4;
        if h < 20 || n + h > p.len() {
            return None;
        }
    } else if usize::from(u16::from_be_bytes([p[n + 4], p[n + 5]])) != p.len() - n {
        return None;
    }
    let (src, dst) = addresses(p)?;
    Some(Tuple {
        src,
        dst,
        sport: u16::from_be_bytes([p[n], p[n + 1]]),
        dport: u16::from_be_bytes([p[n + 2], p[n + 3]]),
        protocol,
    })
}
pub(crate) fn rewrite(p: &[u8], t: Tuple) -> Option<Bytes> {
    let n = header(p)?;
    if p.len() < n + if t.protocol == Protocol::Tcp { 20 } else { 8 } {
        return None;
    }
    let mut out = p.to_vec();
    out[12..16].copy_from_slice(&t.src.octets());
    out[16..20].copy_from_slice(&t.dst.octets());
    out[n..n + 2].copy_from_slice(&t.sport.to_be_bytes());
    out[n + 2..n + 4].copy_from_slice(&t.dport.to_be_bytes());
    finish(&mut out, n, t.protocol);
    Some(Bytes::from(out))
}
fn finish(p: &mut [u8], n: usize, protocol: Protocol) {
    p[10..12].fill(0);
    let c = checksum(&p[..n]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    let offset = n + if protocol == Protocol::Tcp { 16 } else { 6 };
    p[offset..offset + 2].fill(0);
    let mut sum = 0u32;
    for pair in p[12..20].as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    sum += u32::from(p[9]) + (p.len() - n) as u32;
    let c = checksum_seed(&p[n..], sum);
    let c = if c == 0 && protocol == Protocol::Udp {
        0xffff
    } else {
        c
    };
    p[offset..offset + 2].copy_from_slice(&c.to_be_bytes());
}
pub(crate) fn checksum(p: &[u8]) -> u16 {
    checksum_seed(p, 0)
}
fn checksum_seed(p: &[u8], mut sum: u32) -> u16 {
    for pair in p.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
pub(crate) fn tcp_syn(p: &[u8]) -> bool {
    header(p).is_some_and(|n| p[9] == 6 && p.get(n + 13).is_some_and(|f| f & 0x12 == 2))
}
pub(crate) fn syn_sequence(p: &[u8]) -> Option<u32> {
    if !tcp_syn(p) {
        return None;
    }
    let n = header(p)?;
    let bytes = p.get(n + 4..n + 8)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}
pub(crate) fn empty_syn(p: &[u8]) -> bool {
    header(p).is_some_and(|n| {
        tcp_syn(p)
            && p.get(n + 12)
                .is_some_and(|h| n + usize::from(h >> 4) * 4 == p.len())
    })
}
pub(crate) fn syn_ack(p: &[u8]) -> bool {
    header(p).is_some_and(|n| p[9] == 6 && p.get(n + 13).is_some_and(|f| f & 0x12 == 0x12))
}
pub(crate) fn tcp_reset(p: &[u8]) -> bool {
    header(p).is_some_and(|n| p[9] == 6 && p.get(n + 13).is_some_and(|f| f & 4 != 0))
}
/// Rewrites an ICMP error and its quoted original header after NAT lookup.
pub(crate) fn icmp_quote(p: &[u8]) -> Option<Tuple> {
    let n = header(p)?;
    if p[9] != 1 || p.len() < n + 8 + 28 || ![3, 11, 12].contains(&p[n]) {
        return None;
    }
    let q = &p[n + 8..];
    let h = usize::from(q[0] & 15) * 4;
    if q[0] >> 4 != 4 || h < 20 || q.len() < h + 8 {
        return None;
    }
    let protocol = match q[9] {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };
    Some(Tuple {
        src: Ipv4Addr::new(q[12], q[13], q[14], q[15]),
        dst: Ipv4Addr::new(q[16], q[17], q[18], q[19]),
        sport: u16::from_be_bytes([q[h], q[h + 1]]),
        dport: u16::from_be_bytes([q[h + 2], q[h + 3]]),
        protocol,
    })
}
pub(crate) fn rewrite_icmp(p: &[u8], original: Tuple) -> Option<Bytes> {
    let n = header(p)?;
    icmp_quote(p)?;
    let mut out = p.to_vec();
    out[12..16].copy_from_slice(&original.dst.octets());
    out[16..20].copy_from_slice(&original.src.octets());
    let q = &mut out[n + 8..];
    let h = usize::from(q[0] & 15) * 4;
    // Incrementally update the quoted transport checksum when it is present.
    let off = h + if original.protocol == Protocol::Tcp {
        16
    } else {
        6
    };
    if q.len() >= off + 2 {
        let old = u16::from_be_bytes([q[off], q[off + 1]]);
        if old != 0 || original.protocol == Protocol::Tcp {
            let mut sum = u32::from(!old);
            let mut replacement = Vec::from(original.src.octets());
            replacement.extend(original.dst.octets());
            replacement.extend(original.sport.to_be_bytes());
            replacement.extend(original.dport.to_be_bytes());
            let previous = [&q[12..20], &q[h..h + 4]].concat();
            for (a, b) in previous
                .as_chunks::<2>()
                .0
                .iter()
                .zip(replacement.as_chunks::<2>().0)
            {
                sum += u32::from(!u16::from_be_bytes([a[0], a[1]]))
                    + u32::from(u16::from_be_bytes([b[0], b[1]]));
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let c = !(sum as u16);
            q[off..off + 2].copy_from_slice(
                &(if c == 0 && original.protocol == Protocol::Udp {
                    0xffff
                } else {
                    c
                })
                .to_be_bytes(),
            );
        }
    }
    q[12..16].copy_from_slice(&original.src.octets());
    q[16..20].copy_from_slice(&original.dst.octets());
    q[h..h + 2].copy_from_slice(&original.sport.to_be_bytes());
    q[h + 2..h + 4].copy_from_slice(&original.dport.to_be_bytes());
    q[10..12].fill(0);
    let c = checksum(&q[..h]);
    q[10..12].copy_from_slice(&c.to_be_bytes());
    out[n + 2..n + 4].fill(0);
    let c = checksum(&out[n..]);
    out[n + 2..n + 4].copy_from_slice(&c.to_be_bytes());
    out[10..12].fill(0);
    let c = checksum(&out[..n]);
    out[10..12].copy_from_slice(&c.to_be_bytes());
    Some(Bytes::from(out))
}
pub(crate) fn reject(p: &[u8]) -> Option<Bytes> {
    let t = tuple(p)?;
    let n = header(p)?;
    if t.protocol == Protocol::Tcp {
        if !tcp_syn(p) {
            return None;
        }
        let mut out = vec![0; 40];
        out[0] = 0x45;
        out[2..4].copy_from_slice(&40u16.to_be_bytes());
        out[8] = 64;
        out[9] = 6;
        out[12..16].copy_from_slice(&t.dst.octets());
        out[16..20].copy_from_slice(&t.src.octets());
        out[20..22].copy_from_slice(&t.dport.to_be_bytes());
        out[22..24].copy_from_slice(&t.sport.to_be_bytes());
        let seq = u32::from_be_bytes(p[n + 4..n + 8].try_into().ok()?);
        out[28..32].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
        out[32] = 0x50;
        out[33] = 0x14;
        finish(&mut out, 20, Protocol::Tcp);
        Some(Bytes::from(out))
    } else {
        let q = p.len().min(n + 8);
        let mut out = vec![0; 28 + q];
        out[0] = 0x45;
        let len = out.len() as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        out[8] = 64;
        out[9] = 1;
        out[12..16].copy_from_slice(&t.dst.octets());
        out[16..20].copy_from_slice(&t.src.octets());
        out[20] = 3;
        out[21] = 3;
        out[28..].copy_from_slice(&p[..q]);
        let c = checksum(&out[20..]);
        out[22..24].copy_from_slice(&c.to_be_bytes());
        let c = checksum(&out[..20]);
        out[10..12].copy_from_slice(&c.to_be_bytes());
        Some(Bytes::from(out))
    }
}
#[derive(Debug)]
struct Datagram {
    at: Instant,
    header: Option<Vec<u8>>,
    parts: std::collections::BTreeMap<usize, Vec<u8>>,
    end: Option<usize>,
    bytes: usize,
}
type FragmentKey = (Option<[u8; 32]>, Ipv4Addr, Ipv4Addr, u16, u8);
#[derive(Debug, Default)]
pub(crate) struct Reassembly {
    pending: HashMap<FragmentKey, Datagram>,
}
impl Reassembly {
    pub fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, d| now.duration_since(d.at) < Duration::from_secs(5));
    }
    pub fn accept(&mut self, p: Bytes, max: usize, scope: Option<[u8; 32]>) -> Option<Bytes> {
        let n = header(&p)?;
        let flags = u16::from_be_bytes([p[6], p[7]]);
        if flags & 0x3fff == 0 {
            return Some(p);
        }
        let now = Instant::now();
        self.pending
            .retain(|_, d| now.duration_since(d.at) < Duration::from_secs(5));
        let (src, dst) = addresses(&p)?;
        let key = (scope, src, dst, u16::from_be_bytes([p[4], p[5]]), p[9]);
        let start = usize::from(flags & 0x1fff) * 8;
        let payload = &p[n..];
        let end = start.checked_add(payload.len())?;
        if payload.is_empty()
            || end > 65515
            || flags & 0x2000 != 0 && !payload.len().is_multiple_of(8)
        {
            self.pending.remove(&key);
            return None;
        }
        if !self.pending.contains_key(&key) && self.pending.len() >= max {
            return None;
        }
        let d = self.pending.entry(key).or_insert_with(|| Datagram {
            at: now,
            header: None,
            parts: Default::default(),
            end: None,
            bytes: 0,
        });
        if d.parts
            .get(&start)
            .is_some_and(|bytes| bytes.as_slice() == payload)
        {
            return None;
        }
        if d.parts.iter().any(|(s, b)| *s < end && start < s + b.len()) {
            self.pending.remove(&key);
            return None;
        }
        if flags & 0x2000 == 0 {
            if d.end.is_some_and(|e| e != end) {
                self.pending.remove(&key);
                return None;
            }
            d.end = Some(end);
        }
        if d.end.is_some_and(|e| end > e) {
            self.pending.remove(&key);
            return None;
        }
        if start == 0 {
            d.header = Some(p[..n].to_vec());
        }
        d.bytes += payload.len();
        d.parts.insert(start, payload.to_vec());
        let complete = d.end.is_some_and(|e| e == d.bytes) && d.header.is_some();
        if !complete {
            return None;
        }
        let d = self.pending.remove(&key)?;
        let mut out = d.header?;
        for part in d.parts.values() {
            out.extend(part);
        }
        if out.len() > 65535 {
            return None;
        }
        let len = out.len() as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        out[6..8].fill(0);
        out[10..12].fill(0);
        let h = usize::from(out[0] & 15) * 4;
        let c = checksum(&out[..h]);
        out[10..12].copy_from_slice(&c.to_be_bytes());
        Some(Bytes::from(out))
    }
}

/// Re-fragments an assembled NAT datagram for the unchanged overlay MTU.
pub(crate) fn fragments(packet: Bytes, mtu: u32) -> Vec<Bytes> {
    if packet.len() <= mtu as usize {
        return vec![packet];
    }
    let Some(n) = header(&packet) else {
        return vec![];
    };
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x4000 != 0 {
        return vec![];
    }
    let size = (mtu as usize).saturating_sub(n) / 8 * 8;
    if size == 0 {
        return vec![];
    }
    let mut copied = Vec::new();
    let mut offset = 20;
    while offset < n {
        let kind = packet[offset];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            offset += 1;
            continue;
        }
        let Some(&len) = packet.get(offset + 1) else {
            return vec![];
        };
        let len = usize::from(len);
        if len < 2 || offset + len > n {
            return vec![];
        }
        if kind & 0x80 != 0 {
            copied.extend_from_slice(&packet[offset..offset + len]);
        }
        offset += len;
    }
    while !copied.len().is_multiple_of(4) {
        copied.push(0);
    }
    let mut result = Vec::new();
    let payload = &packet[n..];
    for (start, part) in payload.chunks(size).enumerate() {
        let offset = start * size;
        let mut out = if offset == 0 {
            packet[..n].to_vec()
        } else {
            let mut h = packet[..20].to_vec();
            h.extend_from_slice(&copied);
            h[0] = 0x40 | (h.len() / 4) as u8;
            h
        };
        let header_len = out.len();
        out.extend(part);
        let len = out.len() as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        let flags = (offset / 8) as u16
            | if offset + part.len() < payload.len() {
                0x2000
            } else {
                0
            };
        out[6..8].copy_from_slice(&flags.to_be_bytes());
        out[10..12].fill(0);
        let c = checksum(&out[..header_len]);
        out[10..12].copy_from_slice(&c.to_be_bytes());
        result.push(Bytes::from(out));
    }
    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    fn datagram() -> Bytes {
        let mut p = vec![0; 3028];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&3028u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&1000u16.to_be_bytes());
        p[22..24].copy_from_slice(&2000u16.to_be_bytes());
        p[24..26].copy_from_slice(&3008u16.to_be_bytes());
        finish(&mut p, 20, Protocol::Udp);
        Bytes::from(p)
    }
    #[test]
    fn fragmented_udp_reassembles_out_of_order_and_nat_checksums_are_valid() {
        let p = datagram();
        let parts = fragments(p.clone(), 1280);
        assert_eq!(parts.len(), 3);
        let mut reassembly = Reassembly::default();
        let mut result = None;
        for part in parts.into_iter().rev() {
            if let Some(p) = reassembly.accept(part, 8, None) {
                result = Some(p);
            }
        }
        assert_eq!(result, Some(p.clone()));
        let mut t = tuple(&p).unwrap();
        t.dst = Ipv4Addr::new(10, 0, 0, 240);
        t.dport = 53;
        let out = rewrite(&p, t).unwrap();
        assert_eq!(header(&out), Some(20));
        let mut sum = 0u32;
        for pair in out[12..20].as_chunks::<2>().0 {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        sum += 17 + (out.len() - 20) as u32;
        assert_eq!(checksum_seed(&out[20..], sum), 0);
    }
    #[test]
    fn overlaps_and_capacity_are_rejected_without_allocating_unbounded_state() {
        let parts = fragments(datagram(), 1280);
        let mut r = Reassembly::default();
        assert!(r.accept(parts[0].clone(), 0, None).is_none());
        assert!(r.pending.is_empty());
        assert!(r.accept(parts[0].clone(), 1, None).is_none());
        assert!(r.accept(parts[0].clone(), 1, None).is_none());
        assert_eq!(r.pending.len(), 1);
        let mut conflict = parts[0].to_vec();
        conflict[20] ^= 1;
        assert!(r.accept(Bytes::from(conflict), 1, None).is_none());
        assert!(r.pending.is_empty());
        for size in 0..80 {
            let p = vec![0xff; size];
            assert!(tuple(&p).is_none());
            assert!(icmp_quote(&p).is_none());
        }
    }
    #[test]
    fn fragment_assembly_is_scoped_to_authenticated_sender_and_expires_when_idle() {
        let packet = datagram();
        let parts = fragments(packet.clone(), 1280);
        let mut r = Reassembly::default();
        assert!(r.accept(parts[0].clone(), 8, Some([1; 32])).is_none());
        assert!(r.accept(parts[1].clone(), 8, Some([2; 32])).is_none());
        assert!(r.accept(parts[2].clone(), 8, Some([1; 32])).is_none());
        assert_eq!(r.accept(parts[1].clone(), 8, Some([1; 32])), Some(packet));
        assert_eq!(r.pending.len(), 1);
        r.expire(Instant::now() + Duration::from_secs(6));
        assert!(r.pending.is_empty());
    }
}

#[cfg(test)]
mod icmp_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn pmtu_errors_restore_quoted_addresses_ports_and_checksums() {
        let original = Tuple {
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(10, 0, 0, 240),
            sport: 40000,
            dport: 53,
            protocol: Protocol::Udp,
        };
        let mut p = vec![0; 36];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&36u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[24..26].copy_from_slice(&16u16.to_be_bytes());
        let c = checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        let p = rewrite(&p, original).unwrap();
        let wire = Tuple {
            dst: Ipv4Addr::new(10, 0, 0, 2),
            sport: 50000,
            dport: 5353,
            ..original
        };
        let translated = rewrite(&p, wire).unwrap();
        let mut error = vec![0; 56];
        error[0] = 0x45;
        error[2..4].copy_from_slice(&56u16.to_be_bytes());
        error[8] = 64;
        error[9] = 1;
        error[12..16].copy_from_slice(&wire.dst.octets());
        error[16..20].copy_from_slice(&wire.src.octets());
        error[20] = 3;
        error[21] = 4;
        error[26..28].copy_from_slice(&1200u16.to_be_bytes());
        error[28..].copy_from_slice(&translated[..28]);
        let c = checksum(&error[20..]);
        error[22..24].copy_from_slice(&c.to_be_bytes());
        let c = checksum(&error[..20]);
        error[10..12].copy_from_slice(&c.to_be_bytes());
        let restored = rewrite_icmp(&error, original).unwrap();
        assert_eq!(icmp_quote(&restored), Some(original));
        assert_eq!(checksum(&restored[20..]), 0);
        assert_eq!(checksum(&restored[28..48]), 0);
        assert_eq!(&restored[54..56], &p[26..28]);
        assert_eq!(&restored[26..28], &1200u16.to_be_bytes());
        assert_eq!(&restored[12..16], &original.dst.octets());
    }
}
