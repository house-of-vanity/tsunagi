//! Bounded profiles, regenerated for every pair connection attempt.
use crate::masking::{AmneziaConfig, AwgKind, Range};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// An ephemeral masking profile. Secret fields are redacted and erased on drop.
#[derive(Clone, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
pub struct PairProfile {
    id: [u8; 16],
    prefix: u16,
    headers: [[u32; 2]; 4],
    header_key: [u8; 32],
    pub(crate) psk: [u8; 32],
    junk_count: u8,
    junk_min: u16,
    junk_max: u16,
    padding: u16,
    signature: u8,
}
impl std::fmt::Debug for PairProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairProfile([REDACTED])")
    }
}
impl PairProfile {
    /// Generates a new safe profile; no deterministic seed or durable state.
    pub fn generate() -> Self {
        let headers = std::array::from_fn(|i| {
            let base = (i as u32) * 0x4000_0000 + rand::random_range(1024..0x3fff_0000);
            [base, base + rand::random_range(64..1024)]
        });
        Self {
            id: rand::random(),
            prefix: rand::random_range(12..49),
            headers,
            header_key: rand::random(),
            psk: rand::random(),
            junk_count: rand::random_range(4..9),
            junk_min: rand::random_range(24..65),
            junk_max: rand::random_range(80..161),
            padding: rand::random_range(16..65),
            signature: rand::random_range(0..2),
        }
    }
    /// Public attempt identifier, useful for distinguishing retries without revealing secrets.
    pub fn id(&self) -> [u8; 16] {
        self.id
    }
    /// Header key, for packet engines and protocol tests; never log this value.
    pub fn header_key(&self) -> &[u8; 32] {
        &self.header_key
    }
    /// Rejects invalid remote profiles before allocating packets or entering the codec.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(12..=48).contains(&self.prefix)
            || !(4..=8).contains(&self.junk_count)
            || self.junk_min < 24
            || self.junk_min > self.junk_max
            || self.junk_max > 160
            || self.padding > 64
            || self.signature > 1
            || self.header_key == [0; 32]
            || self.psk == [0; 32]
        {
            return Err("invalid AWG profile bounds");
        }
        for (i, [lo, hi]) in self.headers.iter().copied().enumerate() {
            if lo < 5 || lo > hi || hi - lo > 1024 {
                return Err("invalid AWG header range");
            }
            for [other_lo, other_hi] in &self.headers[..i] {
                if lo <= *other_hi && *other_lo <= hi {
                    return Err("overlapping AWG header ranges");
                }
            }
        }
        Ok(())
    }
    fn config(&self) -> AmneziaConfig {
        let range = |i: usize| Range {
            min: self.headers[i][0],
            max: self.headers[i][1],
        };
        AmneziaConfig {
            jc: self.junk_count.into(),
            jmin: self.junk_min.into(),
            jmax: self.junk_max.into(),
            s1: self.prefix.into(),
            s2: self.prefix.into(),
            s3: self.prefix.into(),
            s4: self.prefix.into(),
            h1: range(0),
            h2: range(1),
            h3: range(2),
            h4: range(3),
            i1: String::new(),
            i2: String::new(),
            i3: String::new(),
            i4: String::new(),
            i5: String::new(),
            header_protection_key: Some(self.header_key),
            content_padding_addition: Range {
                min: 0,
                max: self.padding.into(),
            },
            random_trailers: true,
            mtu: 1050,
        }
    }
    /// Masks one standard WireGuard message; invalid types and oversized packets are refused.
    pub fn encode(&self, raw: &[u8]) -> Option<Bytes> {
        let kind = match raw.get(..4)? {
            [1, 0, 0, 0] => AwgKind::Initiation,
            [2, 0, 0, 0] => AwgKind::Response,
            [3, 0, 0, 0] => AwgKind::Cookie,
            [4, 0, 0, 0] => AwgKind::Transport,
            _ => return None,
        };
        if raw.len() < kind.fixed_size() || raw.len() > 1050 {
            return None;
        }
        let config = self.config();
        let range = match kind {
            AwgKind::Initiation => config.h1,
            AwgKind::Response => config.h2,
            AwgKind::Cookie => config.h3,
            AwgKind::Transport => config.h4,
        };
        let mut payload = raw.to_vec();
        payload[..4].copy_from_slice(&range.random().to_le_bytes());
        Some(config.encode(kind, Bytes::from(payload), 1200))
    }
    /// Unmasks a packet and restores standard headers before WireGuard validation.
    pub fn decode(&self, wire: &[u8]) -> Option<Vec<u8>> {
        if wire.len() > 1200 {
            return None;
        }
        let decoded = self.config().decode(&Bytes::copy_from_slice(wire))?;
        let (kind, len) = match decoded.kind {
            AwgKind::Initiation => (1, 148),
            AwgKind::Response => (2, 92),
            AwgKind::Cookie => (3, 64),
            AwgKind::Transport => (4, decoded.message.len()),
        };
        let mut message = decoded.message.get(..len)?.to_vec();
        message[..4].copy_from_slice(&(kind as u32).to_le_bytes());
        Some(message)
    }
    pub(crate) fn pad(&self, packet: Bytes) -> Bytes {
        self.config().prepare_transport_plaintext(packet, 1200)
    }
    /// Generates structured signature packets with fresh fields, never static captures.
    /// These target the other Tsunagi peer, not DNS or SIP services.
    pub fn signature_packets(&self) -> Vec<Vec<u8>> {
        if self.signature == 0 {
            // A complete DNS query. Counts, label lengths and qtype remain valid.
            let label = format!("n{:016x}", rand::random::<u64>());
            let mut packet = Vec::from(rand::random::<u16>().to_be_bytes());
            packet.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
            packet.extend_from_slice(b"\x07example\x03net\0\0");
            packet.push(if rand::random() { 1 } else { 28 });
            packet.extend_from_slice(&[0, 1]);
            vec![packet]
        } else {
            let id = rand::random::<u64>();
            vec![format!("OPTIONS sip:n{id:x}@example.net SIP/2.0\r\nVia: SIP/2.0/UDP example.net;branch=z9hG4bK{id:x}\r\nMax-Forwards: 70\r\nFrom: <sip:a@example.net>;tag={id:x}\r\nTo: <sip:n{id:x}@example.net>\r\nCall-ID: {id:x}@example.net\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n").into_bytes()]
        }
    }
    pub(crate) fn junk_packets(&self) -> Vec<Vec<u8>> {
        (0..self.junk_count)
            .map(|_| {
                let mut packet = vec![0; rand::random_range(self.junk_min..=self.junk_max).into()];
                rand::fill(&mut packet[..]);
                packet
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn unsafe_peer_profiles_are_rejected_before_the_codec() {
        let valid = PairProfile::generate();
        let mut bad = valid.clone();
        bad.prefix = 11;
        assert!(bad.validate().is_err());
        let mut bad = valid.clone();
        bad.headers[1] = bad.headers[0];
        assert!(bad.validate().is_err());
        let mut bad = valid.clone();
        bad.junk_max = u16::MAX;
        assert!(bad.validate().is_err());
        let mut bad = valid.clone();
        bad.padding = u16::MAX;
        assert!(bad.validate().is_err());
        let mut bad = valid.clone();
        bad.psk = [0; 32];
        assert!(bad.validate().is_err());
        let mut bad = valid.clone();
        bad.signature = 2;
        assert!(bad.validate().is_err());
    }
    #[test]
    fn signature_templates_have_consistent_framing_and_fresh_fields() {
        let mut profile = PairProfile::generate();
        profile.signature = 0;
        let dns = profile.signature_packets().remove(0);
        assert_eq!(&dns[2..12], &[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut at = 12;
        while dns[at] != 0 {
            at += 1 + usize::from(dns[at]);
        }
        assert_eq!(at + 5, dns.len());
        assert_eq!(&dns[dns.len() - 2..], &[0, 1]);
        profile.signature = 1;
        let sip = profile.signature_packets().remove(0);
        assert!(sip.starts_with(b"OPTIONS sip:"));
        assert!(sip.ends_with(b"Content-Length: 0\r\n\r\n"));
        assert_ne!(sip, profile.signature_packets().remove(0));
    }
}
