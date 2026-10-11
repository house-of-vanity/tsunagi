// Adapted from RunaRoo/AmneziaWG-RS, commit 51579a7d6e8882d1d8d6d00822f09e18a9423b73.
// Apache-2.0; see LICENSE-AmneziaWG-RS and UPSTREAM.md.
#![allow(dead_code, missing_docs)]
// AmneziaWG configuration, header protection, and traffic shaping.

use bytes::{Bytes, BytesMut};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use rand::RngExt;

pub const HEADER_PROTECTION_NONCE_SIZE: usize = 12;
pub const DEFAULT_UDP_WINDOW: usize = 500;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Range {
    pub min: u32,
    pub max: u32,
}

impl Range {
    pub fn contains(&self, val: u32) -> bool {
        val >= self.min && val <= self.max
    }

    pub fn random(&self) -> u32 {
        if self.min >= self.max {
            self.min
        } else {
            rand::rng().random_range(self.min..=self.max)
        }
    }

    pub fn is_zero(&self) -> bool {
        self.min == 0 && self.max == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwgKind {
    Initiation,
    Response,
    Cookie,
    Transport,
}

impl AwgKind {
    pub fn fixed_size(self) -> usize {
        match self {
            Self::Initiation => 148,
            Self::Response => 92,
            Self::Cookie => 64,
            Self::Transport => 32,
        }
    }

    fn standard_type(self) -> u32 {
        match self {
            Self::Initiation => 1,
            Self::Response => 2,
            Self::Cookie => 3,
            Self::Transport => 4,
        }
    }
}

#[derive(Debug)]
pub struct DecodedPacket {
    pub kind: AwgKind,
    pub message: Bytes,
    pub wire_len: usize,
}

pub struct AmneziaConfig {
    pub jc: u32,
    pub jmin: usize,
    pub jmax: usize,
    pub s1: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub h1: Range,
    pub h2: Range,
    pub h3: Range,
    pub h4: Range,
    pub i1: String,
    pub i2: String,
    pub i3: String,
    pub i4: String,
    pub i5: String,
    pub header_protection_key: Option<[u8; 32]>,
    pub content_padding_addition: Range,
    pub random_trailers: bool,
    pub mtu: usize,
}

impl AmneziaConfig {
    pub fn random_header(&self, range: &Range) -> u32 {
        range.random()
    }

    pub fn random_padding(&self, len: usize) -> Vec<u8> {
        let mut padding = vec![0u8; len];
        if len > 0 {
            rand::fill(&mut padding);
        }
        padding
    }

    fn shape(&self, kind: AwgKind) -> (usize, Range) {
        match kind {
            AwgKind::Initiation => (self.s1, self.h1),
            AwgKind::Response => (self.s2, self.h2),
            AwgKind::Cookie => (self.s3, self.h3),
            AwgKind::Transport => (self.s4, self.h4),
        }
    }

    pub fn encode(&self, kind: AwgKind, payload: Bytes, udp_window: usize) -> Bytes {
        let (padding_len, _) = self.shape(kind);
        let trailer_len = if kind != AwgKind::Transport && self.random_trailers {
            let base = padding_len.saturating_add(payload.len());
            let room = udp_window.max(DEFAULT_UDP_WINDOW).saturating_sub(base);
            if room == 0 {
                0
            } else {
                rand::rng().random_range(0..room)
            }
        } else {
            0
        };

        let mut out = BytesMut::zeroed(padding_len + payload.len() + trailer_len);
        if padding_len > 0 {
            rand::fill(&mut out[..padding_len]);
        }
        out[padding_len..padding_len + payload.len()].copy_from_slice(&payload);
        if trailer_len > 0 {
            rand::fill(&mut out[padding_len + payload.len()..]);
        }

        if self.header_protection_key.is_some() {
            let protected_len = if kind == AwgKind::Transport {
                16
            } else {
                kind.fixed_size()
            };
            self.apply_header_cipher(&mut out, padding_len, protected_len);
        }

        out.freeze()
    }

    pub fn decode(&self, datagram: &Bytes) -> Option<DecodedPacket> {
        if datagram.len() < 4 {
            return None;
        }

        for kind in [
            AwgKind::Initiation,
            AwgKind::Response,
            AwgKind::Cookie,
            AwgKind::Transport,
        ] {
            let (padding_len, headers) = self.shape(kind);
            let minimum = padding_len + kind.fixed_size();
            let size_ok = match kind {
                AwgKind::Transport | AwgKind::Initiation => datagram.len() >= minimum,
                AwgKind::Response | AwgKind::Cookie if self.random_trailers => {
                    datagram.len() >= minimum
                }
                AwgKind::Response | AwgKind::Cookie => datagram.len() == minimum,
            };
            if !size_ok || datagram.len() < padding_len + 4 {
                continue;
            }

            let protected_header =
                u32::from_le_bytes(datagram[padding_len..padding_len + 4].try_into().ok()?);
            let candidate = if self.header_protection_key.is_some() {
                protected_header ^ self.header_type_hash(datagram)?
            } else {
                protected_header
            };
            if !headers.contains(candidate) {
                continue;
            }

            let message_len = match kind {
                AwgKind::Transport | AwgKind::Initiation => datagram.len() - padding_len,
                AwgKind::Response | AwgKind::Cookie => kind.fixed_size(),
            };
            let mut payload = BytesMut::from(&datagram[padding_len..padding_len + message_len]);
            if self.header_protection_key.is_some() {
                let protected_len = if kind == AwgKind::Transport {
                    16
                } else {
                    kind.fixed_size()
                };
                self.apply_header_cipher_with_nonce(
                    &mut payload,
                    0,
                    protected_len,
                    &datagram[..HEADER_PROTECTION_NONCE_SIZE],
                );
            }

            return Some(DecodedPacket {
                kind,
                message: payload.freeze(),
                wire_len: datagram.len(),
            });
        }

        None
    }

    pub fn prepare_transport_plaintext(&self, packet: Bytes, udp_window: usize) -> Bytes {
        if packet.is_empty() {
            return packet;
        }

        let requested = if !self.content_padding_addition.is_zero() {
            self.content_padding_addition.random() as usize
        } else if self.random_trailers {
            let wire_without_padding = self.s4 + AwgKind::Transport.fixed_size() + packet.len();
            let room = udp_window
                .max(DEFAULT_UDP_WINDOW)
                .saturating_sub(wire_without_padding);
            if room == 0 {
                0
            } else {
                rand::rng().random_range(0..room)
            }
        } else {
            let aligned = (packet.len() + 15) & !15;
            aligned.saturating_sub(packet.len())
        };

        let padding = self.clamp_padding_to_mtu(packet.len(), requested);
        if padding == 0 {
            return packet;
        }

        let mut out = BytesMut::with_capacity(packet.len() + padding);
        out.extend_from_slice(&packet);
        out.resize(packet.len() + padding, 0);
        out.freeze()
    }

    pub fn transport_content_length(&self, plaintext: &[u8]) -> Option<usize> {
        if plaintext.is_empty() || plaintext[0] == 0 {
            return Some(0);
        }
        match plaintext[0] >> 4 {
            4 if plaintext.len() >= 20 => {
                let total = u16::from_be_bytes([plaintext[2], plaintext[3]]) as usize;
                (total >= 20 && total <= plaintext.len()).then_some(total)
            }
            6 if plaintext.len() >= 40 => {
                let payload = u16::from_be_bytes([plaintext[4], plaintext[5]]) as usize;
                let total = 40 + payload;
                (total <= plaintext.len()).then_some(total)
            }
            _ => None,
        }
    }

    fn clamp_padding_to_mtu(&self, packet_len: usize, requested: usize) -> usize {
        if self.mtu == 0 {
            return requested;
        }
        let normalized = if packet_len > self.mtu {
            packet_len % self.mtu
        } else {
            packet_len
        };
        requested.min(self.mtu.saturating_sub(normalized))
    }

    fn header_type_hash(&self, datagram: &Bytes) -> Option<u32> {
        if datagram.len() < HEADER_PROTECTION_NONCE_SIZE {
            return None;
        }
        let mut hash = [0u8; 4];
        self.apply_keystream(&mut hash, &datagram[..HEADER_PROTECTION_NONCE_SIZE]);
        Some(u32::from_le_bytes(hash))
    }

    fn apply_header_cipher(&self, packet: &mut [u8], offset: usize, len: usize) {
        if packet.len() < HEADER_PROTECTION_NONCE_SIZE || packet.len() < offset + len {
            return;
        }
        let nonce: [u8; HEADER_PROTECTION_NONCE_SIZE] =
            match packet[..HEADER_PROTECTION_NONCE_SIZE].try_into() {
                Ok(nonce) => nonce,
                Err(_) => return,
            };
        self.apply_header_cipher_with_nonce(packet, offset, len, &nonce);
    }

    fn apply_header_cipher_with_nonce(
        &self,
        packet: &mut [u8],
        offset: usize,
        len: usize,
        nonce: &[u8],
    ) {
        if packet.len() < offset + len {
            return;
        }
        self.apply_keystream(&mut packet[offset..offset + len], nonce);
    }

    fn apply_keystream(&self, data: &mut [u8], nonce: &[u8]) {
        let Some(key) = self.header_protection_key.as_ref() else {
            return;
        };
        if nonce.len() != HEADER_PROTECTION_NONCE_SIZE {
            return;
        }
        let Ok(nonce) = <&[u8; HEADER_PROTECTION_NONCE_SIZE]>::try_from(nonce) else {
            return;
        };
        let mut cipher = ChaCha20::new(key.into(), nonce.into());
        cipher.apply_keystream(data);
    }
}

impl Drop for AmneziaConfig {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.header_protection_key.zeroize();
    }
}
