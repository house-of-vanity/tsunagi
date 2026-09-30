//! End-to-end packet encryption for `tcp-tls`.
//!
//! Uses X25519 Diffie-Hellman key exchange and ChaCha20-Poly1305 AEAD.
//! This ensures that even when traffic passes through intermediate relay nodes,
//! the intermediate nodes cannot inspect or tamper with the payload.

use std::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use iroh::EndpointId;
use sha2::Sha256;
use tsunagi::dataplane::PluginError;
use x25519_dalek::{PublicKey, StaticSecret};

/// Length of the X25519 public key.
pub const KEY_LEN: usize = 32;

/// Domain separator for session key derivation.
const HKDF_SALT: &[u8] = b"tsunagi/e2ee/noise/v1";

/// A session cipher for communicating with one peer.
pub struct PeerCipher {
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    tx_nonce: AtomicU64,
}

impl PeerCipher {
    /// Establishes a new cipher between `local_id` and `remote_id` given
    /// our local secret and their public key.
    pub fn new(
        local_id: EndpointId,
        remote_id: EndpointId,
        local_secret: &StaticSecret,
        remote_public: &PublicKey,
    ) -> Self {
        let shared = local_secret.diffie_hellman(remote_public);
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared.as_bytes());

        let mut key_a_to_b = [0u8; 32];
        let mut key_b_to_a = [0u8; 32];
        let _ = hk.expand(b"tsunagi-key-a-to-b", &mut key_a_to_b);
        let _ = hk.expand(b"tsunagi-key-b-to-a", &mut key_b_to_a);

        // Deterministic role: smaller EndpointId is party A.
        let is_party_a = local_id.as_bytes() < remote_id.as_bytes();
        let (tx_key, rx_key) = if is_party_a {
            (key_a_to_b, key_b_to_a)
        } else {
            (key_b_to_a, key_a_to_b)
        };

        let tx_cipher = ChaCha20Poly1305::new(&tx_key.into());
        let rx_cipher = ChaCha20Poly1305::new(&rx_key.into());

        Self {
            tx_cipher,
            rx_cipher,
            tx_nonce: AtomicU64::new(0),
        }
    }

    /// Encrypts an outbound packet. Prefixes the ciphertext with the 8-byte nonce.
    pub fn encrypt(&self, packet: &[u8]) -> Result<bytes::Bytes, PluginError> {
        let counter = self.tx_nonce.fetch_add(1, Ordering::Relaxed);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .tx_cipher
            .encrypt(nonce, packet)
            .map_err(|err| PluginError::Other(format!("encryption failed: {err}")))?;

        let mut out = Vec::with_capacity(8 + ciphertext.len());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(bytes::Bytes::from(out))
    }

    /// Decrypts an inbound packet prefixed with the 8-byte nonce.
    pub fn decrypt(&self, payload: &[u8]) -> Result<bytes::Bytes, PluginError> {
        if payload.len() < 8 + 16 {
            return Err(PluginError::Other("payload too short".into()));
        }

        let counter_bytes: [u8; 8] = match payload[..8].try_into() {
            Ok(b) => b,
            Err(_) => return Err(PluginError::Other("invalid nonce".into())),
        };
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = self
            .rx_cipher
            .decrypt(nonce, &payload[8..])
            .map_err(|err| PluginError::Other(format!("decryption failed: {err}")))?;

        Ok(bytes::Bytes::from(plaintext))
    }
}
