//! WireGuard key material for pure WireGuard transport.
//!
//! Keys belong to this protocol plugin alone. They are not derived from
//! the iroh device key and not derived from the network secret, so compromising
//! or rotating one does not affect the others.
//!
//! Keys are X25519, encoded the way WireGuard encodes them: standard base64
//! with padding, 44 characters.

use boringtun::x25519;
use data_encoding::BASE64;
use zeroize::{Zeroize, Zeroizing};

use tsunagi::dataplane::PluginError;

/// Length of a raw WireGuard key in bytes.
pub const KEY_LEN: usize = 32;

/// Length of the base64 text form of a key.
pub const KEY_TEXT_LEN: usize = 44;

/// Applies the X25519 clamping WireGuard applies to private keys.
fn clamp(bytes: &mut [u8; KEY_LEN]) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
}

/// A WireGuard public key.
///
/// Public, safe to log, and the identity a peer is known by inside the overlay.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WgPublicKey([u8; KEY_LEN]);

impl WgPublicKey {
    /// Wraps raw key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The key in the form the WireGuard implementation expects.
    pub(crate) fn into_x25519(self) -> x25519::PublicKey {
        x25519::PublicKey::from(self.0)
    }

    /// Whether this is the all-zero key, which is never a valid peer.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; KEY_LEN]
    }

    /// The base64 form WireGuard uses.
    pub fn encode(&self) -> String {
        BASE64.encode(&self.0)
    }

    /// Parses the base64 form WireGuard uses.
    pub fn decode(text: &str) -> Result<Self, PluginError> {
        if text.len() != KEY_TEXT_LEN {
            return Err(PluginError::Rejected(format!(
                "a WireGuard key is {KEY_TEXT_LEN} base64 characters, got {}",
                text.len()
            )));
        }
        let raw = BASE64
            .decode(text.as_bytes())
            .map_err(|_| PluginError::Rejected("key is not valid base64".into()))?;
        let bytes = <[u8; KEY_LEN]>::try_from(raw.as_slice())
            .map_err(|_| PluginError::Rejected("key is not 32 bytes".into()))?;
        Ok(Self(bytes))
    }

    /// A short prefix for logs and diagnostics.
    pub fn fmt_short(&self) -> String {
        self.encode().chars().take(8).collect()
    }
}

impl std::fmt::Display for WgPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode())
    }
}

impl std::fmt::Debug for WgPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WgPublicKey({})", self.fmt_short())
    }
}

/// A WireGuard private key.
///
/// Clamped on creation so it matches what `wg genkey` produces. Zeroized on
/// drop, and prints as `[redacted]` in Debug so it cannot leak into logs.
#[derive(Clone)]
pub struct WgSecretKey {
    bytes: Zeroizing<[u8; KEY_LEN]>,
    public: WgPublicKey,
}

impl WgSecretKey {
    /// Generates a fresh clamped random private key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::fill(&mut bytes);
        clamp(&mut bytes);
        let secret = x25519::StaticSecret::from(bytes);
        let public = WgPublicKey(*x25519::PublicKey::from(&secret).as_bytes());
        Self {
            bytes: Zeroizing::new(bytes),
            public,
        }
    }

    /// Wraps existing key bytes, clamping them to a valid X25519 private key.
    pub fn from_bytes(raw: &[u8; KEY_LEN]) -> Self {
        let mut bytes = *raw;
        clamp(&mut bytes);
        let secret = x25519::StaticSecret::from(bytes);
        let public = WgPublicKey(*x25519::PublicKey::from(&secret).as_bytes());
        Self {
            bytes: Zeroizing::new(bytes),
            public,
        }
    }

    /// The matching public key.
    pub fn public(&self) -> WgPublicKey {
        self.public
    }

    /// The key in the form the WireGuard implementation expects.
    pub(crate) fn to_static_secret(&self) -> x25519::StaticSecret {
        x25519::StaticSecret::from(*self.bytes)
    }

    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl Drop for WgSecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for WgSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgSecretKey")
            .field("bytes", &"[redacted]")
            .field("public", &self.public)
            .finish()
    }
}
