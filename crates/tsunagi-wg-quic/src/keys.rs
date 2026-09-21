//! WireGuard key material.
//!
//! These keys belong to the plugin and to nothing else. They are **not**
//! derived from the iroh device key and **not** derived from the network
//! secret, so compromising or rotating one does not affect the others.
//!
//! Keys are X25519, encoded the way WireGuard encodes them: standard base64
//! with padding, 44 characters.

use boringtun::x25519;
use data_encoding::BASE64;
use zeroize::{Zeroize, Zeroizing};

use tsunagi::dataplane::PluginError;

/// Length of a raw WireGuard key, in bytes.
pub const KEY_LEN: usize = 32;

/// Length of the base64 text form of a key.
pub const KEY_TEXT_LEN: usize = 44;

/// Applies the X25519 clamping WireGuard applies to private keys.
///
/// `wg genkey` clamps, so clamping here keeps the printed private key and the
/// derived public key byte-identical to what the WireGuard tools produce.
fn clamp(bytes: &mut [u8; KEY_LEN]) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
}

/// A WireGuard public key.
///
/// Public, safe to log, and the identity a peer is known by inside the
/// overlay.
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
/// Zeroized on drop and redacted from [`Debug`]. Its base64 form is only ever
/// produced for the configuration handed to the WireGuard backend, and that
/// value is itself zeroized.
#[derive(Clone)]
pub struct WgSecretKey(Zeroizing<[u8; KEY_LEN]>);

impl WgSecretKey {
    /// Generates a fresh clamped private key.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        rand::fill(bytes.as_mut());
        clamp(&mut bytes);
        Self(bytes)
    }

    /// Wraps stored key bytes, clamping them.
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        let mut owned = Zeroizing::new(*bytes);
        clamp(&mut owned);
        Self(owned)
    }

    /// The raw key bytes, for persistence only.
    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The matching public key.
    pub fn public(&self) -> WgPublicKey {
        WgPublicKey(x25519::PublicKey::from(&self.to_static_secret()).to_bytes())
    }

    /// The key in the form the WireGuard implementation expects.
    pub(crate) fn to_static_secret(&self) -> x25519::StaticSecret {
        x25519::StaticSecret::from(*self.0)
    }

    /// The base64 form, for the WireGuard configuration. Zeroized on drop.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut encoded = BASE64.encode(self.0.as_ref());
        let out = Zeroizing::new(encoded.clone());
        encoded.zeroize();
        out
    }
}

impl std::fmt::Debug for WgSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgSecretKey")
            .field("public", &self.public().fmt_short())
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn generated_keys_are_clamped_and_round_trip() {
        let secret = WgSecretKey::generate();
        let raw = *secret.expose();
        assert_eq!(raw[0] & 7, 0, "low three bits must be cleared");
        assert_eq!(raw[31] & 128, 0, "top bit must be cleared");
        assert_eq!(raw[31] & 64, 64, "second-highest bit must be set");

        let text = secret.encode();
        assert_eq!(text.len(), KEY_TEXT_LEN);

        let public = secret.public();
        let parsed = WgPublicKey::decode(&public.encode()).unwrap();
        assert_eq!(parsed, public);
    }

    #[test]
    fn reloading_a_stored_key_gives_the_same_public_key() {
        let secret = WgSecretKey::generate();
        let reloaded = WgSecretKey::from_bytes(secret.expose());
        assert_eq!(secret.public(), reloaded.public());
    }

    #[test]
    fn the_rfc_7748_test_vector_derives_the_expected_public_key() {
        // RFC 7748 section 6.1. WireGuard keys are plain X25519 keys, and
        // X25519 clamps internally, so storing the clamped form must not
        // change the derived public key.
        let private =
            hex_to_key("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let expected =
            hex_to_key("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

        let secret = WgSecretKey::from_bytes(&private);
        assert_eq!(secret.public(), WgPublicKey::from_bytes(expected));
        assert_eq!(
            secret.public().encode(),
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
        );
    }

    fn hex_to_key(text: &str) -> [u8; KEY_LEN] {
        let raw = hex::decode(text).unwrap();
        <[u8; KEY_LEN]>::try_from(raw.as_slice()).unwrap()
    }

    #[test]
    fn malformed_keys_are_rejected_without_panicking() {
        assert!(WgPublicKey::decode("").is_err());
        assert!(WgPublicKey::decode("not base64 at all!!!").is_err());
        assert!(WgPublicKey::decode(&"A".repeat(KEY_TEXT_LEN)).is_err());
        assert!(WgPublicKey::decode(&BASE64.encode(&[0u8; 16])).is_err());
        assert!(WgPublicKey::from_bytes([0u8; KEY_LEN]).is_zero());
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let secret = WgSecretKey::generate();
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(secret.encode().as_str()));
    }
}
