//! Device identity and network space identity.
//!
//! These are two independent things and must not be confused:
//!
//! * [`DeviceIdentity`] wraps the persistent iroh [`SecretKey`]. Its public key
//!   *is* the iroh [`EndpointId`]. It survives restarts and survives a change of
//!   the network secret.
//! * [`NetworkId`] identifies a network space and is derived purely from the
//!   network name and shared secret. It is unrelated to any device key.

mod network;

pub use network::{
    DiscoveryKey, IDENTITY_SCHEME, MAX_NETWORK_NAME_LEN, MAX_NETWORK_SECRET_LEN,
    MIN_NETWORK_SECRET_LEN, NetworkDescriptor, NetworkId, NetworkKeys, NetworkName, NetworkSecret,
    SECRET_TEXT_PREFIX,
};

use iroh::{EndpointId, SecretKey};

/// The persistent identity of this device.
///
/// Created once and stored in the mandatory state store. Restarting the agent
/// must not produce a new peer, so the stored secret key is always reused.
/// Corruption of the stored key is reported as an error and never silently
/// replaced by a fresh key.
#[derive(Clone)]
pub struct DeviceIdentity {
    secret: SecretKey,
}

impl DeviceIdentity {
    /// Generates a brand new device identity.
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(),
        }
    }

    /// Reconstructs a device identity from its stored 32 secret key bytes.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            secret: SecretKey::from_bytes(bytes),
        }
    }

    /// The iroh endpoint id, i.e. the public key of this device.
    pub fn endpoint_id(&self) -> EndpointId {
        self.secret.public()
    }

    /// The raw secret key bytes, for persistence only.
    pub(crate) fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// A clone of the iroh secret key, for endpoint construction only.
    pub(crate) fn secret_key(&self) -> SecretKey {
        self.secret.clone()
    }

    /// A clone of the key used to sign this device's own state records.
    ///
    /// The same persistent identity the control plane authenticates, so a
    /// record signed today is still attributable after any absence.
    pub(crate) fn signing_key(&self) -> SecretKey {
        self.secret.clone()
    }
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("endpoint_id", &self.endpoint_id().fmt_short().to_string())
            .field("secret", &"<redacted>")
            .finish()
    }
}
