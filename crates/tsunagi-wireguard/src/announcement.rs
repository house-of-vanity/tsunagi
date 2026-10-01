//! What a pure WireGuard peer tells the network about itself.
//!
//! Exchanged via [`tsunagi::dataplane::PluginCapability`]. The announcement
//! carries the WireGuard public key, the listening UDP port, and candidate IP addresses
//! for direct UDP packet transport.

use serde::{Deserialize, Serialize};

use tsunagi::dataplane::PluginError;
use tsunagi::identity::NetworkId;

use crate::keys::WgPublicKey;

/// The wire protocol identifier for pure WireGuard.
pub const WG_PROTOCOL: &str = "wg";

/// Wire version of the `wg` announcement format.
pub const ANNOUNCEMENT_VERSION: u16 = 1;

/// Wire version peers compare during capability exchange.
///
/// This is the same as [`ANNOUNCEMENT_VERSION`]; keeping a separate name
/// makes the intent explicit in the CLI protocol registry.
pub const WG_WIRE_VERSION: u16 = ANNOUNCEMENT_VERSION;

/// Maximum number of IP candidates allowed in an announcement.
pub const MAX_CANDIDATE_ADDRS: usize = 32;

/// What one participant advertises for the pure WireGuard UDP data plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgAnnouncement {
    /// Announcement format version.
    pub version: u16,
    /// The peer's WireGuard public key.
    pub public_key: [u8; 32],
    /// The network this key is for.
    pub network: [u8; 32],
    /// The UDP port the peer is listening on for WireGuard packets.
    pub port: u16,
    /// Candidate IP addresses where this peer can be reached on `port`.
    #[serde(default)]
    pub addrs: Vec<std::net::IpAddr>,
}

/// A peer announcement that has been validated against a specific network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAnnouncement {
    /// The peer's WireGuard public key.
    pub public_key: WgPublicKey,
    /// The UDP port the peer listens on.
    pub port: u16,
    /// Validated candidate IP addresses.
    pub addrs: Vec<std::net::IpAddr>,
}

impl WgAnnouncement {
    /// Builds this agent's announcement.
    pub fn new(
        network: NetworkId,
        public_key: &WgPublicKey,
        port: u16,
        addrs: Vec<std::net::IpAddr>,
    ) -> Self {
        Self {
            version: ANNOUNCEMENT_VERSION,
            public_key: *public_key.as_bytes(),
            network: *network.as_bytes(),
            port,
            addrs,
        }
    }

    /// Encodes the announcement into the opaque capability payload.
    pub fn encode(&self) -> Result<Vec<u8>, PluginError> {
        postcard::to_allocvec(self)
            .map_err(|err| PluginError::Other(format!("cannot encode announcement: {err}")))
    }

    /// Decodes and validates a payload received from a peer.
    pub fn decode_and_validate(
        payload: &[u8],
        network: NetworkId,
        local_key: &WgPublicKey,
    ) -> Result<ValidatedAnnouncement, PluginError> {
        let announcement: Self = postcard::from_bytes(payload)
            .map_err(|_| PluginError::Rejected("malformed WireGuard announcement".into()))?;
        announcement.validate(network, local_key)
    }

    fn validate(
        self,
        network: NetworkId,
        local_key: &WgPublicKey,
    ) -> Result<ValidatedAnnouncement, PluginError> {
        if self.version != ANNOUNCEMENT_VERSION {
            return Err(PluginError::Rejected(format!(
                "peer speaks WireGuard announcement version {} but this build speaks \
                 {ANNOUNCEMENT_VERSION}; one of the two needs updating",
                self.version
            )));
        }

        let public_key = WgPublicKey::from_bytes(self.public_key);
        if public_key.is_zero() {
            return Err(PluginError::Rejected(
                "WireGuard public key is all zeroes".into(),
            ));
        }
        if &public_key == local_key {
            return Err(PluginError::Rejected(
                "peer announced this agent's own WireGuard key".into(),
            ));
        }
        if self.network != *network.as_bytes() {
            return Err(PluginError::Rejected(
                "announcement is for a different network".into(),
            ));
        }
        if self.port == 0 {
            return Err(PluginError::Rejected("WireGuard port cannot be 0".into()));
        }
        if self.addrs.len() > MAX_CANDIDATE_ADDRS {
            return Err(PluginError::Rejected(format!(
                "too many candidate addresses: {} > {MAX_CANDIDATE_ADDRS}",
                self.addrs.len()
            )));
        }

        let mut valid_addrs = Vec::new();
        for addr in self.addrs {
            if !addr.is_unspecified() && !valid_addrs.contains(&addr) {
                valid_addrs.push(addr);
            }
        }

        Ok(ValidatedAnnouncement {
            public_key,
            port: self.port,
            addrs: valid_addrs,
        })
    }
}
