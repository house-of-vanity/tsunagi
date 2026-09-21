//! What a WireGuard peer tells the network about itself.
//!
//! This is the opaque payload the control plane carries in a
//! [`crate::dataplane::PluginCapability`]. The agent core never parses it —
//! only this module does, and only after bounding every field.
//!
//! An iroh address is an address for iroh. It is **not** reused here: the
//! plugin advertises its own reachability, gathered by itself, for its own
//! listening port.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::dataplane::PluginError;
use crate::identity::NetworkId;

use super::keys::WgPublicKey;
use super::overlay::overlay_address;

/// Version of the announcement format.
pub const ANNOUNCEMENT_VERSION: u16 = 1;

/// Largest number of advertised endpoints accepted from a peer.
pub const MAX_ENDPOINTS: usize = 8;

/// What one participant advertises for the WireGuard data plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgAnnouncement {
    /// Announcement format version.
    pub version: u16,
    /// The peer's WireGuard public key. Its overlay address is derived from it.
    pub public_key: [u8; 32],
    /// The UDP port the peer's WireGuard interface listens on.
    pub listen_port: u16,
    /// Reachability the plugin gathered for itself. Advisory, may be empty.
    pub endpoints: Vec<SocketAddr>,
    /// The overlay address the peer believes it has.
    ///
    /// Carried for diagnostics and cross-checking only. `AllowedIPs` are
    /// always derived locally, never taken from this field.
    pub overlay_address: Ipv6Addr,
}

/// A peer announcement that has been validated against a specific network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAnnouncement {
    /// The peer's WireGuard public key.
    pub public_key: WgPublicKey,
    /// The peer's listening port.
    pub listen_port: u16,
    /// Usable endpoints, filtered.
    pub endpoints: Vec<SocketAddr>,
    /// The overlay address derived locally for this key. Authoritative.
    pub overlay_address: Ipv6Addr,
}

impl ValidatedAnnouncement {
    /// The endpoint to configure for this peer, if any is usable.
    ///
    /// WireGuard takes a single endpoint. The first usable one wins, and
    /// WireGuard itself will re-learn the peer's real source address from the
    /// first authenticated packet it receives.
    pub fn preferred_endpoint(&self) -> Option<SocketAddr> {
        self.endpoints.first().copied()
    }
}

impl WgAnnouncement {
    /// Builds this agent's announcement.
    pub fn new(
        network: NetworkId,
        public_key: &WgPublicKey,
        listen_port: u16,
        endpoints: Vec<SocketAddr>,
    ) -> Self {
        let mut endpoints = endpoints;
        endpoints.truncate(MAX_ENDPOINTS);
        Self {
            version: ANNOUNCEMENT_VERSION,
            public_key: *public_key.as_bytes(),
            listen_port,
            endpoints,
            overlay_address: overlay_address(network, public_key),
        }
    }

    /// Encodes the announcement into the opaque capability payload.
    pub fn encode(&self) -> Result<Vec<u8>, PluginError> {
        postcard::to_stdvec(self)
            .map_err(|err| PluginError::Other(format!("cannot encode announcement: {err}")))
    }

    /// Decodes and validates a payload received from a peer.
    ///
    /// `network` and `local_key` scope the checks: an announcement is only
    /// meaningful inside one network, and a peer must not claim our own key.
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
                "unsupported WireGuard announcement version {} (this build speaks {ANNOUNCEMENT_VERSION})",
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
        if self.listen_port == 0 {
            return Err(PluginError::Rejected(
                "WireGuard listen port must not be zero".into(),
            ));
        }
        if self.endpoints.len() > MAX_ENDPOINTS {
            return Err(PluginError::Rejected(format!(
                "announcement carries {} endpoints, at most {MAX_ENDPOINTS} are accepted",
                self.endpoints.len()
            )));
        }

        // AllowedIPs are derived, never trusted. A mismatch means the peer is
        // confused or lying, and either way its own claim is discarded.
        let derived = overlay_address(network, &public_key);
        if self.overlay_address != derived {
            return Err(PluginError::Rejected(
                "announced overlay address does not match the one derived from the peer's key"
                    .into(),
            ));
        }

        let endpoints: Vec<SocketAddr> = self
            .endpoints
            .into_iter()
            .filter(is_usable_endpoint)
            .collect();

        Ok(ValidatedAnnouncement {
            public_key,
            listen_port: self.listen_port,
            endpoints,
            overlay_address: derived,
        })
    }
}

/// Whether an advertised endpoint is worth trying.
///
/// Nothing here is trusted; this only discards addresses that cannot be a
/// peer, so the plugin does not waste a WireGuard endpoint slot on them.
fn is_usable_endpoint(endpoint: &SocketAddr) -> bool {
    if endpoint.port() == 0 {
        return false;
    }
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
        }
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};

    use super::super::keys::WgSecretKey;

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![3u8; 32]).unwrap(),
        )
        .network_id()
    }

    fn endpoint(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_well_formed_announcement_round_trips() {
        let id = network("round-trip");
        let peer = WgSecretKey::generate().public();
        let local = WgSecretKey::generate().public();

        let announcement =
            WgAnnouncement::new(id, &peer, 51820, vec![endpoint("192.0.2.10:51820")]);
        let payload = announcement.encode().unwrap();
        let validated = WgAnnouncement::decode_and_validate(&payload, id, &local).unwrap();

        assert_eq!(validated.public_key, peer);
        assert_eq!(validated.listen_port, 51820);
        assert_eq!(validated.overlay_address, overlay_address(id, &peer));
        // 192.0.2.0/24 is documentation space and is filtered out.
        assert!(validated.endpoints.is_empty());
    }

    #[test]
    fn allowed_ips_are_derived_not_taken_from_the_peer() {
        let id = network("no-hijack");
        let victim = WgSecretKey::generate().public();
        let attacker = WgSecretKey::generate().public();
        let local = WgSecretKey::generate().public();

        // An attacker claims the victim's overlay address with its own key.
        let mut forged = WgAnnouncement::new(id, &attacker, 51820, Vec::new());
        forged.overlay_address = overlay_address(id, &victim);

        let result = WgAnnouncement::decode_and_validate(&forged.encode().unwrap(), id, &local);
        assert!(
            matches!(result, Err(PluginError::Rejected(ref reason)) if reason.contains("does not match")),
            "claiming another member's overlay address must be rejected: {result:?}"
        );
    }

    #[test]
    fn an_announcement_from_another_network_does_not_validate() {
        let here = network("here");
        let there = network("there");
        let peer = WgSecretKey::generate().public();
        let local = WgSecretKey::generate().public();

        let payload = WgAnnouncement::new(there, &peer, 51820, Vec::new())
            .encode()
            .unwrap();
        assert!(WgAnnouncement::decode_and_validate(&payload, here, &local).is_err());
    }

    #[test]
    fn hostile_payloads_are_rejected_without_panicking() {
        let id = network("hostile");
        let local = WgSecretKey::generate().public();
        let peer = WgSecretKey::generate().public();

        // Not postcard at all.
        assert!(WgAnnouncement::decode_and_validate(&[0xff; 64], id, &local).is_err());
        assert!(WgAnnouncement::decode_and_validate(&[], id, &local).is_err());

        let wrong_version = WgAnnouncement {
            version: ANNOUNCEMENT_VERSION + 1,
            ..WgAnnouncement::new(id, &peer, 51820, Vec::new())
        };
        assert!(
            WgAnnouncement::decode_and_validate(&wrong_version.encode().unwrap(), id, &local)
                .is_err()
        );

        let zero_key = WgAnnouncement {
            public_key: [0u8; 32],
            ..WgAnnouncement::new(id, &peer, 51820, Vec::new())
        };
        assert!(
            WgAnnouncement::decode_and_validate(&zero_key.encode().unwrap(), id, &local).is_err()
        );

        let zero_port = WgAnnouncement::new(id, &peer, 0, Vec::new());
        assert!(
            WgAnnouncement::decode_and_validate(&zero_port.encode().unwrap(), id, &local).is_err()
        );

        let too_many = WgAnnouncement {
            endpoints: (0..MAX_ENDPOINTS + 1)
                .map(|index| endpoint(&format!("10.0.0.1:{}", 1000 + index)))
                .collect(),
            ..WgAnnouncement::new(id, &peer, 51820, Vec::new())
        };
        assert!(
            WgAnnouncement::decode_and_validate(&too_many.encode().unwrap(), id, &local).is_err()
        );
    }

    #[test]
    fn a_peer_cannot_claim_our_own_key() {
        let id = network("self");
        let local = WgSecretKey::generate().public();
        let payload = WgAnnouncement::new(id, &local, 51820, Vec::new())
            .encode()
            .unwrap();
        assert!(WgAnnouncement::decode_and_validate(&payload, id, &local).is_err());
    }

    #[test]
    fn unusable_endpoints_are_filtered_and_the_rest_kept() {
        let id = network("filter");
        let peer = WgSecretKey::generate().public();
        let local = WgSecretKey::generate().public();

        let announcement = WgAnnouncement::new(
            id,
            &peer,
            51820,
            vec![
                endpoint("0.0.0.0:51820"),
                endpoint("224.0.0.1:51820"),
                endpoint("10.1.2.3:0"),
                endpoint("10.1.2.3:51820"),
                endpoint("[2001:db8::1]:51820"),
            ],
        );
        let validated =
            WgAnnouncement::decode_and_validate(&announcement.encode().unwrap(), id, &local)
                .unwrap();
        assert_eq!(
            validated.endpoints,
            vec![endpoint("10.1.2.3:51820"), endpoint("[2001:db8::1]:51820")]
        );
        assert_eq!(
            validated.preferred_endpoint(),
            Some(endpoint("10.1.2.3:51820"))
        );
    }

    #[test]
    fn announcements_stay_well_under_the_capability_payload_limit() {
        let id = network("size");
        let peer = WgSecretKey::generate().public();
        let endpoints = (0..MAX_ENDPOINTS)
            .map(|index| endpoint(&format!("[2001:db8::{index}]:51820")))
            .collect();
        let payload = WgAnnouncement::new(id, &peer, 51820, endpoints)
            .encode()
            .unwrap();
        assert!(
            payload.len() < crate::config::Limits::default().max_capability_data_len,
            "announcement is {} bytes",
            payload.len()
        );
    }
}
