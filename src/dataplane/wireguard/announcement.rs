//! What a WireGuard peer tells the network about itself.
//!
//! This is the opaque payload the control plane carries in a
//! [`crate::dataplane::PluginCapability`]. The agent core never parses it —
//! only this module does, and only after bounding every field.
//!
//! The announcement is deliberately tiny: a participant says **who it is**,
//! not **where it is**. Reachability is the data plane transport's job, and
//! the transport already solves it — see
//! [`crate::dataplane::transport`]. A plugin that also tried to advertise
//! addresses would be reimplementing NAT traversal badly.

use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

use crate::dataplane::PluginError;
use crate::identity::NetworkId;

use super::keys::WgPublicKey;
use super::overlay::overlay_address;

/// Version of the announcement format.
///
/// Version 3 dropped the IPv4 range again: overlay addressing moved to the
/// signed records in [`crate::state`], which carry the range and survive a
/// participant being away. postcard is not self-describing, so an older peer
/// cannot read a newer announcement; the mismatch is reported, not misparsed.
pub const ANNOUNCEMENT_VERSION: u16 = 3;

/// What one participant advertises for the WireGuard data plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgAnnouncement {
    /// Announcement format version.
    pub version: u16,
    /// The peer's WireGuard public key. Its overlay address is derived from it.
    pub public_key: [u8; 32],
    /// The overlay address the peer believes it has.
    ///
    /// Carried for diagnostics and cross-checking only. Addresses are always
    /// derived locally, never taken from this field.
    pub overlay_address: Ipv6Addr,
}

/// A peer announcement that has been validated against a specific network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAnnouncement {
    /// The peer's WireGuard public key.
    pub public_key: WgPublicKey,
    /// The overlay address derived locally for this key. Authoritative.
    pub overlay_address: Ipv6Addr,
}

impl WgAnnouncement {
    /// Builds this agent's announcement.
    pub fn new(network: NetworkId, public_key: &WgPublicKey) -> Self {
        Self {
            version: ANNOUNCEMENT_VERSION,
            public_key: *public_key.as_bytes(),
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
        // AllowedIPs are derived, never trusted. A mismatch means the peer is
        // confused or lying, and either way its own claim is discarded.
        let derived = overlay_address(network, &public_key);
        if self.overlay_address != derived {
            return Err(PluginError::Rejected(
                "announced overlay address does not match the one derived from the peer's key"
                    .into(),
            ));
        }

        Ok(ValidatedAnnouncement {
            public_key,
            overlay_address: derived,
        })
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

    #[test]
    fn a_well_formed_announcement_round_trips() {
        let id = network("round-trip");
        let peer = WgSecretKey::generate().public();
        let local = WgSecretKey::generate().public();

        let payload = WgAnnouncement::new(id, &peer).encode().unwrap();
        let validated = WgAnnouncement::decode_and_validate(&payload, id, &local).unwrap();

        assert_eq!(validated.public_key, peer);
        assert_eq!(validated.overlay_address, overlay_address(id, &peer));
    }

    #[test]
    fn the_announcement_says_who_not_where() {
        // Reachability belongs to the transport. Nothing address-like is
        // carried here, so there is nothing for a peer to lie about.
        let id = network("identity-only");
        let peer = WgSecretKey::generate().public();
        let payload = WgAnnouncement::new(id, &peer).encode().unwrap();
        assert!(
            payload.len() < 80,
            "the announcement should stay tiny, got {} bytes",
            payload.len()
        );
    }

    #[test]
    fn allowed_ips_are_derived_not_taken_from_the_peer() {
        let id = network("no-hijack");
        let victim = WgSecretKey::generate().public();
        let attacker = WgSecretKey::generate().public();
        let local = WgSecretKey::generate().public();

        // An attacker claims the victim's overlay address with its own key.
        let mut forged = WgAnnouncement::new(id, &attacker);
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

        let payload = WgAnnouncement::new(there, &peer).encode().unwrap();
        assert!(WgAnnouncement::decode_and_validate(&payload, here, &local).is_err());
    }

    #[test]
    fn hostile_payloads_are_rejected_without_panicking() {
        let id = network("hostile");
        let local = WgSecretKey::generate().public();
        let peer = WgSecretKey::generate().public();

        assert!(WgAnnouncement::decode_and_validate(&[0xff; 64], id, &local).is_err());
        assert!(WgAnnouncement::decode_and_validate(&[], id, &local).is_err());

        let wrong_version = WgAnnouncement {
            version: ANNOUNCEMENT_VERSION + 1,
            ..WgAnnouncement::new(id, &peer)
        };
        assert!(
            WgAnnouncement::decode_and_validate(&wrong_version.encode().unwrap(), id, &local)
                .is_err()
        );

        let zero_key = WgAnnouncement {
            public_key: [0u8; 32],
            ..WgAnnouncement::new(id, &peer)
        };
        assert!(
            WgAnnouncement::decode_and_validate(&zero_key.encode().unwrap(), id, &local).is_err()
        );
    }

    #[test]
    fn a_peer_cannot_claim_our_own_key() {
        let id = network("self");
        let local = WgSecretKey::generate().public();
        let payload = WgAnnouncement::new(id, &local).encode().unwrap();
        assert!(WgAnnouncement::decode_and_validate(&payload, id, &local).is_err());
    }

    #[test]
    fn announcements_stay_well_under_the_capability_payload_limit() {
        let id = network("size");
        let peer = WgSecretKey::generate().public();
        let payload = WgAnnouncement::new(id, &peer).encode().unwrap();
        assert!(
            payload.len() < crate::config::Limits::default().max_capability_data_len,
            "announcement is {} bytes",
            payload.len()
        );
    }
}
