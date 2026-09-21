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

use serde::{Deserialize, Serialize};

use crate::dataplane::PluginError;
use crate::identity::NetworkId;

use super::keys::WgPublicKey;

/// Version of the announcement format.
///
/// Version 3 dropped the IPv4 range again: overlay addressing moved to the
/// signed records in [`crate::state`], which carry the range and survive a
/// participant being away. postcard is not self-describing, so an older peer
/// cannot read a newer announcement; the mismatch is reported, not misparsed.
pub const ANNOUNCEMENT_VERSION: u16 = 4;

/// What one participant advertises for the WireGuard data plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgAnnouncement {
    /// Announcement format version.
    pub version: u16,
    /// The peer's WireGuard public key.
    ///
    /// The whole announcement, now that addresses belong to the system
    /// level: this says *who* is at the other end of a tunnel, and nothing
    /// about where.
    pub public_key: [u8; 32],
    /// The network this key is for.
    ///
    /// Strictly redundant — a capability arrives on a session that already
    /// proved membership of one network — and kept anyway, because the
    /// binding used to be a side effect of checking a derived address and
    /// losing it silently when that check went would be the wrong way to
    /// lose it.
    pub network: [u8; 32],
}

/// A peer announcement that has been validated against a specific network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAnnouncement {
    /// The peer's WireGuard public key.
    pub public_key: WgPublicKey,
}

impl WgAnnouncement {
    /// Builds this agent's announcement.
    pub fn new(network: NetworkId, public_key: &WgPublicKey) -> Self {
        Self {
            version: ANNOUNCEMENT_VERSION,
            public_key: *public_key.as_bytes(),
            network: *network.as_bytes(),
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
        if self.network != *network.as_bytes() {
            return Err(PluginError::Rejected(
                "announcement is for a different network".into(),
            ));
        }

        Ok(ValidatedAnnouncement { public_key })
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
    fn there_is_nothing_address_like_to_forge() {
        // Addresses belong to the system level, are allocated there and are
        // signed by the member that holds one. A protocol announcement
        // carries no address at all, so this is not a thing a peer can lie
        // about here — and a peer sending traffic from an address it does
        // not hold is rejected by the agreed address, not by anything it
        // said in this message.
        let id = network("no-hijack");
        let peer = WgSecretKey::generate().public();
        let local = WgSecretKey::generate().public();

        let announcement = WgAnnouncement::new(id, &peer);
        let validated =
            WgAnnouncement::decode_and_validate(&announcement.encode().unwrap(), id, &local)
                .unwrap();
        assert_eq!(validated.public_key, peer);

        // The validated form has one field, and it is an identity.
        assert_eq!(
            std::mem::size_of_val(&validated),
            std::mem::size_of::<WgPublicKey>()
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
