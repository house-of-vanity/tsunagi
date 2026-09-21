//! Deterministic overlay addressing.
//!
//! A mesh with no coordinator cannot hand out addresses, so every participant
//! derives its own from values everybody already knows. The result is an IPv6
//! unique local address (RFC 4193):
//!
//! ```text
//! prefix (/64) = 0xfd || SHA-256( LP(domain) || LP("prefix") || LP(network_id) )[0..7]
//! iid    (64b) =         SHA-256( LP(domain) || LP("interface") || LP(network_id) || LP(wg_public_key) )[0..8]
//! address      = prefix || iid
//! ```
//!
//! Two properties matter:
//!
//! * Every member of a network derives the **same** `/64`, so the overlay is
//!   one subnet without anybody allocating it.
//! * A member's address is bound to its WireGuard public key, so a peer's
//!   `AllowedIPs` can be **derived locally and never taken from what the peer
//!   claims**. A participant can mint many keys and therefore many addresses,
//!   but it cannot choose to collide with an existing member's address without
//!   finding a hash preimage.

use std::net::Ipv6Addr;

use sha2::{Digest, Sha256};

use crate::identity::NetworkId;

use super::keys::WgPublicKey;

/// Frozen domain separator for overlay address derivation.
pub const OVERLAY_DOMAIN: &str = "tsunagi-wireguard-overlay-v1";

/// Prefix length of the overlay subnet.
pub const OVERLAY_PREFIX_LEN: u8 = 64;

/// Prefix length of one member's address inside the overlay.
pub const OVERLAY_HOST_PREFIX_LEN: u8 = 128;

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn digest(label: &str, network: NetworkId, key: Option<&WgPublicKey>) -> [u8; 32] {
    let mut input = Vec::with_capacity(128);
    push_lp(&mut input, OVERLAY_DOMAIN.as_bytes());
    push_lp(&mut input, label.as_bytes());
    push_lp(&mut input, network.as_bytes());
    if let Some(key) = key {
        push_lp(&mut input, key.as_bytes());
    }
    Sha256::digest(&input).into()
}

/// The `/64` every member of `network` shares.
///
/// Returned as the network address of the prefix, i.e. with a zero interface
/// identifier.
pub fn overlay_prefix(network: NetworkId) -> Ipv6Addr {
    let hash = digest("prefix", network, None);
    let mut octets = [0u8; 16];
    // fd00::/8 marks a locally assigned unique local address.
    octets[0] = 0xfd;
    // 40 bits of global id followed by a 16 bit subnet id fill the rest of /64.
    octets[1..8].copy_from_slice(&hash[0..7]);
    Ipv6Addr::from(octets)
}

/// The address a member with `key` has in `network`.
pub fn overlay_address(network: NetworkId, key: &WgPublicKey) -> Ipv6Addr {
    let prefix = overlay_prefix(network).octets();
    let hash = digest("interface", network, Some(key));

    let mut octets = [0u8; 16];
    octets[0..8].copy_from_slice(&prefix[0..8]);
    octets[8..16].copy_from_slice(&hash[0..8]);

    // The all-zero interface identifier is the subnet-router anycast address
    // and must not be handed to a host.
    if octets[8..16] == [0u8; 8] {
        octets[15] = 1;
    }
    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![7u8; 32]).unwrap(),
        )
        .network_id()
    }

    #[test]
    fn the_prefix_is_a_unique_local_address() {
        let prefix = overlay_prefix(network("home"));
        assert_eq!(prefix.octets()[0], 0xfd);
        assert!(prefix.is_unique_local());
        assert_eq!(&prefix.octets()[8..16], &[0u8; 8], "a /64 network address");
    }

    #[test]
    fn everyone_in_a_network_shares_one_prefix() {
        let id = network("shared");
        let a = overlay_address(id, &WgPublicKey::from_bytes([1u8; 32]));
        let b = overlay_address(id, &WgPublicKey::from_bytes([2u8; 32]));
        assert_eq!(a.octets()[0..8], b.octets()[0..8]);
        assert_ne!(a, b, "different keys get different addresses");
        assert_eq!(&overlay_prefix(id).octets()[0..8], &a.octets()[0..8]);
    }

    #[test]
    fn derivation_is_deterministic_and_network_scoped() {
        let key = WgPublicKey::from_bytes([9u8; 32]);
        let first = network("one");
        let second = network("two");
        assert_eq!(overlay_address(first, &key), overlay_address(first, &key));
        assert_ne!(
            overlay_address(first, &key),
            overlay_address(second, &key),
            "the same key in a different network gets a different address"
        );
        assert_ne!(overlay_prefix(first), overlay_prefix(second));
    }

    #[test]
    fn addresses_are_never_the_subnet_router_anycast_address() {
        let id = network("anycast");
        for byte in 0..64u8 {
            let address = overlay_address(id, &WgPublicKey::from_bytes([byte; 32]));
            assert_ne!(&address.octets()[8..16], &[0u8; 8]);
        }
    }
}
