//! Choosing a free overlay address.
//!
//! Allocation, not derivation. Derivation needs no coordination but cannot
//! avoid collisions in a space as small as IPv4; allocation avoids them but
//! has to look at what everybody else already holds. The signed records in
//! [`super`] are what makes that possible without a coordinator.
//!
//! The rules:
//!
//! * an address a participant already holds is kept, because stability across
//!   an absence is the whole point;
//! * otherwise the search starts at a position derived from the participant's
//!   own identity, so two participants joining at once rarely start in the
//!   same place;
//! * the search then walks the range, so a free address is found whenever one
//!   exists.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use iroh::EndpointId;
use sha2::{Digest, Sha256};

use super::Ipv4Range;
use crate::identity::NetworkId;

/// Why no address could be allocated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AllocationError {
    /// Every address in the range is taken.
    #[error("the overlay range {range} is full: {holders} of {usable} addresses are taken")]
    RangeFull {
        /// The range that is full.
        range: Ipv4Range,
        /// How many are held.
        holders: usize,
        /// How many the range has.
        usable: u64,
    },
    /// The range has no usable host addresses.
    #[error("the overlay range {range} has no room for hosts")]
    NoRoom {
        /// The offending range.
        range: Ipv4Range,
    },
}

/// How many host addresses a range holds, excluding network and broadcast.
pub fn usable_addresses(range: Ipv4Range) -> u64 {
    let host_bits = 32u32.saturating_sub(u32::from(range.prefix_len));
    if host_bits < 2 {
        return 0;
    }
    (1u64 << host_bits) - 2
}

/// The nth host address of a range.
fn address_at(range: Ipv4Range, offset: u64) -> Ipv4Addr {
    let host_bits = 32u32.saturating_sub(u32::from(range.prefix_len));
    let mask = if host_bits >= 32 {
        0
    } else {
        u32::MAX << host_bits
    };
    let network_part = u32::from(range.base) & mask;
    // Offsets run 1..=usable, so the network address is never handed out.
    Ipv4Addr::from(network_part | ((offset % (1u64 << host_bits)) as u32))
}

/// Picks an address for `author`, keeping `current` if it is still usable.
///
/// `taken` is what every other participant is known to hold.
pub fn allocate(
    network: NetworkId,
    author: EndpointId,
    range: Ipv4Range,
    taken: &HashSet<Ipv4Addr>,
    current: Option<Ipv4Addr>,
) -> Result<Ipv4Addr, AllocationError> {
    let usable = usable_addresses(range);
    if usable == 0 {
        return Err(AllocationError::NoRoom { range });
    }

    // Keeping what we already hold is what lets a participant come back to
    // the same address after any length of absence.
    if let Some(current) = current
        && range.contains(current)
        && !taken.contains(&current)
    {
        return Ok(current);
    }

    // Start somewhere derived from who we are, so two newcomers do not both
    // begin at the first address and collide every time.
    let mut hash = Sha256::new();
    hash.update(b"tsunagi-ipv4-allocation-v1");
    hash.update(network.as_bytes());
    hash.update(author.as_bytes());
    let digest = hash.finalize();
    let seed = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);

    for step in 0..usable {
        let offset = ((seed.wrapping_add(step)) % usable) + 1;
        let candidate = address_at(range, offset);
        if !taken.contains(&candidate) {
            return Ok(candidate);
        }
    }

    Err(AllocationError::RangeFull {
        range,
        holders: taken.len(),
        usable,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};
    use iroh::SecretKey;

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![7u8; 32]).unwrap(),
        )
        .network_id()
    }

    fn slash24() -> Ipv4Range {
        "10.13.37.0/24".parse().unwrap()
    }

    #[test]
    fn a_range_reports_its_usable_size() {
        assert_eq!(usable_addresses(slash24()), 254);
        assert_eq!(usable_addresses("10.0.0.0/16".parse().unwrap()), 65534);
        assert_eq!(usable_addresses("10.0.0.0/30".parse().unwrap()), 2);
        // The type refuses a /31, but the function is defensive anyway.
        assert!("10.0.0.0/31".parse::<Ipv4Range>().is_err());
        assert_eq!(
            usable_addresses(Ipv4Range {
                base: "10.0.0.0".parse().unwrap(),
                prefix_len: 31
            }),
            0
        );
    }

    #[test]
    fn an_allocated_address_is_inside_the_range_and_not_its_edges() {
        let id = network("inside");
        let taken = HashSet::new();
        for _ in 0..64 {
            let author = SecretKey::generate().public();
            let address = allocate(id, author, slash24(), &taken, None).unwrap();
            assert!(slash24().contains(address));
            assert_ne!(address.octets()[3], 0, "never the network address");
            assert_ne!(address.octets()[3], 255, "never the broadcast address");
        }
    }

    #[test]
    fn an_address_already_held_is_kept() {
        let id = network("sticky");
        let author = SecretKey::generate().public();
        let mine: Ipv4Addr = "10.13.37.42".parse().unwrap();

        // This is what lets a participant return to the same address.
        let taken = HashSet::new();
        assert_eq!(
            allocate(id, author, slash24(), &taken, Some(mine)).unwrap(),
            mine
        );

        // Unless somebody else took it while we were away.
        let taken = HashSet::from([mine]);
        assert_ne!(
            allocate(id, author, slash24(), &taken, Some(mine)).unwrap(),
            mine
        );

        // Or unless the range changed under us.
        let elsewhere: Ipv4Range = "10.99.0.0/16".parse().unwrap();
        let moved = allocate(id, author, elsewhere, &HashSet::new(), Some(mine)).unwrap();
        assert!(elsewhere.contains(moved));
    }

    #[test]
    fn allocation_is_deterministic_and_spread_out() {
        let id = network("spread");
        // Fixed keys, not random ones. With 40 random authors in a /24 the
        // birthday problem alone makes a handful of collisions likely, so a
        // threshold on the count was a coin flip rather than a property.
        let authors: Vec<_> = (0..40u8)
            .map(|seed| SecretKey::from_bytes(&[seed; 32]).public())
            .collect();

        let first: Vec<_> = authors
            .iter()
            .map(|author| allocate(id, *author, slash24(), &HashSet::new(), None).unwrap())
            .collect();
        let again: Vec<_> = authors
            .iter()
            .map(|author| allocate(id, *author, slash24(), &HashSet::new(), None).unwrap())
            .collect();
        assert_eq!(first, again, "the same inputs give the same answer");

        // Starting points are spread, so concurrent newcomers rarely clash.
        let distinct: HashSet<_> = first.iter().collect();
        assert!(
            distinct.len() >= 35,
            "only {} distinct starting points out of 40",
            distinct.len()
        );
    }

    #[test]
    fn the_search_walks_past_everything_taken() {
        let id = network("crowded");
        let author = SecretKey::generate().public();

        // Everything taken except one address.
        let free: Ipv4Addr = "10.13.37.200".parse().unwrap();
        let taken: HashSet<Ipv4Addr> = (1..=254u8)
            .map(|host| Ipv4Addr::new(10, 13, 37, host))
            .filter(|addr| *addr != free)
            .collect();
        assert_eq!(allocate(id, author, slash24(), &taken, None).unwrap(), free);
    }

    #[test]
    fn a_full_range_is_an_error_rather_than_a_duplicate() {
        let id = network("full");
        let author = SecretKey::generate().public();
        let taken: HashSet<Ipv4Addr> = (1..=254u8)
            .map(|host| Ipv4Addr::new(10, 13, 37, host))
            .collect();

        assert!(matches!(
            allocate(id, author, slash24(), &taken, None),
            Err(AllocationError::RangeFull { .. })
        ));
        assert!(matches!(
            allocate(
                id,
                author,
                Ipv4Range {
                    base: "10.0.0.0".parse().unwrap(),
                    prefix_len: 31
                },
                &HashSet::new(),
                None
            ),
            Err(AllocationError::NoRoom { .. })
        ));
    }

    #[test]
    fn every_address_in_a_small_range_can_be_handed_out() {
        let id = network("exhaustive");
        let small: Ipv4Range = "10.13.37.0/29".parse().unwrap();
        let mut taken = HashSet::new();
        let mut handed = Vec::new();

        for _ in 0..usable_addresses(small) {
            let author = SecretKey::generate().public();
            let address = allocate(id, author, small, &taken, None).unwrap();
            assert!(taken.insert(address), "handed out {address} twice");
            handed.push(address);
        }
        assert_eq!(handed.len(), 6);
        // And then it is genuinely full.
        let author = SecretKey::generate().public();
        assert!(allocate(id, author, small, &taken, None).is_err());
    }
}
