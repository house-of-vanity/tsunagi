//! Which peer a packet is for, and whether a peer may have sent it.
//!
//! One agent has one interface, so a packet coming off it could belong to any
//! network the agent is in and to any protocol currently carrying traffic.
//! Deciding which is this table's job, and it is the reason the interface
//! belongs to the system level: the answer comes from signed state, which no
//! protocol owns.
//!
//! Two questions, and they are not the same one:
//!
//! * **Outbound**: this destination address — whose is it? A packet for
//!   nobody is dropped rather than broadcast.
//! * **Inbound**: this peer decrypted a packet with this source address —
//!   is that address actually its? A peer may not speak for anybody else,
//!   and the check consults the signed claim rather than anything the peer
//!   said.
//!
//! Nothing here is derived from a protocol's key. An address is allocated at
//! the system level and signed by the member that holds it, so every protocol
//! carries traffic for the same addresses and the table is the same whichever
//! one is in use.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

use iroh::EndpointId;

use crate::identity::NetworkId;
use crate::state::Ipv4Range;

/// Where an outbound packet is going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The network the destination belongs to.
    pub network: NetworkId,
    /// The member that holds the destination address.
    pub peer: EndpointId,
}

/// What one network contributes to the table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkRoutes {
    /// The range this network allocates from, once it has agreed one.
    pub range: Option<Ipv4Range>,
    /// This agent's own address in the network.
    pub local: Option<Ipv4Addr>,
    /// Every other member's address, as the signed state has it.
    pub peers: Vec<(Ipv4Addr, EndpointId)>,
}

/// Why a network cannot be added to the table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    /// Two networks would answer for the same addresses.
    #[error(
        "network {network} uses {range}, which overlaps {other_range} already in use by \
         {other}. One agent has one interface, so an address can belong to only one of \
         them: give one network a different range."
    )]
    Overlap {
        /// The network being added.
        network: NetworkId,
        /// The range it wants.
        range: Ipv4Range,
        /// The network already using an overlapping range.
        other: NetworkId,
        /// That network's range.
        other_range: Ipv4Range,
    },
}

/// Address ownership across every network this agent is in.
#[derive(Debug, Default)]
pub struct RoutingTable {
    networks: RwLock<HashMap<NetworkId, NetworkRoutes>>,
}

impl RoutingTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<NetworkId, NetworkRoutes>> {
        match self.networks.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<NetworkId, NetworkRoutes>> {
        match self.networks.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Replaces what one network contributes.
    ///
    /// Rejected when its range overlaps another network's. With one
    /// interface an address can belong to only one network, and guessing
    /// which would send somebody's traffic to a stranger.
    pub fn set_network(&self, network: NetworkId, routes: NetworkRoutes) -> Result<(), RouteError> {
        let mut networks = self.write();
        if let Some(range) = routes.range {
            for (other, existing) in networks.iter() {
                if *other == network {
                    continue;
                }
                let Some(other_range) = existing.range else {
                    continue;
                };
                if ranges_overlap(range, other_range) {
                    return Err(RouteError::Overlap {
                        network,
                        range,
                        other: *other,
                        other_range,
                    });
                }
            }
        }
        networks.insert(network, routes);
        Ok(())
    }

    /// Forgets a network.
    pub fn remove_network(&self, network: NetworkId) {
        self.write().remove(&network);
    }

    /// The peer that holds a destination address, if anybody does.
    ///
    /// This agent's own address returns `None`: a packet for ourselves does
    /// not go over a tunnel, and answering with a peer would send it to one.
    pub fn route(&self, destination: Ipv4Addr) -> Option<Route> {
        let networks = self.read();
        for (network, routes) in networks.iter() {
            if routes.local == Some(destination) {
                return None;
            }
            if let Some((_, peer)) = routes
                .peers
                .iter()
                .find(|(address, _)| *address == destination)
            {
                return Some(Route {
                    network: *network,
                    peer: *peer,
                });
            }
        }
        None
    }

    /// Whether a peer may send from a source address.
    pub fn may_send_from(&self, network: NetworkId, peer: EndpointId, source: Ipv4Addr) -> bool {
        self.read().get(&network).is_some_and(|routes| {
            routes
                .peers
                .iter()
                .any(|(address, holder)| *address == source && *holder == peer)
        })
    }

    /// Every address this agent should answer to, with its prefix length.
    pub fn local_addresses(&self) -> Vec<(Ipv4Addr, u8)> {
        let mut addresses: Vec<(Ipv4Addr, u8)> = self
            .read()
            .values()
            .filter_map(|routes| Some((routes.local?, routes.range?.prefix_len)))
            .collect();
        addresses.sort();
        addresses
    }

    /// Whether a range would collide with one another network already uses.
    ///
    /// Asked before proposing a range rather than after: with one interface
    /// an agent that claimed an address it could not route would also be
    /// telling everybody else to use that range, and "the range of the
    /// lowest author wins" would spread the collision instead of containing
    /// it.
    pub fn would_overlap(&self, network: NetworkId, range: Ipv4Range) -> Option<Ipv4Range> {
        self.read().iter().find_map(|(other, existing)| {
            if *other == network {
                return None;
            }
            let other_range = existing.range?;
            ranges_overlap(range, other_range).then_some(other_range)
        })
    }

    /// How many networks the table covers.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether it covers none.
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }
}

/// Whether two ranges share any address.
fn ranges_overlap(one: Ipv4Range, other: Ipv4Range) -> bool {
    // A range contains the other's base, or the other way round. With
    // prefix-aligned ranges that is the whole of it: two blocks either nest
    // or are disjoint.
    one.contains(other.base) || other.contains(one.base)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![4u8; 32]).unwrap(),
        )
        .network_id()
    }

    fn peer(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn addr(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 13, 37, last)
    }

    fn routes() -> NetworkRoutes {
        NetworkRoutes {
            range: Some("10.13.37.0/24".parse().unwrap()),
            local: Some(addr(1)),
            peers: vec![(addr(2), peer(2)), (addr(3), peer(3))],
        }
    }

    #[test]
    fn a_packet_goes_to_the_member_that_holds_its_destination() {
        let table = RoutingTable::new();
        let id = network("routing");
        table.set_network(id, routes()).unwrap();

        assert_eq!(
            table.route(addr(2)),
            Some(Route {
                network: id,
                peer: peer(2)
            })
        );
        assert_eq!(
            table.route(addr(3)),
            Some(Route {
                network: id,
                peer: peer(3)
            })
        );
    }

    #[test]
    fn a_packet_for_nobody_has_nowhere_to_go() {
        // Dropped rather than sent to everybody: a tunnel is not a broadcast
        // domain, and flooding would hand one member another's traffic.
        let table = RoutingTable::new();
        table.set_network(network("routing"), routes()).unwrap();
        assert_eq!(table.route(addr(200)), None);
        assert_eq!(table.route(Ipv4Addr::new(192, 0, 2, 1)), None);
    }

    #[test]
    fn a_packet_for_ourselves_is_not_sent_to_a_peer() {
        let table = RoutingTable::new();
        table.set_network(network("routing"), routes()).unwrap();
        assert_eq!(table.route(addr(1)), None, "that address is ours");
    }

    #[test]
    fn a_peer_may_only_send_from_the_address_it_holds() {
        let table = RoutingTable::new();
        let id = network("ownership");
        table.set_network(id, routes()).unwrap();

        assert!(table.may_send_from(id, peer(2), addr(2)));
        // Somebody else's address, and its own network's.
        assert!(!table.may_send_from(id, peer(2), addr(3)));
        assert!(!table.may_send_from(id, peer(2), addr(1)));
        assert!(!table.may_send_from(id, peer(2), addr(99)));
        // A peer that holds nothing here.
        assert!(!table.may_send_from(id, peer(9), addr(2)));
        // And the question is per network, not global.
        assert!(!table.may_send_from(network("elsewhere"), peer(2), addr(2)));
    }

    #[test]
    fn two_networks_with_overlapping_ranges_are_refused() {
        // One interface means an address belongs to one network. Accepting
        // both and guessing would send somebody's traffic to a stranger.
        let table = RoutingTable::new();
        let first = network("first");
        let second = network("second");
        table.set_network(first, routes()).unwrap();

        let err = table.set_network(second, routes()).unwrap_err();
        let RouteError::Overlap { other, .. } = err;
        assert_eq!(other, first);
        assert!(err.to_string().contains("different range"), "{err}");
        assert_eq!(table.len(), 1, "the overlapping network is not added");

        // A range of its own is fine.
        table
            .set_network(
                second,
                NetworkRoutes {
                    range: Some("10.99.0.0/16".parse().unwrap()),
                    local: Some(Ipv4Addr::new(10, 99, 0, 1)),
                    peers: vec![(Ipv4Addr::new(10, 99, 0, 2), peer(4))],
                },
            )
            .unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(
            table.route(Ipv4Addr::new(10, 99, 0, 2)),
            Some(Route {
                network: second,
                peer: peer(4)
            })
        );
        // And the first network still answers for its own.
        assert_eq!(table.route(addr(2)).map(|route| route.network), Some(first));
    }

    #[test]
    fn a_range_can_be_asked_about_before_it_is_proposed() {
        // The point of asking first: an agent that claims an address it
        // cannot route also tells everybody else to use that range.
        let table = RoutingTable::new();
        let first = network("first");
        let second = network("second");
        table.set_network(first, routes()).unwrap();

        let mine: Ipv4Range = "10.13.37.0/24".parse().unwrap();
        assert_eq!(table.would_overlap(second, mine), Some(mine));
        // Its own range is not a collision with itself.
        assert_eq!(table.would_overlap(first, mine), None);
        assert_eq!(
            table.would_overlap(second, "10.99.0.0/16".parse().unwrap()),
            None
        );
    }

    #[test]
    fn a_nested_range_counts_as_overlapping() {
        let table = RoutingTable::new();
        table
            .set_network(
                network("wide"),
                NetworkRoutes {
                    range: Some("10.0.0.0/8".parse().unwrap()),
                    ..Default::default()
                },
            )
            .unwrap();
        // Inside the /8, in either direction.
        assert!(
            table
                .set_network(
                    network("narrow"),
                    NetworkRoutes {
                        range: Some("10.13.37.0/24".parse().unwrap()),
                        ..Default::default()
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn replacing_a_network_does_not_count_as_overlapping_itself() {
        let table = RoutingTable::new();
        let id = network("refresh");
        table.set_network(id, routes()).unwrap();

        let mut updated = routes();
        updated.peers.push((addr(4), peer(4)));
        table.set_network(id, updated).unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.route(addr(4)).is_some());
    }

    #[test]
    fn forgetting_a_network_takes_its_addresses_with_it() {
        let table = RoutingTable::new();
        let id = network("leaving");
        table.set_network(id, routes()).unwrap();
        table.remove_network(id);

        assert!(table.is_empty());
        assert_eq!(table.route(addr(2)), None);
        assert!(!table.may_send_from(id, peer(2), addr(2)));
    }

    #[test]
    fn the_local_addresses_are_what_the_interface_should_carry() {
        let table = RoutingTable::new();
        table.set_network(network("one"), routes()).unwrap();
        table
            .set_network(
                network("two"),
                NetworkRoutes {
                    range: Some("10.99.0.0/16".parse().unwrap()),
                    local: Some(Ipv4Addr::new(10, 99, 0, 1)),
                    peers: Vec::new(),
                },
            )
            .unwrap();

        assert_eq!(
            table.local_addresses(),
            vec![(addr(1), 24), (Ipv4Addr::new(10, 99, 0, 1), 16)]
        );
    }

    #[test]
    fn a_network_with_no_address_yet_contributes_nothing() {
        let table = RoutingTable::new();
        let id = network("waiting");
        table.set_network(id, NetworkRoutes::default()).unwrap();

        assert!(table.local_addresses().is_empty());
        assert_eq!(table.route(addr(2)), None);
        assert_eq!(table.len(), 1, "the network is known, it just has nothing");
    }
}
