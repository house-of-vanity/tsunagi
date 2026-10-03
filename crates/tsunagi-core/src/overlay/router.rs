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

use super::broadcast::{BroadcastPolicy, BroadcastTable};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

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

/// A network's exit-node settings, as far as packets are concerned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExitPolicy {
    /// This agent offers itself as an exit node here: packets from members
    /// for addresses outside every overlay range are handed to the host.
    pub offer: bool,
    /// The member all other traffic is sent to, if this device uses one.
    pub via: Option<EndpointId>,
}

/// What one network contributes to the table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkRoutes {
    /// Exit-node settings of this network.
    pub exit: ExitPolicy,
    /// Local broadcast policy and authenticated willing recipients.
    pub broadcast: BroadcastPolicy,
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
    broadcast: ArcSwap<BroadcastTable>,
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
        self.broadcast
            .store(Arc::new(BroadcastTable::build(&networks)));
        Ok(())
    }

    /// Forgets a network.
    pub fn remove_network(&self, network: NetworkId) {
        let mut networks = self.write();
        networks.remove(&network);
        self.broadcast
            .store(Arc::new(BroadcastTable::build(&networks)));
    }

    /// Replaces only a network's broadcast participation, without changing addresses.
    pub fn set_broadcast(&self, network: NetworkId, policy: BroadcastPolicy) {
        let mut networks = self.write();
        if let Some(routes) = networks.get_mut(&network) {
            if routes.broadcast == policy {
                return;
            }
            routes.broadcast = policy;
            self.broadcast
                .store(Arc::new(BroadcastTable::build(&networks)));
        }
    }

    /// Replaces only a network's exit-node settings, without changing addresses.
    ///
    /// A network that has no entry yet (its range is not agreed) takes them
    /// from [`NetworkRoutes::exit`] when it is added.
    pub fn set_exit(&self, network: NetworkId, policy: ExitPolicy) {
        if let Some(routes) = self.write().get_mut(&network) {
            routes.exit = policy;
        }
    }

    /// Recognizes limited and configured subnet broadcasts before unicast lookup.
    pub fn is_broadcast(&self, destination: Ipv4Addr) -> bool {
        self.broadcast.load().is_destination(destination)
    }

    /// A precomputed domain-scoped recipient list; no per-packet graph search.
    pub fn broadcast_recipients(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> Option<Arc<[Route]>> {
        self.broadcast.load().outgoing(source, destination)
    }

    /// Local admission after the plugin authenticated and decrypted the sender.
    pub fn accepts_broadcast(
        &self,
        network: NetworkId,
        peer: EndpointId,
        destination: Ipv4Addr,
    ) -> bool {
        self.broadcast.load().accepts(network, peer, destination)
    }

    /// The peer that holds a destination address, if anybody does.
    ///
    /// This agent's own address returns `None`: a packet for ourselves does
    /// not go over a tunnel, and answering with a peer would send it to one.
    ///
    /// An address nobody holds, outside every overlay range and an ordinary
    /// unicast destination, goes to this device's exit node when it has one:
    /// that is what sending *all* traffic through a member means.
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
        // Inside an overlay range, an unowned address is nobody's, not the
        // internet's.
        if !is_internet_destination(destination) || in_any_range(&networks, destination) {
            return None;
        }
        exit_via(&networks).map(|(network, peer)| Route { network, peer })
    }

    /// Whether a peer may send from a source address.
    ///
    /// A peer speaks only for the address the network agreed it holds. The
    /// one exception is this device's exit node: what comes back from the
    /// internet carries the internet's addresses, so from *that* peer any
    /// source outside the overlay ranges is accepted.
    pub fn may_send_from(&self, network: NetworkId, peer: EndpointId, source: Ipv4Addr) -> bool {
        let networks = self.read();
        let Some(routes) = networks.get(&network) else {
            return false;
        };
        if routes
            .peers
            .iter()
            .any(|(address, holder)| *address == source && *holder == peer)
        {
            return true;
        }
        routes.exit.via == Some(peer)
            && is_internet_destination(source)
            && !in_any_range(&networks, source)
    }

    /// Whether this agent, as an exit node of `network`, takes a member's
    /// packet for `destination` to the host.
    ///
    /// Only an ordinary unicast address outside every overlay range, so a
    /// packet for another member, for this agent or for the local network
    /// segment never leaves by this door. The sender's own source address is
    /// checked separately, by [`Self::may_send_from`].
    pub fn accepts_exit_traffic(&self, network: NetworkId, destination: Ipv4Addr) -> bool {
        let networks = self.read();
        networks
            .get(&network)
            .is_some_and(|routes| routes.exit.offer)
            && is_internet_destination(destination)
            && !in_any_range(&networks, destination)
    }

    /// The network and member this device sends its internet traffic through.
    ///
    /// One default route, so one answer; if several networks claim one (they
    /// should not) the lowest network id decides, so two runs agree.
    pub fn exit_via(&self) -> Option<(NetworkId, EndpointId)> {
        exit_via(&self.read())
    }

    /// Networks that offer this agent as an exit node, with the range each
    /// agreed. A network that has not agreed one yet has nothing to
    /// masquerade and is left out.
    pub fn exit_offers(&self) -> Vec<(NetworkId, Ipv4Range)> {
        let mut offers: Vec<(NetworkId, Ipv4Range)> = self
            .read()
            .iter()
            .filter(|(_, routes)| routes.exit.offer)
            .filter_map(|(network, routes)| Some((*network, routes.range?)))
            .collect();
        offers.sort_by_key(|(network, _)| *network);
        offers
    }

    /// The range of every network in the table that has agreed one, sorted.
    pub fn overlay_ranges(&self) -> Vec<Ipv4Range> {
        let mut ranges: Vec<Ipv4Range> = self
            .read()
            .values()
            .filter_map(|routes| routes.range)
            .collect();
        ranges.sort_by_key(|range| (range.base, range.prefix_len));
        ranges.dedup();
        ranges
    }

    /// One network's exit-node settings and its range, if it is in the table.
    pub fn exit_settings(&self, network: NetworkId) -> Option<(ExitPolicy, Option<Ipv4Range>)> {
        self.read()
            .get(&network)
            .map(|routes| (routes.exit, routes.range))
    }

    /// Whether an ordinary packet terminates on this host in this network.
    /// Exported LAN subnets must extend this admission policy explicitly later.
    pub fn is_local_destination(&self, network: NetworkId, destination: Ipv4Addr) -> bool {
        self.read()
            .get(&network)
            .is_some_and(|routes| routes.local == Some(destination))
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

    /// The one network whose address the limited broadcast route is bound to.
    ///
    /// The host has a single `255.255.255.255` route per interface, and one
    /// interface carries every network, so only one overlay address can be its
    /// source. The choice is the lowest [`NetworkId`] among networks that have
    /// broadcast enabled, a range and a local address: deterministic, so two
    /// runs with the same networks pick the same one.
    pub fn broadcast_host_target(&self) -> Option<(Ipv4Addr, Ipv4Range)> {
        let networks = self.read();
        networks
            .iter()
            .filter(|(_, routes)| routes.broadcast.enabled)
            .filter_map(|(network, routes)| Some((*network, routes.local?, routes.range?)))
            .min_by_key(|(network, _, _)| *network)
            .map(|(_, local, range)| (local, range))
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

/// Whether an address is an ordinary unicast one: not this host, not a
/// multicast or broadcast group, not link-local, not unspecified.
fn is_internet_destination(address: Ipv4Addr) -> bool {
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_link_local())
}

/// Whether an address lies in any network's range.
fn in_any_range(networks: &HashMap<NetworkId, NetworkRoutes>, address: Ipv4Addr) -> bool {
    networks
        .values()
        .any(|routes| routes.range.is_some_and(|range| range.contains(address)))
}

/// The exit node in use, if any, from the lowest network that names one.
fn exit_via(networks: &HashMap<NetworkId, NetworkRoutes>) -> Option<(NetworkId, EndpointId)> {
    networks
        .iter()
        .filter_map(|(network, routes)| Some((*network, routes.exit.via?)))
        .min_by_key(|(network, _)| *network)
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
            exit: Default::default(),
            broadcast: Default::default(),
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
                    exit: Default::default(),
                    broadcast: Default::default(),
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
    fn the_host_broadcast_target_is_the_lowest_enabled_network_with_an_address() {
        let table = RoutingTable::new();
        assert_eq!(table.broadcast_host_target(), None);

        let (low, high) = {
            let (a, b) = (network("first"), network("second"));
            if a < b { (a, b) } else { (b, a) }
        };
        let mk = |enabled: bool, base: [u8; 4], local: Option<Ipv4Addr>| NetworkRoutes {
            exit: Default::default(),
            broadcast: BroadcastPolicy {
                enabled,
                ..Default::default()
            },
            range: Some(
                format!("{}.{}.{}.0/24", base[0], base[1], base[2])
                    .parse()
                    .unwrap(),
            ),
            local,
            peers: Vec::new(),
        };
        let a = Ipv4Addr::new(10, 1, 0, 1);
        let b = Ipv4Addr::new(10, 2, 0, 1);

        // The lower id has broadcast off, so the higher one is chosen.
        table
            .set_network(low, mk(false, [10, 1, 0, 0], Some(a)))
            .unwrap();
        table
            .set_network(high, mk(true, [10, 2, 0, 0], Some(b)))
            .unwrap();
        assert_eq!(
            table.broadcast_host_target(),
            Some((b, "10.2.0.0/24".parse().unwrap()))
        );

        // Both enabled: the lowest id wins, whatever the insertion order.
        table
            .set_network(low, mk(true, [10, 1, 0, 0], Some(a)))
            .unwrap();
        assert_eq!(
            table.broadcast_host_target(),
            Some((a, "10.1.0.0/24".parse().unwrap()))
        );

        // No local address yet: it cannot be the route's source.
        table
            .set_network(low, mk(true, [10, 1, 0, 0], None))
            .unwrap();
        assert_eq!(
            table.broadcast_host_target(),
            Some((b, "10.2.0.0/24".parse().unwrap()))
        );

        table.remove_network(high);
        assert_eq!(table.broadcast_host_target(), None);
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
                    exit: Default::default(),
                    broadcast: Default::default(),
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
                        exit: Default::default(),
                        broadcast: Default::default(),
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
                    exit: Default::default(),
                    broadcast: Default::default(),
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

    fn with_exit(offer: bool, via: Option<EndpointId>) -> NetworkRoutes {
        NetworkRoutes {
            exit: ExitPolicy { offer, via },
            ..routes()
        }
    }

    const INTERNET: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    #[test]
    fn without_an_exit_node_the_internet_has_nowhere_to_go() {
        let table = RoutingTable::new();
        table.set_network(network("plain"), routes()).unwrap();
        assert_eq!(table.route(INTERNET), None);
        assert_eq!(table.exit_via(), None);
    }

    #[test]
    fn with_an_exit_node_every_ordinary_destination_goes_to_it() {
        let table = RoutingTable::new();
        let id = network("client");
        table
            .set_network(id, with_exit(false, Some(peer(2))))
            .unwrap();
        let exit = Route {
            network: id,
            peer: peer(2),
        };
        assert_eq!(table.route(INTERNET), Some(exit));
        assert_eq!(table.route(Ipv4Addr::new(192, 168, 1, 10)), Some(exit));
        assert_eq!(table.exit_via(), Some((id, peer(2))));
        // A member's own address still goes to that member.
        assert_eq!(
            table.route(addr(3)),
            Some(Route {
                network: id,
                peer: peer(3)
            })
        );
    }

    #[test]
    fn the_exit_node_is_never_the_answer_for_what_is_not_the_internet() {
        let table = RoutingTable::new();
        table
            .set_network(network("client"), with_exit(false, Some(peer(2))))
            .unwrap();
        // Ourselves, a free address inside the overlay range, and everything
        // that is not an ordinary unicast destination.
        for destination in [
            addr(1),
            addr(200),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(224, 0, 0, 251),
            Ipv4Addr::new(239, 255, 255, 250),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(169, 254, 1, 1),
        ] {
            assert_eq!(table.route(destination), None, "{destination}");
        }
    }

    #[test]
    fn another_networks_range_is_not_the_internet_either() {
        let table = RoutingTable::new();
        table
            .set_network(network("client"), with_exit(false, Some(peer(2))))
            .unwrap();
        table
            .set_network(
                network("other"),
                NetworkRoutes {
                    range: Some("10.99.0.0/16".parse().unwrap()),
                    local: Some(Ipv4Addr::new(10, 99, 0, 1)),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(table.route(Ipv4Addr::new(10, 99, 7, 7)), None);
    }

    #[test]
    fn two_exit_choices_resolve_to_the_lowest_network_id() {
        let table = RoutingTable::new();
        let (a, b) = (network("one"), network("two"));
        table
            .set_network(a, with_exit(false, Some(peer(2))))
            .unwrap();
        table
            .set_network(
                b,
                NetworkRoutes {
                    exit: ExitPolicy {
                        offer: false,
                        via: Some(peer(9)),
                    },
                    range: Some("10.99.0.0/16".parse().unwrap()),
                    ..Default::default()
                },
            )
            .unwrap();
        let (chosen, _) = table.exit_via().unwrap();
        assert_eq!(chosen, a.min(b));
        assert_eq!(table.route(INTERNET).unwrap().network, a.min(b));
    }

    #[test]
    fn the_exit_peer_may_send_from_any_internet_address_but_nobody_else_may() {
        let table = RoutingTable::new();
        let id = network("client");
        table
            .set_network(id, with_exit(false, Some(peer(2))))
            .unwrap();

        // What comes back from the internet carries the internet's addresses.
        assert!(table.may_send_from(id, peer(2), INTERNET));
        // Another member still speaks only for its own address.
        assert!(!table.may_send_from(id, peer(3), INTERNET));
        assert!(table.may_send_from(id, peer(3), addr(3)));
        // The exit peer cannot pass itself off as somebody else in the
        // overlay, nor as this agent, nor as something that is not a source.
        assert!(!table.may_send_from(id, peer(2), addr(3)));
        assert!(!table.may_send_from(id, peer(2), addr(1)));
        assert!(!table.may_send_from(id, peer(2), addr(200)));
        for source in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            assert!(!table.may_send_from(id, peer(2), source), "{source}");
        }
        // Without choosing an exit node nobody gets the exception.
        let plain = RoutingTable::new();
        plain.set_network(id, routes()).unwrap();
        assert!(!plain.may_send_from(id, peer(2), INTERNET));
    }

    #[test]
    fn an_exit_node_takes_a_members_internet_packets_only_while_it_offers() {
        let table = RoutingTable::new();
        let id = network("server");
        table.set_network(id, with_exit(false, None)).unwrap();
        assert!(!table.accepts_exit_traffic(id, INTERNET));

        table.set_exit(
            id,
            ExitPolicy {
                offer: true,
                via: None,
            },
        );
        assert!(table.accepts_exit_traffic(id, INTERNET));
        assert!(table.accepts_exit_traffic(id, Ipv4Addr::new(192, 168, 1, 10)));
        // Never for another member, for this agent, a free overlay address,
        // or anything that is not an ordinary unicast destination.
        for destination in [
            addr(1),
            addr(2),
            addr(200),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(224, 0, 0, 251),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::UNSPECIFIED,
        ] {
            assert!(
                !table.accepts_exit_traffic(id, destination),
                "{destination}"
            );
        }
        // An unknown network offers nothing.
        assert!(!table.accepts_exit_traffic(network("elsewhere"), INTERNET));

        table.set_exit(id, ExitPolicy::default());
        assert!(!table.accepts_exit_traffic(id, INTERNET));
    }

    #[test]
    fn offers_are_listed_by_network_with_the_range_each_agreed() {
        let table = RoutingTable::new();
        let (a, b) = (network("a"), network("b"));
        table.set_network(a, with_exit(true, None)).unwrap();
        table
            .set_network(
                b,
                NetworkRoutes {
                    exit: ExitPolicy {
                        offer: true,
                        via: None,
                    },
                    // No range agreed yet: nothing to masquerade.
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            table.exit_offers(),
            vec![(a, "10.13.37.0/24".parse().unwrap())]
        );
        assert_eq!(
            table.exit_settings(a),
            Some((
                ExitPolicy {
                    offer: true,
                    via: None
                },
                Some("10.13.37.0/24".parse().unwrap())
            ))
        );
        assert_eq!(table.exit_settings(network("none")), None);
    }

    #[test]
    fn setting_exit_for_a_network_with_no_entry_is_remembered_by_the_caller() {
        // The runtime keeps the policy and passes it with the network when
        // its range is agreed; a setter for a network the table does not know
        // yet changes nothing.
        let table = RoutingTable::new();
        table.set_exit(
            network("later"),
            ExitPolicy {
                offer: true,
                via: None,
            },
        );
        assert!(table.is_empty());
    }
}
