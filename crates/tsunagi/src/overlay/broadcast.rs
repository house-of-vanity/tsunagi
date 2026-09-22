//! Scoped LAN discovery fanout at IP ingress. A domain is one logical network;
//! routed copies use ordinary encrypted peer links and are never reflooded.
//! Future subnet exporters must supply explicitly authorized ingress domains
//! here, not teach the encrypted transit router to inspect application bytes.

use super::router::{NetworkRoutes, Route};
use crate::NetworkId;
use iroh::EndpointId;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Local participation and the currently authenticated participants in a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastPolicy {
    /// Whether this agent originates and accepts LAN broadcasts in this network.
    pub enabled: bool,
    /// Live members explicitly advertising that they accept broadcasts.
    pub peers: HashSet<EndpointId>,
}
impl Default for BroadcastPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            peers: HashSet::new(),
        }
    }
}

#[derive(Debug)]
struct Domain {
    network: NetworkId,
    directed: Ipv4Addr,
    enabled: bool,
    recipients: Arc<[Route]>,
    members: HashSet<EndpointId>,
}

/// Immutable ingress-domain index rebuilt with address/policy changes.
#[derive(Debug, Default)]
pub(crate) struct BroadcastTable {
    sources: HashMap<Ipv4Addr, Arc<Domain>>,
    networks: HashMap<NetworkId, Arc<Domain>>,
    destinations: HashSet<Ipv4Addr>,
}
impl BroadcastTable {
    pub fn build(networks: &HashMap<NetworkId, NetworkRoutes>) -> Self {
        let mut table = Self::default();
        for (&network, routes) in networks {
            let (Some(range), Some(local)) = (routes.range, routes.local) else {
                continue;
            };
            if range.prefix_len > 30 {
                continue;
            }
            let directed = Ipv4Addr::from(u32::from(range.base) | (u32::MAX >> range.prefix_len));
            let mut recipients: Vec<_> = routes
                .peers
                .iter()
                .filter(|(_, peer)| routes.broadcast.peers.contains(peer))
                .map(|(_, peer)| Route {
                    network,
                    peer: *peer,
                })
                .collect();
            recipients.sort_by_key(|route| route.peer);
            recipients.dedup();
            let domain = Arc::new(Domain {
                network,
                directed,
                enabled: routes.broadcast.enabled,
                members: recipients.iter().map(|route| route.peer).collect(),
                recipients: recipients.into(),
            });
            table.sources.insert(local, domain.clone());
            table.networks.insert(network, domain);
            table.destinations.insert(directed);
        }
        table
    }
    pub fn is_destination(&self, destination: Ipv4Addr) -> bool {
        destination.is_broadcast() || self.destinations.contains(&destination)
    }
    pub fn outgoing(&self, source: Ipv4Addr, destination: Ipv4Addr) -> Option<Arc<[Route]>> {
        let domain = self.sources.get(&source)?;
        (domain.enabled && (destination.is_broadcast() || destination == domain.directed))
            .then(|| domain.recipients.clone())
    }
    pub fn accepts(&self, network: NetworkId, peer: EndpointId, destination: Ipv4Addr) -> bool {
        self.networks.get(&network).is_some_and(|domain| {
            domain.network == network
                && domain.enabled
                && domain.members.contains(&peer)
                && (destination.is_broadcast() || destination == domain.directed)
        })
    }
}

/// Validates IPv4/UDP lengths before broadcast fanout. No game-specific ports,
/// payload rewriting or checksum changes. IP fragments retain their bytes and
/// are reassembled by the destination OS; even later fragments have protocol 17.
pub(crate) fn valid_udp(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return false;
    }
    let header = usize::from(packet[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header < 20 || total <= header || total > packet.len() {
        return false;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x1fff != 0 {
        return true;
    }
    if total < header + 8 {
        return false;
    }
    let udp = usize::from(u16::from_be_bytes([packet[header + 4], packet[header + 5]]));
    udp >= 8
        && if fragment & 0x2000 != 0 {
            udp >= total - header
        } else {
            udp == total - header
        }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};
    fn id(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes([4; 32]).unwrap(),
        )
        .network_id()
    }
    #[test]
    fn limited_and_directed_broadcasts_never_cross_domains_or_target_disabled_peers() {
        let peer = iroh::SecretKey::from_bytes(&[8; 32]).public();
        let a = NetworkRoutes {
            range: Some("10.0.0.0/24".parse().unwrap()),
            local: Some("10.0.0.1".parse().unwrap()),
            peers: vec![("10.0.0.2".parse().unwrap(), peer)],
            broadcast: BroadcastPolicy {
                enabled: true,
                peers: HashSet::from([peer]),
            },
        };
        let b = NetworkRoutes {
            range: Some("10.1.0.0/24".parse().unwrap()),
            local: Some("10.1.0.1".parse().unwrap()),
            peers: vec![("10.1.0.2".parse().unwrap(), peer)],
            broadcast: BroadcastPolicy::default(),
        };
        let table = BroadcastTable::build(&HashMap::from([(id("a"), a.clone()), (id("b"), b)]));
        let routes = table
            .outgoing(a.local.unwrap(), Ipv4Addr::BROADCAST)
            .unwrap();
        assert_eq!(
            &*routes,
            &[Route {
                network: id("a"),
                peer
            }]
        );
        assert!(
            table
                .outgoing(a.local.unwrap(), "10.1.0.255".parse().unwrap())
                .is_none()
        );
        assert!(
            table
                .outgoing("192.168.1.2".parse().unwrap(), Ipv4Addr::BROADCAST)
                .is_none()
        );
        assert!(
            table
                .outgoing("10.1.0.1".parse().unwrap(), Ipv4Addr::BROADCAST)
                .unwrap()
                .is_empty()
        );
        assert!(!table.accepts(id("a"), peer, "10.1.0.255".parse().unwrap()));
        assert!(!table.accepts(id("b"), peer, Ipv4Addr::BROADCAST));
        assert!(table.accepts(id("a"), peer, Ipv4Addr::BROADCAST));
        let disabled = NetworkRoutes {
            broadcast: BroadcastPolicy {
                enabled: false,
                ..a.broadcast.clone()
            },
            ..a.clone()
        };
        let table = BroadcastTable::build(&HashMap::from([(id("a"), disabled)]));
        assert!(
            table
                .outgoing(a.local.unwrap(), Ipv4Addr::BROADCAST)
                .is_none()
        );
        assert!(!table.accepts(id("a"), peer, Ipv4Addr::BROADCAST));
    }
    #[test]
    fn malformed_udp_is_not_amplified_but_ipv4_fragments_are_supported() {
        let mut packet = vec![0u8; 36];
        packet[0] = 0x45;
        packet[3] = 36;
        packet[9] = 17;
        packet[25] = 16;
        assert!(valid_udp(&packet));
        for length in 0..36 {
            assert!(!valid_udp(&packet[..length]));
        }
        packet[9] = 6;
        assert!(!valid_udp(&packet));
        packet[9] = 17;
        packet[0] = 0x44;
        assert!(!valid_udp(&packet));
        packet[0] = 0x45;
        packet[25] = 8;
        assert!(!valid_udp(&packet));
        packet[6] = 0x20;
        packet[25] = 64;
        assert!(valid_udp(&packet));
        packet[6] = 0;
        packet[7] = 2;
        assert!(valid_udp(&packet));
    }
}
