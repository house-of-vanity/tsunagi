//! Transport-independent routing over opaque identities. Tables are built on
//! topology changes, never on the packet path. No WireGuard or iroh APIs here.
pub(crate) mod envelope;
pub mod flow;

use std::collections::{BTreeSet, HashMap, VecDeque};

/// Opaque authenticated identity; the transport adapter validates its keys.
pub type PeerId = [u8; 32];
/// Stable flow identifier, carried unchanged between transit routers.
pub type FlowId = u64;

/// A shortest route with all equal-cost first hops in stable order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Number of transport links to the destination.
    pub hops: u8,
    /// Equal-cost first hops. Direct destinations have one entry.
    pub next_hops: Box<[PeerId]>,
}

/// Immutable shortest-path table, replaced when connectivity changes.
#[derive(Debug, Clone, Default)]
pub struct RoutingTable {
    routes: HashMap<PeerId, Route>,
}

impl RoutingTable {
    /// Computes shortest directed paths bounded by `hop_limit`.
    /// The caller supplies only authenticated, fresh, compatible edges.
    pub fn build(local: PeerId, graph: &HashMap<PeerId, Vec<PeerId>>, hop_limit: u8) -> Self {
        let mut distances = HashMap::from([(local, 0u8)]);
        let mut first_hops: HashMap<PeerId, BTreeSet<PeerId>> = HashMap::new();
        let mut pending = VecDeque::from([local]);
        while let Some(node) = pending.pop_front() {
            let distance = distances[&node];
            if distance >= hop_limit {
                continue;
            }
            let inherited = first_hops.get(&node).cloned().unwrap_or_default();
            for &next in graph.get(&node).into_iter().flatten() {
                let next_distance = distance + 1;
                match distances.get(&next) {
                    Some(&known) if known < next_distance => continue,
                    None => {
                        distances.insert(next, next_distance);
                        pending.push_back(next);
                    }
                    _ => {}
                }
                let hops = first_hops.entry(next).or_default();
                if node == local {
                    hops.insert(next);
                } else {
                    hops.extend(inherited.iter().copied());
                }
            }
        }
        Self {
            routes: first_hops
                .into_iter()
                .map(|(peer, hops)| {
                    (
                        peer,
                        Route {
                            hops: distances[&peer],
                            next_hops: hops.into_iter().collect(),
                        },
                    )
                })
                .collect(),
        }
    }
    /// Precomputed route to a destination.
    pub fn get(&self, destination: &PeerId) -> Option<&Route> {
        self.routes.get(destination)
    }
    /// All reachable destinations, excluding ourselves.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &Route)> {
        self.routes.iter()
    }
}

/// Stable ECMP mixing, without random state or hashing the payload per hop.
pub(crate) fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    fn p(n: u8) -> PeerId {
        [n; 32]
    }
    #[test]
    fn shortest_paths_keep_equal_cost_hops_and_prefer_direct_links() {
        let mut graph = HashMap::from([
            (p(1), vec![p(3), p(2)]),
            (p(2), vec![p(4)]),
            (p(3), vec![p(4)]),
            (p(4), vec![p(5)]),
            (p(5), vec![p(1)]),
        ]);
        let routes = RoutingTable::build(p(1), &graph, 16);
        assert_eq!(routes.get(&p(5)).unwrap().hops, 3);
        assert_eq!(&*routes.get(&p(5)).unwrap().next_hops, &[p(2), p(3)]);
        assert!(routes.get(&p(1)).is_none());
        assert!(routes.get(&p(9)).is_none());
        graph.get_mut(&p(1)).unwrap().push(p(5));
        assert_eq!(
            RoutingTable::build(p(1), &graph, 16).get(&p(5)).unwrap(),
            &Route {
                hops: 1,
                next_hops: Box::new([p(5)])
            }
        );
    }
    #[test]
    fn topology_removal_and_hop_budget_remove_impossible_routes() {
        let mut graph = HashMap::from([(p(1), vec![p(2)]), (p(2), vec![p(3)]), (p(3), vec![p(4)])]);
        assert!(RoutingTable::build(p(1), &graph, 2).get(&p(4)).is_none());
        assert!(RoutingTable::build(p(1), &graph, 3).get(&p(4)).is_some());
        graph.remove(&p(2));
        assert!(RoutingTable::build(p(1), &graph, 16).get(&p(4)).is_none());
    }
}
