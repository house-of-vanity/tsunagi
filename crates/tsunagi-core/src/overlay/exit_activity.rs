//! Last successful forwarding for older peers that cannot report their exit selection.
use super::NetworkRoutes;
use crate::identity::NetworkId;
use arc_swap::ArcSwap;
use iroh::EndpointId;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

type Stamps = HashMap<EndpointId, Arc<AtomicU64>>;
const RECENT_SECS: u64 = 60;

#[derive(Debug)]
pub(super) struct ExitActivity {
    started: Instant,
    networks: ArcSwap<HashMap<NetworkId, Arc<Stamps>>>,
}

impl Default for ExitActivity {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            networks: ArcSwap::default(),
        }
    }
}

impl ExitActivity {
    // Serialized by the routing write lock. Provision only signed allocations on
    // offering networks. Packets never create entries or lock the routing table here.
    pub(super) fn configure(&self, network: NetworkId, routes: Option<&NetworkRoutes>) {
        let previous = self.networks.load();
        let old = previous.get(&network);
        let offering = routes.filter(|r| r.exit.offer);
        if offering.is_none() && old.is_none() {
            return;
        }
        let mut next = (**previous).clone();
        if let Some(routes) = offering {
            let peers = routes
                .peers
                .iter()
                .map(|(_, id)| {
                    let stamp = old.and_then(|s| s.get(id)).cloned().unwrap_or_default();
                    (*id, stamp)
                })
                .collect();
            next.insert(network, Arc::new(peers));
        } else {
            next.remove(&network);
        }
        self.networks.store(Arc::new(next));
    }

    pub(super) fn stamp(&self, network: NetworkId, peer: EndpointId) -> Option<Arc<AtomicU64>> {
        self.networks.load().get(&network)?.get(&peer).cloned()
    }

    pub(super) fn forwarded(&self, stamp: &AtomicU64) {
        let now = self.started.elapsed().as_secs() + 1;
        if stamp.load(Ordering::Relaxed) < now {
            stamp.fetch_max(now, Ordering::Relaxed);
        }
    }

    pub(super) fn recent(&self, network: NetworkId, peer: EndpointId) -> bool {
        let now = self.started.elapsed().as_secs() + 1;
        self.stamp(network, peer).is_some_and(|s| {
            let last = s.load(Ordering::Relaxed);
            last > 0 && now.saturating_sub(last) < RECENT_SECS
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::ExitPolicy;
    #[test]
    fn only_delivered_exit_packets_count_and_old_stamps_cannot_revive_a_removed_offer() {
        let mut activity = ExitActivity::default();
        let network = NetworkId::from_bytes([1; 32]);
        let peer = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let routes = NetworkRoutes {
            exit: ExitPolicy {
                offer: true,
                via: None,
            },
            peers: vec![(std::net::Ipv4Addr::LOCALHOST, peer)],
            ..Default::default()
        };
        activity.configure(network, Some(&routes));
        assert!(!activity.recent(network, peer));
        let Some(stamp) = activity.stamp(network, peer) else {
            unreachable!()
        };
        activity.forwarded(&stamp);
        assert!(activity.recent(network, peer));
        activity.configure(network, Some(&routes));
        assert!(activity.recent(network, peer));
        activity.started -= std::time::Duration::from_secs(60);
        assert!(!activity.recent(network, peer));
        activity.configure(network, None);
        activity.configure(network, Some(&routes));
        activity.forwarded(&stamp);
        assert!(!activity.recent(network, peer));
    }
}
