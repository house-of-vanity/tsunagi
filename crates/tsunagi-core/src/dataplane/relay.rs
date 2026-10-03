//! Userspace forwarding. Topology updates publish immutable tables; the packet
//! path takes no routing mutex, walks no graph and never inspects plugin bytes.
//! Each transport reader forwards transit immediately, independently of the
//! destination protocol's receive task. Only local delivery enters its inbox.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use bytes::Bytes;
use iroh::EndpointId;
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;

use super::routing::{FlowId, PeerId, RoutingTable, envelope, mix64};
use super::transport::{PacketLink, SharedLink, TransportError};
use crate::BoxFuture;
use crate::config::{MAX_DATA_DATAGRAM, ROUTING_HOP_LIMIT};
use crate::identity::NetworkId;

/// Fixed routing header, subtracted from the logical transport MTU.
pub const RELAY_OVERHEAD: usize = envelope::HEADER;
const INBOX: usize = 256;

/// Forwarding counters, shared by all protocols of one network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayCounters {
    /// Datagrams originated here and sent through another member.
    pub sent_via: u64,
    /// Transit datagrams handed to the next transport link.
    pub forwarded: u64,
    /// Local datagrams received through another member.
    pub received_via: u64,
    /// Missing or failed next hop.
    pub dropped_no_link: u64,
    /// Malformed envelope or unknown member.
    pub dropped_unknown: u64,
    /// Exhausted hop limit, including loops during topology convergence.
    pub dropped_hop_limit: u64,
    /// Full local protocol inbox. Transit does not use this queue.
    pub dropped_congested: u64,
}

#[derive(Debug, Default)]
struct Tally {
    sent_via: AtomicU64,
    forwarded: AtomicU64,
    received_via: AtomicU64,
    dropped_no_link: AtomicU64,
    dropped_unknown: AtomicU64,
    dropped_hop_limit: AtomicU64,
    dropped_congested: AtomicU64,
}

impl Tally {
    fn snapshot(&self) -> RelayCounters {
        RelayCounters {
            sent_via: self.sent_via.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            received_via: self.received_via.load(Ordering::Relaxed),
            dropped_no_link: self.dropped_no_link.load(Ordering::Relaxed),
            dropped_unknown: self.dropped_unknown.load(Ordering::Relaxed),
            dropped_hop_limit: self.dropped_hop_limit.load(Ordering::Relaxed),
            dropped_congested: self.dropped_congested.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
struct NextHop {
    peer: PeerId,
    link: SharedLink,
}

#[derive(Debug)]
struct ForwardRoute {
    hops: u8,
    next: Box<[NextHop]>,
}

impl ForwardRoute {
    fn select(&self, source: &PeerId, flow: FlowId) -> Option<&NextHop> {
        if self.next.len() == 1 {
            return self.next.first().filter(|hop| !hop.link.is_closed());
        }
        let seed = u64::from_le_bytes(source[..8].try_into().ok()?);
        let start = mix64(flow ^ seed) as usize % self.next.len();
        // Stable fallback if a link closed just before its table was replaced.
        (0..self.next.len())
            .map(|i| &self.next[(start + i) % self.next.len()])
            .find(|hop| !hop.link.is_closed())
    }
}

#[derive(Debug, Default)]
struct ForwardingTable {
    routes: HashMap<PeerId, ForwardRoute>,
    inboxes: HashMap<PeerId, mpsc::Sender<Bytes>>,
    members: HashSet<PeerId>,
}

#[derive(Debug)]
struct Plane {
    local: PeerId,
    table: ArcSwap<ForwardingTable>,
    tally: Arc<Tally>,
}

impl Plane {
    /// Synchronous hot path: one snapshot, bounded header decode, table lookup,
    /// and transport send. An exclusively owned buffer is modified in place.
    fn receive(&self, incoming: PeerId, frame: Bytes) {
        let Some(header) = envelope::decode(&frame) else {
            self.tally.dropped_unknown.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let table = self.table.load();
        if !table.members.contains(&header.source) || header.source == self.local {
            self.tally.dropped_unknown.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if header.destination == self.local {
            let Some(inbox) = table.inboxes.get(&header.source) else {
                self.tally.dropped_unknown.fetch_add(1, Ordering::Relaxed);
                return;
            };
            if inbox.try_send(frame.slice(RELAY_OVERHEAD..)).is_err() {
                self.tally.dropped_congested.fetch_add(1, Ordering::Relaxed);
            } else if incoming != header.source {
                self.tally.received_via.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        if header.remaining <= 1 {
            self.tally.dropped_hop_limit.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let hop = table
            .routes
            .get(&header.destination)
            .and_then(|route| route.select(&header.source, header.flow));
        let Some(hop) = hop else {
            self.tally.dropped_no_link.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if hop.link.send(envelope::decrement(frame)).is_ok() {
            self.tally.forwarded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.tally.dropped_no_link.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
struct Protocol {
    plane: Arc<Plane>,
    graph: HashMap<PeerId, Vec<PeerId>>,
    members: HashSet<PeerId>,
    raw: HashMap<PeerId, SharedLink>,
    readers: HashMap<PeerId, JoinHandle<()>>,
    links: HashMap<PeerId, Arc<PeerLink>>,
}

impl Protocol {
    fn publish(&self) {
        let mut graph = self.graph.clone();
        graph.insert(
            self.plane.local,
            self.raw
                .iter()
                .filter(|(_, link)| !link.is_closed())
                .map(|(peer, _)| *peer)
                .collect(),
        );
        let routing = RoutingTable::build(self.plane.local, &graph, ROUTING_HOP_LIMIT);
        let routes = routing
            .iter()
            .filter_map(|(peer, route)| {
                let next: Box<[_]> = route
                    .next_hops
                    .iter()
                    .filter_map(|id| {
                        self.raw.get(id).map(|link| NextHop {
                            peer: *id,
                            link: link.clone(),
                        })
                    })
                    .collect();
                (!next.is_empty()).then_some((
                    *peer,
                    ForwardRoute {
                        hops: route.hops,
                        next,
                    },
                ))
            })
            .collect();
        let mut members = self.members.clone();
        members.extend(self.raw.keys().copied());
        self.plane.table.store(Arc::new(ForwardingTable {
            routes,
            members,
            inboxes: self
                .links
                .iter()
                .map(|(peer, link)| (*peer, link.inbox_tx.clone()))
                .collect(),
        }));
    }
}

impl Drop for Protocol {
    fn drop(&mut self) {
        for task in self.readers.values() {
            task.abort();
        }
        for link in self.links.values() {
            link.close();
        }
        self.plane.table.store(Arc::default());
    }
}

/// One network's transport links and independently published protocol tables.
#[derive(Debug)]
pub struct RelayHub {
    network: NetworkId,
    local: PeerId,
    protocols: Mutex<HashMap<String, Protocol>>,
    tally: Arc<Tally>,
    changed: Arc<Notify>,
}

impl RelayHub {
    /// Creates the router at this network's local endpoint.
    pub fn new(network: NetworkId, local: EndpointId) -> Arc<Self> {
        Arc::new(Self {
            network,
            local: *local.as_bytes(),
            protocols: Mutex::default(),
            tally: Arc::default(),
            changed: Arc::default(),
        })
    }

    fn protocols(&self) -> std::sync::MutexGuard<'_, HashMap<String, Protocol>> {
        self.protocols
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn protocol<'a>(
        &self,
        protocols: &'a mut HashMap<String, Protocol>,
        name: &str,
    ) -> &'a mut Protocol {
        protocols
            .entry(name.to_owned())
            .or_insert_with(|| Protocol {
                plane: Arc::new(Plane {
                    local: self.local,
                    table: ArcSwap::from_pointee(ForwardingTable::default()),
                    tally: self.tally.clone(),
                }),
                graph: HashMap::new(),
                members: HashSet::new(),
                raw: HashMap::new(),
                readers: HashMap::new(),
                links: HashMap::new(),
            })
    }

    /// Wakes the control loop promptly when a transport reader ends.
    pub async fn changed(&self) {
        self.changed.notified().await;
    }

    /// Current counters.
    pub fn counters(&self) -> RelayCounters {
        self.tally.snapshot()
    }

    /// Publishes authenticated topology. Refreshing identical state is cheap.
    pub fn set_topology(
        &self,
        protocol: &str,
        graph: HashMap<PeerId, Vec<PeerId>>,
        members: HashSet<PeerId>,
    ) {
        let mut protocols = self.protocols();
        let state = self.protocol(&mut protocols, protocol);
        if state.graph != graph || state.members != members {
            state.graph = graph;
            state.members = members;
            state.publish();
        }
    }

    /// Whether the current table has a path to this destination.
    pub fn reachable(&self, peer: EndpointId, protocol: &str) -> bool {
        self.protocols().get(protocol).is_some_and(|state| {
            state
                .plane
                .table
                .load()
                .routes
                .contains_key(peer.as_bytes())
        })
    }

    /// Stable logical link, preserved across topology changes.
    pub fn link(&self, peer: EndpointId, protocol: &str) -> Arc<PeerLink> {
        let mut protocols = self.protocols();
        let state = self.protocol(&mut protocols, protocol);
        if let Some(link) = state.links.get(peer.as_bytes()) {
            return link.clone();
        }
        let (inbox_tx, inbox_rx) = mpsc::channel(INBOX);
        let (closed, _) = watch::channel(false);
        let link = Arc::new(PeerLink {
            network: self.network,
            peer,
            plane: state.plane.clone(),
            inbox_tx,
            inbox_rx: tokio::sync::Mutex::new(inbox_rx),
            closed,
        });
        state.links.insert(*peer.as_bytes(), link.clone());
        state.publish();
        link
    }

    /// Whether the protocol already owns its logical link.
    pub fn has_link(&self, peer: EndpointId, protocol: &str) -> bool {
        self.protocols()
            .get(protocol)
            .is_some_and(|state| state.links.contains_key(peer.as_bytes()))
    }

    /// Installs a raw transport link and starts its independent ingress reader.
    pub fn set_direct(&self, peer: EndpointId, protocol: &str, raw: SharedLink) {
        if raw.network() != self.network || raw.peer() != peer {
            return;
        }
        let mut protocols = self.protocols();
        let state = self.protocol(&mut protocols, protocol);
        let id = *peer.as_bytes();
        if let Some(old) = state.readers.remove(&id) {
            old.abort();
        }
        state.raw.insert(id, raw.clone());
        state.publish();
        let plane = state.plane.clone();
        let changed = self.changed.clone();
        state.readers.insert(
            id,
            tokio::spawn(async move {
                let mut batch = 0;
                while let Some(frame) = raw.recv().await {
                    plane.receive(id, frame);
                    batch += 1;
                    if batch == 64 {
                        tokio::task::yield_now().await;
                        batch = 0;
                    }
                }
                changed.notify_one();
            }),
        );
    }

    /// Removes a physical link without tearing down end-to-end protocol state.
    pub fn clear_direct(&self, peer: EndpointId, protocol: &str) {
        if let Some(state) = self.protocols().get_mut(protocol) {
            state.raw.remove(peer.as_bytes());
            if let Some(task) = state.readers.remove(peer.as_bytes()) {
                task.abort();
            }
            state.publish();
        }
    }

    /// Revokes all links and topology involving a departed authenticated peer.
    pub fn remove_peer(&self, peer: EndpointId) {
        for state in self.protocols().values_mut() {
            state.raw.remove(peer.as_bytes());
            if let Some(task) = state.readers.remove(peer.as_bytes()) {
                task.abort();
            }
            if let Some(link) = state.links.remove(peer.as_bytes()) {
                link.close();
            }
            state.members.remove(peer.as_bytes());
            state.graph.remove(peer.as_bytes());
            for neighbors in state.graph.values_mut() {
                neighbors.retain(|id| id != peer.as_bytes());
            }
            state.publish();
        }
    }

    /// Stops every reader and releases all transport handles.
    pub fn close(&self) {
        self.protocols().clear();
    }
}

/// A protocol's end-to-end channel, independent of its current next hop.
#[derive(Debug)]
pub struct PeerLink {
    network: NetworkId,
    peer: EndpointId,
    plane: Arc<Plane>,
    inbox_tx: mpsc::Sender<Bytes>,
    inbox_rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    closed: watch::Sender<bool>,
}

impl PeerLink {
    fn close(&self) {
        self.closed.send_replace(true);
    }
}

impl PacketLink for PeerLink {
    fn network(&self) -> NetworkId {
        self.network
    }
    fn peer(&self) -> EndpointId {
        self.peer
    }
    fn max_datagram_size(&self) -> usize {
        MAX_DATA_DATAGRAM - RELAY_OVERHEAD
    }
    fn send(&self, payload: Bytes) -> Result<(), TransportError> {
        self.send_flow(payload, 0)
    }
    fn send_flow(&self, payload: Bytes, flow: FlowId) -> Result<(), TransportError> {
        if self.is_closed() {
            return Err(TransportError::Closed);
        }
        if payload.len() > self.max_datagram_size() {
            return Err(TransportError::TooLarge {
                size: payload.len(),
                limit: self.max_datagram_size(),
            });
        }
        let table = self.plane.table.load();
        let route = table
            .routes
            .get(self.peer.as_bytes())
            .ok_or(TransportError::Closed)?;
        let hop = route
            .select(&self.plane.local, flow)
            .ok_or(TransportError::Closed)?;
        hop.link.send(envelope::encode(
            self.plane.local,
            *self.peer.as_bytes(),
            flow,
            &payload,
        ))?;
        if route.hops > 1 {
            self.plane.tally.sent_via.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            let mut closed = self.closed.subscribe();
            if *closed.borrow_and_update() {
                return None;
            }
            let mut inbox = self.inbox_rx.lock().await;
            tokio::select! { biased; _ = closed.changed() => None, frame = inbox.recv() => frame }
        })
    }
    fn closed(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut closed = self.closed.subscribe();
            if !*closed.borrow_and_update() {
                let _ = closed.changed().await;
            }
        })
    }
    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
    fn path_description(&self) -> String {
        let table = self.plane.table.load();
        match table.routes.get(self.peer.as_bytes()) {
            Some(route) if route.hops == 1 => route.next[0].link.path_description(),
            Some(route) => format!(
                "relay {} hops via {} ({} equal paths)",
                route.hops,
                hex::encode(route.next[0].peer),
                route.next.len()
            ),
            None => "unreachable".into(),
        }
    }
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
