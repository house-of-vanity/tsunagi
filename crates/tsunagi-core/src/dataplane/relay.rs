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

/// The links to one neighbour, best first. Which transport carries a frame
/// is decided here and nowhere else: the end-to-end protocol is in the
/// envelope and never depends on it.
#[derive(Debug)]
struct NextHop {
    peer: PeerId,
    links: Box<[SharedLink]>,
}

impl NextHop {
    fn usable(&self) -> bool {
        self.links.iter().any(|link| !link.is_closed())
    }

    fn first_open(&self) -> Option<&SharedLink> {
        self.links.iter().find(|link| !link.is_closed())
    }

    /// Hands a frame to the best open link that accepts it. A link that
    /// cannot carry the frame (too large for its path, closed a moment ago)
    /// leaves it to the next one; the frame is only copied when there is
    /// another to try.
    fn send(&self, frame: Bytes) -> Result<(), TransportError> {
        let mut open = self.links.iter().filter(|link| !link.is_closed());
        let Some(mut current) = open.next() else {
            return Err(TransportError::Closed);
        };
        for next in open {
            if current.send(frame.clone()).is_ok() {
                return Ok(());
            }
            current = next;
        }
        current.send(frame)
    }
}

#[derive(Debug)]
struct ForwardRoute {
    hops: u8,
    next: Box<[NextHop]>,
}

impl ForwardRoute {
    fn select(&self, source: &PeerId, flow: FlowId) -> Option<&NextHop> {
        if self.next.len() == 1 {
            return self.next.first().filter(|hop| hop.usable());
        }
        let seed = u64::from_le_bytes(source[..8].try_into().ok()?);
        let start = mix64(flow ^ seed) as usize % self.next.len();
        // Stable fallback if a link closed just before its table was replaced.
        (0..self.next.len())
            .map(|i| &self.next[(start + i) % self.next.len()])
            .find(|hop| hop.usable())
    }
}

#[derive(Debug, Default)]
struct ForwardingTable {
    routes: HashMap<PeerId, ForwardRoute>,
    /// Local delivery, by who sent it and which end-to-end protocol it is.
    inboxes: HashMap<(PeerId, u64), mpsc::Sender<Bytes>>,
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
            let Some(inbox) = table.inboxes.get(&(header.source, header.protocol)) else {
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
        if hop.send(envelope::decrement(frame)).is_ok() {
            self.tally.forwarded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.tally.dropped_no_link.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// One physical link to a neighbour, of whatever kind of transport.
#[derive(Debug)]
struct RawLink {
    kind: String,
    link: SharedLink,
    reader: JoinHandle<()>,
}

/// How a destination is reached right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSummary {
    /// Number of transport links to it. One is a direct link.
    pub hops: u8,
    /// The neighbour the first link goes to. For a direct link that is the
    /// destination itself.
    pub via: EndpointId,
}

#[derive(Debug)]
struct State {
    plane: Arc<Plane>,
    /// Transport kinds, best first. A neighbour with several links is
    /// reached over the first of these it has.
    priority: Vec<String>,
    graph: HashMap<PeerId, Vec<PeerId>>,
    members: HashSet<PeerId>,
    raw: HashMap<PeerId, Vec<RawLink>>,
    links: HashMap<(PeerId, String), Arc<PeerLink>>,
}

impl State {
    fn rank(&self, kind: &str) -> usize {
        self.priority
            .iter()
            .position(|known| known == kind)
            .unwrap_or(usize::MAX)
    }

    /// A neighbour's links, best kind first.
    fn ordered(&self, peer: &PeerId) -> Vec<&RawLink> {
        let mut links: Vec<&RawLink> = self
            .raw
            .get(peer)
            .map(|links| links.iter().collect())
            .unwrap_or_default();
        links.sort_by_key(|raw| (self.rank(&raw.kind), raw.kind.clone()));
        links
    }

    fn publish(&self) {
        let mut graph = self.graph.clone();
        let mut neighbours: Vec<PeerId> = self
            .raw
            .iter()
            .filter(|(_, links)| links.iter().any(|raw| !raw.link.is_closed()))
            .map(|(peer, _)| *peer)
            .collect();
        neighbours.sort_unstable();
        graph.insert(self.plane.local, neighbours);
        let routing = RoutingTable::build(self.plane.local, &graph, ROUTING_HOP_LIMIT);
        let routes = routing
            .iter()
            .filter_map(|(peer, route)| {
                let next: Box<[_]> = route
                    .next_hops
                    .iter()
                    .filter_map(|id| {
                        let links: Box<[_]> = self
                            .ordered(id)
                            .into_iter()
                            .map(|raw| raw.link.clone())
                            .collect();
                        (!links.is_empty()).then_some(NextHop { peer: *id, links })
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
                .map(|((peer, _), link)| ((*peer, link.tag), link.inbox_tx.clone()))
                .collect(),
        }));
    }

    fn stop_readers(&mut self) {
        for raw in self.raw.values().flatten() {
            raw.reader.abort();
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.stop_readers();
        for link in self.links.values() {
            link.close();
        }
        self.plane.table.store(Arc::default());
    }
}

/// One network's transport links and its published forwarding table.
///
/// There is one table for the whole network, whatever protocols run over it.
/// A link is a way to reach a neighbour; a protocol is an end-to-end channel
/// to a peer. The two meet only in the envelope, which names the protocol, so
/// a tunnel keeps working over any mix of transports and a middle member
/// needs no protocol in common with either end.
#[derive(Debug)]
pub struct RelayHub {
    network: NetworkId,
    state: Mutex<State>,
    tally: Arc<Tally>,
    changed: Arc<Notify>,
}

impl RelayHub {
    /// Creates the router at this network's local endpoint.
    pub fn new(network: NetworkId, local: EndpointId) -> Arc<Self> {
        let tally = Arc::new(Tally::default());
        Arc::new(Self {
            network,
            state: Mutex::new(State {
                plane: Arc::new(Plane {
                    local: *local.as_bytes(),
                    table: ArcSwap::from_pointee(ForwardingTable::default()),
                    tally: tally.clone(),
                }),
                priority: Vec::new(),
                graph: HashMap::new(),
                members: HashSet::new(),
                raw: HashMap::new(),
                links: HashMap::new(),
            }),
            tally,
            changed: Arc::default(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Sets which kinds of transport are preferred, best first, when a
    /// neighbour can be reached over more than one.
    pub fn set_priority(&self, kinds: Vec<String>) {
        let mut state = self.state();
        if state.priority != kinds {
            state.priority = kinds;
            state.publish();
        }
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
    ///
    /// Every row of `graph` is one member's own account of who it has a link
    /// to; what kind of link it is does not matter here.
    pub fn set_topology(&self, graph: HashMap<PeerId, Vec<PeerId>>, members: HashSet<PeerId>) {
        let mut state = self.state();
        if state.graph != graph || state.members != members {
            state.graph = graph;
            state.members = members;
            state.publish();
        }
    }

    /// Whether the current table has a path to this destination.
    pub fn reachable(&self, peer: EndpointId) -> bool {
        self.state()
            .plane
            .table
            .load()
            .routes
            .contains_key(peer.as_bytes())
    }

    /// How a destination is reached right now, if it is.
    pub fn route(&self, peer: EndpointId) -> Option<RouteSummary> {
        let table = self.state().plane.table.load_full();
        let route = table.routes.get(peer.as_bytes())?;
        let via = EndpointId::from_bytes(&route.next.first()?.peer).ok()?;
        Some(RouteSummary {
            hops: route.hops,
            via,
        })
    }

    /// The kinds of transport with an open direct link to a peer, best
    /// first.
    pub fn direct_kinds(&self, peer: EndpointId) -> Vec<String> {
        let state = self.state();
        state
            .ordered(peer.as_bytes())
            .into_iter()
            .filter(|raw| !raw.link.is_closed())
            .map(|raw| raw.kind.clone())
            .collect()
    }

    /// Stable end-to-end channel for a protocol, preserved across topology
    /// and transport changes.
    pub fn link(&self, peer: EndpointId, protocol: &str) -> Arc<PeerLink> {
        let mut state = self.state();
        let key = (*peer.as_bytes(), protocol.to_owned());
        if let Some(link) = state.links.get(&key) {
            return link.clone();
        }
        let (inbox_tx, inbox_rx) = mpsc::channel(INBOX);
        let (closed, _) = watch::channel(false);
        let link = Arc::new(PeerLink {
            network: self.network,
            peer,
            tag: envelope::protocol_tag(protocol),
            plane: state.plane.clone(),
            inbox_tx,
            inbox_rx: tokio::sync::Mutex::new(inbox_rx),
            closed,
        });
        state.links.insert(key, link.clone());
        state.publish();
        link
    }

    /// Whether the protocol already owns its end-to-end channel to a peer.
    pub fn has_link(&self, peer: EndpointId, protocol: &str) -> bool {
        self.state()
            .links
            .contains_key(&(*peer.as_bytes(), protocol.to_owned()))
    }

    /// Installs a raw transport link and starts its independent ingress reader.
    ///
    /// A neighbour may have one link per kind of transport; installing a
    /// second of the same kind replaces the first.
    pub fn set_direct(&self, peer: EndpointId, kind: &str, raw: SharedLink) {
        if raw.network() != self.network || raw.peer() != peer {
            return;
        }
        let mut state = self.state();
        let id = *peer.as_bytes();
        let plane = state.plane.clone();
        let changed = self.changed.clone();
        let reader_link = raw.clone();
        let reader = tokio::spawn(async move {
            let mut batch = 0;
            while let Some(frame) = reader_link.recv().await {
                plane.receive(id, frame);
                batch += 1;
                if batch == 64 {
                    tokio::task::yield_now().await;
                    batch = 0;
                }
            }
            changed.notify_one();
        });
        let links = state.raw.entry(id).or_default();
        if let Some(position) = links.iter().position(|known| known.kind == kind) {
            links.remove(position).reader.abort();
        }
        links.push(RawLink {
            kind: kind.to_owned(),
            link: raw,
            reader,
        });
        state.publish();
    }

    /// Removes one physical link without tearing down end-to-end protocol state.
    pub fn clear_direct(&self, peer: EndpointId, kind: &str) {
        let mut state = self.state();
        let mut changed = false;
        if let Some(links) = state.raw.get_mut(peer.as_bytes()) {
            if let Some(position) = links.iter().position(|known| known.kind == kind) {
                links.remove(position).reader.abort();
                changed = true;
            }
            if links.is_empty() {
                state.raw.remove(peer.as_bytes());
            }
        }
        if changed {
            state.publish();
        }
    }

    /// Revokes all links and topology involving a departed authenticated peer.
    pub fn remove_peer(&self, peer: EndpointId) {
        let mut state = self.state();
        if let Some(links) = state.raw.remove(peer.as_bytes()) {
            for raw in links {
                raw.reader.abort();
            }
        }
        let gone: Vec<_> = state
            .links
            .keys()
            .filter(|(id, _)| id == peer.as_bytes())
            .cloned()
            .collect();
        for key in gone {
            if let Some(link) = state.links.remove(&key) {
                link.close();
            }
        }
        state.members.remove(peer.as_bytes());
        state.graph.remove(peer.as_bytes());
        for neighbors in state.graph.values_mut() {
            neighbors.retain(|id| id != peer.as_bytes());
        }
        state.publish();
    }

    /// Stops every reader and releases all transport handles.
    pub fn close(&self) {
        let mut state = self.state();
        state.stop_readers();
        state.raw.clear();
        for link in state.links.values() {
            link.close();
        }
        state.links.clear();
        state.graph.clear();
        state.members.clear();
        state.plane.table.store(Arc::default());
    }
}

/// A protocol's end-to-end channel, independent of its current next hop.
#[derive(Debug)]
pub struct PeerLink {
    network: NetworkId,
    peer: EndpointId,
    tag: u64,
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
        hop.send(envelope::encode(
            self.plane.local,
            *self.peer.as_bytes(),
            flow,
            self.tag,
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
            Some(route) if route.hops == 1 => route.next[0]
                .first_open()
                .map_or_else(|| "unreachable".into(), |link| link.path_description()),
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
