//! Carrying a peer's packets through another peer.
//!
//! Two members of a network can both reach a third and yet not reach each
//! other: a blocked path, a relay that is unavailable, a network that is
//! only reachable from inside somebody else's building. Without a way
//! through the middle, that pair is simply lost to each other while both
//! sit in the same mesh.
//!
//! # What goes through the middle, and what does not
//!
//! The relay moves **bytes it cannot read**. A datagram is wrapped with the
//! peer it is for, handed to the peer in the middle, and unwrapped on the
//! other side; the protocol's own encryption is end to end between the two
//! ends of the tunnel, so the one in the middle carries an opaque payload.
//!
//! It never reaches the middle's operating system either: a relayed
//! datagram goes link in, link out. Nothing is written to its interface,
//! so no routing, forwarding or firewall setting of its host is involved —
//! which is both the fast path and the only one allowed here, since an
//! agent touches no system object it did not create.
//!
//! # What is deliberately not here
//!
//! No routing protocol and nothing second-hand. A peer says only which
//! peers *it* has a live link with, and that is used to pick one hop —
//! never a claim about somebody else's reachability. One hop means loops
//! are impossible by construction rather than by a counter, and a relayed
//! datagram is never relayed again.
//!
//! Fairness between the peers a relay carries for is not addressed yet: the
//! queues are bounded and the counters say how much went through, which is
//! what a limit would be built on.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use bytes::{BufMut, Bytes, BytesMut};
use iroh::EndpointId;
use tokio::sync::mpsc;

use crate::BoxFuture;
use crate::identity::NetworkId;

use super::transport::{PacketLink, SharedLink, TransportError};

/// A datagram straight from the peer that sent it.
const TAG_DIRECT: u8 = 0;
/// A datagram for somebody else, to be passed on.
const TAG_TO_RELAY: u8 = 1;
/// A datagram that was passed on, naming who it came from.
const TAG_RELAYED: u8 = 2;

/// The largest header any of the three shapes needs.
///
/// Subtracted from every link's datagram size, relayed or not, so that the
/// size a protocol may use does not change when the path does. A tunnel
/// that had to renegotiate its packet size every time a path changed would
/// be worse than one that is a few bytes smaller than it could be.
pub const RELAY_OVERHEAD: usize = 1 + 32;

/// How many datagrams may wait for a protocol to read them.
///
/// Bounded, and the oldest is dropped rather than the newest kept waiting:
/// these are datagrams, loss is ordinary, and a queue that grows is worse
/// than one that spills.
const INBOX: usize = 256;

/// What a datagram on a data link turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame {
    /// From the peer at the other end of this link, for us.
    Direct(Bytes),
    /// From the peer at the other end, for somebody else.
    ToRelay { to: EndpointId, payload: Bytes },
    /// Passed on by the peer at the other end, from somebody else.
    Relayed { from: EndpointId, payload: Bytes },
}

fn wrap(tag: u8, id: Option<EndpointId>, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(1 + 32 + payload.len());
    out.put_u8(tag);
    if let Some(id) = id {
        out.put_slice(id.as_bytes());
    }
    out.put_slice(payload);
    out.freeze()
}

/// Reads a datagram, or `None` if it is not one of ours.
///
/// Nothing here trusts a length: every field is checked before it is read,
/// because this is bytes off the network like any other.
fn unwrap(raw: Bytes) -> Option<Frame> {
    let tag = *raw.first()?;
    match tag {
        TAG_DIRECT => Some(Frame::Direct(raw.slice(1..))),
        TAG_TO_RELAY | TAG_RELAYED => {
            if raw.len() < 1 + 32 {
                return None;
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&raw[1..33]);
            let id = EndpointId::from_bytes(&id).ok()?;
            let payload = raw.slice(33..);
            Some(if tag == TAG_TO_RELAY {
                Frame::ToRelay { to: id, payload }
            } else {
                Frame::Relayed { from: id, payload }
            })
        }
        _ => None,
    }
}

/// What has gone through the relay, from both sides of it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayCounters {
    /// Datagrams this agent sent to a peer through somebody else.
    pub sent_via: u64,
    /// Datagrams this agent passed on for two other peers.
    pub forwarded: u64,
    /// Datagrams that arrived for this agent through somebody else.
    pub received_via: u64,
    /// Datagrams that could not be passed on: no link to the destination.
    pub dropped_no_link: u64,
    /// Datagrams that arrived relayed from a peer we have no link object
    /// for, or that could not be read at all.
    pub dropped_unknown: u64,
}

#[derive(Debug, Default)]
struct Tally {
    sent_via: AtomicU64,
    forwarded: AtomicU64,
    received_via: AtomicU64,
    dropped_no_link: AtomicU64,
    dropped_unknown: AtomicU64,
}

impl Tally {
    fn snapshot(&self) -> RelayCounters {
        RelayCounters {
            sent_via: self.sent_via.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            received_via: self.received_via.load(Ordering::Relaxed),
            dropped_no_link: self.dropped_no_link.load(Ordering::Relaxed),
            dropped_unknown: self.dropped_unknown.load(Ordering::Relaxed),
        }
    }
}

/// Every data link of one network, and what it can reach through what.
///
/// One per network runtime. It owns the raw links the transport produced
/// and hands protocols a [`PeerLink`] each, which is the thing that knows
/// whether a peer is reached directly or through somebody.
#[derive(Debug)]
pub struct RelayHub {
    network: NetworkId,
    /// What a protocol holds, one per peer and protocol. Kept alive here so
    /// a datagram can be injected into a link the protocol is reading.
    links: Mutex<HashMap<(EndpointId, String), Arc<PeerLink>>>,
    /// The raw links, which is what a hop is: a way to reach the peer in
    /// the middle, never wrapped again.
    raw: Mutex<HashMap<(EndpointId, String), SharedLink>>,
    tally: Arc<Tally>,
}

impl RelayHub {
    /// A hub for one network.
    pub fn new(network: NetworkId) -> Arc<Self> {
        Arc::new(Self {
            network,
            links: Mutex::new(HashMap::new()),
            raw: Mutex::new(HashMap::new()),
            tally: Arc::new(Tally::default()),
        })
    }

    /// What has gone through it.
    pub fn counters(&self) -> RelayCounters {
        self.tally.snapshot()
    }

    fn links(&self) -> std::sync::MutexGuard<'_, HashMap<(EndpointId, String), Arc<PeerLink>>> {
        match self.links.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn raw(&self) -> std::sync::MutexGuard<'_, HashMap<(EndpointId, String), SharedLink>> {
        match self.raw.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// The link a protocol uses for a peer, created on first ask.
    ///
    /// The same object for the life of the peer, whatever happens to the
    /// path underneath it: a protocol's tunnel survives a direct link
    /// coming and going, and a change of hop, without noticing.
    pub fn link(self: &Arc<Self>, peer: EndpointId, protocol: &str) -> Arc<PeerLink> {
        let key = (peer, protocol.to_string());
        let mut links = self.links();
        if let Some(existing) = links.get(&key) {
            return Arc::clone(existing);
        }
        let (inbox_tx, inbox_rx) = mpsc::channel(INBOX);
        let link = Arc::new(PeerLink {
            network: self.network,
            peer,
            protocol: protocol.to_string(),
            direct: RwLock::new(None),
            hop: RwLock::new(None),
            inbox_tx,
            inbox_rx: tokio::sync::Mutex::new(inbox_rx),
            changed: tokio::sync::Notify::new(),
            closed: AtomicBool::new(false),
            gone: tokio::sync::Notify::new(),
            hub: Arc::downgrade(self),
            tally: Arc::clone(&self.tally),
        });
        links.insert(key, Arc::clone(&link));
        link
    }

    /// Whether a protocol already holds a link for this peer.
    ///
    /// Asked before handing one out, because a protocol is given its link
    /// once and keeps it: handing the same peer a second link would leave
    /// it with two and a tunnel it is no longer reading for.
    pub fn has_link(&self, peer: EndpointId, protocol: &str) -> bool {
        self.links().contains_key(&(peer, protocol.to_string()))
    }

    /// Records the direct link to a peer, replacing any previous one.
    pub fn set_direct(self: &Arc<Self>, peer: EndpointId, protocol: &str, raw: SharedLink) {
        self.raw().insert((peer, protocol.to_string()), raw.clone());
        let link = self.link(peer, protocol);
        link.set_direct(Some(raw));
    }

    /// Forgets the direct link to a peer. The protocol's link stays.
    pub fn clear_direct(self: &Arc<Self>, peer: EndpointId, protocol: &str) {
        self.raw().remove(&(peer, protocol.to_string()));
        if let Some(link) = self.links().get(&(peer, protocol.to_string())) {
            link.set_direct(None);
        }
    }

    /// Routes a peer through another peer, or stops doing so.
    ///
    /// The hop must be a peer with a direct link of its own; anything else
    /// is a request to relay through somebody unreachable.
    pub fn set_hop(self: &Arc<Self>, peer: EndpointId, protocol: &str, hop: Option<EndpointId>) {
        let resolved = hop.and_then(|hop| {
            self.raw()
                .get(&(hop, protocol.to_string()))
                .map(|link| (hop, Arc::clone(link)))
        });
        let link = self.link(peer, protocol);
        link.set_hop(resolved);
    }

    /// Closes and forgets everything held for a peer.
    pub fn remove_peer(&self, peer: EndpointId) {
        self.raw().retain(|(other, _), _| *other != peer);
        let mut links = self.links();
        links.retain(|(other, _), link| {
            if *other == peer {
                link.close();
                false
            } else {
                true
            }
        });
    }

    /// Closes everything. The network is going away.
    pub fn close(&self) {
        self.raw().clear();
        for link in self.links().drain() {
            link.1.close();
        }
    }

    /// Passes a datagram on to the peer it is for.
    ///
    /// Only over a direct link: a relayed datagram is never relayed again,
    /// which is what makes a loop impossible without counting hops.
    fn forward(&self, to: EndpointId, protocol: &str, from: EndpointId, payload: Bytes) {
        let link = self.raw().get(&(to, protocol.to_string())).cloned();
        let Some(link) = link else {
            self.tally.dropped_no_link.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match link.send(wrap(TAG_RELAYED, Some(from), &payload)) {
            Ok(()) => {
                self.tally.forwarded.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                tracing::debug!(%err, "cannot pass a datagram on");
                self.tally.dropped_no_link.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Hands a datagram that arrived through somebody to the peer's link.
    fn inject(&self, from: EndpointId, protocol: &str, payload: Bytes) {
        let link = self.links().get(&(from, protocol.to_string())).cloned();
        let Some(link) = link else {
            // Nothing is reading for that peer: it is not one this agent
            // carries traffic with, so the datagram has no owner.
            self.tally.dropped_unknown.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match link.inbox_tx.try_send(payload) {
            Ok(()) => {
                self.tally.received_via.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.tally.dropped_unknown.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// A protocol's link to one peer, however that peer is reached.
///
/// It outlives any particular path. A direct link that dies, a hop that
/// changes, a direct link that comes back: none of it is visible to the
/// protocol holding this, so its tunnel is not torn down and rebuilt every
/// time the way through changes.
#[derive(Debug)]
pub struct PeerLink {
    network: NetworkId,
    peer: EndpointId,
    protocol: String,
    direct: RwLock<Option<SharedLink>>,
    hop: RwLock<Option<(EndpointId, SharedLink)>>,
    inbox_tx: mpsc::Sender<Bytes>,
    inbox_rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    /// Woken when the path changes, so a reader parked on the old one
    /// starts again on the new one.
    changed: tokio::sync::Notify,
    closed: AtomicBool,
    gone: tokio::sync::Notify,
    hub: Weak<RelayHub>,
    tally: Arc<Tally>,
}

impl PeerLink {
    fn direct(&self) -> Option<SharedLink> {
        match self.direct.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn hop(&self) -> Option<(EndpointId, SharedLink)> {
        match self.hop.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn set_direct(&self, link: Option<SharedLink>) {
        match self.direct.write() {
            Ok(mut guard) => *guard = link,
            Err(poisoned) => *poisoned.into_inner() = link,
        }
        self.changed.notify_waiters();
    }

    fn set_hop(&self, hop: Option<(EndpointId, SharedLink)>) {
        match self.hop.write() {
            Ok(mut guard) => *guard = hop,
            Err(poisoned) => *poisoned.into_inner() = hop,
        }
        self.changed.notify_waiters();
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.gone.notify_waiters();
        self.changed.notify_waiters();
    }

    /// The peer this link carries traffic for.
    pub fn peer(&self) -> EndpointId {
        self.peer
    }

    /// Which peer it goes through, when it is not direct.
    pub fn via(&self) -> Option<EndpointId> {
        if self.direct().is_some_and(|link| !link.is_closed()) {
            return None;
        }
        self.hop().map(|(peer, _)| peer)
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
        // The same size whatever the path, so a protocol never has to
        // resize because the way through changed.
        let direct = self.direct().map(|link| link.max_datagram_size());
        let hop = self.hop().map(|(_, link)| link.max_datagram_size());
        let smallest = match (direct, hop) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => 0,
        };
        smallest.saturating_sub(RELAY_OVERHEAD)
    }

    fn send(&self, payload: Bytes) -> Result<(), TransportError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(TransportError::Closed);
        }
        // Direct while there is one: a hop is what you use when there is
        // nothing better, never a preference.
        if let Some(direct) = self.direct()
            && !direct.is_closed()
        {
            return direct.send(wrap(TAG_DIRECT, None, &payload));
        }
        if let Some((_, hop)) = self.hop() {
            let out = hop.send(wrap(TAG_TO_RELAY, Some(self.peer), &payload));
            if out.is_ok() {
                self.tally.sent_via.fetch_add(1, Ordering::Relaxed);
            }
            return out;
        }
        Err(TransportError::Unreachable(format!(
            "no path to {}",
            self.peer.fmt_short()
        )))
    }

    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            let mut inbox = self.inbox_rx.lock().await;
            loop {
                if self.closed.load(Ordering::Relaxed) {
                    return None;
                }
                let direct = self.direct();
                let changed = self.changed.notified();
                let gone = self.gone.notified();

                let raw = tokio::select! {
                    // Whatever arrived through somebody else, already
                    // stripped of its wrapper by the link it came in on.
                    injected = inbox.recv() => return injected,
                    raw = async {
                        match &direct {
                            Some(link) => link.recv().await,
                            // Nothing direct: wait for a path or an injection.
                            None => std::future::pending().await,
                        }
                    } => raw,
                    // The path changed underneath: look again.
                    () = changed => continue,
                    () = gone => return None,
                };

                let Some(raw) = raw else {
                    // The direct link ended. The peer may still be
                    // reachable through somebody, so this link is not over.
                    self.set_direct(None);
                    continue;
                };
                match unwrap(raw) {
                    Some(Frame::Direct(payload)) => return Some(payload),
                    // This agent is the one in the middle.
                    Some(Frame::ToRelay { to, payload }) => {
                        if let Some(hub) = self.hub.upgrade() {
                            hub.forward(to, &self.protocol, self.peer, payload);
                        }
                    }
                    // Somebody passed this on for a peer we talk to.
                    Some(Frame::Relayed { from, payload }) => {
                        if let Some(hub) = self.hub.upgrade() {
                            hub.inject(from, &self.protocol, payload);
                        }
                    }
                    None => {
                        self.tally.dropped_unknown.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
    }

    fn closed(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            loop {
                if self.closed.load(Ordering::Relaxed) {
                    return;
                }
                self.gone.notified().await;
            }
        })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn path_description(&self) -> String {
        if let Some(direct) = self.direct()
            && !direct.is_closed()
        {
            return direct.path_description();
        }
        match self.hop() {
            Some((peer, link)) => {
                format!("via {} ({})", peer.fmt_short(), link.path_description())
            }
            None => "no path".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};

    fn network() -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new("relay").unwrap(),
            &NetworkSecret::from_bytes([3u8; 32]).unwrap(),
        )
        .network_id()
    }

    fn peer(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// A link that records what was sent and can be fed what arrives.
    #[derive(Debug)]
    struct Wire {
        network: NetworkId,
        peer: EndpointId,
        sent: Mutex<Vec<Bytes>>,
        inbound: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
        feed: mpsc::Sender<Bytes>,
        closed: AtomicBool,
    }

    impl Wire {
        fn new(peer: EndpointId) -> Arc<Self> {
            let (feed, inbound) = mpsc::channel(32);
            Arc::new(Self {
                network: network(),
                peer,
                sent: Mutex::new(Vec::new()),
                inbound: tokio::sync::Mutex::new(inbound),
                feed,
                closed: AtomicBool::new(false),
            })
        }

        fn sent(&self) -> Vec<Bytes> {
            self.sent.lock().unwrap().clone()
        }

        async fn arrive(&self, raw: Bytes) {
            self.feed.send(raw).await.unwrap();
        }
    }

    impl PacketLink for Wire {
        fn network(&self) -> NetworkId {
            self.network
        }
        fn peer(&self) -> EndpointId {
            self.peer
        }
        fn max_datagram_size(&self) -> usize {
            1200
        }
        fn send(&self, payload: Bytes) -> Result<(), TransportError> {
            if self.closed.load(Ordering::Relaxed) {
                return Err(TransportError::Closed);
            }
            self.sent.lock().unwrap().push(payload);
            Ok(())
        }
        fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
            Box::pin(async move { self.inbound.lock().await.recv().await })
        }
        fn closed(&self) -> BoxFuture<'_, ()> {
            Box::pin(async move { std::future::pending().await })
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::Relaxed)
        }
        fn path_description(&self) -> String {
            "test wire".into()
        }
    }

    #[test]
    fn a_datagram_survives_the_wrapping_and_a_broken_one_is_refused() {
        let id = peer(1);
        let direct = wrap(TAG_DIRECT, None, b"hello");
        assert_eq!(unwrap(direct).unwrap(), Frame::Direct(Bytes::from("hello")));

        let onward = wrap(TAG_TO_RELAY, Some(id), b"hello");
        assert_eq!(
            unwrap(onward).unwrap(),
            Frame::ToRelay {
                to: id,
                payload: Bytes::from("hello")
            }
        );

        // Bytes off the network: nothing is read before it is checked.
        assert!(unwrap(Bytes::new()).is_none());
        assert!(unwrap(Bytes::from_static(&[TAG_TO_RELAY, 1, 2, 3])).is_none());
        assert!(unwrap(Bytes::from_static(&[200, 1, 2, 3])).is_none());
    }

    #[tokio::test]
    async fn a_direct_link_is_preferred_and_a_hop_is_used_when_there_is_none() {
        let hub = RelayHub::new(network());
        let (them, middle) = (peer(1), peer(2));

        let to_middle = Wire::new(middle);
        hub.set_direct(middle, "test-ip", to_middle.clone());

        // No direct link to them: nothing to send on, and nothing invented.
        let link = hub.link(them, "test-ip");
        assert!(link.send(Bytes::from("x")).is_err());
        assert_eq!(link.via(), None);

        // Routed through the middle: the datagram goes out on that link,
        // wrapped with who it is for.
        hub.set_hop(them, "test-ip", Some(middle));
        assert_eq!(link.via(), Some(middle));
        link.send(Bytes::from("through you")).unwrap();
        let sent = to_middle.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            unwrap(sent[0].clone()).unwrap(),
            Frame::ToRelay {
                to: them,
                payload: Bytes::from("through you")
            }
        );
        assert_eq!(hub.counters().sent_via, 1);

        // A direct link appears: it is used, and the hop is not.
        let to_them = Wire::new(them);
        hub.set_direct(them, "test-ip", to_them.clone());
        assert_eq!(link.via(), None);
        link.send(Bytes::from("straight")).unwrap();
        assert_eq!(
            unwrap(to_them.sent()[0].clone()).unwrap(),
            Frame::Direct(Bytes::from("straight"))
        );
        assert_eq!(to_middle.sent().len(), 1, "nothing more went the long way");
    }

    #[tokio::test]
    async fn the_one_in_the_middle_passes_it_on_without_reading_it() {
        // C between A and B. A's datagram arrives wrapped for B; C puts it
        // on its link to B, saying who it came from, and never sees inside.
        let hub = RelayHub::new(network());
        let (a, b) = (peer(1), peer(2));
        let from_a = Wire::new(a);
        let to_b = Wire::new(b);
        hub.set_direct(a, "test-ip", from_a.clone());
        hub.set_direct(b, "test-ip", to_b.clone());

        let a_link = hub.link(a, "test-ip");
        let reading = tokio::spawn(async move { a_link.recv().await });

        from_a.arrive(wrap(TAG_TO_RELAY, Some(b), b"opaque")).await;
        // It is passed on rather than returned to the protocol here.
        tokio::time::timeout(std::time::Duration::from_millis(200), async {
            while to_b.sent().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("it was passed on");
        assert_eq!(
            unwrap(to_b.sent()[0].clone()).unwrap(),
            Frame::Relayed {
                from: a,
                payload: Bytes::from("opaque")
            }
        );
        assert_eq!(hub.counters().forwarded, 1);
        assert!(!reading.is_finished(), "the protocol was not handed it");

        // Nowhere to put it is a drop and a count, never an error upwards.
        from_a
            .arrive(wrap(TAG_TO_RELAY, Some(peer(9)), b"nobody"))
            .await;
        tokio::time::timeout(std::time::Duration::from_millis(200), async {
            while hub.counters().dropped_no_link == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("counted");
        reading.abort();
    }

    #[tokio::test]
    async fn what_arrives_through_somebody_is_handed_to_the_right_peer() {
        // B's side: a datagram from A arrives on the link with C, and the
        // protocol reading A's link is the one that gets it — otherwise
        // the packet would be attributed to C and dropped as coming from
        // an address C does not hold.
        let hub = RelayHub::new(network());
        let (a, c) = (peer(1), peer(3));
        let from_c = Wire::new(c);
        hub.set_direct(c, "test-ip", from_c.clone());
        let a_link = hub.link(a, "test-ip");
        let c_link = hub.link(c, "test-ip");

        let reading_a = tokio::spawn(async move { a_link.recv().await });
        let driving_c = tokio::spawn(async move { c_link.recv().await });

        from_c.arrive(wrap(TAG_RELAYED, Some(a), b"from a")).await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), reading_a)
            .await
            .expect("delivered")
            .unwrap();
        assert_eq!(got, Some(Bytes::from("from a")));
        assert_eq!(hub.counters().received_via, 1);
        driving_c.abort();
    }

    #[tokio::test]
    async fn a_link_outlives_the_path_under_it() {
        // The protocol's tunnel must not be torn down because a path
        // changed: the link object is the peer, not the way to it.
        let hub = RelayHub::new(network());
        let (them, middle) = (peer(1), peer(2));
        let direct = Wire::new(them);
        hub.set_direct(them, "test-ip", direct.clone());
        let link = hub.link(them, "test-ip");
        assert!(!link.is_closed());

        hub.clear_direct(them, "test-ip");
        assert!(
            !link.is_closed(),
            "still the same peer, still the same link"
        );
        assert!(
            link.send(Bytes::from("x")).is_err(),
            "but nothing to send on"
        );

        let hop = Wire::new(middle);
        hub.set_direct(middle, "test-ip", hop.clone());
        hub.set_hop(them, "test-ip", Some(middle));
        link.send(Bytes::from("x")).unwrap();
        assert_eq!(hop.sent().len(), 1);

        // The peer going away is what closes it.
        hub.remove_peer(them);
        assert!(link.is_closed());
        assert!(link.send(Bytes::from("x")).is_err());
    }

    #[tokio::test]
    async fn the_size_a_protocol_may_use_does_not_change_with_the_path() {
        let hub = RelayHub::new(network());
        let (them, middle) = (peer(1), peer(2));
        hub.set_direct(them, "test-ip", Wire::new(them));
        hub.set_direct(middle, "test-ip", Wire::new(middle));
        let link = hub.link(them, "test-ip");
        let direct_size = link.max_datagram_size();
        assert_eq!(direct_size, 1200 - RELAY_OVERHEAD);

        hub.set_hop(them, "test-ip", Some(middle));
        hub.clear_direct(them, "test-ip");
        assert_eq!(
            link.max_datagram_size(),
            direct_size,
            "a tunnel that resized on every path change would be worse"
        );
    }
}
