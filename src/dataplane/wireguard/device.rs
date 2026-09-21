//! Userspace WireGuard.
//!
//! The protocol itself is [`boringtun::noise::Tunn`], which is pure state
//! machine: no sockets, no TUN, no kernel module. That is what lets this work
//! the same way on any platform and be tested end to end without privileges.
//!
//! ```text
//!   TunDevice (IP packets)                 PacketLink per peer
//!        |                                        |
//!        v                                        v
//!   destination address -> peer  --Tunn.encapsulate-->  ciphertext
//!   source address checked       <--Tunn.decapsulate--  ciphertext
//! ```
//!
//! # Address ownership is enforced here
//!
//! Kernel WireGuard enforces `AllowedIPs`; in userspace we must do it
//! ourselves, and we do:
//!
//! * outbound, a packet is routed to the peer that **owns** its destination
//!   address, where ownership is the derivation in [`super::overlay`];
//! * inbound, a decrypted packet is dropped unless its **source** is exactly
//!   the address derived for the peer whose tunnel decrypted it.
//!
//! So a participant cannot receive traffic addressed to someone else, and
//! cannot forge traffic that appears to come from someone else, no matter
//! what it announced.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use bytes::Bytes;
use iroh::EndpointId;
use tokio::task::JoinHandle;

use crate::dataplane::PluginError;
use crate::dataplane::transport::{SharedLink, TransportError};
use crate::identity::NetworkId;

use super::keys::{WgPublicKey, WgSecretKey};
use super::overlay::{overlay_address, overlay_address_v4};
use super::packet::IpHeader;
use super::tun::TunDevice;

/// How often WireGuard's own timers are driven.
///
/// boringtun expects this at least every few hundred milliseconds; it is what
/// drives handshakes, rekeying and keepalives.
const TIMER_INTERVAL: Duration = Duration::from_millis(250);

/// Scratch space for one encapsulate or decapsulate call.
const SCRATCH: usize = 4096;

/// Counters for one peer's tunnel.
#[derive(Debug, Default)]
struct PeerCounters {
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    dropped_wrong_source: AtomicU64,
    dropped_oversize: AtomicU64,
    protocol_errors: AtomicU64,
}

/// A snapshot of one peer's tunnel counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Plaintext packets encrypted and sent to this peer.
    pub tx_packets: u64,
    /// Plaintext bytes encrypted and sent to this peer.
    pub tx_bytes: u64,
    /// Plaintext packets decrypted from this peer and given to the OS.
    pub rx_packets: u64,
    /// Plaintext bytes decrypted from this peer and given to the OS.
    pub rx_bytes: u64,
    /// Packets dropped because their source was not this peer's address.
    ///
    /// A non-zero value means a peer tried to use an address it does not own.
    pub dropped_wrong_source: u64,
    /// Packets dropped because they did not fit in one link datagram.
    pub dropped_oversize: u64,
    /// WireGuard protocol errors, including packets that failed to decrypt.
    pub protocol_errors: u64,
}

/// Whether a peer's tunnel has completed a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerHealth {
    /// Time since the last successful WireGuard handshake.
    ///
    /// `None` means no handshake has completed yet, so the tunnel is not
    /// carrying traffic. This is reported as it is, never guessed.
    pub since_handshake: Option<Duration>,
}

impl PeerHealth {
    /// Whether the tunnel has ever completed a handshake.
    pub fn is_up(&self) -> bool {
        self.since_handshake.is_some()
    }
}

struct Peer {
    endpoint_id: EndpointId,
    public_key: WgPublicKey,
    overlay: Ipv6Addr,
    /// The IPv4 address this peer owns, when the overlay is dual stack and
    /// nobody else derived the same one.
    overlay_v4: Mutex<Option<Ipv4Addr>>,
    tunn: Mutex<Tunn>,
    link: SharedLink,
    counters: Arc<PeerCounters>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("peer", &self.endpoint_id.fmt_short().to_string())
            .field("public_key", &self.public_key)
            .field("overlay", &self.overlay)
            .finish()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.task.lock()
            && let Some(task) = guard.take()
        {
            task.abort();
        }
    }
}

impl Peer {
    fn stats(&self) -> PeerStats {
        PeerStats {
            tx_packets: self.counters.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.counters.tx_bytes.load(Ordering::Relaxed),
            rx_packets: self.counters.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.counters.rx_bytes.load(Ordering::Relaxed),
            dropped_wrong_source: self.counters.dropped_wrong_source.load(Ordering::Relaxed),
            dropped_oversize: self.counters.dropped_oversize.load(Ordering::Relaxed),
            protocol_errors: self.counters.protocol_errors.load(Ordering::Relaxed),
        }
    }

    fn health(&self) -> PeerHealth {
        let guard = match self.tunn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        PeerHealth {
            since_handshake: guard.time_since_last_handshake(),
        }
    }
}

/// What a peer's tunnel looks like from outside.
#[derive(Debug, Clone)]
pub struct PeerSummary {
    /// The peer's control plane identity.
    pub endpoint_id: EndpointId,
    /// The peer's WireGuard public key.
    pub public_key: WgPublicKey,
    /// The overlay address this agent derived for it.
    pub overlay_address: Ipv6Addr,
    /// Its IPv4 overlay address, when the overlay is dual stack.
    ///
    /// `None` with `ipv4_conflict` set means another member derived the same
    /// address and won it; that peer is still fully reachable over IPv6.
    pub overlay_address_v4: Option<Ipv4Addr>,
    /// Whether this peer lost an IPv4 address to a derivation collision.
    pub ipv4_conflict: bool,
    /// Whether the tunnel has handshaken.
    pub health: PeerHealth,
    /// Traffic counters.
    pub stats: PeerStats,
    /// What the transport reports about the path carrying this tunnel.
    pub path: String,
    /// Largest datagram the link accepts.
    pub max_datagram: usize,
}

struct Inner {
    network: NetworkId,
    private_key: WgSecretKey,
    tun: Arc<dyn TunDevice>,
    /// The IPv4 overlay range, when the overlay is dual stack.
    ipv4_range: Option<(Ipv4Addr, u8)>,
    peers: RwLock<HashMap<WgPublicKey, Arc<Peer>>>,
    /// Both families, so one lookup routes any packet.
    routes: RwLock<HashMap<IpAddr, WgPublicKey>>,
    next_index: AtomicU32,
    unroutable: AtomicU64,
    multicast: AtomicU64,
    ipv4_conflicts: AtomicU64,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("network", &self.network.fmt_short())
            .field("tun", &self.tun.name())
            .finish()
    }
}

/// A userspace WireGuard interface for one network.
#[derive(Debug)]
pub struct WireguardDevice {
    inner: Arc<Inner>,
    tasks: Vec<JoinHandle<()>>,
}

impl WireguardDevice {
    /// Starts a device on top of `tun`.
    pub fn start(
        network: NetworkId,
        private_key: WgSecretKey,
        tun: Arc<dyn TunDevice>,
        ipv4_range: Option<(Ipv4Addr, u8)>,
    ) -> Self {
        let inner = Arc::new(Inner {
            network,
            private_key,
            tun,
            ipv4_range,
            peers: RwLock::new(HashMap::new()),
            routes: RwLock::new(HashMap::new()),
            next_index: AtomicU32::new(1),
            unroutable: AtomicU64::new(0),
            multicast: AtomicU64::new(0),
            ipv4_conflicts: AtomicU64::new(0),
        });

        let reader = tokio::spawn(read_from_os(Arc::clone(&inner)));
        let timers = tokio::spawn(drive_timers(Arc::clone(&inner)));

        Self {
            inner,
            tasks: vec![reader, timers],
        }
    }

    /// The interface name in use.
    pub fn interface(&self) -> &str {
        self.inner.tun.name()
    }

    /// The interface MTU.
    pub fn mtu(&self) -> u32 {
        self.inner.tun.mtu()
    }

    /// Adds or replaces a peer and starts its tunnel.
    pub fn add_peer(
        &self,
        endpoint_id: EndpointId,
        public_key: WgPublicKey,
        link: SharedLink,
        keepalive: Option<u16>,
    ) -> Result<(), PluginError> {
        if public_key == self.inner.private_key.public() {
            return Err(PluginError::Rejected(
                "refusing to add ourselves as a WireGuard peer".into(),
            ));
        }

        let index = self.inner.next_index.fetch_add(1, Ordering::Relaxed);
        let tunn = Tunn::new(
            self.inner.private_key.to_static_secret(),
            public_key.into_x25519(),
            None,
            keepalive,
            index,
            None,
        );

        let overlay = overlay_address(self.inner.network, &public_key);
        let overlay_v4 = self.claim_ipv4(&public_key);
        let peer = Arc::new(Peer {
            endpoint_id,
            public_key,
            overlay,
            overlay_v4: Mutex::new(overlay_v4),
            tunn: Mutex::new(tunn),
            link,
            counters: Arc::new(PeerCounters::default()),
            task: Mutex::new(None),
        });

        let task = tokio::spawn(read_from_link(Arc::clone(&self.inner), Arc::clone(&peer)));
        if let Ok(mut guard) = peer.task.lock() {
            *guard = Some(task);
        }

        write_lock(&self.inner.peers).insert(public_key, Arc::clone(&peer));
        write_lock(&self.inner.routes).insert(IpAddr::V6(overlay), public_key);
        if let Some(v4) = overlay_v4 {
            write_lock(&self.inner.routes).insert(IpAddr::V4(v4), public_key);
        }

        // Start the handshake now instead of waiting for the next timer tick,
        // so the tunnel is usable as soon as the link exists.
        kick_handshake(&peer);
        Ok(())
    }

    /// Decides which IPv4 address a new peer gets, if any.
    ///
    /// IPv4 has far too little room for a derived address to be collision
    /// free. When two members derive the same one, the member whose public
    /// key sorts lower keeps it — a rule every member computes identically,
    /// so they all agree on the outcome without talking about it. The other
    /// member simply has no IPv4 address; it is still fully reachable over
    /// IPv6, which never collides.
    fn claim_ipv4(&self, public_key: &WgPublicKey) -> Option<Ipv4Addr> {
        let range = self.inner.ipv4_range?;
        let wanted = overlay_address_v4(self.inner.network, public_key, range)?;

        let holder = read_lock(&self.inner.routes)
            .get(&IpAddr::V4(wanted))
            .copied();
        let Some(holder) = holder else {
            return Some(wanted);
        };
        if holder == *public_key {
            return Some(wanted);
        }

        self.inner.ipv4_conflicts.fetch_add(1, Ordering::Relaxed);
        if holder.as_bytes() <= public_key.as_bytes() {
            // The peer already holding it wins.
            return None;
        }
        // The newcomer wins; take the address away from the other peer.
        if let Some(loser) = read_lock(&self.inner.peers).get(&holder).cloned() {
            let mut slot = match loser.overlay_v4.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *slot = None;
        }
        Some(wanted)
    }

    /// Removes a peer and stops its tunnel.
    pub fn remove_peer(&self, public_key: &WgPublicKey) {
        if let Some(peer) = write_lock(&self.inner.peers).remove(public_key) {
            let mut routes = write_lock(&self.inner.routes);
            routes.remove(&IpAddr::V6(peer.overlay));
            let v4 = match peer.overlay_v4.lock() {
                Ok(guard) => *guard,
                Err(poisoned) => *poisoned.into_inner(),
            };
            if let Some(v4) = v4 {
                routes.remove(&IpAddr::V4(v4));
            }
        }
    }

    /// How many IPv4 derivation collisions have been resolved.
    pub fn ipv4_conflicts(&self) -> u64 {
        self.inner.ipv4_conflicts.load(Ordering::Relaxed)
    }

    /// Removes every peer whose key is not in `keep`.
    pub fn retain_peers(&self, keep: &[WgPublicKey]) {
        let stale: Vec<WgPublicKey> = read_lock(&self.inner.peers)
            .keys()
            .filter(|key| !keep.contains(key))
            .copied()
            .collect();
        for key in stale {
            self.remove_peer(&key);
        }
    }

    /// Whether a peer's tunnel exists.
    pub fn has_peer(&self, public_key: &WgPublicKey) -> bool {
        read_lock(&self.inner.peers).contains_key(public_key)
    }

    /// A snapshot of every peer.
    pub fn peers(&self) -> Vec<PeerSummary> {
        let mut peers: Vec<PeerSummary> = read_lock(&self.inner.peers)
            .values()
            .map(|peer| {
                let overlay_v4 = match peer.overlay_v4.lock() {
                    Ok(guard) => *guard,
                    Err(poisoned) => *poisoned.into_inner(),
                };
                PeerSummary {
                    endpoint_id: peer.endpoint_id,
                    public_key: peer.public_key,
                    overlay_address: peer.overlay,
                    overlay_address_v4: overlay_v4,
                    ipv4_conflict: overlay_v4.is_none() && self.inner.ipv4_range.is_some(),
                    health: peer.health(),
                    stats: peer.stats(),
                    path: peer.link.path_description(),
                    max_datagram: peer.link.max_datagram_size(),
                }
            })
            .collect();
        peers.sort_by_key(|peer| peer.public_key);
        peers
    }

    /// Unicast packets the operating system sent to an address no peer owns.
    ///
    /// A non-zero value means something tried to reach a host that is not in
    /// the overlay.
    pub fn unroutable_packets(&self) -> u64 {
        self.inner.unroutable.load(Ordering::Relaxed)
    }

    /// Multicast packets dropped.
    ///
    /// Expected and harmless: Linux emits multicast listener and router
    /// solicitation traffic on any IPv6 interface, and this overlay is
    /// unicast only. Counted separately so it does not look like a fault.
    pub fn multicast_packets(&self) -> u64 {
        self.inner.multicast.load(Ordering::Relaxed)
    }
}

impl Drop for WireguardDevice {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Asks boringtun for a handshake initiation and sends it.
///
/// Encapsulating an empty packet is how the protocol state machine is told
/// "there is something to say"; with no session yet it answers with the
/// handshake initiation.
fn kick_handshake(peer: &Peer) {
    let mut scratch = vec![0u8; SCRATCH];
    let len = {
        let mut tunn = match peer.tunn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match tunn.encapsulate(&[], &mut scratch) {
            TunnResult::WriteToNetwork(out) => Some(out.len()),
            _ => None,
        }
    };
    if let Some(len) = len {
        send_to_peer(peer, &scratch[..len]);
    }
}

/// Sends whatever boringtun produced, without holding the tunnel lock.
fn send_to_peer(peer: &Peer, payload: &[u8]) {
    match peer.link.send(Bytes::copy_from_slice(payload)) {
        Ok(()) => {}
        Err(TransportError::TooLarge { .. }) => {
            peer.counters
                .dropped_oversize
                .fetch_add(1, Ordering::Relaxed);
        }
        Err(TransportError::Closed) => {}
        Err(err) => {
            tracing::trace!(%err, "dropping a WireGuard packet the link refused");
        }
    }
}

/// Operating system -> peer.
async fn read_from_os(inner: Arc<Inner>) {
    loop {
        let Some(packet) = inner.tun.recv().await else {
            return;
        };

        // Route by destination: only the peer that owns that overlay address
        // may receive it. Both families go through the same table.
        let Some(destination) = IpHeader::parse(&packet).map(|header| header.destination()) else {
            inner.unroutable.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        // The kernel emits multicast on every IPv6 interface. The overlay is
        // unicast only, so this is dropped, but it is not a fault.
        if destination.is_multicast() {
            inner.multicast.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let target = read_lock(&inner.routes).get(&destination).copied();
        let Some(target) = target else {
            inner.unroutable.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let peer = read_lock(&inner.peers).get(&target).cloned();
        let Some(peer) = peer else {
            inner.unroutable.fetch_add(1, Ordering::Relaxed);
            continue;
        };

        let mut scratch = vec![0u8; SCRATCH];
        let outcome = {
            let mut tunn = match peer.tunn.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            match tunn.encapsulate(&packet, &mut scratch) {
                TunnResult::WriteToNetwork(out) => Some(out.len()),
                TunnResult::Done => None,
                TunnResult::Err(err) => {
                    tracing::trace!(?err, "wireguard encapsulation failed");
                    peer.counters
                        .protocol_errors
                        .fetch_add(1, Ordering::Relaxed);
                    None
                }
                _ => None,
            }
        };

        if let Some(len) = outcome {
            send_to_peer(&peer, &scratch[..len]);
            peer.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
            peer.counters
                .tx_bytes
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
        }
    }
}

/// Peer -> operating system.
async fn read_from_link(inner: Arc<Inner>, peer: Arc<Peer>) {
    loop {
        let Some(datagram) = peer.link.recv().await else {
            return;
        };

        let mut scratch = vec![0u8; SCRATCH];
        // boringtun may need several passes: a handshake reply first, then
        // any packets that were queued while the session was coming up.
        let mut input: Option<&[u8]> = Some(&datagram);
        loop {
            let outcome = {
                let mut tunn = match peer.tunn.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match tunn.decapsulate(None, input.unwrap_or(&[]), &mut scratch) {
                    TunnResult::WriteToNetwork(out) => Outcome::ToNetwork(out.len()),
                    TunnResult::WriteToTunnelV6(out, source) => {
                        Outcome::ToTunnel(out.len(), IpAddr::V6(source))
                    }
                    TunnResult::WriteToTunnelV4(out, source) => {
                        Outcome::ToTunnel(out.len(), IpAddr::V4(source))
                    }
                    TunnResult::Done => Outcome::Done,
                    TunnResult::Err(err) => {
                        tracing::trace!(?err, "wireguard decapsulation failed");
                        Outcome::Failed
                    }
                }
            };

            match outcome {
                Outcome::ToNetwork(len) => {
                    send_to_peer(&peer, &scratch[..len]);
                    // Keep draining with an empty datagram, as boringtun asks.
                    input = None;
                    continue;
                }
                Outcome::ToTunnel(len, source) => {
                    let payload = Bytes::copy_from_slice(&scratch[..len]);
                    // Enforce address ownership: a peer may only send from an
                    // address derived for its own key, in either family.
                    let owned = match source {
                        IpAddr::V6(addr) => addr == peer.overlay,
                        IpAddr::V4(addr) => {
                            let held = match peer.overlay_v4.lock() {
                                Ok(guard) => *guard,
                                Err(poisoned) => *poisoned.into_inner(),
                            };
                            held == Some(addr)
                        }
                    };
                    if !owned {
                        peer.counters
                            .dropped_wrong_source
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    if inner.tun.send(payload).await.is_ok() {
                        peer.counters.rx_packets.fetch_add(1, Ordering::Relaxed);
                        peer.counters
                            .rx_bytes
                            .fetch_add(len as u64, Ordering::Relaxed);
                    }
                    break;
                }
                Outcome::Failed => {
                    peer.counters
                        .protocol_errors
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Outcome::Done => break,
            }
        }
    }
}

enum Outcome {
    ToNetwork(usize),
    ToTunnel(usize, IpAddr),
    Done,
    Failed,
}

/// Drives WireGuard's handshake, rekey and keepalive timers.
async fn drive_timers(inner: Arc<Inner>) {
    let mut ticker = tokio::time::interval(TIMER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let peers: Vec<Arc<Peer>> = read_lock(&inner.peers).values().cloned().collect();
        for peer in peers {
            let mut scratch = vec![0u8; SCRATCH];
            let len = {
                let mut tunn = match peer.tunn.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match tunn.update_timers(&mut scratch) {
                    TunnResult::WriteToNetwork(out) => Some(out.len()),
                    TunnResult::Err(err) => {
                        tracing::trace!(?err, "wireguard timer produced an error");
                        None
                    }
                    _ => None,
                }
            };
            if let Some(len) = len {
                send_to_peer(&peer, &scratch[..len]);
            }
        }
    }
}
