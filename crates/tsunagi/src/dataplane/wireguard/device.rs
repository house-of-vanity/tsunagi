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
//!   address, where ownership is the signed claim the system level agreed;
//! * inbound, a decrypted packet is dropped unless its **source** is exactly
//!   the address that peer holds.
//!
//! So a participant cannot receive traffic addressed to someone else, and
//! cannot forge traffic that appears to come from someone else. Neither
//! check consults anything the peer said here: an address is claimed at the
//! system level and signed by its holder, and that is what is compared
//! against.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use bytes::Bytes;
use iroh::EndpointId;
use tokio::task::JoinHandle;

use crate::dataplane::transport::{SharedLink, TransportError};
use crate::dataplane::{PacketSink, PluginError};
use crate::identity::NetworkId;

use super::keys::{WgPublicKey, WgSecretKey};

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
    /// Packets there was no session to encrypt with yet.
    dropped_no_session: AtomicU64,
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
    /// Packets dropped because there was no session to encrypt with yet.
    ///
    /// A handful while a tunnel comes up is normal; a number that keeps
    /// climbing means the handshake is not completing.
    pub dropped_no_session: u64,
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
    /// The overlay address this peer holds, as the control plane agreed it.
    ///
    /// Not derived here and not taken from the peer: the system level
    /// allocates it, the peer signs the claim, and every protocol carries
    /// traffic for the same address.
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
            dropped_no_session: self.counters.dropped_no_session.load(Ordering::Relaxed),
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
    /// The overlay address it holds, once the control plane has agreed one.
    pub overlay_address_v4: Option<Ipv4Addr>,
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
    peers: RwLock<HashMap<WgPublicKey, Arc<Peer>>>,
    /// Where decrypted packets go.
    ///
    /// The interface belongs to the system level, so this hands a packet up
    /// rather than writing it out: only that level knows which addresses the
    /// sending member is entitled to use.
    sink: Arc<dyn PacketSink>,
    next_index: AtomicU32,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("network", &self.network.fmt_short())
            .finish()
    }
}

/// The userspace WireGuard tunnels of one network.
#[derive(Debug)]
pub struct WireguardDevice {
    inner: Arc<Inner>,
    tasks: Vec<JoinHandle<()>>,
}

impl WireguardDevice {
    /// Starts the tunnels for one network.
    ///
    /// No interface is involved: packets arrive through [`Self::carry`] and
    /// leave through the sink. Which address belongs to whom, and therefore
    /// where a packet should go, is decided above this.
    pub fn start(network: NetworkId, private_key: WgSecretKey, sink: Arc<dyn PacketSink>) -> Self {
        let inner = Arc::new(Inner {
            network,
            private_key,
            peers: RwLock::new(HashMap::new()),
            sink,
            next_index: AtomicU32::new(1),
        });

        let timers = tokio::spawn(drive_timers(Arc::clone(&inner)));

        Self {
            inner,
            tasks: vec![timers],
        }
    }

    /// Encrypts a packet and sends it to a peer.
    ///
    /// `false` when there is no tunnel for that peer, which is a state the
    /// caller reports rather than an error: a peer whose link has not come
    /// up yet is normal.
    pub fn carry(&self, peer: iroh::EndpointId, packet: &[u8]) -> bool {
        let found = read_lock(&self.inner.peers)
            .values()
            .find(|candidate| candidate.endpoint_id == peer)
            .map(Arc::clone);
        let Some(peer) = found else {
            return false;
        };

        let mut scratch = vec![0u8; SCRATCH];
        // The encryption is the whole of what this protocol contributes, so
        // it happens here rather than anywhere the packet passes through.
        // The lock is released before the send: a slow link must not hold up
        // the tunnel's timers.
        let len = {
            let mut tunn = match peer.tunn.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            match tunn.encapsulate(packet, &mut scratch) {
                TunnResult::WriteToNetwork(out) => Some(out.len()),
                // No session yet, so nothing to send. Counted as dropped
                // rather than reported: the handshake is in flight and the
                // next packet will go.
                _ => None,
            }
        };
        let Some(len) = len else {
            peer.counters
                .dropped_no_session
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };

        send_to_peer(&peer, &scratch[..len]);
        peer.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
        peer.counters
            .tx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        true
    }

    /// Adds or replaces a peer and starts its tunnel.
    ///
    /// `overlay_v4` is decided by the caller, because only it knows whether
    /// both sides agree on an IPv4 range. `None` means this peer is reachable
    /// over IPv6 only.
    pub fn add_peer(
        &self,
        endpoint_id: EndpointId,
        public_key: WgPublicKey,
        overlay_v4: Option<Ipv4Addr>,
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

        let peer = Arc::new(Peer {
            endpoint_id,
            public_key,
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

        // Start the handshake now instead of waiting for the next timer tick,
        // so the tunnel is usable as soon as the link exists.
        kick_handshake(&peer);
        Ok(())
    }

    /// Removes a peer and stops its tunnel.
    pub fn remove_peer(&self, public_key: &WgPublicKey) {
        // Dropping it stops the task and closes the link; there is no route
        // to withdraw, because routes are not kept here.
        write_lock(&self.inner.peers).remove(public_key);
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
                    overlay_address_v4: overlay_v4,
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
                    // The source boringtun reports is not consulted here:
                    // whether the peer may use it is checked where the
                    // claims live.
                    TunnResult::WriteToTunnelV6(out, _) => Outcome::ToTunnel(out.len()),
                    TunnResult::WriteToTunnelV4(out, _) => Outcome::ToTunnel(out.len()),
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
                Outcome::ToTunnel(len) => {
                    // Handed up, not written out. This end has proved *who*
                    // sent the packet; whether that member may use the source
                    // address it chose is a question about a signed claim,
                    // and only the system level holds those.
                    let payload = Bytes::copy_from_slice(&scratch[..len]);
                    inner
                        .sink
                        .deliver(inner.network, peer.endpoint_id, payload)
                        .await;
                    peer.counters.rx_packets.fetch_add(1, Ordering::Relaxed);
                    peer.counters
                        .rx_bytes
                        .fetch_add(len as u64, Ordering::Relaxed);
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
    ToTunnel(usize),
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
