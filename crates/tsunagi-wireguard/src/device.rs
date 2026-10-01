//! Userspace WireGuard device implementation over direct UDP links.
//!
//! Uses [`boringtun::noise::Tunn`] state machine to encrypt and decrypt
//! standard WireGuard protocol packets directly over a [`SharedLink`].

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use bytes::Bytes;
use iroh::EndpointId;
use tokio::task::JoinHandle;

use tsunagi::dataplane::routing::{FlowId, flow::ip_flow};
use tsunagi::dataplane::transport::{SharedLink, TransportError};
use tsunagi::dataplane::{PacketSink, PluginContext, PluginError};
use tsunagi::identity::NetworkId;

use crate::keys::{WgPublicKey, WgSecretKey};
use crate::transport::WireguardTransport;

const TIMER_INTERVAL: Duration = Duration::from_millis(250);
const SCRATCH: usize = 4096;

/// Maximum consecutive rekey timeout retransmissions before declaring a tunnel dead.
pub const MAX_REKEY_TIMEOUTS: u32 = 3;

/// Overall maximum duration trying to establish or rekey a handshake before declaring it dead.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

struct FlowTunnel {
    tunn: Tunn,
    queued: VecDeque<FlowId>,
    handshake_started_at: Option<std::time::Instant>,
    rekey_timeouts: u32,
}

fn is_data(result: &TunnResult<'_>) -> bool {
    matches!(result, TunnResult::WriteToNetwork(bytes) if bytes.starts_with(&[4, 0, 0, 0]))
}

impl FlowTunnel {
    fn encapsulate<'a>(
        &mut self,
        packet: &[u8],
        scratch: &'a mut [u8],
        flow: FlowId,
    ) -> (TunnResult<'a>, FlowId) {
        let result = self.tunn.encapsulate(packet, scratch);
        if is_data(&result) {
            return (result, flow);
        }
        if matches!(result, TunnResult::WriteToNetwork(ref b) if !b.is_empty() && b[0] == 1)
            && self.handshake_started_at.is_none()
        {
            self.handshake_started_at = Some(std::time::Instant::now());
            self.rekey_timeouts = 0;
        }
        if self.queued.len() < 256 {
            self.queued.push_back(flow);
        }
        (result, 0)
    }

    fn decapsulate<'a>(
        &mut self,
        packet: &[u8],
        scratch: &'a mut [u8],
    ) -> (TunnResult<'a>, FlowId) {
        let result = self.tunn.decapsulate(None, packet, scratch);
        if self.tunn.time_since_last_handshake().is_some() {
            self.handshake_started_at = None;
            self.rekey_timeouts = 0;
        }
        let mut flow = 0;
        if packet.is_empty() {
            if is_data(&result) {
                flow = self.queued.pop_front().unwrap_or(0);
            } else if let Some(pending) = self.queued.pop_front() {
                self.queued.push_back(pending);
            }
        }
        (result, flow)
    }

    fn update_timers<'a>(&mut self, scratch: &'a mut [u8]) -> (TunnResult<'a>, bool) {
        let result = self.tunn.update_timers(scratch);
        if matches!(
            result,
            TunnResult::Err(boringtun::noise::errors::WireGuardError::ConnectionExpired)
        ) || self.tunn.is_expired()
        {
            self.queued.clear();
            self.handshake_started_at = None;
            self.rekey_timeouts = 0;
            return (result, true);
        }

        if let TunnResult::WriteToNetwork(ref bytes) = result
            && !bytes.is_empty()
            && bytes[0] == 1
            && self.handshake_started_at.is_none()
        {
            self.handshake_started_at = Some(std::time::Instant::now());
        }

        if let Some(started) = self.handshake_started_at
            && started.elapsed() >= HANDSHAKE_TIMEOUT
        {
            self.queued.clear();
            self.handshake_started_at = None;
            self.rekey_timeouts = 0;
            return (result, true);
        }

        (result, false)
    }
}

#[derive(Debug, Default)]
struct PeerCounters {
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    dropped_wrong_source: AtomicU64,
    dropped_oversize: AtomicU64,
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
    pub dropped_wrong_source: u64,
    /// Packets dropped because they did not fit in one link datagram.
    pub dropped_oversize: u64,
    /// Packets dropped because there was no session to encrypt with yet.
    pub dropped_no_session: u64,
    /// WireGuard protocol errors, including packets that failed to decrypt.
    pub protocol_errors: u64,
}

/// Whether a peer's tunnel has completed a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerHealth {
    /// Time since the last successful WireGuard handshake.
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
    overlay_v4: Mutex<Option<Ipv4Addr>>,
    tunn: Mutex<FlowTunnel>,
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
            since_handshake: guard.tunn.time_since_last_handshake(),
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
    /// The overlay address it holds, once agreed.
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
    sink: Arc<dyn PacketSink>,
    transport: Arc<WireguardTransport>,
    context: PluginContext,
    next_index: AtomicU32,
}

impl Inner {
    fn on_tunnel_failed(&self, peer: EndpointId) {
        self.transport.close_link(self.network, peer);
        self.context.report_peer_protocol_failure(
            self.network,
            peer,
            crate::announcement::WG_PROTOCOL,
            "WireGuard rekey timeout",
        );
    }
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
    /// Starts the WireGuard tunnels for one network.
    pub fn start(
        network: NetworkId,
        private_key: WgSecretKey,
        sink: Arc<dyn PacketSink>,
        transport: Arc<WireguardTransport>,
        context: PluginContext,
    ) -> Self {
        let inner = Arc::new(Inner {
            network,
            private_key,
            peers: RwLock::new(HashMap::new()),
            sink,
            transport,
            context,
            next_index: AtomicU32::new(1),
        });

        let timers = tokio::spawn(drive_timers(Arc::clone(&inner)));

        Self {
            inner,
            tasks: vec![timers],
        }
    }

    /// Encrypts an IP packet and sends it to a peer over its direct link.
    pub fn carry(&self, peer: EndpointId, packet: &[u8]) -> bool {
        let found = read_lock(&self.inner.peers)
            .values()
            .find(|candidate| candidate.endpoint_id == peer)
            .cloned();
        let Some(peer) = found else {
            return false;
        };

        let mut scratch = [0u8; SCRATCH];
        let flow = ip_flow(packet);
        let result = {
            let mut tunn = match peer.tunn.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let (result, selected_flow) = tunn.encapsulate(packet, &mut scratch, flow);
            match result {
                TunnResult::WriteToNetwork(out) => Some((out.len(), selected_flow)),
                _ => None,
            }
        };
        let Some((len, selected_flow)) = result else {
            peer.counters
                .dropped_no_session
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };

        send_to_peer_flow(&peer, &scratch[..len], selected_flow);
        peer.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
        peer.counters
            .tx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        true
    }

    /// Adds or replaces a peer and starts its tunnel.
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
            tunn: Mutex::new(FlowTunnel {
                tunn,
                queued: VecDeque::new(),
                handshake_started_at: None,
                rekey_timeouts: 0,
            }),
            link,
            counters: Arc::new(PeerCounters::default()),
            task: Mutex::new(None),
        });

        let task = tokio::spawn(read_from_link(Arc::clone(&self.inner), Arc::clone(&peer)));
        if let Ok(mut guard) = peer.task.lock() {
            *guard = Some(task);
        }

        write_lock(&self.inner.peers).insert(public_key, Arc::clone(&peer));
        kick_handshake(&peer);
        Ok(())
    }

    /// Removes a peer and stops its tunnel.
    pub fn remove_peer(&self, public_key: &WgPublicKey) {
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

fn kick_handshake(peer: &Peer) {
    let mut scratch = vec![0u8; SCRATCH];
    let len = {
        let mut tunn = match peer.tunn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match tunn.tunn.format_handshake_initiation(&mut scratch, false) {
            TunnResult::WriteToNetwork(out) => {
                tunn.handshake_started_at = Some(std::time::Instant::now());
                tunn.rekey_timeouts = 0;
                Some(out.len())
            }
            _ => None,
        }
    };
    if let Some(len) = len {
        send_to_peer(peer, &scratch[..len]);
    }
}

fn send_to_peer(peer: &Peer, payload: &[u8]) {
    send_to_peer_flow(peer, payload, 0);
}

fn send_to_peer_flow(peer: &Peer, payload: &[u8], flow: FlowId) {
    match peer.link.send_flow(Bytes::copy_from_slice(payload), flow) {
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
    let mut scratch = vec![0u8; SCRATCH];
    loop {
        let Some(datagram) = peer.link.recv().await else {
            return;
        };

        let mut input: Option<&[u8]> = Some(&datagram);
        loop {
            let outcome = {
                let mut tunn = match peer.tunn.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let (result, flow) = tunn.decapsulate(input.unwrap_or(&[]), &mut scratch);
                match result {
                    TunnResult::WriteToNetwork(out) => Outcome::ToNetwork(out.len(), flow),
                    TunnResult::WriteToTunnelV6(out, _) => Outcome::ToTunnel(out.len()),
                    TunnResult::WriteToTunnelV4(out, _) => Outcome::ToTunnel(out.len()),
                    TunnResult::Done => Outcome::Done,
                    TunnResult::Err(err) => {
                        tracing::trace!(?err, "WireGuard decapsulation failed");
                        Outcome::Failed
                    }
                }
            };

            match outcome {
                Outcome::ToNetwork(len, flow) => {
                    send_to_peer_flow(&peer, &scratch[..len], flow);
                    input = None;
                    continue;
                }
                Outcome::ToTunnel(len) => {
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
    ToNetwork(usize, FlowId),
    ToTunnel(usize),
    Done,
    Failed,
}

async fn drive_timers(inner: Arc<Inner>) {
    let mut ticker = tokio::time::interval(TIMER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let peers: Vec<Arc<Peer>> = read_lock(&inner.peers).values().cloned().collect();
        for peer in peers {
            let mut scratch = vec![0u8; SCRATCH];
            let (len, failed) = {
                let mut tunn = match peer.tunn.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let (result, failed) = tunn.update_timers(&mut scratch);
                let len = match result {
                    TunnResult::WriteToNetwork(out) => Some(out.len()),
                    TunnResult::Err(err) => {
                        tracing::trace!(?err, "WireGuard timer error");
                        None
                    }
                    _ => None,
                };
                (len, failed)
            };
            if let Some(len) = len {
                send_to_peer(&peer, &scratch[..len]);
            }
            if failed {
                tracing::warn!(
                    peer = %peer.endpoint_id.fmt_short(),
                    "WireGuard tunnel failed due to rekey timeout, triggering fallback"
                );
                inner.on_tunnel_failed(peer.endpoint_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_tunnel_rekey_timeout_triggers_failure() {
        let my_secret = WgSecretKey::generate();
        let their_secret = WgSecretKey::generate();
        let their_public = their_secret.public();
        let tunn = Tunn::new(
            my_secret.to_static_secret(),
            their_public.into_x25519(),
            None,
            None,
            1,
            None,
        );

        let mut tunnel = FlowTunnel {
            tunn,
            queued: VecDeque::new(),
            handshake_started_at: Some(std::time::Instant::now() - Duration::from_secs(16)),
            rekey_timeouts: 0,
        };

        let mut scratch = vec![0u8; SCRATCH];
        // When handshake timeout exceeds HANDSHAKE_TIMEOUT (15s), update_timers returns true (failed)
        let (_, failed) = tunnel.update_timers(&mut scratch);
        assert!(failed, "handshake timeout should report failure");
        assert!(tunnel.handshake_started_at.is_none());
    }

    #[test]
    fn test_flow_tunnel_reset_on_handshake() {
        let my_secret = WgSecretKey::generate();
        let their_secret = WgSecretKey::generate();
        let their_public = their_secret.public();
        let tunn = Tunn::new(
            my_secret.to_static_secret(),
            their_public.into_x25519(),
            None,
            None,
            1,
            None,
        );

        let mut tunnel = FlowTunnel {
            tunn,
            queued: VecDeque::new(),
            handshake_started_at: Some(std::time::Instant::now()),
            rekey_timeouts: 2,
        };

        let mut scratch = vec![0u8; SCRATCH];
        let _ = tunnel.decapsulate(&[], &mut scratch);
        // decapsulate without handshake response doesn't establish session
        assert_eq!(tunnel.rekey_timeouts, 2);
    }
}
