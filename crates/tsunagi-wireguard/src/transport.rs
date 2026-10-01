//! Pure WireGuard UDP packet transport and link implementation.
//!
//! Provides [`WireguardTransport`] implementing [`PacketTransport`]
//! and [`WireguardLink`] implementing [`PacketLink`].

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use bytes::Bytes;
use iroh::EndpointId;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc, oneshot};

use tsunagi::BoxFuture;
use tsunagi::dataplane::transport::{
    InboundLink, PacketLink, PacketTransport, SharedLink, TransportError,
};
use tsunagi::identity::{DeviceIdentity, NetworkId};

/// Default UDP port to bind and listen on for pure WireGuard.
pub const DEFAULT_PORT: u16 = 51820;

/// Maximum payload length for a single framed datagram over UDP.
pub const MAX_UDP_DATAGRAM_SIZE: usize = 65507;

const PROBE_MAGIC: &[u8; 19] = b"TSUNAGI_WG_PROBE_V1";
const PROBE_TYPE_PING: u8 = 1;
const PROBE_TYPE_PONG: u8 = 2;
const PROBE_LEN: usize = 19 + 1 + 32 + 32 + 32 + 8; // 124 bytes

fn encode_probe(
    msg_type: u8,
    sender: EndpointId,
    receiver: EndpointId,
    network: NetworkId,
    cookie: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PROBE_LEN);
    buf.extend_from_slice(PROBE_MAGIC);
    buf.push(msg_type);
    buf.extend_from_slice(sender.as_bytes());
    buf.extend_from_slice(receiver.as_bytes());
    buf.extend_from_slice(network.as_bytes());
    buf.extend_from_slice(&cookie.to_be_bytes());
    buf
}

struct DecodedProbe {
    msg_type: u8,
    sender: EndpointId,
    receiver: EndpointId,
    network: NetworkId,
    cookie: u64,
}

fn decode_probe(bytes: &[u8]) -> Option<DecodedProbe> {
    if bytes.len() < PROBE_LEN || &bytes[..19] != PROBE_MAGIC {
        return None;
    }
    let msg_type = bytes[19];
    if msg_type != PROBE_TYPE_PING && msg_type != PROBE_TYPE_PONG {
        return None;
    }
    let sender = EndpointId::from_bytes(&bytes[20..52].try_into().ok()?).ok()?;
    let receiver = EndpointId::from_bytes(&bytes[52..84].try_into().ok()?).ok()?;
    let network = NetworkId::from_bytes(bytes[84..116].try_into().ok()?);
    let cookie = u64::from_be_bytes(bytes[116..124].try_into().ok()?);
    Some(DecodedProbe {
        msg_type,
        sender,
        receiver,
        network,
        cookie,
    })
}

/// An authenticated datagram link carried over direct UDP.
#[derive(Debug)]
pub struct WireguardLink {
    network: NetworkId,
    peer: EndpointId,
    target_addr: Arc<RwLock<SocketAddr>>,
    candidates: Arc<RwLock<Vec<SocketAddr>>>,
    confirmed: Arc<AtomicBool>,
    tx: mpsc::Sender<Bytes>,
    inbound_tx: mpsc::Sender<Bytes>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    closed_notify: Arc<Notify>,
    is_closed: Arc<AtomicBool>,
}

impl WireguardLink {
    /// Creates a new `WireguardLink` targeting `target_addr` over `socket`.
    pub fn new(
        network: NetworkId,
        peer: EndpointId,
        target_addr: SocketAddr,
        candidates: Vec<SocketAddr>,
        socket: Arc<UdpSocket>,
    ) -> Self {
        let (tx_out, mut rx_out) = mpsc::channel::<Bytes>(1024);
        let (tx_in, rx_in) = mpsc::channel::<Bytes>(1024);

        let is_closed = Arc::new(AtomicBool::new(false));
        let confirmed = Arc::new(AtomicBool::new(false));
        let closed_notify = Arc::new(Notify::new());

        let target_holder = Arc::new(RwLock::new(target_addr));
        let candidates_holder = Arc::new(RwLock::new(candidates));

        let socket_w = Arc::clone(&socket);
        let target_r = Arc::clone(&target_holder);
        let candidates_r = Arc::clone(&candidates_holder);
        let confirmed_r = Arc::clone(&confirmed);
        let is_closed_w = Arc::clone(&is_closed);
        let closed_notify_w = Arc::clone(&closed_notify);

        tokio::spawn(async move {
            while let Some(msg) = rx_out.recv().await {
                if msg.len() > MAX_UDP_DATAGRAM_SIZE {
                    continue;
                }
                // Check if this is a WireGuard handshake initiation packet:
                // An enveloped packet has a 74-byte header (envelope::HEADER).
                // A raw packet may directly have WireGuard type at index 0.
                let is_handshake_init = if msg.len() >= 74 + 4 && msg[0] == 1 {
                    msg[74] == 1
                } else if !msg.is_empty() {
                    msg[0] == 1
                } else {
                    false
                };
                if confirmed_r.load(Ordering::Acquire) && !is_handshake_init {
                    let target = match target_r.read() {
                        Ok(g) => *g,
                        Err(p) => *p.into_inner(),
                    };
                    if let Err(err) = socket_w.send_to(&msg, target).await {
                        tracing::trace!(%err, %target, "failed to send WireGuard UDP datagram");
                    }
                } else {
                    let targets = match candidates_r.read() {
                        Ok(g) => g.clone(),
                        Err(p) => p.into_inner().clone(),
                    };
                    if targets.is_empty() {
                        let target = match target_r.read() {
                            Ok(g) => *g,
                            Err(p) => *p.into_inner(),
                        };
                        let _ = socket_w.send_to(&msg, target).await;
                    } else {
                        for target in targets {
                            let _ = socket_w.send_to(&msg, target).await;
                        }
                    }
                }
            }
            is_closed_w.store(true, Ordering::Release);
            closed_notify_w.notify_waiters();
        });

        Self {
            network,
            peer,
            target_addr: target_holder,
            candidates: candidates_holder,
            confirmed,
            tx: tx_out,
            inbound_tx: tx_in,
            rx: tokio::sync::Mutex::new(rx_in),
            closed_notify,
            is_closed,
        }
    }

    /// Delivers an inbound packet received from UDP into this link's receive queue.
    pub fn deliver_inbound(&self, payload: Bytes) -> bool {
        if self.is_closed.load(Ordering::Acquire) {
            return false;
        }
        self.confirmed.store(true, Ordering::Release);
        self.inbound_tx.try_send(payload).is_ok()
    }

    /// Marks this link as confirmed by a probe response or verified packet.
    pub fn confirm(&self) {
        self.confirmed.store(true, Ordering::Release);
    }

    /// Whether this link has had verified two-way direct connectivity.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed.load(Ordering::Acquire)
    }

    /// Updates candidate addresses for this peer.
    pub fn update_candidates(&self, addrs: impl IntoIterator<Item = SocketAddr>) {
        if let Ok(mut guard) = self.candidates.write() {
            let new_candidates: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|a| !a.ip().is_unspecified())
                .collect();
            if !new_candidates.is_empty() {
                *guard = new_candidates;
            }
        }
    }

    /// Updates the target socket address (roaming / NAT hole punch update).
    pub fn update_target(&self, new_target: SocketAddr) {
        if new_target.ip().is_unspecified() {
            return;
        }
        self.confirmed.store(true, Ordering::Release);
        if let Ok(mut guard) = self.target_addr.write()
            && *guard != new_target
        {
            tracing::debug!(peer = %self.peer.fmt_short(), old = %*guard, new = %new_target, "WireGuard endpoint roamed");
            *guard = new_target;
        }
    }

    /// Explicitly closes this link, notifying any pending readers or waiters.
    pub fn close(&self) {
        if !self.is_closed.swap(true, Ordering::AcqRel) {
            self.closed_notify.notify_waiters();
        }
    }

    /// Returns the current target address.
    pub fn target_addr(&self) -> SocketAddr {
        match self.target_addr.read() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        }
    }
}

impl PacketLink for WireguardLink {
    fn network(&self) -> NetworkId {
        self.network
    }

    fn peer(&self) -> EndpointId {
        self.peer
    }

    fn max_datagram_size(&self) -> usize {
        MAX_UDP_DATAGRAM_SIZE
    }

    fn send(&self, payload: Bytes) -> Result<(), TransportError> {
        if payload.len() > MAX_UDP_DATAGRAM_SIZE {
            return Err(TransportError::TooLarge {
                size: payload.len(),
                limit: MAX_UDP_DATAGRAM_SIZE,
            });
        }
        if self.is_closed.load(Ordering::Acquire) {
            return Err(TransportError::Closed);
        }
        self.tx
            .try_send(payload)
            .map_err(|_| TransportError::Closed)
    }

    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            if self.is_closed.load(Ordering::Acquire) {
                return None;
            }
            tokio::select! {
                biased;
                _ = self.closed_notify.notified() => None,
                msg = async {
                    let mut guard = self.rx.lock().await;
                    guard.recv().await
                } => msg,
            }
        })
    }

    fn closed(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.is_closed.load(Ordering::Acquire) {
                return;
            }
            self.closed_notify.notified().await;
        })
    }

    fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Acquire)
    }

    fn path_description(&self) -> String {
        format!("wireguard via {}", self.target_addr())
    }
}

type InboundCallback = Box<dyn Fn(InboundLink) + Send + Sync + 'static>;
type PendingProbes = Arc<Mutex<HashMap<(NetworkId, EndpointId, u64), oneshot::Sender<SocketAddr>>>>;

/// Direct UDP WireGuard packet transport.
pub struct WireguardTransport {
    local_id: EndpointId,
    listen_port: u16,
    socket: Arc<UdpSocket>,
    peer_addresses: RwLock<HashMap<EndpointId, Vec<SocketAddr>>>,
    peer_networks: RwLock<HashMap<EndpointId, HashSet<NetworkId>>>,
    links: RwLock<HashMap<(NetworkId, EndpointId), Arc<WireguardLink>>>,
    inbound_cb: Arc<Mutex<Option<InboundCallback>>>,
    pending_probes: PendingProbes,
}

impl std::fmt::Debug for WireguardTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireguardTransport")
            .field("local_id", &self.local_id.fmt_short().to_string())
            .field("listen_port", &self.listen_port)
            .finish()
    }
}

impl WireguardTransport {
    /// Binds a UDP socket for pure WireGuard transport.
    ///
    /// Attempts `requested_port` (default 51820). If that fails, falls back to an ephemeral port.
    pub async fn bind(
        identity: &DeviceIdentity,
        requested_port: Option<u16>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let target_port = requested_port.unwrap_or(DEFAULT_PORT);
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], target_port));

        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(err) if target_port > 0 => {
                tracing::warn!(%err, port = target_port, "failed to bind WireGuard UDP port, falling back to ephemeral port");
                UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?
            }
            Err(err) => return Err(Box::new(err)),
        };

        let bound_port = socket.local_addr()?.port();
        tracing::info!(port = bound_port, "WireGuard UDP transport bound");

        Ok(Self {
            local_id: identity.endpoint_id(),
            listen_port: bound_port,
            socket: Arc::new(socket),
            peer_addresses: RwLock::new(HashMap::new()),
            peer_networks: RwLock::new(HashMap::new()),
            links: RwLock::new(HashMap::new()),
            inbound_cb: Arc::new(Mutex::new(None)),
            pending_probes: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// The local port this transport is listening on.
    pub fn bound_port(&self) -> u16 {
        self.listen_port
    }

    /// Associates a peer with a network ID.
    pub fn set_peer_network(&self, peer: EndpointId, network: NetworkId) {
        if let Ok(mut guard) = self.peer_networks.write() {
            guard.entry(peer).or_default().insert(network);
        }
    }

    /// Records an observed UDP target address for a peer.
    pub fn set_peer_addr(&self, peer: EndpointId, addr: SocketAddr) {
        if !addr.is_ipv4() || addr.ip().is_unspecified() {
            return;
        }
        if let Ok(mut guard) = self.peer_addresses.write() {
            let addrs = guard.entry(peer).or_default();
            addrs.retain(|a| *a != addr);
            addrs.insert(0, addr);
        }
    }

    /// Records multiple observed UDP target addresses for a peer.
    pub fn set_peer_addrs(&self, peer: EndpointId, addrs: impl IntoIterator<Item = SocketAddr>) {
        if let Ok(mut guard) = self.peer_addresses.write() {
            let entry = guard.entry(peer).or_default();
            for addr in addrs {
                if addr.is_ipv4() && !addr.ip().is_unspecified() && !entry.contains(&addr) {
                    entry.push(addr);
                }
            }
        }
    }

    /// Returns candidate socket addresses known for a peer.
    pub fn peer_addrs(&self, peer: EndpointId) -> Vec<SocketAddr> {
        let guard = match self.peer_addresses.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.get(&peer).cloned().unwrap_or_default()
    }

    /// Explicitly closes any active direct link for the given network and peer.
    pub fn close_link(&self, network: NetworkId, peer: EndpointId) {
        let link = {
            let guard = match self.links.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.get(&(network, peer)).cloned()
        };
        if let Some(link) = link {
            link.close();
        }
    }

    /// Notifies the transport that a peer's capability was announced.
    ///
    /// When `we_accept` is true, sends a hole-punch probe to candidate addresses
    /// to open stateful NAT firewalls, but does NOT create an unverified direct link
    /// in the hub before packets actually flow.
    pub fn notify_peer_capability(
        &self,
        network: NetworkId,
        peer: EndpointId,
        addrs: &[SocketAddr],
        we_accept: bool,
    ) {
        self.set_peer_network(peer, network);
        let ipv4_addrs: Vec<SocketAddr> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
        self.set_peer_addrs(peer, ipv4_addrs.iter().copied());

        // Update candidate addresses on any existing link for this peer
        if let Ok(guard) = self.links.read()
            && let Some(link) = guard.get(&(network, peer))
        {
            link.update_candidates(ipv4_addrs.iter().copied());
        }

        // Send hole punching probe if we accept and have candidate addresses.
        if we_accept && !ipv4_addrs.is_empty() {
            let socket = Arc::clone(&self.socket);
            let local_id = self.local_id;
            tokio::spawn(async move {
                let cookie: u64 = rand::random();
                let probe = encode_probe(PROBE_TYPE_PING, local_id, peer, network, cookie);
                for addr in ipv4_addrs {
                    let _ = socket.send_to(&probe, addr).await;
                }
            });
        }
    }

    /// Runs the receive loop for incoming UDP datagrams.
    pub async fn accept_loop<F>(&self, on_inbound: F)
    where
        F: Fn(InboundLink) + Send + Sync + 'static,
    {
        {
            let mut guard = match self.inbound_cb.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            *guard = Some(Box::new(on_inbound));
        }

        let socket = Arc::clone(&self.socket);
        let mut buf = [0u8; MAX_UDP_DATAGRAM_SIZE];

        while let Ok((len, src_addr)) = socket.recv_from(&mut buf).await {
            if src_addr.ip().is_unspecified() {
                continue;
            }

            // 1. Direct UDP probe packet handling
            if len >= PROBE_LEN
                && &buf[..19] == PROBE_MAGIC
                && let Some(probe) = decode_probe(&buf[..len])
            {
                if probe.receiver != self.local_id {
                    continue;
                }

                if probe.msg_type == PROBE_TYPE_PING {
                    let is_known = {
                        let guard = match self.peer_networks.read() {
                            Ok(g) => g,
                            Err(p) => p.into_inner(),
                        };
                        guard
                            .get(&probe.sender)
                            .is_some_and(|nets| nets.contains(&probe.network))
                    };
                    if is_known {
                        let pong = encode_probe(
                            PROBE_TYPE_PONG,
                            self.local_id,
                            probe.sender,
                            probe.network,
                            probe.cookie,
                        );
                        let _ = socket.send_to(&pong, src_addr).await;

                        self.set_peer_addr(probe.sender, src_addr);

                        let link = {
                            let mut guard = match self.links.write() {
                                Ok(g) => g,
                                Err(p) => p.into_inner(),
                            };
                            if let Some(existing) = guard.get(&(probe.network, probe.sender))
                                && !existing.is_closed()
                            {
                                existing.update_target(src_addr);
                                existing.confirm();
                                None
                            } else {
                                let candidates = self.peer_addrs(probe.sender);
                                let link = Arc::new(WireguardLink::new(
                                    probe.network,
                                    probe.sender,
                                    src_addr,
                                    candidates,
                                    Arc::clone(&self.socket),
                                ));
                                link.confirm();
                                guard.insert((probe.network, probe.sender), Arc::clone(&link));
                                Some(link)
                            }
                        };

                        if let Some(link) = link {
                            let cb_guard = match self.inbound_cb.lock() {
                                Ok(g) => g,
                                Err(p) => p.into_inner(),
                            };
                            if let Some(ref cb) = *cb_guard {
                                cb(InboundLink {
                                    network: probe.network,
                                    peer: probe.sender,
                                    protocol: crate::announcement::WG_PROTOCOL.to_string(),
                                    link,
                                });
                            }
                        }
                    }
                    continue;
                } else if probe.msg_type == PROBE_TYPE_PONG {
                    self.set_peer_addr(probe.sender, src_addr);
                    let waiter = {
                        let mut probes = match self.pending_probes.lock() {
                            Ok(g) => g,
                            Err(p) => p.into_inner(),
                        };
                        probes.remove(&(probe.network, probe.sender, probe.cookie))
                    };
                    if let Some(tx) = waiter {
                        let _ = tx.send(src_addr);
                    }
                    continue;
                }
            }

            // 2. Data / handshake packet handling
            let datagram = Bytes::copy_from_slice(&buf[..len]);

            // Identify which peer this packet comes from
            let matched_peer = {
                // If it's an envelope packet (VERSION 1, len >= 74), read source endpoint ID directly
                let from_envelope = if len >= 74 && buf[0] == 1 {
                    let dest = &buf[34..66];
                    if dest == self.local_id.as_bytes() {
                        EndpointId::from_bytes(&buf[2..34].try_into().unwrap_or([0u8; 32])).ok()
                    } else {
                        None
                    }
                } else {
                    None
                };

                from_envelope.or_else(|| {
                    let links_guard = match self.links.read() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    links_guard
                        .values()
                        .find(|link| link.target_addr() == src_addr)
                        .map(|link| link.peer())
                        .or_else(|| {
                            let addrs_guard = match self.peer_addresses.read() {
                                Ok(g) => g,
                                Err(p) => p.into_inner(),
                            };
                            addrs_guard
                                .iter()
                                .find(|(_, addrs)| addrs.contains(&src_addr))
                                .map(|(peer, _)| *peer)
                                .or_else(|| {
                                    links_guard
                                        .values()
                                        .find(|link| link.target_addr().ip() == src_addr.ip())
                                        .map(|link| link.peer())
                                        .or_else(|| {
                                            addrs_guard
                                                .iter()
                                                .find(|(_, addrs)| {
                                                    addrs.iter().any(|a| a.ip() == src_addr.ip())
                                                })
                                                .map(|(peer, _)| *peer)
                                        })
                                })
                        })
                })
            };

            let Some(peer) = matched_peer else {
                continue;
            };

            self.set_peer_addr(peer, src_addr);

            // Deliver to ALL active links for this peer (across all networks this peer shares with us)
            let peer_links: Vec<Arc<WireguardLink>> = {
                let guard = match self.links.read() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                guard
                    .values()
                    .filter(|l| l.peer() == peer && !l.is_closed())
                    .cloned()
                    .collect()
            };

            if !peer_links.is_empty() {
                for link in peer_links {
                    link.update_target(src_addr);
                    link.deliver_inbound(datagram.clone());
                }
                continue;
            }

            // If no active link exists for this peer yet, create inbound links for all networks known for this peer
            let networks: Vec<NetworkId> = {
                let guard = match self.peer_networks.read() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                guard
                    .get(&peer)
                    .map(|s| s.iter().copied().collect())
                    .unwrap_or_default()
            };

            for network in networks {
                let link = {
                    let mut guard = match self.links.write() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    if let Some(existing) = guard.get(&(network, peer))
                        && !existing.is_closed()
                    {
                        existing.update_target(src_addr);
                        existing.deliver_inbound(datagram.clone());
                        continue;
                    }
                    let candidates = self.peer_addrs(peer);
                    let link = Arc::new(WireguardLink::new(
                        network,
                        peer,
                        src_addr,
                        candidates,
                        Arc::clone(&self.socket),
                    ));
                    link.update_target(src_addr);
                    link.deliver_inbound(datagram.clone());
                    guard.insert((network, peer), Arc::clone(&link));
                    link
                };

                let cb_guard = match self.inbound_cb.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                if let Some(ref cb) = *cb_guard {
                    cb(InboundLink {
                        network,
                        peer,
                        protocol: crate::announcement::WG_PROTOCOL.to_string(),
                        link,
                    });
                }
            }
        }
    }
}

impl PacketTransport for WireguardTransport {
    fn name(&self) -> &str {
        "wireguard"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn open<'a>(
        &'a self,
        network: NetworkId,
        peer: EndpointId,
        _protocol: &'a str,
    ) -> BoxFuture<'a, Result<SharedLink, TransportError>> {
        Box::pin(async move {
            let mut addrs = self.peer_addrs(peer);
            if addrs.is_empty() {
                return Err(TransportError::Unreachable(format!(
                    "no candidate UDP address known for peer {}",
                    peer.fmt_short()
                )));
            }
            crate::plugin::prioritize_local_subnet(&mut addrs);

            // If an existing confirmed link is alive, reuse it
            {
                let guard = match self.links.read() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                if let Some(existing) = guard.get(&(network, peer))
                    && !existing.is_closed()
                    && existing.is_confirmed()
                {
                    existing.update_candidates(addrs);
                    return Ok(Arc::clone(existing) as SharedLink);
                }
            }

            // Probe candidate addresses with PING
            let cookie: u64 = rand::random();
            let (tx, rx) = oneshot::channel::<SocketAddr>();
            {
                let mut probes = match self.pending_probes.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                probes.insert((network, peer, cookie), tx);
            }

            let probe_ping = encode_probe(PROBE_TYPE_PING, self.local_id, peer, network, cookie);
            let socket = Arc::clone(&self.socket);
            let candidates = addrs.clone();

            let probe_task = tokio::spawn(async move {
                for i in 0..3 {
                    for target in &candidates {
                        let _ = socket.send_to(&probe_ping, *target).await;
                    }
                    if i < 2 {
                        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
                    }
                }
            });

            let confirmed_addr =
                match tokio::time::timeout(std::time::Duration::from_millis(1200), rx).await {
                    Ok(Ok(addr)) => {
                        probe_task.abort();
                        addr
                    }
                    _ => {
                        probe_task.abort();
                        let mut probes = match self.pending_probes.lock() {
                            Ok(g) => g,
                            Err(p) => p.into_inner(),
                        };
                        probes.remove(&(network, peer, cookie));
                        return Err(TransportError::Unreachable(format!(
                            "direct UDP probe to peer {} timed out",
                            peer.fmt_short()
                        )));
                    }
                };

            let link = {
                let mut guard = match self.links.write() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                if let Some(existing) = guard.get(&(network, peer))
                    && !existing.is_closed()
                {
                    existing.update_target(confirmed_addr);
                    existing.update_candidates(addrs);
                    existing.confirm();
                    return Ok(Arc::clone(existing) as SharedLink);
                }
                let link = Arc::new(WireguardLink::new(
                    network,
                    peer,
                    confirmed_addr,
                    addrs,
                    Arc::clone(&self.socket),
                ));
                link.confirm();
                guard.insert((network, peer), Arc::clone(&link));
                link
            };

            Ok(link as SharedLink)
        })
    }
}
