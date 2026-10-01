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
use tokio::sync::{Notify, mpsc};

use tsunagi::BoxFuture;
use tsunagi::dataplane::transport::{
    InboundLink, PacketLink, PacketTransport, SharedLink, TransportError,
};
use tsunagi::identity::{DeviceIdentity, NetworkId};

/// Default UDP port to bind and listen on for pure WireGuard.
pub const DEFAULT_PORT: u16 = 51820;

/// Maximum payload length for a single framed datagram over UDP.
pub const MAX_UDP_DATAGRAM_SIZE: usize = 65507;

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
                if confirmed_r.load(Ordering::Acquire) {
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

    /// Updates candidate addresses for this peer.
    pub fn update_candidates(&self, addrs: impl IntoIterator<Item = SocketAddr>) {
        if let Ok(mut guard) = self.candidates.write() {
            for addr in addrs {
                if !guard.contains(&addr) {
                    guard.push(addr);
                }
            }
        }
    }

    /// Updates the target socket address (roaming / NAT hole punch update).
    pub fn update_target(&self, new_target: SocketAddr) {
        self.confirmed.store(true, Ordering::Release);
        if let Ok(mut guard) = self.target_addr.write()
            && *guard != new_target
        {
            tracing::debug!(peer = %self.peer.fmt_short(), old = %*guard, new = %new_target, "WireGuard endpoint roamed");
            *guard = new_target;
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
            let mut guard = self.rx.lock().await;
            guard.recv().await
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

/// Direct UDP WireGuard packet transport.
pub struct WireguardTransport {
    local_id: EndpointId,
    listen_port: u16,
    socket: Arc<UdpSocket>,
    peer_addresses: RwLock<HashMap<EndpointId, Vec<SocketAddr>>>,
    peer_networks: RwLock<HashMap<EndpointId, HashSet<NetworkId>>>,
    links: RwLock<HashMap<(NetworkId, EndpointId), Arc<WireguardLink>>>,
    inbound_cb: Arc<Mutex<Option<InboundCallback>>>,
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
        if !addr.is_ipv4() {
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
                if addr.is_ipv4() && !entry.contains(&addr) {
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

    /// Notifies the transport that a peer's capability was announced.
    ///
    /// When `we_accept` is true (i.e. `local_id > peer`), the transport can proactively
    /// create and install an inbound link so both ends are ready and can punch NAT.
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

        if we_accept && !ipv4_addrs.is_empty() {
            let mut guard = match self.links.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let std::collections::hash_map::Entry::Vacant(entry) = guard.entry((network, peer)) {
                let link = Arc::new(WireguardLink::new(
                    network,
                    peer,
                    ipv4_addrs[0],
                    ipv4_addrs,
                    Arc::clone(&self.socket),
                ));
                entry.insert(Arc::clone(&link));
                drop(guard);

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
            let datagram = Bytes::copy_from_slice(&buf[..len]);

            // 1. Identify which peer this packet comes from.
            let matched_peer = {
                let links_guard = match self.links.read() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                links_guard
                    .values()
                    .find(|link| {
                        link.target_addr() == src_addr || link.target_addr().ip() == src_addr.ip()
                    })
                    .map(|link| link.peer())
                    .or_else(|| {
                        let addrs_guard = match self.peer_addresses.read() {
                            Ok(g) => g,
                            Err(p) => p.into_inner(),
                        };
                        addrs_guard
                            .iter()
                            .find(|(_, addrs)| {
                                addrs
                                    .iter()
                                    .any(|a| *a == src_addr || a.ip() == src_addr.ip())
                            })
                            .map(|(peer, _)| *peer)
                    })
            };

            let Some(peer) = matched_peer else {
                continue;
            };

            // 2. Deliver to ALL active links for this peer (across all networks this peer shares with us).
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

            // 3. If no active link exists for this peer yet, create inbound links for all networks known for this peer.
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
            let addrs = self.peer_addrs(peer);
            let Some(target) = addrs.first().copied() else {
                return Err(TransportError::Unreachable(format!(
                    "no candidate UDP address known for peer {}",
                    peer.fmt_short()
                )));
            };

            let link = {
                let mut guard = match self.links.write() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                if let Some(existing) = guard.get(&(network, peer))
                    && !existing.is_closed()
                {
                    existing.update_candidates(addrs);
                    return Ok(Arc::clone(existing) as SharedLink);
                }
                let link = Arc::new(WireguardLink::new(
                    network,
                    peer,
                    target,
                    addrs,
                    Arc::clone(&self.socket),
                ));
                guard.insert((network, peer), Arc::clone(&link));
                link
            };

            Ok(link as SharedLink)
        })
    }
}
