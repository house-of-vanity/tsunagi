//! The pure WireGuard IP plugin implementation.
//!
//! Provides [`WireguardPlugin`] implementing [`IpPlugin`].

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use iroh::EndpointId;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use tsunagi::BoxFuture;
use tsunagi::dataplane::PacketSink;
use tsunagi::dataplane::transport::SharedLink;
use tsunagi::dataplane::{IpPlugin, PluginCapability, PluginContext, PluginError, ProtocolOption};
use tsunagi::identity::NetworkId;
use tsunagi::state::Ipv4Range;

use crate::announcement::{
    ANNOUNCEMENT_VERSION, ValidatedAnnouncement, WG_PROTOCOL, WgAnnouncement,
};
use crate::device::{PeerSummary, WireguardDevice};
use crate::keys::{WgPublicKey, WgSecretKey};
use crate::store::WgKeyStore;
use crate::transport::WireguardTransport;

/// Smallest interface MTU the overlay accepts.
pub const MIN_MTU: u32 = 576;

/// Default interface MTU.
pub const DEFAULT_MTU: u32 = 1280;

/// WireGuard packet overhead.
pub const WIREGUARD_OVERHEAD: u32 = 32;

/// Discovers local network interface IPs to announce to peers, excluding loopback, overlay interfaces, and virtual bridges.
pub fn local_ip_candidates() -> Vec<IpAddr> {
    let mut candidates = Vec::new();
    for iface in netdev::get_interfaces() {
        if !is_candidate_interface(&iface) {
            continue;
        }
        for ip in &iface.ipv4 {
            let addr = ip.addr();
            if is_candidate_ipv4(addr) {
                let priority = ip_priority(&iface, IpAddr::V4(addr));
                candidates.push((priority, IpAddr::V4(addr)));
            }
        }
    }
    // Sort descending by priority so the most viable physical / WAN / LAN IP is candidate #0
    candidates.sort_by_key(|b| std::cmp::Reverse(b.0));
    let mut seen = std::collections::HashSet::new();
    let mut ips = Vec::new();
    for (_, ip) in candidates {
        if seen.insert(ip) {
            ips.push(ip);
        }
    }
    ips
}

pub(crate) fn is_candidate_interface(iface: &netdev::Interface) -> bool {
    if !iface.is_up() || iface.is_loopback() {
        return false;
    }

    let name = iface.name.to_lowercase();
    let friendly = iface
        .friendly_name
        .as_deref()
        .map(str::to_lowercase)
        .unwrap_or_default();
    let desc = iface
        .description
        .as_deref()
        .map(str::to_lowercase)
        .unwrap_or_default();

    // Skip Tsunagi / Wintun overlay interfaces
    if name.starts_with("tsun")
        || name.contains("tsunagi")
        || name.contains("wintun")
        || friendly.starts_with("tsun")
        || friendly.contains("tsunagi")
        || friendly.contains("wintun")
        || desc.contains("wintun")
        || desc.contains("tsunagi")
    {
        return false;
    }

    // Skip container, VM, and virtual bridge interfaces
    if name.starts_with("docker")
        || name.starts_with("br-")
        || name.starts_with("veth")
        || name.starts_with("virbr")
        || name.starts_with("cni")
        || name.starts_with("flannel")
        || name.starts_with("cali")
        || name.starts_with("kube")
        || name.starts_with("dummy")
        || name.starts_with("lxc")
        || name.starts_with("podman")
        || friendly.contains("vethernet")
        || friendly.contains("vboxnet")
        || friendly.contains("vmnet")
        || desc.contains("virtualbox")
        || desc.contains("hyper-v")
        || desc.contains("vmware")
    {
        return false;
    }

    true
}

pub(crate) fn is_candidate_ipv4(addr: std::net::Ipv4Addr) -> bool {
    if addr.is_loopback() || addr.is_unspecified() || addr.is_link_local() || addr.is_broadcast() {
        return false;
    }
    if addr.is_documentation() {
        return false;
    }
    true
}

pub(crate) fn is_candidate_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_candidate_ipv4(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return false;
            }
            let segments = v6.segments();
            // Filter link-local fe80::/10
            if (segments[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            true
        }
    }
}

pub(crate) fn ip_priority(iface: &netdev::Interface, ip: IpAddr) -> u32 {
    let has_gateway = iface.gateway.is_some();
    let base = if has_gateway { 100 } else { 0 };
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Tailscale: 100.64.0.0/10
            let is_tailscale = octets[0] == 100 && (octets[1] & 0xc0) == 64;
            let is_private = v4.is_private();
            if !is_private && !is_tailscale {
                // Public / globally routable IP
                base + 50
            } else if has_gateway && is_private {
                // Primary LAN IP with gateway (e.g. 192.168.1.117)
                base + 40
            } else if is_tailscale {
                // Tailscale / CGNAT
                base + 30
            } else {
                // Other private / virtual
                base + 10
            }
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let is_global = (segments[0] & 0xe000) == 0x2000;
            if is_global { base + 45 } else { base + 20 }
        }
    }
}

/// Configuration of the pure WireGuard plugin.
#[derive(Debug, Clone)]
pub struct WireguardConfig {
    /// Directory for the plugin's own key store.
    pub state_dir: PathBuf,
    /// WireGuard keepalive in seconds.
    pub keepalive: Option<u16>,
    /// The largest packet a tunnel will carry.
    pub mtu: u32,
    /// UDP port to listen on.
    pub port: Option<u16>,
    /// How long to coalesce changes before reconciling.
    pub reconcile_debounce: Duration,
    /// Periodic reconcile interval.
    pub reconcile_interval: Duration,
}

impl WireguardConfig {
    /// Creates a configuration rooted at `state_dir`.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            keepalive: Some(25),
            mtu: DEFAULT_MTU,
            port: None,
            reconcile_debounce: Duration::from_millis(200),
            reconcile_interval: Duration::from_secs(15),
        }
    }

    /// Sets the interface MTU.
    pub fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Sets the UDP listen port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Path of the plugin's key store.
    pub fn key_store_path(&self) -> PathBuf {
        self.state_dir.join("wireguard.sqlite")
    }
}

/// What this agent has set up for one network.
#[derive(Debug, Clone)]
pub struct NetworkOverview {
    /// The network.
    pub network: NetworkId,
    /// The largest packet a tunnel in this network will carry.
    pub mtu: u32,
    /// This agent's WireGuard public key in this network.
    pub public_key: WgPublicKey,
    /// This agent's overlay address, once agreed.
    pub overlay_address_v4: Option<Ipv4Addr>,
    /// The IPv4 overlay range in use.
    pub ipv4_range: Option<Ipv4Range>,
    /// Peers this agent knows about.
    pub peers: Vec<PeerOverview>,
}

/// One peer of the overlay.
#[derive(Debug, Clone)]
pub struct PeerOverview {
    /// The peer's control plane identity.
    pub endpoint_id: EndpointId,
    /// The peer's WireGuard public key.
    pub public_key: WgPublicKey,
    /// The overlay address the network agreed it holds.
    pub overlay_address_v4: Option<Ipv4Addr>,
    /// Whether a data plane link to it exists.
    pub has_link: bool,
    /// The running tunnel, once there is a link.
    pub tunnel: Option<PeerSummary>,
}

impl PeerOverview {
    /// Whether the tunnel to this peer has handshaken and can carry traffic.
    pub fn is_up(&self) -> bool {
        self.tunnel
            .as_ref()
            .is_some_and(|tunnel| tunnel.health.is_up())
    }
}

#[derive(Debug)]
struct NetworkState {
    key: WgSecretKey,
    device: Option<Arc<WireguardDevice>>,
    announcements: HashMap<EndpointId, ValidatedAnnouncement>,
    links: HashMap<EndpointId, SharedLink>,
    allocations: HashMap<EndpointId, Ipv4Addr>,
    ipv4_range: Option<Ipv4Range>,
}

#[derive(Debug, Default)]
struct Shared {
    networks: HashMap<NetworkId, NetworkState>,
}

#[derive(Debug)]
enum Command {
    Prepare(NetworkId),
    Sync(NetworkId),
    Link {
        network: NetworkId,
        peer: EndpointId,
        link: SharedLink,
    },
    Teardown(NetworkId),
    Stop(oneshot::Sender<()>),
}

struct Worker {
    config: WireguardConfig,
    transport: Arc<WireguardTransport>,
    local_id: OnceLock<EndpointId>,
    store: WgKeyStore,
    shared: Mutex<Shared>,
    context: OnceLock<PluginContext>,
    sink: OnceLock<Arc<dyn PacketSink>>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("store", &self.store.path())
            .field("port", &self.transport.bound_port())
            .finish()
    }
}

/// The pure WireGuard data plane plugin.
#[derive(Debug)]
pub struct WireguardPlugin {
    worker: Arc<Worker>,
    commands: mpsc::Sender<Command>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl WireguardPlugin {
    /// Supported options for pure WireGuard.
    pub const OPTIONS: &'static [ProtocolOption] = &[
        ProtocolOption {
            key: "port",
            value: "PORT",
            help: "UDP port to listen on for WireGuard packets",
            default: Some("51820"),
        },
        ProtocolOption {
            key: "keepalive",
            value: "SECONDS",
            help: "keeps a tunnel and NAT mapping warm; 0 turns it off",
            default: Some("25"),
        },
        ProtocolOption {
            key: "mtu",
            value: "BYTES",
            help: "largest packet a tunnel will carry, at least 576",
            default: Some("1280"),
        },
    ];

    /// Applies `key=value` settings to a configuration.
    pub fn configure(
        mut config: WireguardConfig,
        options: &[(String, String)],
    ) -> Result<WireguardConfig, PluginError> {
        for (key, value) in options {
            match key.as_str() {
                "port" => {
                    let port: u16 = value.parse().map_err(|_| {
                        PluginError::Other(format!("port={value} is not a valid port number"))
                    })?;
                    config = config.with_port(port);
                }
                "keepalive" => {
                    let seconds: u16 = value.parse().map_err(|_| {
                        PluginError::Other(format!("keepalive={value} is not a number of seconds"))
                    })?;
                    config.keepalive = (seconds > 0).then_some(seconds);
                }
                "mtu" => {
                    let mtu: u32 = value.parse().map_err(|_| {
                        PluginError::Other(format!("mtu={value} is not a number of bytes"))
                    })?;
                    config = config.with_mtu(mtu);
                }
                other => {
                    let known: Vec<&str> = Self::OPTIONS.iter().map(|spec| spec.key).collect();
                    return Err(PluginError::Other(format!(
                        "`{other}` is not a setting of {WG_PROTOCOL}; it takes {}",
                        known.join(", ")
                    )));
                }
            }
        }
        Ok(config)
    }

    /// Opens the plugin's key store, binds the UDP transport and starts the reconciliation worker.
    pub async fn open(
        config: WireguardConfig,
        transport: Arc<WireguardTransport>,
    ) -> Result<Arc<Self>, PluginError> {
        if config.mtu < MIN_MTU {
            return Err(PluginError::Other(format!(
                "an MTU of {} is below the {MIN_MTU} bytes every IPv4 host must be able to reassemble",
                config.mtu
            )));
        }

        let path = config.key_store_path();
        let store = tokio::task::spawn_blocking(move || WgKeyStore::open(path))
            .await
            .map_err(|err| PluginError::Other(format!("key store task failed: {err}")))??;

        let worker = Arc::new(Worker {
            config,
            transport,
            local_id: OnceLock::new(),
            store,
            shared: Mutex::new(Shared::default()),
            context: OnceLock::new(),
            sink: OnceLock::new(),
        });

        let (commands, receiver) = mpsc::channel(64);
        let task = tokio::spawn(run(Arc::clone(&worker), receiver));

        Ok(Arc::new(Self {
            worker,
            commands,
            task: Mutex::new(Some(task)),
        }))
    }

    /// What this agent has set up for a network.
    pub fn overview(&self, network: NetworkId) -> Option<NetworkOverview> {
        let shared = self.worker.lock_shared();
        let state = shared.networks.get(&network)?;

        let tunnels: HashMap<WgPublicKey, PeerSummary> = state
            .device
            .as_ref()
            .map(|device| {
                device
                    .peers()
                    .into_iter()
                    .map(|summary| (summary.public_key, summary))
                    .collect()
            })
            .unwrap_or_default();

        let mut peers: Vec<PeerOverview> = state
            .announcements
            .iter()
            .map(|(endpoint_id, announcement)| PeerOverview {
                endpoint_id: *endpoint_id,
                public_key: announcement.public_key,
                overlay_address_v4: state.allocations.get(endpoint_id).copied(),
                has_link: state.links.contains_key(endpoint_id),
                tunnel: tunnels.get(&announcement.public_key).cloned(),
            })
            .collect();
        peers.sort_by_key(|peer| peer.public_key);

        Some(NetworkOverview {
            network,
            mtu: self.worker.config.mtu,
            public_key: state.key.public(),
            overlay_address_v4: state.allocations.get(&self.worker.local_id()).copied(),
            ipv4_range: state.ipv4_range,
            peers,
        })
    }

    fn nudge(&self, command: Command) {
        if let Err(err) = self.commands.try_send(command) {
            tracing::debug!(%err, "WireGuard command queue is busy");
        }
    }
}

impl Worker {
    fn local_id(&self) -> EndpointId {
        self.local_id.get().copied().unwrap_or_else(|| {
            EndpointId::from_bytes(&[1u8; 32]).unwrap_or_else(|_| unreachable!("a fixed valid key"))
        })
    }

    fn lock_shared(&self) -> std::sync::MutexGuard<'_, Shared> {
        match self.shared.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn report(&self, network: NetworkId, reason: impl std::fmt::Display) {
        tracing::warn!(network = %network.fmt_short(), %reason, "pure WireGuard plugin error");
        if let Some(context) = self.context.get() {
            context.report_error(network, WG_PROTOCOL, reason.to_string());
        }
    }

    fn request_reannounce(&self, network: NetworkId) {
        if let Some(context) = self.context.get() {
            context.request_reannounce(network);
        }
    }

    async fn prepare(self: &Arc<Self>, network: NetworkId) -> Result<bool, PluginError> {
        let existing = {
            let shared = self.lock_shared();
            shared
                .networks
                .get(&network)
                .map(|state| state.device.is_some())
        };

        if let Some(has_device) = existing {
            if has_device {
                return Ok(false);
            }
            self.ensure_device(network).await?;
            return Ok(false);
        }

        let worker = Arc::clone(self);
        let key = tokio::task::spawn_blocking(move || worker.store.load_or_create(network))
            .await
            .map_err(|err| PluginError::Other(format!("key store task failed: {err}")))??;

        {
            let mut shared = self.lock_shared();
            shared.networks.entry(network).or_insert(NetworkState {
                key,
                device: None,
                announcements: HashMap::new(),
                links: HashMap::new(),
                allocations: HashMap::new(),
                ipv4_range: None,
            });
        }

        let device = self.ensure_device(network).await;
        if let Err(err) = device {
            self.report(network, err);
        }
        Ok(true)
    }

    async fn ensure_device(&self, network: NetworkId) -> Result<(), PluginError> {
        let key = {
            let shared = self.lock_shared();
            match shared.networks.get(&network) {
                Some(state) if state.device.is_none() => state.key.clone(),
                _ => return Ok(()),
            }
        };

        let sink = match self.sink.get() {
            Some(sink) => Arc::clone(sink),
            None => Arc::new(tsunagi::dataplane::DiscardPackets) as Arc<dyn PacketSink>,
        };
        let device = Arc::new(WireguardDevice::start(network, key, sink));

        let mut shared = self.lock_shared();
        if let Some(state) = shared.networks.get_mut(&network) {
            state.device = Some(device);
        }
        Ok(())
    }

    fn sync(&self, network: NetworkId) {
        let mut shared = self.lock_shared();
        let Some(state) = shared.networks.get_mut(&network) else {
            return;
        };
        let Some(device) = state.device.clone() else {
            return;
        };

        let allocations = state.allocations.clone();
        let mut wanted: Vec<WgPublicKey> = Vec::new();
        for (endpoint_id, announcement) in &state.announcements {
            let Some(link) = state.links.get(endpoint_id) else {
                continue;
            };
            if link.is_closed() {
                continue;
            }
            wanted.push(announcement.public_key);
            if device.has_peer(&announcement.public_key) {
                continue;
            }

            let peer_v4 = allocations.get(endpoint_id).copied();
            if let Err(err) = device.add_peer(
                *endpoint_id,
                announcement.public_key,
                peer_v4,
                Arc::clone(link),
                self.config.keepalive,
            ) {
                tracing::debug!(%err, "cannot start WireGuard tunnel");
            }
        }
        device.retain_peers(&wanted);
    }

    async fn teardown(&self, network: NetworkId) {
        self.lock_shared().networks.remove(&network);
    }

    fn known_networks(&self) -> Vec<NetworkId> {
        self.lock_shared().networks.keys().copied().collect()
    }
}

async fn run(worker: Arc<Worker>, mut commands: mpsc::Receiver<Command>) {
    let mut pending: BTreeSet<NetworkId> = BTreeSet::new();
    let mut deadline: Option<tokio::time::Instant> = None;
    let mut ticker = tokio::time::interval(worker.config.reconcile_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        let wait_until = deadline;
        tokio::select! {
            biased;
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::Prepare(network) => {
                        match worker.prepare(network).await {
                            Ok(true) => worker.request_reannounce(network),
                            Ok(false) => {}
                            Err(err) => worker.report(network, err),
                        }
                        pending.insert(network);
                    }
                    Command::Sync(network) => {
                        pending.insert(network);
                    }
                    Command::Link { network, peer, link } => {
                        {
                            let mut shared = worker.lock_shared();
                            if let Some(state) = shared.networks.get_mut(&network) {
                                state.links.insert(peer, link);
                            }
                        }
                        pending.insert(network);
                    }
                    Command::Teardown(network) => {
                        pending.remove(&network);
                        worker.teardown(network).await;
                        continue;
                    }
                    Command::Stop(reply) => {
                        for network in worker.known_networks() {
                            worker.teardown(network).await;
                        }
                        let _ = reply.send(());
                        return;
                    }
                }
                deadline = Some(tokio::time::Instant::now() + worker.config.reconcile_debounce);
            }
            _ = async {
                match wait_until {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            }, if wait_until.is_some() => {
                deadline = None;
                for network in std::mem::take(&mut pending) {
                    worker.sync(network);
                }
            }
            _ = ticker.tick() => {
                for network in worker.known_networks() {
                    if let Err(err) = worker.ensure_device(network).await {
                        tracing::debug!(%err, "WireGuard device still unavailable");
                    }
                    worker.sync(network);
                }
            }
        }
    }
}

impl IpPlugin for WireguardPlugin {
    fn protocol_id(&self) -> &str {
        WG_PROTOCOL
    }

    fn protocol_version(&self) -> u16 {
        ANNOUNCEMENT_VERSION
    }

    fn options(&self) -> &'static [ProtocolOption] {
        Self::OPTIONS
    }

    fn attach(&self, context: PluginContext) {
        if let Some(local) = context.local_endpoint_id() {
            let _ = self.worker.local_id.set(local);
        }
        let _ = self.worker.sink.set(context.packet_sink());
        let _ = self.worker.context.set(context);
    }

    fn on_network_activated(&self, network: NetworkId) {
        self.nudge(Command::Prepare(network));
    }

    fn local_capability(
        &self,
        network: NetworkId,
    ) -> Result<Option<PluginCapability>, PluginError> {
        let shared = self.worker.lock_shared();
        let Some(state) = shared.networks.get(&network) else {
            drop(shared);
            self.nudge(Command::Prepare(network));
            return Ok(None);
        };

        let bound_port = self.worker.transport.bound_port();
        let addrs = local_ip_candidates();
        let announcement = WgAnnouncement::new(network, &state.key.public(), bound_port, addrs);

        Ok(Some(PluginCapability {
            protocol: WG_PROTOCOL.to_string(),
            version: ANNOUNCEMENT_VERSION,
            enabled: true,
            data: announcement.encode()?,
        }))
    }

    fn on_peer_capability(
        &self,
        network: NetworkId,
        peer: EndpointId,
        capability: &PluginCapability,
    ) -> Result<(), PluginError> {
        let local_key = {
            let shared = self.worker.lock_shared();
            match shared.networks.get(&network) {
                Some(state) => state.key.public(),
                None => {
                    drop(shared);
                    self.nudge(Command::Prepare(network));
                    return Err(PluginError::Unavailable(
                        "WireGuard is not ready for this network yet".into(),
                    ));
                }
            }
        };

        let validated = WgAnnouncement::decode_and_validate(&capability.data, network, &local_key)?;

        let is_overlay_ip = |ip: &IpAddr| -> bool {
            let shared = self.worker.lock_shared();
            shared.networks.values().any(|s| {
                if let Some(range) = s.ipv4_range {
                    match ip {
                        IpAddr::V4(v4) => range.contains(*v4),
                        IpAddr::V6(_) => false,
                    }
                } else {
                    false
                }
            })
        };

        let socket_addrs: Vec<SocketAddr> = validated
            .addrs
            .iter()
            .filter(|ip| is_candidate_ip(**ip) && !is_overlay_ip(ip))
            .map(|ip| SocketAddr::new(*ip, validated.port))
            .collect();

        // Record candidate addresses in transport and optionally notify if we are the acceptor
        let local_id = self.worker.local_id();
        let we_accept = local_id.as_bytes() > peer.as_bytes();
        self.worker
            .transport
            .notify_peer_capability(network, peer, &socket_addrs, we_accept);

        let changed = {
            let mut shared = self.worker.lock_shared();
            match shared.networks.get_mut(&network) {
                Some(state) => {
                    state.announcements.insert(peer, validated.clone()) != Some(validated)
                }
                None => false,
            }
        };
        if changed {
            self.nudge(Command::Sync(network));
        }
        Ok(())
    }

    fn on_address_allocation(
        &self,
        network: NetworkId,
        range: Ipv4Range,
        allocations: &[(EndpointId, Ipv4Addr)],
    ) {
        let changed = {
            let mut shared = self.worker.lock_shared();
            match shared.networks.get_mut(&network) {
                Some(state) => {
                    let fresh: HashMap<EndpointId, Ipv4Addr> =
                        allocations.iter().copied().collect();
                    let changed = state.allocations != fresh || state.ipv4_range != Some(range);
                    state.allocations = fresh;
                    state.ipv4_range = Some(range);
                    changed
                }
                None => false,
            }
        };
        if changed {
            self.nudge(Command::Sync(network));
        }
    }

    fn carry(&self, network: NetworkId, peer: EndpointId, packet: bytes::Bytes) -> bool {
        let shared = self.worker.lock_shared();
        shared
            .networks
            .get(&network)
            .and_then(|state| state.device.as_ref())
            .is_some_and(|device| device.carry(peer, &packet))
    }

    fn on_peer_link(&self, network: NetworkId, peer: EndpointId, link: SharedLink) {
        self.nudge(Command::Link {
            network,
            peer,
            link,
        });
    }

    fn on_peer_gone(&self, network: NetworkId, peer: EndpointId) {
        let removed = {
            let mut shared = self.worker.lock_shared();
            match shared.networks.get_mut(&network) {
                Some(state) => {
                    let had_link = state.links.remove(&peer).is_some();
                    state.announcements.remove(&peer).is_some() || had_link
                }
                None => false,
            }
        };
        if removed {
            self.nudge(Command::Sync(network));
        }
    }

    fn on_network_deactivated(&self, network: NetworkId) {
        self.nudge(Command::Teardown(network));
    }

    fn on_network_forgotten(&self, network: NetworkId) {
        if let Err(err) = self.worker.store.forget(network) {
            tracing::warn!(%err, "could not forget WireGuard key for network");
        }
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            if self.commands.send(Command::Stop(tx)).await.is_ok() {
                let _ = rx.await;
            }
            let task = match self.task.lock() {
                Ok(mut guard) => guard.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            if let Some(task) = task {
                let _ = task.await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_candidate_interface_filters_overlay_and_bridges() {
        let mut iface = netdev::Interface::dummy();
        iface.flags = 1; // UP

        // Standard Ethernet - should pass
        iface.name = "eth0".to_string();
        assert!(is_candidate_interface(&iface));

        // Standard Wi-Fi - should pass
        iface.name = "wlan0".to_string();
        assert!(is_candidate_interface(&iface));

        // Windows Ethernet with GUID name - should pass
        iface.name = "{B6149D2C-1234-5678-9ABC-DEF012345678}".to_string();
        iface.friendly_name = Some("Ethernet".to_string());
        iface.description = Some("Intel(R) Ethernet Connection".to_string());
        assert!(is_candidate_interface(&iface));

        // Linux tsun0 overlay - must be filtered
        iface.name = "tsun0".to_string();
        iface.friendly_name = None;
        iface.description = None;
        assert!(!is_candidate_interface(&iface));

        // Windows Wintun overlay (GUID name with tsun0 friendly name) - must be filtered!
        iface.name = "{72D85D76-F1A5-42AC-BC49-2169527CDDDF}".to_string();
        iface.friendly_name = Some("tsun0".to_string());
        iface.description = Some("Wintun Userspace Tunnel".to_string());
        assert!(!is_candidate_interface(&iface));

        // Windows Wintun overlay with description containing Wintun - must be filtered!
        iface.friendly_name = Some("Local Area Connection 2".to_string());
        iface.description = Some("Wintun Userspace Tunnel".to_string());
        assert!(!is_candidate_interface(&iface));

        // Docker bridge - must be filtered
        iface.name = "docker0".to_string();
        iface.friendly_name = None;
        iface.description = None;
        assert!(!is_candidate_interface(&iface));

        // Docker network bridge br-* - must be filtered
        iface.name = "br-4f6d3a9b1c2e".to_string();
        assert!(!is_candidate_interface(&iface));

        // Virtual ethernet veth* - must be filtered
        iface.name = "veth12345".to_string();
        assert!(!is_candidate_interface(&iface));

        // Libvirt NAT bridge virbr* - must be filtered
        iface.name = "virbr0".to_string();
        assert!(!is_candidate_interface(&iface));

        // CNI bridge - must be filtered
        iface.name = "cni0".to_string();
        assert!(!is_candidate_interface(&iface));

        // Hyper-V / WSL vEthernet switch on Windows - must be filtered
        iface.name = "{A1B2C3D4-E5F6-7890-1234-567890ABCDEF}".to_string();
        iface.friendly_name = Some("vEthernet (WSL)".to_string());
        iface.description = Some("Hyper-V Virtual Ethernet Adapter".to_string());
        assert!(!is_candidate_interface(&iface));

        // Down interface - must be filtered
        let mut down_iface = netdev::Interface::dummy();
        down_iface.flags = 0; // Not UP
        down_iface.name = "eth0".to_string();
        assert!(!is_candidate_interface(&down_iface));
    }

    #[test]
    fn test_is_candidate_ip() {
        // Valid LAN IP
        assert!(is_candidate_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 117))));
        // Valid Tailscale IP
        assert!(is_candidate_ip(IpAddr::V4(Ipv4Addr::new(
            100, 77, 155, 120
        ))));
        // Valid Public IP
        assert!(is_candidate_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        // Valid IPv6 GUA
        assert!(is_candidate_ip(IpAddr::V6(Ipv6Addr::new(
            0x2a01, 0x4b00, 0xb8e3, 0x4e00, 0, 0, 0, 1
        ))));

        // Loopback - must be rejected
        assert!(!is_candidate_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_candidate_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // Unspecified - must be rejected
        assert!(!is_candidate_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_candidate_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));

        // Link-local - must be rejected
        assert!(!is_candidate_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_candidate_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0x1ff, 0xfe00, 1
        ))));

        // Broadcast - must be rejected
        assert!(!is_candidate_ip(IpAddr::V4(Ipv4Addr::BROADCAST)));
    }

    #[test]
    fn test_ip_priority_ordering() {
        let mut iface_lan = netdev::Interface::dummy();
        iface_lan.flags = 1;
        iface_lan.gateway = Some(netdev::net::device::NetworkDevice::new());

        let mut iface_vpn = netdev::Interface::dummy();
        iface_vpn.flags = 1;
        iface_vpn.name = "tailscale0".to_string();

        let lan_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 117));
        let tailscale_ip = IpAddr::V4(Ipv4Addr::new(100, 77, 155, 120));

        let p_lan = ip_priority(&iface_lan, lan_ip);
        let p_ts = ip_priority(&iface_vpn, tailscale_ip);

        // LAN IP with gateway should score higher than VPN IP without gateway
        assert!(p_lan > p_ts);
    }
}
