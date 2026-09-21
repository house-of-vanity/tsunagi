//! The WireGuard IP plugin.
//!
//! Each agent builds its own view of the overlay from the set of participants
//! the control plane agreed on. For a full mesh of `N` members that is `N - 1`
//! tunnels locally. Nobody is handed a configuration by anybody else, and no
//! participant is authoritative.
//!
//! # What this plugin does and does not know
//!
//! * It does **not** know where a peer is. It is handed a
//!   [`PacketLink`](crate::dataplane::transport::PacketLink) per peer and runs
//!   a WireGuard tunnel over it. Reachability, hole punching and relaying are
//!   the transport's problem.
//! * It owns one WireGuard key per network, in its own store, unrelated to the
//!   iroh device key and to the network secret.
//! * It owns one packet interface per network, named deterministically.
//! * It never touches an interface it did not create, and never changes
//!   routing, DNS or firewall settings beyond its own device.
//!
//! WireGuard runs in userspace via [`boringtun`], so there is no kernel module
//! and no `wg` tool to depend on. The only privileged step is creating the
//! packet interface, and even that is behind [`TunFactory`] so the whole data
//! plane can run unprivileged in tests.
//!
//! A failure here is reported and retried. It never stops the control plane.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use iroh::EndpointId;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::BoxFuture;
use crate::dataplane::transport::SharedLink;
use crate::dataplane::{IpPlugin, PluginCapability, PluginContext, PluginError};
use crate::identity::NetworkId;

use super::announcement::{ValidatedAnnouncement, WgAnnouncement};
use super::config::{DEFAULT_INTERFACE_PREFIX, interface_name};
use super::device::{PeerSummary, WireguardDevice};
use super::keys::{WgPublicKey, WgSecretKey};
use super::overlay::{OVERLAY_PREFIX_LEN, overlay_address, overlay_prefix};
use super::store::WgKeyStore;
use super::tun::{TunFactory, TunRequest};
use crate::state::Ipv4Range;

/// The protocol identifier this plugin announces.
pub const WIREGUARD_PROTOCOL: &str = "wireguard";

/// Smallest interface MTU IPv6 permits, from RFC 8200.
///
/// This is not advice, it is a hard limit. Linux tears IPv6 down entirely on
/// an interface whose MTU is below it — the per-device `/proc/sys/net/ipv6`
/// entries disappear and `ip -6 address add` fails with `Invalid argument` —
/// so the overlay address could never be assigned. Anything smaller is
/// rejected up front instead of failing obscurely later.
pub const MIN_MTU: u32 = 1280;

/// Default interface MTU.
///
/// Equal to [`MIN_MTU`], because the overlay is IPv6 and there is no room
/// below it.
pub const DEFAULT_MTU: u32 = MIN_MTU;

/// Bytes WireGuard adds to a packet: type and reserved, receiver index,
/// counter and the Poly1305 tag.
///
/// A link therefore has to carry `mtu + WIREGUARD_OVERHEAD` bytes in one
/// datagram for a full-size packet to get through.
pub const WIREGUARD_OVERHEAD: u32 = 32;

/// Configuration of the WireGuard plugin.
#[derive(Debug, Clone)]
pub struct WireguardConfig {
    /// Directory for the plugin's own key store. Separate from agent state.
    pub state_dir: PathBuf,
    /// Prefix of the interface names this plugin creates.
    ///
    /// Two agents on one host in the same network need different prefixes,
    /// because the rest of the name is derived from the network id.
    pub interface_prefix: String,
    /// WireGuard keepalive, which keeps tunnels and their links warm.
    pub keepalive: Option<u16>,
    /// Interface MTU. See [`DEFAULT_MTU`].
    pub mtu: u32,
    /// How long to coalesce changes before reconciling.
    pub reconcile_debounce: Duration,
    /// How often to reconcile anyway, which is also when a packet interface
    /// that could not be created before is retried.
    pub reconcile_interval: Duration,
}

impl WireguardConfig {
    /// Creates a configuration rooted at `state_dir` with sensible defaults.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            interface_prefix: DEFAULT_INTERFACE_PREFIX.to_string(),
            keepalive: Some(25),
            mtu: DEFAULT_MTU,
            reconcile_debounce: Duration::from_millis(200),
            reconcile_interval: Duration::from_secs(15),
        }
    }

    /// Sets the interface name prefix.
    pub fn with_interface_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.interface_prefix = prefix.into();
        self
    }

    /// Sets the interface MTU.
    ///
    /// Validated when the plugin is opened; see [`MIN_MTU`].
    pub fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Sets the reconciliation timings.
    pub fn with_reconcile(mut self, debounce: Duration, interval: Duration) -> Self {
        self.reconcile_debounce = debounce;
        self.reconcile_interval = interval;
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
    /// Packet interface this plugin created for it.
    pub interface: String,
    /// Interface MTU.
    pub mtu: u32,
    /// This agent's WireGuard public key in this network.
    pub public_key: WgPublicKey,
    /// This agent's overlay address.
    pub overlay_address: IpAddr,
    /// The overlay subnet every member shares.
    pub overlay_prefix: IpAddr,
    /// Prefix length of the overlay subnet.
    pub overlay_prefix_len: u8,
    /// This agent's IPv4 overlay address, when the overlay is dual stack.
    pub overlay_address_v4: Option<Ipv4Addr>,
    /// The IPv4 overlay range in use.
    pub ipv4_range: Option<Ipv4Range>,
    /// Peers this agent knows about.
    pub peers: Vec<PeerOverview>,
    /// Unicast packets the operating system sent to an address no peer owns.
    pub unroutable_packets: u64,
    /// Multicast packets dropped. Expected, not a fault.
    pub multicast_packets: u64,
    /// One destination nobody owned, if there was one.
    pub unroutable_sample: Option<IpAddr>,
}

impl NetworkOverview {
    /// Peers whose tunnel has completed a handshake.
    pub fn established_peers(&self) -> usize {
        self.peers.iter().filter(|peer| peer.is_up()).count()
    }
}

/// One peer of the overlay.
#[derive(Debug, Clone)]
pub struct PeerOverview {
    /// The peer's control plane identity.
    pub endpoint_id: EndpointId,
    /// The peer's WireGuard public key.
    pub public_key: WgPublicKey,
    /// The overlay address derived for it locally.
    pub overlay_address: IpAddr,
    /// Its IPv4 overlay address, once a tunnel exists and it won the address.
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
    interface: String,
    device: Option<Arc<WireguardDevice>>,
    announcements: HashMap<EndpointId, ValidatedAnnouncement>,
    links: HashMap<EndpointId, SharedLink>,
    /// What the network agreed, pushed in by the agent. Authoritative.
    allocations: HashMap<EndpointId, Ipv4Addr>,
    /// The range those allocations came from.
    ipv4_range: Option<Ipv4Range>,
    /// The address last reported as missing, so it is said once, not forever.
    reported_missing_v4: Option<Ipv4Addr>,
    /// What was last applied to the host interface.
    ///
    /// The overlay IPv4 address is allocated at run time and can change while
    /// the agent runs, so the interface has to be brought back in line
    /// without being recreated — recreating it would drop every tunnel.
    applied: Option<TunRequest>,
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
    /// This agent's endpoint id, learned when the plugin is attached.
    local_id: OnceLock<EndpointId>,
    tun_factory: Arc<dyn TunFactory>,
    store: WgKeyStore,
    shared: Mutex<Shared>,
    context: OnceLock<PluginContext>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("tun", &self.tun_factory.name())
            .field("store", &self.store.path())
            .finish()
    }
}

/// The WireGuard data plane plugin.
#[derive(Debug)]
pub struct WireguardPlugin {
    worker: Arc<Worker>,
    commands: mpsc::Sender<Command>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl WireguardPlugin {
    /// Opens the plugin's key store and starts its reconciliation task.
    ///
    /// Must be called from inside a tokio runtime; the plugin starts no
    /// runtime of its own.
    pub async fn open(
        config: WireguardConfig,
        tun_factory: Arc<dyn TunFactory>,
    ) -> Result<Arc<Self>, PluginError> {
        // Validate the prefix once, here, rather than failing per network.
        interface_name(&config.interface_prefix, NetworkId::from_bytes([0u8; 32]))?;

        if config.mtu < MIN_MTU {
            return Err(PluginError::Other(format!(
                "an MTU of {} is below the {MIN_MTU} bytes IPv6 requires (RFC 8200). \
                 Linux disables IPv6 on an interface below that, so the overlay address \
                 could never be assigned.",
                config.mtu
            )));
        }

        let path = config.key_store_path();
        let store = tokio::task::spawn_blocking(move || WgKeyStore::open(path))
            .await
            .map_err(|err| PluginError::Other(format!("key store task failed: {err}")))??;

        let worker = Arc::new(Worker {
            config,
            local_id: OnceLock::new(),
            tun_factory,
            store,
            shared: Mutex::new(Shared::default()),
            context: OnceLock::new(),
        });

        let (commands, receiver) = mpsc::channel(64);
        let task = tokio::spawn(run(Arc::clone(&worker), receiver));

        Ok(Arc::new(Self {
            worker,
            commands,
            task: Mutex::new(Some(task)),
        }))
    }

    /// What this agent has set up for a network, if anything yet.
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
                overlay_address: IpAddr::V6(announcement.overlay_address),
                overlay_address_v4: state.allocations.get(endpoint_id).copied(),
                has_link: state.links.contains_key(endpoint_id),
                tunnel: tunnels.get(&announcement.public_key).cloned(),
            })
            .collect();
        peers.sort_by_key(|peer| peer.public_key);

        Some(NetworkOverview {
            network,
            interface: state.interface.clone(),
            mtu: self.worker.config.mtu,
            public_key: state.key.public(),
            overlay_address: IpAddr::V6(overlay_address(network, &state.key.public())),
            overlay_prefix: IpAddr::V6(overlay_prefix(network)),
            overlay_prefix_len: OVERLAY_PREFIX_LEN,
            overlay_address_v4: state.allocations.get(&self.worker.local_id()).copied(),
            ipv4_range: state.ipv4_range,
            peers,
            unroutable_packets: state
                .device
                .as_ref()
                .map(|device| device.unroutable_packets())
                .unwrap_or(0),
            multicast_packets: state
                .device
                .as_ref()
                .map(|device| device.multicast_packets())
                .unwrap_or(0),
            unroutable_sample: state
                .device
                .as_ref()
                .and_then(|device| device.unroutable_sample()),
        })
    }

    /// Asks the reconciliation task to run now.
    pub async fn reconcile_now(&self, network: NetworkId) {
        let _ = self.commands.send(Command::Sync(network)).await;
    }

    fn nudge(&self, command: Command) {
        if let Err(err) = self.commands.try_send(command) {
            // A full queue means work is already scheduled; the periodic
            // reconcile picks up anything that was missed.
            tracing::debug!(%err, "wireguard command queue is busy");
        }
    }
}

impl Worker {
    /// This agent's endpoint id, or a placeholder before it is attached.
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
        tracing::warn!(network = %network.fmt_short(), %reason, "wireguard plugin error");
        if let Some(context) = self.context.get() {
            context.report_error(network, WIREGUARD_PROTOCOL, reason.to_string());
        }
    }

    fn request_reannounce(&self, network: NetworkId) {
        if let Some(context) = self.context.get() {
            context.request_reannounce(network);
        }
    }

    /// Makes sure a network has a key, a name and a running packet interface.
    ///
    /// Returns `true` when the key became available now, so peers should be
    /// told. Creating the interface may fail without privileges; the key and
    /// the announcement still work, and the interface is retried.
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
            // The key is there but the interface is not. Try again.
            self.ensure_device(network).await?;
            return Ok(false);
        }

        let name = interface_name(&self.config.interface_prefix, network)?;
        let worker = Arc::clone(self);
        let key = tokio::task::spawn_blocking(move || worker.store.load_or_create(network))
            .await
            .map_err(|err| PluginError::Other(format!("key store task failed: {err}")))??;

        {
            let mut shared = self.lock_shared();
            shared.networks.entry(network).or_insert(NetworkState {
                key,
                interface: name,
                device: None,
                announcements: HashMap::new(),
                links: HashMap::new(),
                allocations: HashMap::new(),
                ipv4_range: None,
                reported_missing_v4: None,
                applied: None,
            });
        }

        // The announcement only needs the key, so peers can be told even if
        // the interface is not up yet.
        let device = self.ensure_device(network).await;
        if let Err(err) = device {
            self.report(network, err);
        }
        Ok(true)
    }

    /// What the host interface for a network should look like.
    fn desired_request(&self, state: &NetworkState, network: NetworkId) -> TunRequest {
        let own_range = state.ipv4_range;
        TunRequest {
            name: state.interface.clone(),
            address: overlay_address(network, &state.key.public()),
            prefix_len: OVERLAY_PREFIX_LEN,
            address_v4: state.allocations.get(&self.local_id()).copied(),
            prefix_len_v4: own_range.map_or(0, |range| range.prefix_len),
            mtu: self.config.mtu,
        }
    }

    /// Creates the packet interface and starts the WireGuard device.
    async fn ensure_device(&self, network: NetworkId) -> Result<(), PluginError> {
        let (request, key, own_range) = {
            let shared = self.lock_shared();
            match shared.networks.get(&network) {
                Some(state) if state.device.is_none() => (
                    self.desired_request(state, network),
                    state.key.clone(),
                    state.ipv4_range,
                ),
                _ => return Ok(()),
            }
        };

        let applied = request.clone();
        let tun = self.tun_factory.create(request).await?;
        let device = Arc::new(WireguardDevice::start(network, key, tun, own_range));

        let mut shared = self.lock_shared();
        if let Some(state) = shared.networks.get_mut(&network) {
            state.interface = device.interface().to_string();
            state.device = Some(device);
            state.applied = Some(applied);
        }
        Ok(())
    }

    /// Brings a live interface back in line after the overlay changed its
    /// mind about this agent's address.
    async fn ensure_addresses(&self, network: NetworkId) {
        let wanted = {
            let shared = self.lock_shared();
            match shared.networks.get(&network) {
                Some(state) if state.device.is_some() => {
                    let wanted = self.desired_request(state, network);
                    if state.applied.as_ref() == Some(&wanted) {
                        return;
                    }
                    wanted
                }
                _ => return,
            }
        };

        match self.tun_factory.reconfigure(wanted.clone()).await {
            Ok(()) => {
                let mut shared = self.lock_shared();
                if let Some(state) = shared.networks.get_mut(&network) {
                    state.applied = Some(wanted);
                }
            }
            Err(err) => {
                // Not fatal: the tunnels keep running on the addresses that
                // are there, and the next reconciliation tries again.
                tracing::warn!(%err, "cannot update the overlay interface addresses");
                self.report(network, err);
            }
        }
    }

    /// Brings the running tunnels in line with what is known.
    ///
    /// A peer gets a tunnel once both halves have arrived: its announcement,
    /// which says who it is, and a link, which says packets can reach it.
    fn sync(&self, network: NetworkId) {
        let mut shared = self.lock_shared();
        let Some(state) = shared.networks.get_mut(&network) else {
            return;
        };
        let Some(device) = state.device.clone() else {
            return;
        };

        let allocations = state.allocations.clone();
        let own_v4 = state.allocations.get(&self.local_id()).copied();
        let interface = state.device.as_ref().map(|_| state.interface.clone());
        let range = state.ipv4_range;
        let state_reported = state.reported_missing_v4;
        let mut wanted: Vec<WgPublicKey> = Vec::new();
        let mut too_small: Vec<(usize, usize)> = Vec::new();
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

            // A link that cannot carry a full-size packet will silently drop
            // the large ones, which looks like a broken network rather than a
            // configuration problem. Say so when the tunnel is set up.
            let needed = self.config.mtu.saturating_add(WIREGUARD_OVERHEAD) as usize;
            let available = link.max_datagram_size();
            if available < needed {
                too_small.push((available, needed));
            }

            // The address comes from the agreed signed state, not from
            // anything this peer said and not from a derivation: that is what
            // makes it survive the peer being away.
            let peer_v4 = allocations.get(endpoint_id).copied();

            if let Err(err) = device.add_peer(
                *endpoint_id,
                announcement.public_key,
                peer_v4,
                Arc::clone(link),
                self.config.keepalive,
            ) {
                tracing::debug!(%err, "cannot start a WireGuard tunnel");
            }
        }
        device.retain_peers(&wanted);

        // The agent assigns this address itself, so finding it absent means
        // the assignment did not take — something outside removed it, or the
        // provisioner reported a success it did not achieve. Left unsaid it
        // looks like a broken network: the kernel would send packets with the
        // wrong source address and every peer would drop them. So it is
        // checked rather than assumed, because the assumption is exactly the
        // kind that has been wrong here before.
        let missing_v4 = match (own_v4, interface.as_deref(), range) {
            (Some(address), Some(interface), Some(range))
                if !super::tun::address_is_local(IpAddr::V4(address)) =>
            {
                let already = state_reported == Some(address);
                if let Some(state) = shared.networks.get_mut(&network) {
                    state.reported_missing_v4 = Some(address);
                }
                (!already).then_some((address, interface.to_string(), range))
            }
            _ => {
                if let Some(state) = shared.networks.get_mut(&network) {
                    state.reported_missing_v4 = None;
                }
                None
            }
        };
        drop(shared);

        if let Some((address, interface, range)) = missing_v4 {
            self.report(
                network,
                format!(
                    "this agent was allocated {address}/{} but the address is not on any \
                     interface, so IPv4 cannot work: packets would leave with the wrong \
                     source and every peer would drop them. It should have been assigned \
                     to `{interface}` automatically; check whether something else removed \
                     it.",
                    range.prefix_len
                ),
            );
        }

        for (available, needed) in too_small {
            self.report(
                network,
                format!(
                    "this path carries only {available} byte datagrams but a {} byte MTU needs \
                     {needed}; packets larger than {} bytes will be dropped. Lower the MTU only \
                     if you can stay at or above {MIN_MTU}, which IPv6 requires.",
                    self.config.mtu,
                    available.saturating_sub(WIREGUARD_OVERHEAD as usize)
                ),
            );
        }
    }

    /// Removes a network's interface and tunnels, keeping its key.
    async fn teardown(&self, network: NetworkId) {
        // Dropping the state drops the device, which stops its tasks and
        // closes the packet interface. Closing it is already enough for the
        // kernel to remove an interface this agent created; the explicit
        // destroy makes that immediate and definite rather than dependent on
        // the last reader letting go.
        let removed = self.lock_shared().networks.remove(&network);
        if let Some(state) = removed {
            drop(state.device);
            self.tun_factory.destroy(&state.interface).await;
        }
    }

    fn known_networks(&self) -> Vec<NetworkId> {
        self.lock_shared().networks.keys().copied().collect()
    }
}

/// The reconciliation task.
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
                    worker.ensure_addresses(network).await;
                    worker.sync(network);
                }
            }
            _ = ticker.tick() => {
                for network in worker.known_networks() {
                    // Also the retry for an interface that could not be
                    // created earlier.
                    if let Err(err) = worker.ensure_device(network).await {
                        tracing::debug!(%err, "packet interface still unavailable");
                    }
                    worker.ensure_addresses(network).await;
                    worker.sync(network);
                }
            }
        }
    }
}

impl IpPlugin for WireguardPlugin {
    fn protocol_id(&self) -> &str {
        WIREGUARD_PROTOCOL
    }

    fn attach(&self, context: PluginContext) {
        if let Some(local) = context.local_endpoint_id() {
            let _ = self.worker.local_id.set(local);
        }
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
            // Not ready yet. Ask for preparation; once the key exists the
            // plugin asks the agent to re-announce.
            drop(shared);
            self.nudge(Command::Prepare(network));
            return Ok(None);
        };

        // Identity only. Where to send packets is the transport's business.
        let announcement = WgAnnouncement::new(network, &state.key.public());
        Ok(Some(PluginCapability {
            protocol: WIREGUARD_PROTOCOL.to_string(),
            version: super::announcement::ANNOUNCEMENT_VERSION,
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

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            if self.commands.send(Command::Stop(reply_tx)).await.is_ok() {
                let _ = reply_rx.await;
            }
            let task = self.task.lock().ok().and_then(|mut guard| guard.take());
            if let Some(task) = task {
                let _ = task.await;
            }
        })
    }
}

impl Drop for WireguardPlugin {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.task.lock()
            && let Some(task) = guard.take()
        {
            task.abort();
        }
    }
}
