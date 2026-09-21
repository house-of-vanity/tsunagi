//! The WireGuard protocol plugin.
//!
//! Each agent builds its own view of the overlay from the set of participants
//! the control plane agreed on. For a full mesh of `N` members that is `N - 1`
//! tunnels locally. Nobody is handed a configuration by anybody else, and no
//! participant is authoritative.
//!
//! # What this plugin does and does not know
//!
//! * It does **not** know where a peer is. It is handed a
//!   [`PacketLink`](tsunagi::dataplane::transport::PacketLink) per peer and runs
//!   a WireGuard tunnel over it. Reachability, hole punching and relaying are
//!   the transport's problem.
//! * It does **not** know which addresses anybody holds, and owns no
//!   interface. One agent has one interface, at the system level, and every
//!   protocol carries traffic for the same addresses on it. A packet arrives
//!   here already routed and leaves here already decrypted.
//! * It owns one WireGuard key per network, in its own store, unrelated to the
//!   iroh device key and to the network secret.
//!
//! WireGuard runs in userspace via [`boringtun`], so there is no kernel module
//! and no `wg` tool to depend on, and nothing this plugin does needs
//! privileges: creating the interface is somebody else's job now.
//!
//! A failure here is reported and retried. It never stops the control plane.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use iroh::EndpointId;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use tsunagi::BoxFuture;
use tsunagi::dataplane::PacketSink;
use tsunagi::dataplane::transport::SharedLink;
use tsunagi::dataplane::{IpPlugin, PluginCapability, PluginContext, PluginError};
use tsunagi::identity::NetworkId;

use crate::announcement::{ValidatedAnnouncement, WgAnnouncement};
use crate::device::{PeerSummary, WireguardDevice};
use crate::keys::{WgPublicKey, WgSecretKey};
use crate::store::WgKeyStore;
use tsunagi::state::Ipv4Range;
use tsunagi::task::{TASK_GRACE, wind_down};

/// The protocol identifier this plugin announces.
/// The protocol id of this plugin.
///
/// `wg-quic`, because that is what it is: WireGuard's cryptography carried
/// in QUIC datagrams. The name is on the wire, so it is a protocol name and
/// not a description of the implementation.
pub const WIREGUARD_PROTOCOL: &str = "wg-quic";

/// Smallest interface MTU the overlay accepts.
///
/// 576 bytes is what IPv4 guarantees every host can reassemble (RFC 1122),
/// so nothing below it is worth offering. The floor used to be 1280 because
/// Linux tears IPv6 down on an interface below that; the overlay is IPv4
/// now, so that constraint is gone and a path with small datagrams — a
/// relay, typically — can be matched instead of warned about.
pub const MIN_MTU: u32 = 576;

/// Default interface MTU.
///
/// Comfortably under what a direct path carries, and the same number the
/// overlay used before, so an existing network does not have to change.
pub const DEFAULT_MTU: u32 = 1280;

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
    /// WireGuard keepalive, which keeps tunnels and their links warm.
    pub keepalive: Option<u16>,
    /// The largest packet a tunnel will carry.
    ///
    /// Not the interface MTU, which belongs to the agent: this is what this
    /// protocol refuses to encrypt because it would not fit one datagram.
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
            keepalive: Some(25),
            mtu: DEFAULT_MTU,
            reconcile_debounce: Duration::from_millis(200),
            reconcile_interval: Duration::from_secs(15),
        }
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
    /// The largest packet a tunnel in this network will carry.
    pub mtu: u32,
    /// This agent's WireGuard public key in this network.
    pub public_key: WgPublicKey,
    /// This agent's overlay address, once the network has agreed one.
    pub overlay_address_v4: Option<Ipv4Addr>,
    /// The IPv4 overlay range in use.
    pub ipv4_range: Option<Ipv4Range>,
    /// Peers this agent knows about.
    pub peers: Vec<PeerOverview>,
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
    /// What the network agreed, pushed in by the agent. Authoritative.
    allocations: HashMap<EndpointId, Ipv4Addr>,
    /// The range those allocations came from.
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
    /// This agent's endpoint id, learned when the plugin is attached.
    local_id: OnceLock<EndpointId>,
    store: WgKeyStore,
    shared: Mutex<Shared>,
    context: OnceLock<PluginContext>,
    /// Where decrypted packets go, once the agent has attached one.
    sink: OnceLock<Arc<dyn PacketSink>>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
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
    /// The settings this protocol accepts.
    pub const OPTIONS: &'static [tsunagi::dataplane::ProtocolOption] = &[
        tsunagi::dataplane::ProtocolOption {
            key: "keepalive",
            value: "SECONDS",
            help: "keeps a tunnel and its link warm through a NAT; 0 turns it off",
            default: Some("25"),
        },
        tsunagi::dataplane::ProtocolOption {
            key: "mtu",
            value: "BYTES",
            help: "largest packet a tunnel will carry, at least 576",
            default: Some("1280"),
        },
    ];

    /// Applies `key=value` settings to a configuration.
    ///
    /// An unknown key is refused rather than ignored: a setting that was
    /// silently dropped looks exactly like one that did not work.
    pub fn configure(
        mut config: WireguardConfig,
        options: &[(String, String)],
    ) -> Result<WireguardConfig, PluginError> {
        for (key, value) in options {
            match key.as_str() {
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
                        "`{other}` is not a setting of {WIREGUARD_PROTOCOL}; it takes {}",
                        known.join(", ")
                    )));
                }
            }
        }
        Ok(config)
    }

    /// Opens the plugin's key store and starts its reconciliation task.
    ///
    /// Must be called from inside a tokio runtime; the plugin starts no
    /// runtime of its own.
    pub async fn open(config: WireguardConfig) -> Result<Arc<Self>, PluginError> {
        if config.mtu < MIN_MTU {
            return Err(PluginError::Other(format!(
                "an MTU of {} is below the {MIN_MTU} bytes every IPv4 host must be able \
                 to reassemble (RFC 1122)",
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

        // The announcement only needs the key, so peers can be told even if
        // the interface is not up yet.
        let device = self.ensure_device(network).await;
        if let Err(err) = device {
            self.report(network, err);
        }
        Ok(true)
    }

    /// Starts this network's tunnels.
    ///
    /// No interface is created: one agent has one, it belongs to the system
    /// level, and decrypted packets are handed there rather than written
    /// out.
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
            // Not attached to an agent: the protocol still runs, and its
            // packets have nowhere to go.
            None => Arc::new(tsunagi::dataplane::DiscardPackets) as Arc<dyn PacketSink>,
        };
        let device = Arc::new(WireguardDevice::start(network, key, sink));

        let mut shared = self.lock_shared();
        if let Some(state) = shared.networks.get_mut(&network) {
            state.device = Some(device);
        }
        Ok(())
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

        drop(shared);

        for (available, needed) in too_small {
            self.report(
                network,
                format!(
                    "this path carries only {available} byte datagrams but a {} byte MTU needs \
                     {needed}; packets larger than {} bytes will be dropped. The floor is \
                     {MIN_MTU} bytes, what every IPv4 host must be able to reassemble.",
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
        // Dropping the state drops the tunnels, which stops their tasks and
        // closes their links. There is no interface to remove: the agent owns
        // it, and it outlives any one network.
        self.lock_shared().networks.remove(&network);
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

    fn protocol_version(&self) -> u16 {
        crate::announcement::ANNOUNCEMENT_VERSION
    }

    fn options(&self) -> &'static [tsunagi::dataplane::ProtocolOption] {
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
            version: crate::announcement::ANNOUNCEMENT_VERSION,
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
        // The key is this protocol's identity in that network and nothing
        // else's. Keeping it after leaving would keep a secret for a
        // network this agent is no longer in — and hand back the same
        // overlay address on a rejoin that everyone else has moved past.
        if let Err(err) = self.worker.store.forget(network) {
            tracing::warn!(%err, "cannot remove the WireGuard key of a network we left");
        }
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            if self.commands.send(Command::Stop(reply_tx)).await.is_ok() {
                // Bounded here as well as by the agent's grace: that grace
                // abandons this future, which would leave the runtime task
                // running behind it.
                let _ = tokio::time::timeout(TASK_GRACE, reply_rx).await;
            }
            let task = self.task.lock().ok().and_then(|mut guard| guard.take());
            if let Some(task) = task {
                wind_down(task, TASK_GRACE, "wg-quic runtime").await;
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
