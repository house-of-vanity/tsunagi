//! The WireGuard IP plugin.
//!
//! Each agent builds its **own** local configuration from the set of
//! participants the control plane agreed on. For a full mesh of `N` members
//! that is `N - 1` peers locally. Nobody is handed a configuration by anybody
//! else, and no participant is authoritative.
//!
//! What the plugin owns and what it never touches:
//!
//! * it owns one WireGuard key per network, in its own store;
//! * it owns one interface per network, named deterministically from the
//!   network id and its configured prefix;
//! * it never enumerates, adopts or edits an interface it did not create, and
//!   it never changes routing, DNS or firewall settings.
//!
//! Reconciliation runs on every change and on a timer, so a configuration
//! edited by hand is put back the way it should be.
//!
//! A failure here is reported and retried. It never stops the control plane:
//! the agent keeps receiving state and stays manageable.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use iroh::EndpointId;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::BoxFuture;
use crate::dataplane::{IpPlugin, PluginCapability, PluginContext, PluginError};
use crate::identity::NetworkId;

use super::announcement::{ValidatedAnnouncement, WgAnnouncement};
use super::backend::WireguardBackend;
use super::config::{
    DEFAULT_INTERFACE_PREFIX, InterfaceConfig, InterfaceParams, PortPolicy, build_interface,
    interface_name,
};
use super::keys::{WgPublicKey, WgSecretKey};
use super::overlay::{overlay_address, overlay_prefix};
use super::store::WgKeyStore;

/// The protocol identifier this plugin announces.
pub const WIREGUARD_PROTOCOL: &str = "wireguard";

/// How the plugin advertises its own reachability.
///
/// An iroh address is an address for iroh. WireGuard needs its own, so the
/// plugin gathers its own rather than reusing the control plane's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvertisePolicy {
    /// Advertise nothing.
    ///
    /// Peers can still reach this agent if they are reachable themselves:
    /// WireGuard learns a peer's real source address from the first
    /// authenticated packet it receives.
    None,
    /// Advertise exactly these addresses, combined with the listening port.
    Explicit(Vec<IpAddr>),
    /// Advertise the host's own non-loopback addresses.
    LocalInterfaces,
}

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
    /// How the listening port is chosen.
    pub ports: PortPolicy,
    /// What reachability to advertise.
    pub advertise: AdvertisePolicy,
    /// Keepalive interval, which holds a NAT mapping open.
    pub keepalive: Option<u16>,
    /// Interface MTU.
    pub mtu: Option<u32>,
    /// How long to coalesce changes before reconciling.
    pub reconcile_debounce: Duration,
    /// How often to reconcile even when nothing changed, which is what
    /// corrects a configuration someone edited by hand.
    pub reconcile_interval: Duration,
}

impl WireguardConfig {
    /// Creates a configuration rooted at `state_dir` with sensible defaults.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            interface_prefix: DEFAULT_INTERFACE_PREFIX.to_string(),
            ports: PortPolicy::default(),
            advertise: AdvertisePolicy::LocalInterfaces,
            keepalive: Some(25),
            mtu: Some(1380),
            reconcile_debounce: Duration::from_millis(200),
            reconcile_interval: Duration::from_secs(30),
        }
    }

    /// Sets the interface name prefix.
    pub fn with_interface_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.interface_prefix = prefix.into();
        self
    }

    /// Sets the port policy.
    pub fn with_ports(mut self, ports: PortPolicy) -> Self {
        self.ports = ports;
        self
    }

    /// Sets what reachability to advertise.
    pub fn with_advertise(mut self, advertise: AdvertisePolicy) -> Self {
        self.advertise = advertise;
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
    /// Interface this plugin created for it.
    pub interface: String,
    /// This agent's WireGuard public key in this network.
    pub public_key: WgPublicKey,
    /// This agent's overlay address.
    pub overlay_address: IpAddr,
    /// The overlay subnet every member shares.
    pub overlay_prefix: IpAddr,
    /// Port the interface listens on.
    pub listen_port: u16,
    /// Reachability advertised to peers.
    pub advertised: Vec<SocketAddr>,
    /// Peers whose announcements were accepted.
    pub peers: Vec<PeerOverview>,
}

/// One accepted peer.
#[derive(Debug, Clone)]
pub struct PeerOverview {
    /// The peer's control plane identity.
    pub endpoint_id: EndpointId,
    /// The peer's WireGuard public key.
    pub public_key: WgPublicKey,
    /// The overlay address derived for it locally.
    pub overlay_address: IpAddr,
    /// Endpoint that will be configured for it, if any.
    pub endpoint: Option<SocketAddr>,
}

#[derive(Debug)]
struct NetworkState {
    key: WgSecretKey,
    interface: String,
    listen_port: u16,
    advertised: Vec<SocketAddr>,
    peers: HashMap<EndpointId, ValidatedAnnouncement>,
}

#[derive(Debug, Default)]
struct Shared {
    networks: HashMap<NetworkId, NetworkState>,
}

#[derive(Debug)]
enum Command {
    /// Make sure a network has keys, a name and a port.
    Prepare(NetworkId),
    /// Bring the interface in line with the known peers.
    Sync(NetworkId),
    /// Remove the interface for a network.
    Teardown(NetworkId),
    /// Tear everything down and stop.
    Stop(oneshot::Sender<()>),
}

struct Worker {
    config: WireguardConfig,
    backend: Arc<dyn WireguardBackend>,
    store: WgKeyStore,
    shared: Mutex<Shared>,
    context: OnceLock<PluginContext>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("backend", &self.backend.name())
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
        backend: Arc<dyn WireguardBackend>,
    ) -> Result<Arc<Self>, PluginError> {
        // Validate the prefix once, here, rather than failing per network.
        interface_name(&config.interface_prefix, NetworkId::from_bytes([0u8; 32]))?;

        let path = config.key_store_path();
        let store = tokio::task::spawn_blocking(move || WgKeyStore::open(path))
            .await
            .map_err(|err| PluginError::Other(format!("key store task failed: {err}")))??;

        let worker = Arc::new(Worker {
            config,
            backend,
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
        let mut peers: Vec<PeerOverview> = state
            .peers
            .iter()
            .map(|(endpoint_id, announcement)| PeerOverview {
                endpoint_id: *endpoint_id,
                public_key: announcement.public_key,
                overlay_address: IpAddr::V6(announcement.overlay_address),
                endpoint: announcement.preferred_endpoint(),
            })
            .collect();
        peers.sort_by_key(|peer| peer.public_key);

        Some(NetworkOverview {
            network,
            interface: state.interface.clone(),
            public_key: state.key.public(),
            overlay_address: IpAddr::V6(overlay_address(network, &state.key.public())),
            overlay_prefix: IpAddr::V6(overlay_prefix(network)),
            listen_port: state.listen_port,
            advertised: state.advertised.clone(),
            peers,
        })
    }

    /// Asks the reconciliation task to run now, and waits for it to be queued.
    ///
    /// Tests use it to avoid waiting for the periodic tick.
    pub async fn reconcile_now(&self, network: NetworkId) {
        let _ = self.commands.send(Command::Sync(network)).await;
    }

    fn nudge(&self, command: Command) {
        if let Err(err) = self.commands.try_send(command) {
            // A full queue means work is already scheduled; the periodic
            // reconcile will pick anything up that was missed.
            tracing::debug!(%err, "wireguard command queue is busy");
        }
    }
}

impl Worker {
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

    /// Gathers the addresses to advertise for our own listening port.
    async fn advertised_endpoints(&self, listen_port: u16) -> Vec<SocketAddr> {
        let addresses: Vec<IpAddr> = match &self.config.advertise {
            AdvertisePolicy::None => Vec::new(),
            AdvertisePolicy::Explicit(addresses) => addresses.clone(),
            AdvertisePolicy::LocalInterfaces => {
                let state = netwatch::interfaces::State::new().await;
                state.local_addresses.regular
            }
        };

        let mut endpoints: Vec<SocketAddr> = addresses
            .into_iter()
            .filter(|addr| !addr.is_loopback() && !addr.is_unspecified() && !is_link_local(addr))
            .map(|addr| SocketAddr::new(addr, listen_port))
            .collect();
        endpoints.sort();
        endpoints.dedup();
        endpoints.truncate(super::announcement::MAX_ENDPOINTS);
        endpoints
    }

    /// Makes sure a network has a key, an interface name and a port.
    ///
    /// Returns `true` when something changed and peers should be told.
    async fn prepare(self: &Arc<Self>, network: NetworkId) -> Result<bool, PluginError> {
        let existing = {
            let shared = self.lock_shared();
            shared
                .networks
                .get(&network)
                .map(|state| (state.listen_port, state.advertised.clone()))
        };

        let listen_port = match existing {
            Some((port, _)) => port,
            None => self.config.ports.port_for(network)?,
        };
        let advertised = self.advertised_endpoints(listen_port).await;

        if let Some((_, previous)) = existing {
            if previous == advertised {
                return Ok(false);
            }
            let mut shared = self.lock_shared();
            if let Some(state) = shared.networks.get_mut(&network) {
                state.advertised = advertised;
            }
            return Ok(true);
        }

        let name = interface_name(&self.config.interface_prefix, network)?;
        let worker = Arc::clone(self);
        let key = tokio::task::spawn_blocking(move || worker.store.load_or_create(network))
            .await
            .map_err(|err| PluginError::Other(format!("key store task failed: {err}")))??;

        let mut shared = self.lock_shared();
        shared.networks.entry(network).or_insert(NetworkState {
            key,
            interface: name,
            listen_port,
            advertised,
            peers: HashMap::new(),
        });
        Ok(true)
    }

    /// Builds the configuration this agent wants for a network.
    fn desired_config(&self, network: NetworkId) -> Option<InterfaceConfig> {
        let shared = self.lock_shared();
        let state = shared.networks.get(&network)?;

        let endpoints: HashMap<WgPublicKey, SocketAddr> = state
            .peers
            .values()
            .filter_map(|announcement| {
                announcement
                    .preferred_endpoint()
                    .map(|endpoint| (announcement.public_key, endpoint))
            })
            .collect();
        let keys: Vec<WgPublicKey> = state
            .peers
            .values()
            .map(|announcement| announcement.public_key)
            .collect();

        Some(build_interface(
            InterfaceParams {
                network,
                name: state.interface.clone(),
                private_key: state.key.clone(),
                listen_port: state.listen_port,
                mtu: self.config.mtu,
                keepalive: self.config.keepalive,
            },
            keys,
            |key| endpoints.get(key).copied(),
        ))
    }

    /// Brings the interface in line with the desired configuration.
    async fn sync(&self, network: NetworkId) -> Result<(), PluginError> {
        let Some(desired) = self.desired_config(network) else {
            return Ok(());
        };
        let backend = Arc::clone(&self.backend);
        tokio::task::spawn_blocking(move || {
            let current = backend.inspect(&desired.name)?;
            // Reconciliation: anything that drifted, including an edit made by
            // hand, is corrected here.
            if current.as_ref() == Some(&desired.to_state()) {
                return Ok(());
            }
            backend.apply(&desired)
        })
        .await
        .map_err(|err| PluginError::Other(format!("wireguard apply task failed: {err}")))?
    }

    /// Removes the interface for a network, keeping its key.
    async fn teardown(&self, network: NetworkId) -> Result<(), PluginError> {
        let interface = {
            let mut shared = self.lock_shared();
            shared
                .networks
                .remove(&network)
                .map(|state| state.interface)
        };
        let Some(interface) = interface else {
            return Ok(());
        };
        let backend = Arc::clone(&self.backend);
        tokio::task::spawn_blocking(move || backend.remove(&interface))
            .await
            .map_err(|err| PluginError::Other(format!("wireguard remove task failed: {err}")))?
    }

    fn known_networks(&self) -> Vec<NetworkId> {
        self.lock_shared().networks.keys().copied().collect()
    }
}

/// The reconciliation task.
///
/// Changes are coalesced over a short debounce so that a burst of peer
/// announcements produces one apply, and a periodic tick reconciles even when
/// nothing changed locally.
async fn run(worker: Arc<Worker>, mut commands: mpsc::Receiver<Command>) {
    let mut pending: BTreeSet<NetworkId> = BTreeSet::new();
    let mut deadline: Option<tokio::time::Instant> = None;
    let mut ticker = tokio::time::interval(worker.config.reconcile_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires immediately and would reconcile nothing.
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
                    Command::Teardown(network) => {
                        pending.remove(&network);
                        if let Err(err) = worker.teardown(network).await {
                            worker.report(network, err);
                        }
                        continue;
                    }
                    Command::Stop(reply) => {
                        for network in worker.known_networks() {
                            if let Err(err) = worker.teardown(network).await {
                                tracing::warn!(%err, "wireguard teardown failed during shutdown");
                            }
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
                    // Never resolves; the branch is disabled by the guard.
                    None => std::future::pending::<()>().await,
                }
            }, if wait_until.is_some() => {
                deadline = None;
                for network in std::mem::take(&mut pending) {
                    if let Err(err) = worker.sync(network).await {
                        worker.report(network, err);
                    }
                }
            }
            _ = ticker.tick() => {
                // Periodic reconciliation is what corrects drift nobody told
                // us about.
                for network in worker.known_networks() {
                    if let Err(err) = worker.sync(network).await {
                        worker.report(network, err);
                    }
                }
            }
        }
    }
}

fn is_link_local(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

impl IpPlugin for WireguardPlugin {
    fn protocol_id(&self) -> &str {
        WIREGUARD_PROTOCOL
    }

    fn attach(&self, context: PluginContext) {
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
            // Not ready yet. Ask for preparation; once it finishes the plugin
            // asks the agent to re-announce, so peers are not left waiting.
            drop(shared);
            self.nudge(Command::Prepare(network));
            return Ok(None);
        };

        let announcement = WgAnnouncement::new(
            network,
            &state.key.public(),
            state.listen_port,
            state.advertised.clone(),
        );
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
                    state.peers.insert(peer, validated) != state.peers.get(&peer).cloned()
                }
                None => false,
            }
        };
        if changed {
            self.nudge(Command::Sync(network));
        }
        Ok(())
    }

    fn on_peer_gone(&self, network: NetworkId, peer: EndpointId) {
        let removed = {
            let mut shared = self.worker.lock_shared();
            shared
                .networks
                .get_mut(&network)
                .and_then(|state| state.peers.remove(&peer))
                .is_some()
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
        // Safety net for a plugin dropped without an explicit shutdown.
        if let Ok(mut guard) = self.task.lock()
            && let Some(task) = guard.take()
        {
            task.abort();
        }
    }
}
