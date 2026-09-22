//! The agent runtime.
//!
//! An [`Agent`] owns one persistent identity, one iroh endpoint, one state
//! directory and any number of networks. It is started explicitly with
//! [`Agent::spawn`] and stopped explicitly with [`Agent::shutdown`]; it starts
//! no runtime of its own, installs no global logger, handles no signals and
//! never calls `process::exit`. Several agents can therefore run side by side in
//! one process, which is exactly what the integration tests do.
//!
//! # Local readiness
//!
//! [`Agent::spawn`] returns as soon as the local agent is ready. It never waits
//! for other participants to appear or for a relay to become reachable.
//!
//! # Failure containment
//!
//! A bad signature, a wrong secret, a malformed frame or an unknown version
//! rejects that message or that session. It never stops another network and
//! never stops the agent. There is no global, irreversible error flag.

mod events;
mod network;
mod session;
mod shutdown;
mod status;

pub use events::Event;
pub use status::{
    AgentStatus, CandidateStatus, MemberStatus, NetworkMetrics, NetworkState, NetworkStatus,
    OverlayStatus, PeerStatus,
};

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use iroh::{EndpointAddr, EndpointId};
use tokio::sync::{RwLock, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::BoxFuture;
use crate::config::{AgentConfig, Limits};
use crate::dataplane::transport::PacketTransport;
use crate::dataplane::transport::iroh_link::{IrohTransport, TransportContext};
use crate::dataplane::{PacketSink, PluginContext, PluginRequest};
use crate::error::{Error, Result};
use crate::identity::{DeviceIdentity, NetworkId, NetworkKeys, NetworkName, NetworkSecret};
use crate::net::EndpointAdapter;
use crate::overlay::PacketCarrier;
use crate::proto::handshake;
use crate::proto::message::ControlMessage;
use crate::state::Ipv4Range;
use crate::storage::{CacheOutcome, Storage};

use crate::task::{TASK_GRACE, wind_down};
use network::{InboundSession, NetCommand, NetworkHandle, RuntimeParams};
use shutdown::Shutdown;

/// Summary of a configured network, whether or not it is running.
#[derive(Debug, Clone)]
pub struct ConfiguredNetwork {
    /// Saved local broadcast participation.
    pub broadcast: bool,
    /// Public network identifier.
    pub network_id: NetworkId,
    /// Network name.
    pub name: NetworkName,
    /// Whether it is activated automatically at startup.
    pub auto_start: bool,
    /// Whether it is currently running.
    pub active: bool,
}

/// A running agent.
///
/// Cloning gives another handle to the same agent.
#[derive(Debug, Clone)]
pub struct Agent {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: AgentConfig,
    limits: Arc<Limits>,
    storage: Storage,
    identity: DeviceIdentity,
    adapter: EndpointAdapter,
    /// Behind a lock because it can be changed while the agent runs.
    hostname: std::sync::RwLock<String>,
    events: broadcast::Sender<Event>,
    networks: RwLock<HashMap<NetworkId, NetworkHandle>>,
    shutdown: Shutdown,
    accept_task: std::sync::Mutex<Option<JoinHandle<()>>>,
    plugin_task: std::sync::Mutex<Option<JoinHandle<()>>>,
    transport: std::sync::OnceLock<Arc<dyn PacketTransport>>,
    /// Who holds which overlay address, across every network.
    routes: Arc<crate::overlay::RoutingTable>,
    /// The one interface, when the agent was given a way to make one.
    interface: std::sync::OnceLock<Arc<crate::overlay::Interface>>,
}

impl Inner {
    /// The name this agent currently answers to.
    fn read_hostname(&self) -> String {
        match self.hostname.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Replaces it. Only [`Agent::set_hostname`] does this.
    fn write_hostname(&self, hostname: String) {
        match self.hostname.write() {
            Ok(mut guard) => *guard = hostname,
            Err(poisoned) => *poisoned.into_inner() = hostname,
        }
    }
}

/// Routes an outbound packet to whichever protocol can carry it.
///
/// Holds a weak reference: the interface belongs to the agent, and a strong
/// one here would keep the agent alive for as long as its own interface.
struct Carrier(Weak<Inner>);

impl std::fmt::Debug for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Carrier")
    }
}

impl std::fmt::Debug for Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sink")
    }
}

impl PacketCarrier for Carrier {
    fn carry(&self, route: crate::overlay::Route, packet: bytes::Bytes) -> bool {
        let Some(inner) = self.0.upgrade() else {
            return false;
        };
        // Offered to each protocol in turn. With one configured this is a
        // single call; the shape is what allows several to be live at once,
        // each carrying the peers it has a link to.
        inner
            .config
            .plugins
            .iter()
            .any(|plugin| plugin.carry(route.network, route.peer, packet.clone()))
    }
}

/// Writes a packet a protocol decrypted to the interface.
struct Sink(Weak<Inner>);

impl PacketSink for Sink {
    fn deliver<'a>(
        &'a self,
        network: NetworkId,
        peer: EndpointId,
        packet: bytes::Bytes,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let Some(inner) = self.0.upgrade() else {
                return;
            };
            let Some(interface) = inner.interface.get() else {
                return;
            };
            // The rejection is already counted on the interface; there is
            // nothing useful to do with it here.
            let _ = interface.deliver(network, peer, packet).await;
        })
    }
}

/// Answers the data plane transport's questions about the agent.
///
/// Holds a weak reference for the same reason as [`Carrier`]: the transport
/// lives inside the agent, so a strong one would be a cycle and the agent —
/// with its open databases and its directory lock — would never be released.
#[derive(Debug)]
struct TransportCtx(Weak<Inner>);

impl TransportContext for TransportCtx {
    fn snapshot(&self) -> crate::BoxFuture<'_, HashMap<NetworkId, NetworkKeys>> {
        Box::pin(async move {
            let Some(inner) = self.0.upgrade() else {
                return HashMap::new();
            };
            inner
                .networks
                .read()
                .await
                .iter()
                .map(|(id, handle)| (*id, handle.keys.clone()))
                .collect()
        })
    }

    fn serves<'a>(&'a self, network: NetworkId, protocol: &'a str) -> crate::BoxFuture<'a, bool> {
        Box::pin(async move {
            let Some(inner) = self.0.upgrade() else {
                return false;
            };
            if !inner.networks.read().await.contains_key(&network) {
                return false;
            }
            inner
                .config
                .plugins
                .iter()
                .any(|plugin| plugin.protocol_id() == protocol)
        })
    }
}

impl Agent {
    /// Starts an agent.
    ///
    /// Opens the state store (taking its ownership lock), restores the
    /// persistent device identity, binds the iroh endpoint and activates every
    /// configured network whose auto-start flag is set.
    pub async fn spawn(config: AgentConfig) -> Result<Self> {
        let storage = Storage::open(&config.paths)?;
        let identity = storage.device_identity().await?;
        let adapter = EndpointAdapter::bind(&config, &identity).await?;

        let hostname = resolve_hostname(&config, &storage, identity.endpoint_id())?;
        storage.set_hostname(hostname.clone()).await?;
        let hostname = std::sync::RwLock::new(hostname);

        let (events, _) = broadcast::channel(config.limits.event_buffer);
        let limits = Arc::new(config.limits.clone());

        let inner = Arc::new(Inner {
            limits,
            storage,
            identity,
            adapter,
            hostname,
            events,
            networks: RwLock::new(HashMap::new()),
            shutdown: Shutdown::new(),
            accept_task: std::sync::Mutex::new(None),
            plugin_task: std::sync::Mutex::new(None),
            transport: std::sync::OnceLock::new(),
            routes: Arc::new(crate::overlay::RoutingTable::new()),
            interface: std::sync::OnceLock::new(),
            config,
        });

        // One interface for the agent, if it was given a way to make one.
        // Failing to is reported and not fatal: the control plane works, and
        // so do the protocols, they just have nowhere to put packets.
        if let Some(factory) = inner.config.tun_factory.clone() {
            let carrier = Arc::new(Carrier(Arc::downgrade(&inner))) as Arc<dyn PacketCarrier>;
            match crate::overlay::Interface::start(
                factory,
                inner.config.interface_name.clone(),
                inner.config.interface_mtu,
                Arc::clone(&inner.routes),
                carrier,
            )
            .await
            {
                Ok(interface) => {
                    let _ = inner.interface.set(Arc::new(interface));
                }
                Err(err) => {
                    let _ = inner.events.send(Event::PluginError {
                        network: NetworkId::from_bytes([0u8; 32]),
                        protocol: "overlay".into(),
                        reason: err.to_string(),
                    });
                }
            }
        }

        // The data plane rides on iroh too, which is where it gets hole
        // punching and relay fallback from. It is a separate ALPN and a
        // separate connection, so the two planes stay independent.
        let transport: Arc<dyn PacketTransport> = Arc::new(IrohTransport::new(
            inner.adapter.clone(),
            Arc::clone(&inner.limits),
            Arc::new(TransportCtx(Arc::downgrade(&inner))) as Arc<dyn TransportContext>,
        ));
        let _ = inner.transport.set(transport);

        if let CacheOutcome::Reset(reason) = inner.storage.cache_outcome().clone() {
            let _ = inner.events.send(Event::CacheReset { reason });
        }

        let accept = tokio::spawn(accept_loop(Arc::downgrade(&inner)));
        if let Ok(mut guard) = inner.accept_task.lock() {
            *guard = Some(accept);
        }

        // Plugins get a handle to ask for re-announcements and report errors.
        // A bounded queue keeps a noisy plugin from growing memory without
        // bound; overflow drops the request rather than stalling the plugin.
        if !inner.config.plugins.is_empty() {
            let (plugin_tx, plugin_rx) = mpsc::channel(64);
            let sink = inner
                .interface
                .get()
                .map(|_| Arc::new(Sink(Arc::downgrade(&inner))) as Arc<dyn PacketSink>);
            let context = PluginContext::new(plugin_tx, inner.identity.endpoint_id(), sink);
            for plugin in &inner.config.plugins {
                plugin.attach(context.clone());
            }
            let task = tokio::spawn(plugin_request_loop(Arc::downgrade(&inner), plugin_rx));
            if let Ok(mut guard) = inner.plugin_task.lock() {
                *guard = Some(task);
            }
        }

        let agent = Self { inner };

        for stored in agent.inner.storage.list_networks().await? {
            if stored.auto_start {
                let keys = NetworkKeys::derive(&stored.name, &stored.secret);
                agent.activate_with_keys(keys).await?;
            }
        }

        Ok(agent)
    }

    /// This device's persistent endpoint id.
    pub fn endpoint_id(&self) -> EndpointId {
        self.inner.identity.endpoint_id()
    }

    /// This endpoint's dialable address as iroh currently reports it.
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.inner.adapter.addr()
    }

    /// An address containing only the locally bound sockets.
    ///
    /// Handy when relays and address lookup are disabled and peers must be
    /// handed literal addresses, as in the test suite.
    pub fn local_addr(&self) -> EndpointAddr {
        self.inner.adapter.loopback_addr()
    }

    /// Reserves the configured overlay range for a network, if it can.
    ///
    /// Done here, where activations are serialised, rather than inside the
    /// runtime: whether a range is free depends on what the other networks
    /// took, and deciding that in a task would make the answer depend on
    /// which task ran first.
    ///
    /// `None` means this agent will not propose a range for that network and
    /// waits to adopt whatever it settles on. One agent has one interface, so
    /// proposing a range it could not route would be worse than having none:
    /// the lowest author's range wins, and the collision would spread.
    fn reserve_range(&self, network: NetworkId) -> RangePlan {
        let Some(configured) = self.inner.config.overlay_ipv4_range else {
            return RangePlan::default();
        };
        let reserve = |wanted: Ipv4Range| {
            let reservation = crate::overlay::NetworkRoutes {
                broadcast: Default::default(),
                range: Some(wanted),
                local: None,
                peers: Vec::new(),
            };
            self.inner.routes.set_network(network, reservation).is_ok()
        };

        // The configured range first, so a network a device has always had
        // keeps the addresses it has always had.
        if reserve(configured) {
            return RangePlan {
                propose: Some(configured),
                ..RangePlan::default()
            };
        }

        // A second network on the same agent cannot have it — one agent,
        // one interface — so it falls back to the range derived from its
        // own id, which every one of its members derives identically
        // without being told.
        let derived = crate::state::derived_ipv4_range(network);
        if reserve(derived) {
            tracing::info!(
                %network,
                range = %derived,
                "another network here holds the configured range; this one uses the \
                 range derived from its id unless its members settled another"
            );
            return RangePlan {
                fallback: Some(derived),
                conflict: Some(configured),
                ..RangePlan::default()
            };
        }

        tracing::info!(%network, "not proposing a range for this network");
        RangePlan {
            conflict: Some(configured),
            ..RangePlan::default()
        }
    }

    /// The overlay interface this agent owns, when it has one.
    ///
    /// One agent, one interface, so this is not asked per network: a packet
    /// on it may belong to any of them.
    pub fn overlay(&self) -> Option<OverlayStatus> {
        let interface = self.inner.interface.get()?;
        Some(OverlayStatus {
            interface: interface.name().to_string(),
            on_host: interface.on_host(),
            mtu: interface.mtu(),
            addresses: interface.wanted_addresses(),
            counters: interface.counters(),
        })
    }

    /// The hostname announced to peers.
    pub fn hostname(&self) -> String {
        self.inner.read_hostname()
    }

    /// Changes the name this agent answers to, and tells everyone.
    ///
    /// The name is reduced to a canonical form first, so what is stored is
    /// what every peer will compare against; the accepted form is returned.
    ///
    /// Every running network publishes a fresh signed claim, which is what
    /// gives up the previous name: there is one record per author, so a new
    /// version replaces the whole claim and no replica can keep the old name
    /// standing. A network that is not running picks it up when it starts.
    pub async fn set_hostname(&self, hostname: &str) -> Result<String> {
        let hostname = crate::state::sanitise_hostname(hostname);
        if hostname.is_empty() {
            return Err(Error::InvalidEncoding {
                kind: "hostname",
                reason: "must contain at least one letter, digit, `-`, `.` or `_`",
            });
        }

        // Stored first: if the process dies here, the next start uses the new
        // name rather than silently reverting to the old one.
        self.inner.storage.set_hostname(hostname.clone()).await?;
        self.inner.write_hostname(hostname.clone());

        let senders: Vec<mpsc::Sender<NetCommand>> = self
            .inner
            .networks
            .read()
            .await
            .values()
            .map(|handle| handle.commands.clone())
            .collect();
        for sender in senders {
            let _ = sender.send(NetCommand::SetHostname(hostname.clone())).await;
        }
        Ok(hostname)
    }

    /// The underlying iroh endpoint, for callers that need more detail.
    pub fn endpoint(&self) -> &iroh::Endpoint {
        self.inner.adapter.endpoint()
    }

    /// Subscribes to agent events.
    ///
    /// The channel is bounded; a subscriber that falls behind is lagged rather
    /// than allowed to stall the runtime.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    /// Makes this agent a member of a network, activating it.
    ///
    /// The same `(name, secret)` always produces the same [`NetworkId`], on
    /// every device.
    ///
    /// This is declarative and therefore **idempotent**: joining a network
    /// that is already active succeeds and changes nothing. That matters
    /// because a configured network is activated automatically at startup, so
    /// running the same command twice must not be an error. Use
    /// [`Agent::activate_network`] when you specifically want to know whether
    /// an inactive network was started.
    pub async fn join_network(
        &self,
        name: &NetworkName,
        secret: &NetworkSecret,
    ) -> Result<NetworkId> {
        self.join_network_with_broadcast(name, secret, None).await
    }

    /// Joins with an explicit broadcast choice; absent preserves saved policy.
    pub async fn join_network_with_broadcast(
        &self,
        name: &NetworkName,
        secret: &NetworkSecret,
        broadcast: Option<bool>,
    ) -> Result<NetworkId> {
        let keys = NetworkKeys::derive(name, secret);
        let network_id = keys.network_id();

        // A network's identity is its name *and* its secret, so the same
        // name with a different secret is a different network — and one that
        // looks identical in anything that shows a name. Almost always a
        // mistyped secret, so it is said out loud rather than left to be
        // discovered as an empty network sitting beside a working one.
        if let Ok(configured) = self.inner.storage.list_networks().await {
            for other in configured {
                if other.name == *name && other.network_id != network_id {
                    tracing::warn!(
                        "`{name}` is already configured with a different secret, as {}. \
                         Joining with this one adds a second network under the same name; \
                         they share nothing. Check the secret, or use \
                         `tsunagi network secret` \
                         to see which is which.",
                        other.network_id
                    );
                }
            }
        }

        self.inner
            .storage
            .upsert_network(network_id, name.clone(), secret.clone(), true)
            .await?;
        if let Some(enabled) = broadcast {
            self.set_broadcast(network_id, enabled).await?;
        }
        match self.activate_with_keys(keys).await {
            // Already a member of exactly this network space: nothing to do.
            Ok(()) | Err(Error::NetworkAlreadyActive(_)) => Ok(network_id),
            Err(err) => Err(err),
        }
    }

    /// Changes a network's local broadcast policy now and after restart.
    pub async fn set_broadcast(&self, network_id: NetworkId, enabled: bool) -> Result<()> {
        self.inner
            .storage
            .set_broadcast(network_id, enabled)
            .await?;
        if self.is_active(network_id).await {
            let (reply, receive) = oneshot::channel();
            self.command(network_id, NetCommand::SetBroadcast { enabled, reply })
                .await?;
            receive.await.map_err(|_| Error::Stopped)?;
        }
        Ok(())
    }

    /// Activates a configured network that is currently inactive.
    ///
    /// Fails with [`Error::NetworkAlreadyActive`] if it is already running.
    /// [`Agent::join_network`] is the forgiving version.
    pub async fn activate_network(&self, network_id: NetworkId) -> Result<()> {
        let stored = self
            .inner
            .storage
            .list_networks()
            .await?
            .into_iter()
            .find(|stored| stored.network_id == network_id)
            .ok_or(Error::NetworkUnknown(network_id))?;
        let keys = NetworkKeys::derive(&stored.name, &stored.secret);
        self.inner.storage.set_auto_start(network_id, true).await?;
        self.activate_with_keys(keys).await
    }

    async fn activate_with_keys(&self, keys: NetworkKeys) -> Result<()> {
        if self.inner.shutdown.is_triggered() {
            return Err(Error::Stopped);
        }
        let network_id = keys.network_id();
        let mut networks = self.inner.networks.write().await;
        if networks.contains_key(&network_id) {
            return Err(Error::NetworkAlreadyActive(network_id));
        }

        let range = self.reserve_range(network_id);
        let mut backends = Vec::new();
        if let Some(discovery) = &self.inner.config.discovery {
            backends.push(discovery.clone());
        }
        if let Some(dht) = &self.inner.config.dht {
            backends.push(dht.for_network(&keys));
        }
        let discovery = if backends.is_empty() {
            None
        } else {
            Some(
                Arc::new(crate::discovery::CompositeDiscovery::new(backends))
                    as Arc<dyn crate::discovery::NetworkDiscovery>,
            )
        };
        let broadcast = self
            .inner
            .storage
            .list_networks()
            .await?
            .into_iter()
            .find(|stored| stored.network_id == network_id)
            .is_none_or(|stored| stored.broadcast);
        let handle = network::spawn(RuntimeParams {
            broadcast,
            keys,
            adapter: self.inner.adapter.clone(),
            storage: self.inner.storage.clone(),
            events: self.inner.events.clone(),
            limits: Arc::clone(&self.inner.limits),
            reconnect: self.inner.config.reconnect.clone(),
            discovery,
            discovery_interval: self.inner.config.discovery_interval,
            discovery_policy: self.inner.config.discovery_policy.clone(),
            plugins: self.inner.config.plugins.clone(),
            routes: Arc::clone(&self.inner.routes),
            interface: self.inner.interface.get().cloned(),
            hostname: self.inner.read_hostname(),
            transport: self.inner.transport.get().cloned(),
            device_secret: self.inner.identity.signing_key(),
            #[cfg(feature = "testing")]
            unreachable_data_peers: Arc::clone(&self.inner.config.unreachable_data_peers),
            ipv4_range: range.propose,
            ipv4_fallback: range.fallback,
            range_conflict: range.conflict,
        });
        networks.insert(network_id, handle);
        drop(networks);

        for plugin in &self.inner.config.plugins {
            plugin.on_network_activated(network_id);
        }

        let _ = self.inner.events.send(Event::NetworkActivated {
            network: network_id,
        });
        Ok(())
    }

    /// Deactivates a running network, leaving its configuration in place.
    ///
    /// This is a local action. It is not a signed revocation of membership and
    /// it does not remove this agent from anyone else's view of the network.
    /// Other networks keep running.
    pub async fn deactivate_network(&self, network_id: NetworkId) -> Result<()> {
        let handle = {
            let mut networks = self.inner.networks.write().await;
            networks
                .remove(&network_id)
                .ok_or(Error::NetworkNotActive(network_id))?
        };
        handle.stop().await;
        for plugin in &self.inner.config.plugins {
            plugin.on_network_deactivated(network_id);
        }
        // The network's addresses come off the interface; the interface
        // itself stays, because the agent owns it and other networks may
        // still be using it.
        self.inner.routes.remove_network(network_id);
        if let Some(interface) = self.inner.interface.get()
            && let Err(err) = interface.sync_addresses().await
        {
            tracing::warn!(%err, "cannot update the overlay addresses");
        }
        self.inner.storage.set_auto_start(network_id, false).await?;
        Ok(())
    }

    /// Deactivates a network if it is running and removes it from the state
    /// store together with its cached hints.
    ///
    /// Local and silent: nobody is told. [`Agent::leave_network`] is the one
    /// that says goodbye first, and is what a person means by leaving.
    pub async fn forget_network(&self, network_id: NetworkId) -> Result<()> {
        if self.is_active(network_id).await {
            self.deactivate_network(network_id).await?;
        }
        self.inner.storage.remove_network(network_id).await?;
        // Whatever a protocol kept for this network goes with it. The
        // agent cannot know what that is, only that there is no longer any
        // reason to hold it.
        for plugin in &self.inner.config.plugins {
            plugin.on_network_forgotten(network_id);
        }
        Ok(())
    }

    /// Leaves a network: gives up what was claimed, then forgets it.
    ///
    /// The order matters and cannot be improved on. A signed `Release` goes
    /// out first, while there are still sessions to carry it, so the address
    /// and name this agent held are freed for somebody else rather than
    /// staying reserved to a member that has gone. Only then is the network
    /// deactivated and removed.
    ///
    /// Reaching every member is not on offer and never could be: a member
    /// that is away hears the tombstone from the ones that were here, the
    /// same way it hears everything else. Leaving with nobody connected
    /// tells nobody, and says so in the outcome rather than pretending.
    ///
    /// The author's version counter is deliberately **kept**. Rejoining the
    /// same network with the same device key must continue from a higher
    /// version than the release, or every replica would treat the new claim
    /// as stale and ignore it.
    pub async fn leave_network(&self, network_id: NetworkId) -> Result<LeaveOutcome> {
        let mut outcome = LeaveOutcome::default();
        if self.is_active(network_id).await {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command(network_id, NetCommand::Release { reply: reply_tx })
                .await?;
            if let Ok(peers) = reply_rx.await {
                outcome.announced = true;
                outcome.peers_told = peers;
            }
            // The tombstone is queued on each session, not yet written to
            // the wire. A short pause is the difference between peers
            // hearing it now and hearing it from somebody else much later.
            if outcome.peers_told > 0 {
                tokio::time::sleep(RELEASE_FLUSH).await;
            }
        }
        self.forget_network(network_id).await?;
        Ok(outcome)
    }

    /// Whether a network is currently running.
    pub async fn is_active(&self, network_id: NetworkId) -> bool {
        self.inner.networks.read().await.contains_key(&network_id)
    }

    /// Lists configured networks and whether each is running.
    pub async fn list_networks(&self) -> Result<Vec<ConfiguredNetwork>> {
        let active: Vec<NetworkId> = self.inner.networks.read().await.keys().copied().collect();
        Ok(self
            .inner
            .storage
            .list_networks()
            .await?
            .into_iter()
            .map(|stored| ConfiguredNetwork {
                broadcast: stored.broadcast,
                network_id: stored.network_id,
                name: stored.name,
                auto_start: stored.auto_start,
                active: active.contains(&stored.network_id),
            })
            .collect())
    }

    /// Sends a control message to one authenticated peer in one network.
    ///
    /// Fails if that network is not active or if there is no authenticated
    /// session with that peer *in that network*. Being authenticated in network
    /// A never grants the right to send into network B.
    pub async fn send(
        &self,
        network_id: NetworkId,
        peer: EndpointId,
        message: ControlMessage,
    ) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command(
            network_id,
            NetCommand::Send {
                peer,
                message,
                reply: reply_tx,
            },
        )
        .await?;
        reply_rx.await.map_err(|_| Error::Stopped)?
    }

    /// Sends a control message to every authenticated peer in a network.
    ///
    /// Returns how many sessions accepted it into their outbound queue.
    pub async fn broadcast(&self, network_id: NetworkId, message: ControlMessage) -> Result<usize> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command(
            network_id,
            NetCommand::Broadcast {
                message,
                reply: reply_tx,
            },
        )
        .await?;
        reply_rx.await.map_err(|_| Error::Stopped)
    }

    /// Status of one running network.
    pub async fn network_status(&self, network_id: NetworkId) -> Result<NetworkStatus> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command(network_id, NetCommand::Status { reply: reply_tx })
            .await?;
        reply_rx
            .await
            .map(|boxed| *boxed)
            .map_err(|_| Error::Stopped)
    }

    /// Status of the whole agent, including configured but inactive networks.
    pub async fn status(&self) -> Result<AgentStatus> {
        let endpoint = self.inner.adapter.snapshot();
        let active: Vec<NetworkId> = self.inner.networks.read().await.keys().copied().collect();

        let mut networks = Vec::new();
        for stored in self.inner.storage.list_networks().await? {
            if active.contains(&stored.network_id)
                && let Ok(status) = self.network_status(stored.network_id).await
            {
                networks.push(status);
                continue;
            }
            let keys = NetworkKeys::derive(&stored.name, &stored.secret);
            networks.push(NetworkStatus {
                broadcast: stored.broadcast,
                descriptor: keys.descriptor(),
                name: stored.name,
                network_id: stored.network_id,
                state: NetworkState::Inactive,
                peers: Vec::new(),
                candidates: Vec::new(),
                // An inactive network has no runtime to ask; the roster and
                // the range come from one. Empty, not invented.
                members: Vec::new(),
                range: None,
                range_conflict: None,
                metrics: NetworkMetrics::default(),
                relay: Default::default(),
            });
        }

        Ok(AgentStatus {
            endpoint_id: endpoint.endpoint_id,
            hostname: self.inner.read_hostname(),
            bound_sockets: endpoint.bound_sockets,
            observed_addrs: endpoint.observed_addrs,
            endpoint_addr: self.inner.adapter.addr(),
            cache_outcome: self.inner.storage.cache_outcome().clone(),
            cache_healthy: self.inner.storage.cache_healthy(),
            networks,
        })
    }

    /// Resends this agent's announcement to every peer of a network.
    ///
    /// Plugins normally trigger this themselves through
    /// [`crate::dataplane::PluginContext::request_reannounce`] when their
    /// capability changes.
    pub async fn reannounce(&self, network_id: NetworkId) -> Result<()> {
        self.command(network_id, NetCommand::Reannounce).await
    }

    /// Asks one network to re-evaluate known peers and dials right now.
    /// External lookup still follows its connected/isolation policy.
    ///
    /// Call this when the host's network environment changed. Platform wake-up
    /// notifications can be wired to it later.
    pub async fn recheck_network(&self, network_id: NetworkId) -> Result<()> {
        self.command(network_id, NetCommand::Recheck).await
    }

    /// Asks every running network to re-evaluate known peers right now.
    pub async fn recheck(&self) {
        let senders: Vec<mpsc::Sender<NetCommand>> = self
            .inner
            .networks
            .read()
            .await
            .values()
            .map(|handle| handle.commands.clone())
            .collect();
        for sender in senders {
            let _ = sender.send(NetCommand::Recheck).await;
        }
    }

    /// Stops every network, the accept loop and the endpoint.
    ///
    /// After this returns, the state directory can be opened by another agent.
    pub async fn shutdown(&self) {
        self.inner.shutdown.trigger();

        let handles: Vec<NetworkHandle> = {
            let mut networks = self.inner.networks.write().await;
            networks.drain().map(|(_, handle)| handle).collect()
        };
        for handle in handles {
            handle.stop().await;
        }

        if let Some(dht) = &self.inner.config.dht {
            dht.shutdown().await;
        }

        // iroh's own close waits for peers to acknowledge; a peer that has
        // gone silent must not decide how long that takes.
        if tokio::time::timeout(TASK_GRACE, self.inner.adapter.close())
            .await
            .is_err()
        {
            tracing::warn!("the endpoint did not close in time; abandoning it");
        }

        for (what, handle) in [
            ("inbound connections", &self.inner.accept_task),
            ("plugin requests", &self.inner.plugin_task),
        ] {
            let task = handle.lock().ok().and_then(|mut guard| guard.take());
            if let Some(task) = task {
                wind_down(task, TASK_GRACE, what).await;
            }
        }

        // The interface goes with the agent that owns it. Before the
        // plugins, so nothing is still trying to write to it.
        if let Some(interface) = self.inner.interface.get() {
            interface.remove().await;
        }

        // Plugins remove whatever system objects they created. A plugin that
        // misbehaves here must not hold up the agent, so this is bounded.
        for plugin in &self.inner.config.plugins {
            if tokio::time::timeout(PLUGIN_SHUTDOWN_GRACE, plugin.shutdown())
                .await
                .is_err()
            {
                tracing::warn!(
                    protocol = plugin.protocol_id(),
                    "plugin did not shut down in time"
                );
            }
        }

        // Release the directory so another instance can claim it right away.
        self.inner.storage.release_ownership_lock();
    }

    async fn command(&self, network_id: NetworkId, command: NetCommand) -> Result<()> {
        let sender = {
            let networks = self.inner.networks.read().await;
            networks
                .get(&network_id)
                .map(|handle| handle.commands.clone())
                .ok_or(Error::NetworkNotActive(network_id))?
        };
        sender.send(command).await.map_err(|_| Error::Stopped)
    }
}

/// What a network may propose as its overlay range, and what it cannot have.
#[derive(Debug, Clone, Copy, Default)]
struct RangePlan {
    /// Proposed straight away: the configured range, when it is free here.
    propose: Option<Ipv4Range>,
    /// Proposed after a moment, when the configured range is another
    /// network's: the range derived from this network's own id.
    fallback: Option<Ipv4Range>,
    /// The configured range, when this network cannot have it.
    conflict: Option<Ipv4Range>,
}

/// How long a release is given to reach the sessions it was queued on.
///
/// Short: it is one small message on a connection that is already open, and
/// the alternative to waiting at all is tearing the sessions down underneath
/// it.
const RELEASE_FLUSH: std::time::Duration = std::time::Duration::from_millis(300);

/// What happened when an agent left a network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LeaveOutcome {
    /// Whether a signed release was published at all.
    ///
    /// `false` when the network was not running: there was nothing to
    /// publish it from, so this was a local removal only.
    pub announced: bool,
    /// How many connected peers it was sent to.
    ///
    /// Zero with `announced` true means the tombstone is in this agent's
    /// own state and nowhere else, and it is leaving with it — so nobody
    /// will learn of it.
    pub peers_told: usize,
}

/// How long each plugin gets to tear itself down during agent shutdown.
const PLUGIN_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Serves requests plugins make of the agent.
///
/// Holds only a weak reference, so it exits once the agent is dropped.
async fn plugin_request_loop(weak: Weak<Inner>, mut requests: mpsc::Receiver<PluginRequest>) {
    let Some(inner) = weak.upgrade() else {
        return;
    };
    let shutdown = inner.shutdown.clone();
    drop(inner);

    loop {
        let request = tokio::select! {
            biased;
            _ = shutdown.wait() => break,
            request = requests.recv() => match request {
                Some(request) => request,
                None => break,
            },
        };

        let Some(inner) = weak.upgrade() else {
            break;
        };

        match request {
            PluginRequest::Reannounce(network) => {
                let sender = {
                    let networks = inner.networks.read().await;
                    networks.get(&network).map(|handle| handle.commands.clone())
                };
                // A plugin asking about a network that is no longer active is
                // normal, not an error.
                if let Some(sender) = sender {
                    let _ = sender.send(NetCommand::Reannounce).await;
                }
            }
            PluginRequest::Error {
                network,
                protocol,
                reason,
            } => {
                let sender = {
                    let networks = inner.networks.read().await;
                    networks.get(&network).map(|handle| handle.commands.clone())
                };
                match sender {
                    // The runtime owns this network's counters, so the error
                    // is counted and published in one place.
                    Some(sender) => {
                        let _ = sender
                            .send(NetCommand::PluginError { protocol, reason })
                            .await;
                    }
                    // The network is gone; there is nothing to count it
                    // against, but the report is still worth publishing.
                    None => {
                        let _ = inner.events.send(Event::PluginError {
                            network,
                            protocol,
                            reason,
                        });
                    }
                }
            }
        }
    }
}

/// Accepts inbound connections and routes authenticated sessions to networks.
///
/// Holds only a weak reference, so dropping every [`Agent`] handle lets the
/// runtime state be released and this loop exit.
async fn accept_loop(weak: Weak<Inner>) {
    let Some(inner) = weak.upgrade() else {
        return;
    };
    let endpoint = inner.adapter.endpoint().clone();
    let shutdown = inner.shutdown.clone();
    let permits = Arc::new(tokio::sync::Semaphore::new(
        inner.limits.max_inbound_handshakes,
    ));
    drop(inner);

    loop {
        let incoming = tokio::select! {
            biased;
            _ = shutdown.wait() => break,
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
        };

        let Some(inner) = weak.upgrade() else {
            break;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            // Too many handshakes in flight: refuse cheaply instead of queueing.
            incoming.refuse();
            continue;
        };

        tokio::spawn(async move {
            let _permit = permit;
            handle_incoming(inner, incoming).await;
        });
    }
}

async fn handle_incoming(inner: Arc<Inner>, incoming: iroh::endpoint::Incoming) {
    let connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(err) => {
            tracing::debug!(%err, "inbound connection could not be accepted");
            return;
        }
    };
    let conn = match connecting.await {
        Ok(conn) => conn,
        Err(err) => {
            tracing::debug!(%err, "inbound connection failed during setup");
            return;
        }
    };
    let peer = conn.remote_id();

    // Two protocols share the endpoint; they are told apart here and never mix.
    if conn.alpn() == crate::proto::message::DATA_ALPN {
        handle_inbound_data(inner, conn).await;
        return;
    }

    let (mut send, mut recv) = match conn.accept_bi().await {
        Ok(streams) => streams,
        Err(err) => {
            tracing::debug!(%err, "peer did not open a control stream");
            return;
        }
    };

    // Snapshot the active networks so the handshake's lookup stays synchronous.
    let known: HashMap<NetworkId, NetworkKeys> = inner
        .networks
        .read()
        .await
        .iter()
        .map(|(id, handle)| (*id, handle.keys.clone()))
        .collect();

    let local_id = inner.identity.endpoint_id();
    let outcome = handshake::respond(
        &conn,
        &mut send,
        &mut recv,
        local_id,
        &inner.limits,
        |network_id| known.get(&network_id).cloned(),
    )
    .await;

    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            // The network id is deliberately not reported here: before a
            // successful handshake the peer's claim is unverified.
            let network = None;
            conn.close(2u32.into(), b"handshake rejected");
            let _ = inner.events.send(Event::HandshakeRejected {
                network,
                peer: Some(peer),
                reason: err.to_string(),
            });
            return;
        }
    };

    let sender = {
        let networks = inner.networks.read().await;
        networks
            .get(&outcome.network_id)
            .map(|handle| handle.commands.clone())
    };
    let Some(sender) = sender else {
        // The network was deactivated while the handshake ran.
        conn.close(3u32.into(), b"network no longer active");
        return;
    };

    let inbound = InboundSession {
        conn,
        send,
        recv,
        outcome,
    };
    if sender
        .send(NetCommand::Inbound(Box::new(inbound)))
        .await
        .is_err()
    {
        tracing::debug!("network runtime stopped before the session could be installed");
    }
}

/// Completes an inbound data plane connection and routes it to its network.
async fn handle_inbound_data(inner: Arc<Inner>, conn: iroh::endpoint::Connection) {
    let Some(transport) = inner.transport.get().cloned() else {
        conn.close(5u32.into(), b"data plane not ready");
        return;
    };
    // Downcasting is avoided by keeping the accept side on the concrete type.
    let Some(iroh_transport) = transport.as_ref().as_any().downcast_ref::<IrohTransport>() else {
        conn.close(5u32.into(), b"unsupported data transport");
        return;
    };

    let inbound = match iroh_transport.accept(conn).await {
        Ok(inbound) => inbound,
        Err(err) => {
            tracing::debug!(%err, "inbound data channel rejected");
            return;
        }
    };

    let sender = {
        let networks = inner.networks.read().await;
        networks
            .get(&inbound.network)
            .map(|handle| handle.commands.clone())
    };
    let Some(sender) = sender else {
        // The network went away while the channel was being set up.
        return;
    };
    if sender
        .send(NetCommand::InboundLink(Box::new(inbound)))
        .await
        .is_err()
    {
        tracing::debug!("network runtime stopped before the data link was installed");
    }
}

/// Picks the hostname to announce.
///
/// Order: an explicit choice, then one the user set earlier and the store
/// kept, then the machine's own name, then a fallback derived from the
/// endpoint id for the rare host that has no usable name.
///
/// No shell is involved at any step: the system name comes from the platform
/// call, not from running `hostname`.
fn resolve_hostname(
    config: &AgentConfig,
    storage: &Storage,
    endpoint_id: EndpointId,
) -> Result<String> {
    if let Some(hostname) = &config.hostname {
        return Ok(crate::state::sanitise_hostname(hostname));
    }
    if let Some(stored) = storage.hostname_blocking()?
        && !stored.is_empty()
    {
        return Ok(crate::state::sanitise_hostname(&stored));
    }
    if let Some(system) = system_hostname() {
        return Ok(system);
    }
    Ok(format!("tsunagi-{}", endpoint_id.fmt_short()))
}

/// The machine's own name, if it has a usable one.
///
/// Some hosts answer with `localhost`, or with nothing at all. That is not a
/// name that distinguishes this device from any other, so it is treated as
/// absent and the caller falls back to something that does.
pub fn system_hostname() -> Option<String> {
    let raw = gethostname::gethostname();
    let name = crate::state::sanitise_hostname(&raw.to_string_lossy());
    if name.is_empty() || name.eq_ignore_ascii_case("localhost") {
        return None;
    }
    Some(name)
}
