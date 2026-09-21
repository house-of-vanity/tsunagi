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
    AgentStatus, CandidateStatus, NetworkMetrics, NetworkState, NetworkStatus, PeerStatus,
};

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use iroh::{EndpointAddr, EndpointId};
use tokio::sync::{RwLock, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::{AgentConfig, Limits};
use crate::dataplane::transport::PacketTransport;
use crate::dataplane::transport::iroh_link::{IrohTransport, TransportContext};
use crate::dataplane::{PluginContext, PluginRequest};
use crate::error::{Error, Result};
use crate::identity::{DeviceIdentity, NetworkId, NetworkKeys, NetworkName, NetworkSecret};
use crate::net::EndpointAdapter;
use crate::proto::handshake;
use crate::proto::message::ControlMessage;
use crate::storage::{CacheOutcome, Storage};

use network::{InboundSession, NetCommand, NetworkHandle, RuntimeParams};
use shutdown::Shutdown;

/// Summary of a configured network, whether or not it is running.
#[derive(Debug, Clone)]
pub struct ConfiguredNetwork {
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
    hostname: String,
    events: broadcast::Sender<Event>,
    networks: RwLock<HashMap<NetworkId, NetworkHandle>>,
    shutdown: Shutdown,
    accept_task: std::sync::Mutex<Option<JoinHandle<()>>>,
    plugin_task: std::sync::Mutex<Option<JoinHandle<()>>>,
    transport: std::sync::OnceLock<Arc<dyn PacketTransport>>,
}

/// Answers the data plane transport's questions about the agent.
///
/// Holds a weak reference on purpose: the transport lives inside the agent, so
/// a strong one would be a cycle and the agent — with its open databases and
/// its directory lock — would never be released.
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
            config,
        });

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
            let context = PluginContext::new(plugin_tx, inner.identity.endpoint_id());
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

    /// The hostname announced to peers.
    pub fn hostname(&self) -> &str {
        &self.inner.hostname
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
        let keys = NetworkKeys::derive(name, secret);
        let network_id = keys.network_id();
        self.inner
            .storage
            .upsert_network(network_id, name.clone(), secret.clone(), true)
            .await?;
        match self.activate_with_keys(keys).await {
            // Already a member of exactly this network space: nothing to do.
            Ok(()) | Err(Error::NetworkAlreadyActive(_)) => Ok(network_id),
            Err(err) => Err(err),
        }
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

        let handle = network::spawn(RuntimeParams {
            keys,
            adapter: self.inner.adapter.clone(),
            storage: self.inner.storage.clone(),
            events: self.inner.events.clone(),
            limits: Arc::clone(&self.inner.limits),
            reconnect: self.inner.config.reconnect.clone(),
            discovery: self.inner.config.discovery.clone(),
            discovery_interval: self.inner.config.discovery_interval,
            plugins: self.inner.config.plugins.clone(),
            hostname: self.inner.hostname.clone(),
            transport: self.inner.transport.get().cloned(),
            device_secret: self.inner.identity.signing_key(),
            ipv4_range: self.inner.config.overlay_ipv4_range,
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
        self.inner.storage.set_auto_start(network_id, false).await?;
        Ok(())
    }

    /// Deactivates a network if it is running and removes it from the state
    /// store together with its cached hints.
    pub async fn forget_network(&self, network_id: NetworkId) -> Result<()> {
        if self.is_active(network_id).await {
            self.deactivate_network(network_id).await?;
        }
        self.inner.storage.remove_network(network_id).await
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
                descriptor: keys.descriptor(),
                name: stored.name,
                network_id: stored.network_id,
                state: NetworkState::Inactive,
                peers: Vec::new(),
                candidates: Vec::new(),
                metrics: NetworkMetrics::default(),
            });
        }

        Ok(AgentStatus {
            endpoint_id: endpoint.endpoint_id,
            hostname: self.inner.hostname.clone(),
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

    /// Asks one network to re-run discovery and re-evaluate dials right now.
    ///
    /// Call this when the host's network environment changed. Platform wake-up
    /// notifications can be wired to it later.
    pub async fn recheck_network(&self, network_id: NetworkId) -> Result<()> {
        self.command(network_id, NetCommand::Recheck).await
    }

    /// Asks every running network to re-run discovery right now.
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

        self.inner.adapter.close().await;

        for handle in [&self.inner.accept_task, &self.inner.plugin_task] {
            let task = handle.lock().ok().and_then(|mut guard| guard.take());
            if let Some(task) = task {
                let _ = task.await;
            }
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
/// Order: explicit configuration, then what the state store already holds, then
/// a best-effort environment variable, then a stable fallback derived from the
/// endpoint id. The library does not shell out to discover a hostname.
fn resolve_hostname(
    config: &AgentConfig,
    storage: &Storage,
    endpoint_id: EndpointId,
) -> Result<String> {
    if let Some(hostname) = &config.hostname {
        return Ok(hostname.clone());
    }
    if let Some(stored) = storage.hostname_blocking()?
        && !stored.is_empty()
    {
        return Ok(stored);
    }
    for key in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(value) = std::env::var(key) {
            let value = value.trim();
            if !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }
    Ok(format!("tsunagi-{}", endpoint_id.fmt_short()))
}
