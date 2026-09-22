//! Boundary between the control plane core and future IP plugins.
//!
//! The data plane is where actual IP connectivity is created. WireGuard is the
//! first planned plugin; none is implemented here.
//!
//! Two rules shape this module:
//!
//! 1. **The core never parses plugin payloads.** A [`PluginCapability`] carries
//!    a protocol id, a version, an enabled flag and a bounded opaque blob. The
//!    core transports the blob and hands it to the matching plugin. It does not
//!    know what a WireGuard configuration looks like.
//! 2. **Plugin keys and lifecycle are separate from iroh identity and from the
//!    network secret.** A plugin owns its own keys and its own system objects.
//!
//! An iroh address is *not* automatically a WireGuard address. A future plugin
//! is expected to gather its own reachability information and ship it through
//! the control plane as its announcement payload.
//!
//! A data plane failure never stops the daemon: errors returned here are
//! recorded and surfaced, the control plane keeps running.

pub mod relay;
pub mod transport;

use std::sync::Arc;

use iroh::EndpointId;
use tokio::sync::mpsc;

use crate::BoxFuture;
use crate::identity::NetworkId;

pub use transport::{PacketLink, PacketTransport, SharedLink, TransportError};

/// Maximum length of a plugin protocol identifier.
pub const MAX_PROTOCOL_ID_LEN: usize = 32;

/// An announcement of one IP plugin's capability.
///
/// `data` is opaque to the core. Nothing in it may be interpreted as a shell
/// command, a filesystem path or an OS setting by the core; a plugin that
/// chooses to do so must validate it itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PluginCapability {
    /// Protocol identifier, e.g. `wg-quic`. Bounded by [`MAX_PROTOCOL_ID_LEN`].
    pub protocol: String,
    /// Version of the plugin's announcement format.
    pub version: u16,
    /// Whether the peer currently has this plugin enabled.
    pub enabled: bool,
    /// Opaque, bounded, plugin-defined payload.
    pub data: Vec<u8>,
}

/// Where a protocol hands the packets it has decrypted.
///
/// A protocol proves *who* sent a packet; it does not know what that member
/// is entitled to say, because entitlement is an address claim the system
/// level holds. So a decrypted packet goes here rather than straight to an
/// interface, and is checked on the way.
pub trait PacketSink: Send + Sync + 'static {
    /// Hands over one packet, attributed to the peer whose tunnel decrypted
    /// it.
    fn deliver<'a>(
        &'a self,
        network: NetworkId,
        peer: EndpointId,
        packet: bytes::Bytes,
    ) -> BoxFuture<'a, ()>;
}

/// A sink that drops everything, for a protocol running without an interface.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardPackets;

impl PacketSink for DiscardPackets {
    fn deliver<'a>(
        &'a self,
        _network: NetworkId,
        _peer: EndpointId,
        _packet: bytes::Bytes,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {})
    }
}

/// One setting a protocol accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolOption {
    /// The key, as written in `key=value`.
    pub key: &'static str,
    /// A word for the value, for the help line: `BYTES`, `NAME`.
    pub value: &'static str,
    /// What it does.
    pub help: &'static str,
    /// What happens when it is not given.
    pub default: Option<&'static str>,
}

/// Errors a plugin may return. They are recorded, never fatal for the agent.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PluginError {
    /// The plugin is not currently able to produce or apply configuration.
    #[error("plugin unavailable: {0}")]
    Unavailable(String),
    /// A peer announcement was not acceptable to the plugin.
    #[error("rejected peer announcement: {0}")]
    Rejected(String),
    /// Anything else.
    #[error("plugin error: {0}")]
    Other(String),
}

/// A request a plugin makes of the agent that owns it.
#[derive(Debug)]
pub(crate) enum PluginRequest {
    /// Re-send this agent's announcement to every peer of a network.
    Reannounce(NetworkId),
    /// Surface a plugin error on the agent's event stream.
    Error {
        /// Network the error is scoped to.
        network: NetworkId,
        /// Plugin protocol id.
        protocol: String,
        /// Human readable reason, free of secrets.
        reason: String,
    },
}

/// The agent-side handle a plugin is given when it is attached.
///
/// It is deliberately tiny: a plugin may ask for its announcement to be resent
/// and may report an error. It cannot reach into agent state, cannot send
/// arbitrary control messages and knows nothing about sessions.
///
/// All calls are non-blocking. If the agent is gone or its queue is full the
/// request is dropped rather than stalling the plugin.
#[derive(Clone)]
pub struct PluginContext {
    sender: Option<mpsc::Sender<PluginRequest>>,
    local: Option<EndpointId>,
    /// Where decrypted packets go. Absent when nothing is carrying traffic,
    /// in which case a protocol still runs and its packets are discarded.
    sink: Option<Arc<dyn PacketSink>>,
}

impl PluginContext {
    pub(crate) fn new(
        sender: mpsc::Sender<PluginRequest>,
        local: EndpointId,
        sink: Option<Arc<dyn PacketSink>>,
    ) -> Self {
        Self {
            sender: Some(sender),
            local: Some(local),
            sink,
        }
    }

    /// Where to hand a decrypted packet.
    ///
    /// Always answers: with no interface to write to, the packets are
    /// discarded, which is what `--no-tun` means and is not an error.
    pub fn packet_sink(&self) -> Arc<dyn PacketSink> {
        match &self.sink {
            Some(sink) => Arc::clone(sink),
            None => Arc::new(DiscardPackets),
        }
    }

    /// A context that discards everything, for plugins used outside an agent.
    pub fn detached() -> Self {
        Self {
            sender: None,
            local: None,
            sink: None,
        }
    }

    /// This agent's own endpoint id, when the context is attached.
    ///
    /// A plugin needs it to find itself in the agreed allocation.
    pub fn local_endpoint_id(&self) -> Option<EndpointId> {
        self.local
    }

    fn send(&self, request: PluginRequest) {
        let Some(sender) = &self.sender else {
            return;
        };
        if let Err(err) = sender.try_send(request) {
            tracing::debug!(%err, "dropping plugin request");
        }
    }

    /// Asks the agent to resend this agent's announcement in `network`.
    ///
    /// A plugin calls this when its own capability changed — it finished
    /// starting up, its keys or reachability changed — so that peers learn the
    /// new value without waiting for a reconnect.
    pub fn request_reannounce(&self, network: NetworkId) {
        self.send(PluginRequest::Reannounce(network));
    }

    /// Reports a plugin error on the agent's event stream.
    ///
    /// Plugin work happens in the plugin's own tasks, so errors cannot always
    /// be returned from a trait call. They are never fatal for the agent.
    pub fn report_error(
        &self,
        network: NetworkId,
        protocol: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.send(PluginRequest::Error {
            network,
            protocol: protocol.into(),
            reason: reason.into(),
        });
    }
}

impl std::fmt::Debug for PluginContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginContext")
            .field("attached", &self.sender.is_some())
            .field("local", &self.local.map(|id| id.fmt_short().to_string()))
            .finish()
    }
}

/// The contract an IP plugin implements.
///
/// Implementations must be cheap and non-blocking: the agent calls them from
/// its runtime tasks. Anything slow belongs in the plugin's own tasks.
pub trait IpPlugin: Send + Sync + std::fmt::Debug + 'static {
    /// Stable protocol identifier, e.g. `wg-quic`.
    ///
    /// Must be non-empty and at most [`MAX_PROTOCOL_ID_LEN`] bytes.
    fn protocol_id(&self) -> &str;

    /// The wire version of this protocol.
    ///
    /// Two peers carry traffic for each other only when they have the same
    /// protocol at the same version. There is no negotiating a middle
    /// ground: a protocol either speaks the same words at both ends or it
    /// does not, and pretending otherwise produces a link that fails later
    /// and less clearly.
    ///
    /// **Not the software version.** A plugin crate has its own version and
    /// it is nobody else's business: two peers on different builds work
    /// together for as long as the wire between them has not changed. This
    /// number moves only when the bytes do, so it must never be derived from
    /// `CARGO_PKG_VERSION` or anything else that moves with a release.
    fn protocol_version(&self) -> u16;

    /// The settings this protocol accepts, and what they mean.
    ///
    /// Declared rather than documented elsewhere, so the agent can list them
    /// without knowing anything about the protocol.
    fn options(&self) -> &'static [ProtocolOption] {
        &[]
    }

    /// Called once, when the agent starts, before any network is activated.
    ///
    /// The plugin keeps the context to ask for re-announcements and to report
    /// errors that happen in its own tasks.
    fn attach(&self, context: PluginContext) {
        let _ = context;
    }

    /// Produces this agent's announcement for a given network.
    ///
    /// Returning `Ok(None)` means "nothing to announce right now", which is
    /// different from an error.
    fn local_capability(
        &self,
        network: NetworkId,
    ) -> std::result::Result<Option<PluginCapability>, PluginError>;

    /// Called when a network is activated locally, before any peer appears.
    ///
    /// A plugin uses it to get its per-network state ready, so that the first
    /// announcement already carries its capability.
    fn on_network_activated(&self, network: NetworkId) {
        let _ = network;
    }

    /// Called when a peer announces a capability for this plugin's protocol.
    ///
    /// The core has already bounded the payload size but has not interpreted it.
    fn on_peer_capability(
        &self,
        network: NetworkId,
        peer: EndpointId,
        capability: &PluginCapability,
    ) -> std::result::Result<(), PluginError>;

    /// The overlay addresses the network has agreed on.
    ///
    /// Allocated rather than derived, and backed by the signed records in
    /// [`crate::state`], so a participant keeps its address across restarts
    /// and long absences. Called whenever the agreed picture changes.
    fn on_address_allocation(
        &self,
        network: NetworkId,
        range: crate::state::Ipv4Range,
        allocations: &[(EndpointId, std::net::Ipv4Addr)],
    ) {
        let _ = (network, range, allocations);
    }

    /// Carries one packet to a peer, encrypting it however this protocol
    /// does.
    ///
    /// `false` when it cannot right now — no link, no tunnel, not this
    /// protocol's peer — which the caller reports rather than treats as an
    /// error. The packet came off the one interface the agent owns, and
    /// which protocol takes it is settled by asking.
    ///
    /// The default carries nothing, which is right for a plugin that only
    /// announces something.
    fn carry(&self, _network: NetworkId, _peer: EndpointId, _packet: bytes::Bytes) -> bool {
        false
    }

    /// A data plane link to a peer is available for this plugin's protocol.
    ///
    /// The plugin moves its packets over this link and never learns how the
    /// link is carried. A new link for a peer replaces any previous one.
    fn on_peer_link(&self, network: NetworkId, peer: EndpointId, link: SharedLink) {
        let _ = (network, peer, link);
    }

    /// Called when a peer's session in a network goes away.
    ///
    /// Any link handed to the plugin for that peer must be dropped here.
    fn on_peer_gone(&self, network: NetworkId, peer: EndpointId);

    /// Called when a network is deactivated locally.
    ///
    /// This is a local deactivation, not a signed revocation of membership.
    /// The plugin is expected to remove whatever it created for that network.
    fn on_network_deactivated(&self, network: NetworkId);

    /// Called when this agent has left a network for good.
    ///
    /// Deactivation is temporary and keeps everything ready for next time;
    /// this is the other one. Whatever the plugin holds *durably* for that
    /// network — a key of its own, a file, a record — goes now, because the
    /// agent is no longer a member and keeping it is keeping a secret for a
    /// network it cannot rejoin without being told the secret again.
    ///
    /// Always preceded by [`IpPlugin::on_network_deactivated`], so this is
    /// only about what outlives a session. Defaulted to nothing, for a
    /// plugin that stores nothing.
    fn on_network_forgotten(&self, _network: NetworkId) {}

    /// Called once when the agent shuts down.
    ///
    /// The plugin removes the system objects it created and stops its tasks.
    /// It must be bounded: the agent awaits it during shutdown.
    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// A shared handle to a plugin.
pub type SharedPlugin = Arc<dyn IpPlugin>;

/// A plugin used in tests and examples.
///
/// It announces an explicitly test-only protocol id, so nothing in this crate
/// ever advertises WireGuard as an available transport before it exists.
#[derive(Debug)]
pub struct TestCapabilityPlugin {
    protocol: String,
    payload: Vec<u8>,
    seen: std::sync::Mutex<Vec<(NetworkId, EndpointId, PluginCapability)>>,
}

impl TestCapabilityPlugin {
    /// Creates a plugin announcing `protocol` with a fixed opaque payload.
    pub fn new(protocol: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            protocol: protocol.into(),
            payload: payload.into(),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Returns everything this plugin was handed so far.
    pub fn observed(&self) -> Vec<(NetworkId, EndpointId, PluginCapability)> {
        match self.seen.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl IpPlugin for TestCapabilityPlugin {
    fn protocol_id(&self) -> &str {
        &self.protocol
    }

    fn protocol_version(&self) -> u16 {
        1
    }

    fn local_capability(
        &self,
        _network: NetworkId,
    ) -> std::result::Result<Option<PluginCapability>, PluginError> {
        Ok(Some(PluginCapability {
            protocol: self.protocol.clone(),
            version: 1,
            enabled: true,
            data: self.payload.clone(),
        }))
    }

    fn on_peer_capability(
        &self,
        network: NetworkId,
        peer: EndpointId,
        capability: &PluginCapability,
    ) -> std::result::Result<(), PluginError> {
        let mut guard = match self.seen.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.push((network, peer, capability.clone()));
        Ok(())
    }

    fn on_peer_gone(&self, _network: NetworkId, _peer: EndpointId) {}

    fn on_network_deactivated(&self, _network: NetworkId) {}
}
