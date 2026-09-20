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

use std::sync::Arc;

use iroh::EndpointId;

use crate::identity::NetworkId;

/// Maximum length of a plugin protocol identifier.
pub const MAX_PROTOCOL_ID_LEN: usize = 32;

/// An announcement of one IP plugin's capability.
///
/// `data` is opaque to the core. Nothing in it may be interpreted as a shell
/// command, a filesystem path or an OS setting by the core; a plugin that
/// chooses to do so must validate it itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PluginCapability {
    /// Protocol identifier, e.g. `wireguard`. Bounded by [`MAX_PROTOCOL_ID_LEN`].
    pub protocol: String,
    /// Version of the plugin's announcement format.
    pub version: u16,
    /// Whether the peer currently has this plugin enabled.
    pub enabled: bool,
    /// Opaque, bounded, plugin-defined payload.
    pub data: Vec<u8>,
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

/// The minimal contract a future IP plugin implements.
///
/// Implementations must be cheap and non-blocking: the agent calls them from
/// its runtime tasks. Anything slow belongs in the plugin's own tasks.
pub trait IpPlugin: Send + Sync + std::fmt::Debug + 'static {
    /// Stable protocol identifier, e.g. `wireguard`.
    ///
    /// Must be non-empty and at most [`MAX_PROTOCOL_ID_LEN`] bytes.
    fn protocol_id(&self) -> &str;

    /// Produces this agent's announcement for a given network.
    ///
    /// Returning `Ok(None)` means "nothing to announce right now", which is
    /// different from an error.
    fn local_capability(
        &self,
        network: NetworkId,
    ) -> std::result::Result<Option<PluginCapability>, PluginError>;

    /// Called when a peer announces a capability for this plugin's protocol.
    ///
    /// The core has already bounded the payload size but has not interpreted it.
    fn on_peer_capability(
        &self,
        network: NetworkId,
        peer: EndpointId,
        capability: &PluginCapability,
    ) -> std::result::Result<(), PluginError>;

    /// Called when a peer's session in a network goes away.
    fn on_peer_gone(&self, network: NetworkId, peer: EndpointId);

    /// Called when a network is deactivated locally.
    ///
    /// This is a local deactivation, not a signed revocation of membership.
    fn on_network_deactivated(&self, network: NetworkId);
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
