//! External link negotiation, deliberately separate from the IP encryption plugin.
use crate::dataplane::{PluginCapability, PluginError, ProtocolOption};
use crate::{BoxFuture, NetworkId};
use iroh::EndpointId;
use std::sync::Arc;

/// Capability and lifecycle of one external data carrier.
/// Only this layer sees reachability. It never receives plaintext overlay IP packets.
pub trait DataCarrier: Send + Sync + std::fmt::Debug + 'static {
    /// External protocol identifier used in local policy and peer negotiation.
    fn protocol_id(&self) -> &str;
    /// Wire version, independent of software releases and the internal tunnel.
    fn protocol_version(&self) -> u16;
    /// Whether the peer may dial back after an unsuccessful elected dial.
    fn supports_reverse_dial(&self) -> bool {
        false
    }
    /// Supported carrier settings.
    fn options(&self) -> &'static [ProtocolOption] {
        &[]
    }
    /// Bounded opaque reachability/negotiation capability for one network.
    fn local_capability(&self, network: NetworkId)
    -> Result<Option<PluginCapability>, PluginError>;
    /// Installs a capability received through an authenticated membership session.
    fn on_peer_capability(
        &self,
        network: NetworkId,
        peer: EndpointId,
        capability: &PluginCapability,
    ) -> Result<(), PluginError>;
    /// Adds IP hints from verified direct control paths. Their UDP ports do not
    /// identify a TCP listener. Carriers authenticate their own data path.
    fn on_peer_capability_at(
        &self,
        network: NetworkId,
        peer: EndpointId,
        capability: &PluginCapability,
        _ips: &[std::net::IpAddr],
    ) -> Result<(), PluginError> {
        self.on_peer_capability(network, peer, capability)
    }
    /// Supplies the actual owned interface name, including kernel-assigned names.
    fn on_interface_ready(&self, _name: &str) {}
    /// Activates this carrier for one local network.
    fn on_network_activated(&self, _network: NetworkId) {}
    /// Retires all negotiation and links for this member.
    fn on_peer_gone(&self, network: NetworkId, peer: EndpointId);
    /// Retires this network's sockets and negotiations.
    fn on_network_deactivated(&self, network: NetworkId);
    /// Forgets durable carrier settings, if any.
    fn on_network_forgotten(&self, _network: NetworkId) {}
    /// Stops carrier tasks, with the agent enforcing a shutdown deadline.
    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}
/// One shared carrier adapter.
pub type SharedCarrier = Arc<dyn DataCarrier>;
