//! Carrier capabilities only. End-to-end encryption belongs to the agent's tunnel.
use crate::transport::AwgTransport;
use iroh::EndpointId;
use std::sync::Arc;
use tsunagi::dataplane::{PluginCapability, PluginError, ProtocolOption};
use tsunagi::{BoxFuture, NetworkId};

/// Capability and lifecycle adapter for an encrypted UDP carrier.
#[derive(Debug)]
pub struct AwgPlugin {
    transport: Arc<AwgTransport>,
}
impl AwgPlugin {
    /// The carrier's own NAT discovery setting.
    pub const OPTIONS: &'static [ProtocolOption] = &[ProtocolOption {
        key: "stun",
        value: "HOST:PORT|off",
        help: "UDP public mapping discovery; disabled in local reach mode",
        default: Some("stun.l.google.com:19302"),
    }];
    /// Registers one carrier without creating an internal IP encryption engine.
    pub fn new(transport: Arc<AwgTransport>) -> Arc<Self> {
        Arc::new(Self { transport })
    }
}
impl tsunagi::dataplane::transport::DataCarrier for AwgPlugin {
    fn protocol_id(&self) -> &str {
        self.transport.protocol_id()
    }
    fn protocol_version(&self) -> u16 {
        self.transport.wire_version()
    }
    fn options(&self) -> &'static [ProtocolOption] {
        Self::OPTIONS
    }
    fn on_interface_ready(&self, name: &str) {
        self.transport.exclude_interface(name.into());
    }
    fn local_capability(&self, _: NetworkId) -> Result<Option<PluginCapability>, PluginError> {
        Ok(Some(PluginCapability {
            protocol: self.protocol_id().into(),
            version: self.protocol_version(),
            enabled: true,
            data: Vec::new(),
        }))
    }
    fn on_peer_capability(
        &self,
        network: NetworkId,
        peer: EndpointId,
        capability: &PluginCapability,
    ) -> Result<(), PluginError> {
        if capability.protocol != self.protocol_id()
            || capability.version != self.protocol_version()
            || !capability.enabled
            || !capability.data.is_empty()
        {
            return Err(PluginError::Rejected(
                "unsupported UDP carrier capability".into(),
            ));
        }
        self.transport.allow_peer(network, peer);
        Ok(())
    }
    fn on_peer_gone(&self, network: NetworkId, peer: EndpointId) {
        self.transport.forget_peer(network, peer);
    }
    fn on_network_deactivated(&self, network: NetworkId) {
        self.transport.stop_network(network);
    }
    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.transport.shutdown();
        })
    }
}
