//! End-to-end encryption remains independent of physical Amnezia pair links.
use crate::{AWG_PROTOCOL, AWG_WIRE_VERSION, AwgTransport};
use iroh::EndpointId;
use std::sync::Arc;
use tsunagi::dataplane::transport::SharedLink;
use tsunagi::dataplane::{IpPlugin, PluginCapability, PluginContext, PluginError, ProtocolOption};
use tsunagi::state::Ipv4Range;
use tsunagi::{BoxFuture, NetworkId};
use tsunagi_wg_quic::{NetworkOverview, WireguardConfig, WireguardPlugin};

/// AWG capability and an independent end-to-end WireGuard engine.
/// Pair transport keys/profiles never enter its durable end-to-end key store.
#[derive(Debug)]
pub struct AwgPlugin {
    inner: Arc<WireguardPlugin>,
    transport: Arc<AwgTransport>,
}
impl AwgPlugin {
    /// Uses standard tunnel MTU/keepalive options; pair ports and profiles are ephemeral.
    pub const OPTIONS: &'static [ProtocolOption] = &[
        ProtocolOption {
            key: "keepalive",
            value: "SECONDS",
            help: "end-to-end tunnel keepalive; 0 disables it",
            default: Some("25"),
        },
        ProtocolOption {
            key: "mtu",
            value: "BYTES",
            help: "maximum overlay packet size",
            default: Some("1280"),
        },
        ProtocolOption {
            key: "stun",
            value: "HOST:PORT|off",
            help: "UDP public mapping discovery; disabled in local reach mode",
            default: Some("stun.l.google.com:19302"),
        },
    ];
    /// Opens the end-to-end engine, retaining separate pair transport state.
    pub async fn open(
        mut config: WireguardConfig,
        transport: Arc<AwgTransport>,
    ) -> Result<Arc<Self>, PluginError> {
        config.protocol = AWG_PROTOCOL;
        Ok(Arc::new(Self {
            inner: WireguardPlugin::open(config).await?,
            transport,
        }))
    }
    /// Reports end-to-end tunnel health and traffic counters.
    pub fn overview(&self, network: NetworkId) -> Option<NetworkOverview> {
        self.inner.overview(network)
    }
}
impl IpPlugin for AwgPlugin {
    fn protocol_id(&self) -> &str {
        AWG_PROTOCOL
    }
    fn protocol_version(&self) -> u16 {
        AWG_WIRE_VERSION
    }
    fn options(&self) -> &'static [ProtocolOption] {
        Self::OPTIONS
    }
    fn attach(&self, context: PluginContext) {
        self.inner.attach(context);
    }
    fn local_capability(
        &self,
        network: NetworkId,
    ) -> Result<Option<PluginCapability>, PluginError> {
        self.inner.local_capability(network).map(|cap| {
            cap.map(|mut cap| {
                cap.protocol = AWG_PROTOCOL.into();
                cap.version = AWG_WIRE_VERSION;
                cap
            })
        })
    }
    fn on_network_activated(&self, network: NetworkId) {
        self.inner.on_network_activated(network);
    }
    fn on_peer_capability(
        &self,
        network: NetworkId,
        peer: EndpointId,
        capability: &PluginCapability,
    ) -> Result<(), PluginError> {
        if capability.protocol != AWG_PROTOCOL
            || capability.version != AWG_WIRE_VERSION
            || !capability.enabled
        {
            return Err(PluginError::Rejected("unsupported AWG capability".into()));
        }
        self.inner.on_peer_capability(network, peer, capability)?;
        self.transport.allow_peer(network, peer);
        Ok(())
    }
    fn on_address_allocation(
        &self,
        network: NetworkId,
        range: Ipv4Range,
        allocations: &[(EndpointId, std::net::Ipv4Addr)],
    ) {
        self.inner
            .on_address_allocation(network, range, allocations);
    }
    fn carry(&self, network: NetworkId, peer: EndpointId, packet: bytes::Bytes) -> bool {
        self.inner.carry(network, peer, packet)
    }
    fn on_peer_link(&self, network: NetworkId, peer: EndpointId, link: SharedLink) {
        self.inner.on_peer_link(network, peer, link);
    }
    fn on_peer_gone(&self, network: NetworkId, peer: EndpointId) {
        self.transport.forget_peer(network, peer);
        self.inner.on_peer_gone(network, peer);
    }
    fn on_network_deactivated(&self, network: NetworkId) {
        self.transport.stop_network(network);
        self.inner.on_network_deactivated(network);
    }
    fn on_network_forgotten(&self, network: NetworkId) {
        self.inner.on_network_forgotten(network);
    }
    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.transport.shutdown();
            self.inner.shutdown().await;
        })
    }
}
