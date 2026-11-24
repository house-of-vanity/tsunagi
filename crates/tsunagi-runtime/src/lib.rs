//! Construct the native data transports in one place for both the CLI and Android.
//! The embedding application supplies the Tokio runtime, TUN and discovery policy.
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};
use tokio::{sync::watch, task::JoinSet};
use tsunagi::{
    Agent, AgentConfig, TransportPolicy, dataplane::transport::iroh_link::IrohCarrier,
    iroh_types::EndpointAddr,
};
use tsunagi_awg::{AWG_PROTOCOL, AWG_WIRE_VERSION, AwgPlugin, AwgTransport};
use tsunagi_tcp_tls::{TCP_TLS_PROTOCOL, TcpTlsCarrier, TcpTlsConfig, TcpTlsTransport};
use tsunagi_wireguard::WG_PROTOCOL;

pub mod report;

/// What a protocol is called, what it speaks, and what it takes.
///
/// A registry rather than a lookup on the plugins themselves, because
/// `tsng protocols` has to answer before anything is constructed, and
/// because this is the list `--protocol` resolves against.
pub struct ProtocolSpec {
    /// The name on the wire, which is what peers compare.
    pub name: &'static str,
    /// The wire version. Not the software version: two peers on different
    /// builds carry traffic for each other as long as this matches.
    pub version: u16,
    /// One line about what it is.
    pub summary: &'static str,
    /// The settings it accepts.
    pub options: &'static [tsunagi::dataplane::ProtocolOption],
}

const WG_OPTIONS: &[tsunagi::dataplane::ProtocolOption] = &[tsunagi::dataplane::ProtocolOption {
    key: "port",
    value: "PORT",
    help: "preferred local UDP port; additional pairs use dynamic ports",
    default: Some("51820"),
}];

/// Every protocol this build has.
pub const PROTOCOLS: &[ProtocolSpec] = &[
    ProtocolSpec {
        name: WG_PROTOCOL,
        version: tsunagi_wireguard::WG_WIRE_VERSION,
        summary: "Pure WireGuard direct UDP transport",
        options: WG_OPTIONS,
    },
    ProtocolSpec {
        name: AWG_PROTOCOL,
        version: AWG_WIRE_VERSION,
        summary: "Pairwise Amnezia-masked UDP with fresh private profiles on every connection attempt",
        options: AwgPlugin::OPTIONS,
    },
    ProtocolSpec {
        name: "wg-quic",
        version: 1,
        summary: "iroh QUIC datagram carrier with NAT traversal and relays",
        options: &[],
    },
    ProtocolSpec {
        name: TCP_TLS_PROTOCOL,
        version: tsunagi_tcp_tls::TCP_TLS_VERSION,
        summary: "TCP TLS 1.3 carrier",
        options: TcpTlsConfig::OPTIONS,
    },
];

/// Incoming direct connections to attach after the agent has acquired its identity.
pub struct Carriers {
    udp: [Arc<AwgTransport>; 2],
    tls: Arc<TcpTlsTransport>,
}

impl Carriers {
    /// Register the complete catalog. CLI options and phone defaults use the same
    /// constructors and wire versions. Android supplies the addresses of its selected
    /// physical network; desktop discovers addresses on its host interfaces.
    pub async fn configure(
        mut config: AgentConfig,
        bootstrap: &[EndpointAddr],
        underlay: Option<watch::Receiver<Vec<IpAddr>>>,
        options: impl Fn(&ProtocolSpec) -> Vec<(String, String)>,
    ) -> Result<(AgentConfig, Self), Box<dyn std::error::Error>> {
        let options_for = |name| {
            PROTOCOLS
                .iter()
                .find(|p| p.name == name)
                .map(&options)
                .unwrap_or_default()
        };
        let wg_opts = options_for(WG_PROTOCOL);
        let port = wg_opts
            .iter()
            .find(|(k, _)| k == "port")
            .map(|(_, v)| v.parse::<u16>())
            .transpose()?
            .unwrap_or(51820);
        let awg_opts = options_for(AWG_PROTOCOL);
        const STUN: &str = "stun.l.google.com:19302";
        let server = awg_opts
            .iter()
            .find(|(key, _)| key == "stun")
            .map_or(STUN, |(_, value)| value.as_str());
        if server.len() > 255 || (server != "off" && !server.contains(':')) {
            return Err("awg:stun must be HOST:PORT or off".into());
        }
        let public = config.transport != TransportPolicy::LocalOnly;
        let db = config.paths.state_db();
        let identity = tokio::task::spawn_blocking(move || {
            tsunagi::storage::StateStore::open(db)?.load_or_create_device_identity()
        })
        .await??;
        let bind = Ipv4Addr::UNSPECIFIED;
        let udp = [
            AwgTransport::wireguard_with_port(
                identity.endpoint_id(),
                bind,
                public.then(|| STUN.into()),
                port,
            ),
            AwgTransport::new_with_stun(
                identity.endpoint_id(),
                bind,
                (public && server != "off").then(|| server.into()),
            ),
        ];
        for transport in &udp {
            transport.exclude_interface(config.interface_name.clone());
            if let Some(source) = &underlay {
                transport.set_underlay(source.clone());
            }
            config = config
                .with_carrier(AwgPlugin::new(transport.clone()))
                .with_custom_transport(transport.protocol_id(), transport.clone());
        }
        let settings =
            TcpTlsConfig::configure(TcpTlsConfig::new(), &options_for(TCP_TLS_PROTOCOL))?;
        let tls = Arc::new(
            TcpTlsTransport::bind(&identity, settings.port, settings.sni)
                .await
                .map_err(|error| -> Box<dyn std::error::Error> { error })?,
        );
        for address in bootstrap {
            for ip in address.ip_addrs() {
                tls.set_peer_addr(address.id, *ip);
            }
        }
        let carrier = TcpTlsCarrier::with_interface(tls.clone(), config.interface_name.clone());
        if let Some(source) = underlay {
            carrier.set_underlay(source);
        }
        config = config
            .with_carrier(Arc::new(IrohCarrier))
            .with_carrier(carrier)
            .with_custom_transport(TCP_TLS_PROTOCOL, tls.clone());
        Ok((config, Self { udp, tls }))
    }

    /// Accept incoming authenticated links until the caller drops the returned task set.
    #[must_use = "keep the listeners alive for the lifetime of this agent"]
    pub fn listen(self, agent: &Agent) -> JoinSet<()> {
        let mut tasks = JoinSet::new();
        for transport in self.udp {
            let agent = agent.clone();
            tasks.spawn(async move {
                while let Some(inbound) = transport.next_inbound().await {
                    if let Err(error) = agent.install_inbound_link(inbound).await {
                        tracing::debug!(%error, protocol=transport.protocol_id(), "inbound link rejected");
                    }
                }
            });
        }
        let agent = agent.clone();
        tasks.spawn(async move {
            self.tls
                .accept_loop(move |inbound| {
                    let agent = agent.clone();
                    tokio::spawn(async move {
                        if let Err(error) = agent.install_inbound_link(inbound).await {
                            tracing::debug!(%error, "inbound tcp-tls link rejected");
                        }
                    });
                })
                .await;
        });
        tasks
    }
}
