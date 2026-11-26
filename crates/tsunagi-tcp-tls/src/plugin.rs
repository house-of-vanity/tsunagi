//! TLS carrier options and bounded reachability announcements. No IP cipher lives here.
use crate::{candidates::TcpEndpoint, transport::TcpTlsTransport};
use iroh::EndpointId;
use serde::Deserialize;
use std::sync::Arc;
use tsunagi::NetworkId;
use tsunagi::dataplane::{PluginError, ProtocolOption};
/// External TLS carrier identifier.
pub const TCP_TLS_PROTOCOL: &str = "tcp-tls";
/// Carrier announcement wire version.
pub const TCP_TLS_VERSION: u16 = 2;
/// Configuration for the `tcp-tls` protocol plugin.
#[derive(Debug, Clone, Default)]
pub struct TcpTlsConfig {
    /// Requested port to bind.
    pub port: Option<u16>,
    /// Custom SNI domain to disguise TLS connections.
    pub sni: Option<String>,
}

impl TcpTlsConfig {
    /// Creates a configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the TCP listen port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Sets the SNI domain used to disguise TLS connections.
    pub fn with_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into());
        self
    }
}

/// Discovers local network interface IPs to announce to peers.
pub fn local_ip_candidates() -> Vec<std::net::IpAddr> {
    local_ip_candidates_excluding(None)
}

fn local_ip_candidates_excluding(excluded_interface: Option<&str>) -> Vec<std::net::IpAddr> {
    let mut candidates = Vec::new();
    for iface in netdev::get_interfaces() {
        if excluded_interface.is_some_and(|name| {
            iface.name.eq_ignore_ascii_case(name)
                || iface
                    .friendly_name
                    .as_deref()
                    .is_some_and(|friendly| friendly.eq_ignore_ascii_case(name))
        }) || !is_candidate_interface(&iface)
        {
            continue;
        }
        for ip in &iface.ipv4 {
            let addr = ip.addr();
            if is_candidate_ipv4(addr) {
                let priority = ip_priority(&iface, std::net::IpAddr::V4(addr));
                candidates.push((priority, std::net::IpAddr::V4(addr)));
            }
        }
        for ip in &iface.ipv6 {
            let addr = ip.addr();
            if is_candidate_ip(std::net::IpAddr::V6(addr)) {
                let priority = ip_priority(&iface, std::net::IpAddr::V6(addr));
                candidates.push((priority, std::net::IpAddr::V6(addr)));
            }
        }
    }
    // Sort descending by priority so best interface IP is candidate #0
    candidates.sort_by_key(|b| std::cmp::Reverse(b.0));
    let mut seen = std::collections::HashSet::new();
    let mut ips = Vec::new();
    for (_, ip) in candidates {
        if seen.insert(ip) {
            ips.push(ip);
        }
    }
    ips
}

pub(crate) fn is_candidate_interface(iface: &netdev::Interface) -> bool {
    if !iface.is_up() || iface.is_loopback() {
        return false;
    }

    let name = iface.name.to_lowercase();
    let friendly = iface
        .friendly_name
        .as_deref()
        .map(str::to_lowercase)
        .unwrap_or_default();
    let desc = iface
        .description
        .as_deref()
        .map(str::to_lowercase)
        .unwrap_or_default();

    // Skip Tsunagi / Wintun overlay interfaces
    if name.starts_with("tsun")
        || name.contains("tsunagi")
        || name.contains("wintun")
        || friendly.starts_with("tsun")
        || friendly.contains("tsunagi")
        || friendly.contains("wintun")
        || desc.contains("wintun")
        || desc.contains("tsunagi")
    {
        return false;
    }

    // Skip container, VM, and virtual bridge interfaces
    if name.starts_with("docker")
        || name.starts_with("br-")
        || name.starts_with("veth")
        || name.starts_with("virbr")
        || name.starts_with("cni")
        || name.starts_with("flannel")
        || name.starts_with("cali")
        || name.starts_with("kube")
        || name.starts_with("dummy")
        || name.starts_with("lxc")
        || name.starts_with("podman")
        || friendly.contains("vethernet")
        || friendly.contains("vboxnet")
        || friendly.contains("vmnet")
        || desc.contains("virtualbox")
        || desc.contains("hyper-v")
        || desc.contains("vmware")
    {
        return false;
    }

    true
}

pub(crate) fn is_candidate_ipv4(addr: std::net::Ipv4Addr) -> bool {
    if addr.is_multicast()
        || addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_link_local()
        || addr.is_broadcast()
    {
        return false;
    }
    if addr.is_documentation() {
        return false;
    }
    true
}

pub(crate) fn is_candidate_ip(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => is_candidate_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            if v6.is_multicast() || v6.is_loopback() || v6.is_unspecified() {
                return false;
            }
            let segments = v6.segments();
            // Filter link-local fe80::/10
            (segments[0] & 0xffc0) != 0xfe80
        }
    }
}

pub(crate) fn ip_priority(iface: &netdev::Interface, ip: std::net::IpAddr) -> u32 {
    let has_gateway = iface.gateway.is_some();
    let base = if has_gateway { 100 } else { 0 };
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Tailscale: 100.64.0.0/10
            let is_tailscale = octets[0] == 100 && (octets[1] & 0xc0) == 64;
            let is_private = v4.is_private();
            if !is_private && !is_tailscale {
                base + 50
            } else if has_gateway && is_private {
                base + 40
            } else if is_tailscale {
                base + 30
            } else {
                base + 10
            }
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            let is_global = (segments[0] & 0xe000) == 0x2000;
            if is_global { base + 45 } else { base + 20 }
        }
    }
}
impl TcpTlsConfig {
    /// Supported options for `tcp-tls`.
    pub const OPTIONS: &'static [ProtocolOption] = &[
        ProtocolOption {
            key: "port",
            value: "PORT",
            help: "TCP port to listen on for TLS 1.3 connections",
            default: Some("9442"),
        },
        ProtocolOption {
            key: "sni",
            value: "DOMAIN",
            help: "Server Name Indication (SNI) domain to disguise TLS connections",
            default: Some(crate::cert::DEFAULT_SNI),
        },
    ];

    /// Configures settings from parsed `-o` options.
    pub fn configure(
        mut config: TcpTlsConfig,
        options: &[(String, String)],
    ) -> Result<TcpTlsConfig, String> {
        for (key, value) in options {
            match key.as_str() {
                "port" => {
                    let port: u16 = value
                        .parse()
                        .map_err(|_| format!("invalid port `{value}`"))?;
                    config.port = Some(port);
                }
                "sni" => {
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        return Err("sni domain cannot be empty".into());
                    }
                    config.sni = Some(trimmed.to_string());
                }
                other => return Err(format!("unknown option `{other}` for tcp-tls")),
            }
        }
        Ok(config)
    }
}
/// Native TLS carrier, retaining the original registration API.
pub type TcpTlsCarrier = TcpCarrier<TcpTlsTransport>;

/// Bounded TCP address announcements shared by carriers with independent listeners.
#[derive(Debug)]
pub struct TcpCarrier<T> {
    transport: Arc<T>,
    excluded_interface: std::sync::Mutex<Option<String>>,
    bootstrap: std::sync::OnceLock<std::collections::HashMap<EndpointId, Vec<std::net::IpAddr>>>,
    underlay: std::sync::OnceLock<tokio::sync::watch::Receiver<Vec<std::net::IpAddr>>>,
}
impl<T: TcpEndpoint> TcpCarrier<T> {
    /// Announces the actual listener's port.
    pub fn new(transport: Arc<T>) -> Arc<Self> {
        Arc::new(Self {
            transport,
            excluded_interface: Default::default(),
            bootstrap: Default::default(),
            underlay: Default::default(),
        })
    }
    /// Excludes the agent's own interface from physical addresses.
    pub fn with_interface(transport: Arc<T>, interface: String) -> Arc<Self> {
        Arc::new(Self {
            transport,
            excluded_interface: std::sync::Mutex::new(Some(interface)),
            bootstrap: Default::default(),
            underlay: Default::default(),
        })
    }
    /// Bootstrap IPs can be candidates for this peer's separately announced TCP port.
    pub fn set_bootstrap(&self, endpoints: &[iroh::EndpointAddr]) {
        let _ = self.bootstrap.set(
            endpoints
                .iter()
                .map(|endpoint| {
                    (
                        endpoint.id,
                        endpoint.ip_addrs().take(32).map(|a| a.ip()).collect(),
                    )
                })
                .collect(),
        );
    }
    /// Use only the addresses assigned to the OS-selected physical network.
    pub fn set_underlay(&self, source: tokio::sync::watch::Receiver<Vec<std::net::IpAddr>>) {
        let _ = self.underlay.set(source);
    }
}

impl<T: TcpEndpoint> tsunagi::dataplane::transport::DataCarrier for TcpCarrier<T> {
    fn protocol_id(&self) -> &str {
        self.transport.name()
    }
    fn protocol_version(&self) -> u16 {
        self.transport.wire_version()
    }
    fn supports_reverse_dial(&self) -> bool {
        true
    }
    fn on_interface_ready(&self, name: &str) {
        *self
            .excluded_interface
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(name.into());
    }
    fn local_capability(
        &self,
        _: NetworkId,
    ) -> Result<Option<tsunagi::dataplane::PluginCapability>, PluginError> {
        let ips = match self.underlay.get() {
            Some(source) => source
                .borrow()
                .iter()
                .copied()
                .filter(|ip| is_candidate_ip(*ip))
                .collect(),
            None => local_ip_candidates_excluding(
                self.excluded_interface
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .as_deref(),
            ),
        };
        let data = postcard::to_allocvec(&(
            self.transport.bound_port(),
            ips.into_iter().take(32).collect::<Vec<_>>(),
        ))
        .map_err(|_| PluginError::Other("cannot encode TCP addresses".into()))?;
        Ok(Some(tsunagi::dataplane::PluginCapability {
            protocol: self.protocol_id().into(),
            version: self.protocol_version(),
            enabled: true,
            data,
        }))
    }
    fn on_peer_capability(
        &self,
        network: NetworkId,
        peer: EndpointId,
        cap: &tsunagi::dataplane::PluginCapability,
    ) -> Result<(), PluginError> {
        self.on_peer_capability_at(network, peer, cap, &[])
    }
    fn on_peer_capability_at(
        &self,
        network: NetworkId,
        peer: EndpointId,
        cap: &tsunagi::dataplane::PluginCapability,
        observed: &[std::net::IpAddr],
    ) -> Result<(), PluginError> {
        if !cap.enabled
            || cap.protocol != self.protocol_id()
            || cap.version != self.protocol_version()
        {
            return Err(PluginError::Rejected("unsupported TCP carrier".into()));
        }
        // Decode a fixed bounded array through the existing common announcement limit.
        #[derive(Deserialize)]
        struct Addresses(
            u16,
            #[serde(deserialize_with = "bounded_ips")] Vec<std::net::IpAddr>,
        );
        let Addresses(port, ips) = postcard::from_bytes(&cap.data)
            .map_err(|_| PluginError::Rejected("invalid TCP carrier addresses".into()))?;
        if port == 0 {
            return Err(PluginError::Rejected("invalid TCP carrier port".into()));
        }
        let configured = self.bootstrap.get().and_then(|peers| peers.get(&peer));
        let mut addresses = Vec::new();
        for ip in observed
            .iter()
            .copied()
            .chain(configured.into_iter().flatten().copied())
            .chain(ips)
        {
            let ip = ip.to_canonical();
            let addr = std::net::SocketAddr::new(ip, port);
            if is_candidate_ip(ip) && !addresses.contains(&addr) {
                addresses.push(addr);
            }
            if addresses.len() == 32 {
                break;
            }
        }
        self.transport
            .set_pair_addresses(network, peer, Some(addresses));
        Ok(())
    }
    fn on_peer_gone(&self, network: NetworkId, peer: EndpointId) {
        self.transport.set_pair_addresses(network, peer, None);
    }
    fn on_network_deactivated(&self, network: NetworkId) {
        self.transport.clear_network(network);
    }
}
fn bounded_ips<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<std::net::IpAddr>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<std::net::IpAddr>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 32 IP candidates")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|n| n > 32) {
                return Err(serde::de::Error::custom("too many IP candidates"));
            }
            let mut ips = Vec::new();
            while let Some(ip) = seq.next_element()? {
                if ips.len() == 32 {
                    return Err(serde::de::Error::custom("too many IP candidates"));
                }
                ips.push(ip);
            }
            Ok(ips)
        }
    }
    deserializer.deserialize_seq(Visitor)
}
