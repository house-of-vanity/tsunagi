//! TLS carrier options and bounded reachability announcements. No IP cipher lives here.
use crate::transport::TcpTlsTransport;
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
    if addr.is_loopback() || addr.is_unspecified() || addr.is_link_local() || addr.is_broadcast() {
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
            if v6.is_loopback() || v6.is_unspecified() {
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
            default: Some("443"),
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
/// TLS carrier announcements and lifecycle, independent of IP encryption.
#[derive(Debug)]
pub struct TcpTlsCarrier {
    transport: Arc<TcpTlsTransport>,
    excluded_interface: std::sync::Mutex<Option<String>>,
    underlay: std::sync::OnceLock<tokio::sync::watch::Receiver<Vec<std::net::IpAddr>>>,
    peers: std::sync::Mutex<
        std::collections::HashMap<(NetworkId, EndpointId), Vec<std::net::SocketAddr>>,
    >,
}
impl TcpTlsCarrier {
    /// Shares the transport's listener; creates no end-to-end cipher.
    pub fn new(transport: Arc<TcpTlsTransport>) -> Arc<Self> {
        Arc::new(Self {
            transport,
            excluded_interface: std::sync::Mutex::new(None),
            underlay: Default::default(),
            peers: Default::default(),
        })
    }
    /// Registers a carrier while excluding the agent's own, possibly custom-named interface.
    pub fn with_interface(transport: Arc<TcpTlsTransport>, interface: String) -> Arc<Self> {
        Arc::new(Self {
            transport,
            excluded_interface: std::sync::Mutex::new(Some(interface)),
            underlay: Default::default(),
            peers: Default::default(),
        })
    }
    /// Use only the addresses assigned to the OS-selected physical network.
    pub fn set_underlay(&self, source: tokio::sync::watch::Receiver<Vec<std::net::IpAddr>>) {
        let _ = self.underlay.set(source);
    }
    fn update_peer(
        &self,
        network: NetworkId,
        peer: EndpointId,
        addrs: Option<Vec<std::net::SocketAddr>>,
    ) {
        let mut peers = self.peers.lock().unwrap_or_else(|p| p.into_inner());
        match addrs {
            Some(addrs) => {
                peers.insert((network, peer), addrs);
            }
            None => {
                peers.remove(&(network, peer));
            }
        }
        let mut combined = peers
            .iter()
            .filter(|((_, id), _)| *id == peer)
            .flat_map(|(_, addrs)| addrs.iter().copied())
            .collect::<Vec<_>>();
        combined.sort_unstable();
        combined.dedup();
        combined.truncate(32);
        self.transport.replace_peer_addrs(peer, combined);
    }
}
impl tsunagi::dataplane::transport::DataCarrier for TcpTlsCarrier {
    fn protocol_id(&self) -> &str {
        TCP_TLS_PROTOCOL
    }
    fn protocol_version(&self) -> u16 {
        2
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
        .map_err(|_| PluginError::Other("cannot encode TLS addresses".into()))?;
        Ok(Some(tsunagi::dataplane::PluginCapability {
            protocol: TCP_TLS_PROTOCOL.into(),
            version: 2,
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
        if !cap.enabled || cap.protocol != TCP_TLS_PROTOCOL || cap.version != 2 {
            return Err(PluginError::Rejected("unsupported TLS carrier".into()));
        }
        // Decode a fixed bounded array through the existing common announcement limit.
        #[derive(Deserialize)]
        struct Addresses(
            u16,
            #[serde(deserialize_with = "bounded_ips")] Vec<std::net::IpAddr>,
        );
        let Addresses(port, ips) = postcard::from_bytes(&cap.data)
            .map_err(|_| PluginError::Rejected("invalid TLS carrier addresses".into()))?;
        if port == 0 {
            return Err(PluginError::Rejected("invalid TLS carrier port".into()));
        }
        self.update_peer(
            network,
            peer,
            Some(
                ips.into_iter()
                    .filter(|ip| is_candidate_ip(*ip))
                    .map(|ip| std::net::SocketAddr::new(ip, port))
                    .collect(),
            ),
        );
        Ok(())
    }
    fn on_peer_gone(&self, network: NetworkId, peer: EndpointId) {
        self.update_peer(network, peer, None);
    }
    fn on_network_deactivated(&self, network: NetworkId) {
        let peers: Vec<_> = self
            .peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .filter(|(id, _)| *id == network)
            .map(|(_, peer)| *peer)
            .collect();
        for peer in peers {
            self.update_peer(network, peer, None);
        }
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
