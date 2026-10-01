//! The `tcp-tls` IP plugin implementation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use tsunagi::dataplane::tunnel::{GenericTunnelPlugin, TunnelCodec};
use tsunagi::dataplane::{PluginError, ProtocolOption};
use tsunagi::identity::NetworkId;

use crate::crypto::PeerCipher;
use crate::transport::TcpTlsTransport;

/// The wire protocol identifier for `tcp-tls`.
pub const TCP_TLS_PROTOCOL: &str = "tcp-tls";

/// Wire version for `tcp-tls`.
pub const TCP_TLS_VERSION: u16 = 1;

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

/// Announcement payload exchanged between peers for `tcp-tls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpTlsAnnouncement {
    /// X25519 public key for E2EE noise encryption.
    pub noise_public: [u8; 32],
    /// TCP port the peer is listening on.
    pub port: u16,
    /// Candidate IP addresses where this peer can be reached on `port`.
    #[serde(default)]
    pub addrs: Vec<std::net::IpAddr>,
}

/// Discovers local network interface IPs to announce to peers.
pub fn local_ip_candidates() -> Vec<std::net::IpAddr> {
    let mut candidates = Vec::new();
    for iface in netdev::get_interfaces() {
        if !is_candidate_interface(&iface) {
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
            if (segments[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            true
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

/// The codec implementing cryptographic transformation and announcements for `tcp-tls`.
pub struct TcpTlsCodec {
    local_id: EndpointId,
    static_secret: StaticSecret,
    public_key: PublicKey,
    transport: Arc<TcpTlsTransport>,
    ciphers: RwLock<HashMap<(NetworkId, EndpointId), Arc<PeerCipher>>>,
}

impl std::fmt::Debug for TcpTlsCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTlsCodec")
            .field("local_id", &self.local_id.fmt_short().to_string())
            .field("port", &self.transport.bound_port())
            .finish()
    }
}

impl TcpTlsCodec {
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

    /// Creates a new `TcpTlsCodec`.
    pub fn new(local_id: EndpointId, transport: Arc<TcpTlsTransport>) -> Self {
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let static_secret = StaticSecret::from(secret_bytes);
        let public_key = PublicKey::from(&static_secret);

        Self {
            local_id,
            static_secret,
            public_key,
            transport,
            ciphers: RwLock::new(HashMap::new()),
        }
    }

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

impl TunnelCodec for TcpTlsCodec {
    fn protocol_id(&self) -> &str {
        TCP_TLS_PROTOCOL
    }

    fn protocol_version(&self) -> u16 {
        TCP_TLS_VERSION
    }

    fn options(&self) -> &'static [ProtocolOption] {
        Self::OPTIONS
    }

    fn local_capability_data(&self, _network: NetworkId) -> Result<Vec<u8>, PluginError> {
        let announcement = TcpTlsAnnouncement {
            noise_public: *self.public_key.as_bytes(),
            port: self.transport.bound_port(),
            addrs: local_ip_candidates(),
        };
        postcard::to_allocvec(&announcement)
            .map_err(|err| PluginError::Other(format!("encode announcement failed: {err}")))
    }

    fn on_peer_capability_data(
        &self,
        network: NetworkId,
        peer: EndpointId,
        data: &[u8],
    ) -> Result<(), PluginError> {
        let announcement: TcpTlsAnnouncement = postcard::from_bytes(data)
            .map_err(|err| PluginError::Rejected(format!("invalid announcement: {err}")))?;

        for ip in &announcement.addrs {
            if is_candidate_ip(*ip) {
                self.transport
                    .set_peer_addr(peer, std::net::SocketAddr::new(*ip, announcement.port));
            }
        }

        let peer_noise_pubkey = PublicKey::from(announcement.noise_public);
        let cipher = Arc::new(PeerCipher::new(
            self.local_id,
            peer,
            &self.static_secret,
            &peer_noise_pubkey,
        ));

        let mut guard = match self.ciphers.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.insert((network, peer), cipher);
        Ok(())
    }

    fn on_peer_down(&self, network: NetworkId, peer: EndpointId) {
        let mut guard = match self.ciphers.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.remove(&(network, peer));
    }

    fn encrypt(
        &self,
        network: NetworkId,
        peer: EndpointId,
        packet: &[u8],
    ) -> Result<Bytes, PluginError> {
        let cipher = {
            let guard = match self.ciphers.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.get(&(network, peer)).cloned()
        };

        let Some(cipher) = cipher else {
            return Err(PluginError::Unavailable("no cipher for peer".into()));
        };

        cipher.encrypt(packet)
    }

    fn decrypt(
        &self,
        network: NetworkId,
        peer: EndpointId,
        payload: &[u8],
    ) -> Result<Bytes, PluginError> {
        let cipher = {
            let guard = match self.ciphers.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.get(&(network, peer)).cloned()
        };

        let Some(cipher) = cipher else {
            return Err(PluginError::Unavailable("no cipher for peer".into()));
        };

        cipher.decrypt(payload)
    }
}

/// The complete `tcp-tls` plugin.
pub type TcpTlsPlugin = GenericTunnelPlugin<TcpTlsCodec>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_candidate_interface_filters_overlay_and_bridges() {
        let mut iface = netdev::Interface::dummy();
        iface.flags = 1; // UP

        // Standard Ethernet - should pass
        iface.name = "eth0".to_string();
        assert!(is_candidate_interface(&iface));

        // Windows Ethernet with GUID name - should pass
        iface.name = "{B6149D2C-1234-5678-9ABC-DEF012345678}".to_string();
        iface.friendly_name = Some("Ethernet".to_string());
        iface.description = Some("Intel(R) Ethernet Connection".to_string());
        assert!(is_candidate_interface(&iface));

        // Linux tsun0 overlay - must be filtered
        iface.name = "tsun0".to_string();
        iface.friendly_name = None;
        iface.description = None;
        assert!(!is_candidate_interface(&iface));

        // Windows Wintun overlay (GUID name with tsun0 friendly name) - must be filtered!
        iface.name = "{72D85D76-F1A5-42AC-BC49-2169527CDDDF}".to_string();
        iface.friendly_name = Some("tsun0".to_string());
        iface.description = Some("Wintun Userspace Tunnel".to_string());
        assert!(!is_candidate_interface(&iface));

        // Windows Wintun overlay with description containing Wintun - must be filtered!
        iface.friendly_name = Some("Local Area Connection 2".to_string());
        iface.description = Some("Wintun Userspace Tunnel".to_string());
        assert!(!is_candidate_interface(&iface));

        // Docker bridge - must be filtered
        iface.name = "docker0".to_string();
        iface.friendly_name = None;
        iface.description = None;
        assert!(!is_candidate_interface(&iface));

        // Docker network bridge br-* - must be filtered
        iface.name = "br-4f6d3a9b1c2e".to_string();
        assert!(!is_candidate_interface(&iface));

        // Virtual ethernet veth* - must be filtered
        iface.name = "veth12345".to_string();
        assert!(!is_candidate_interface(&iface));

        // Libvirt NAT bridge virbr* - must be filtered
        iface.name = "virbr0".to_string();
        assert!(!is_candidate_interface(&iface));

        // CNI bridge - must be filtered
        iface.name = "cni0".to_string();
        assert!(!is_candidate_interface(&iface));

        // Hyper-V / WSL vEthernet switch on Windows - must be filtered
        iface.name = "{A1B2C3D4-E5F6-7890-1234-567890ABCDEF}".to_string();
        iface.friendly_name = Some("vEthernet (WSL)".to_string());
        iface.description = Some("Hyper-V Virtual Ethernet Adapter".to_string());
        assert!(!is_candidate_interface(&iface));

        // Down interface - must be filtered
        let mut down_iface = netdev::Interface::dummy();
        down_iface.flags = 0; // Not UP
        down_iface.name = "eth0".to_string();
        assert!(!is_candidate_interface(&down_iface));
    }

    #[test]
    fn test_is_candidate_ip() {
        // Valid LAN IP
        assert!(is_candidate_ip(std::net::IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 117
        ))));
        // Valid Tailscale IP
        assert!(is_candidate_ip(std::net::IpAddr::V4(Ipv4Addr::new(
            100, 77, 155, 120
        ))));
        // Valid Public IP
        assert!(is_candidate_ip(std::net::IpAddr::V4(Ipv4Addr::new(
            1, 1, 1, 1
        ))));
        // Valid IPv6 GUA
        assert!(is_candidate_ip(std::net::IpAddr::V6(Ipv6Addr::new(
            0x2a01, 0x4b00, 0xb8e3, 0x4e00, 0, 0, 0, 1
        ))));

        // Loopback - must be rejected
        assert!(!is_candidate_ip(std::net::IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(!is_candidate_ip(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // Unspecified - must be rejected
        assert!(!is_candidate_ip(std::net::IpAddr::V4(
            Ipv4Addr::UNSPECIFIED
        )));
        assert!(!is_candidate_ip(std::net::IpAddr::V6(
            Ipv6Addr::UNSPECIFIED
        )));

        // Link-local - must be rejected
        assert!(!is_candidate_ip(std::net::IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(!is_candidate_ip(std::net::IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0x1ff, 0xfe00, 1
        ))));

        // Broadcast - must be rejected
        assert!(!is_candidate_ip(std::net::IpAddr::V4(Ipv4Addr::BROADCAST)));
    }

    #[test]
    fn test_ip_priority_ordering() {
        let mut iface_lan = netdev::Interface::dummy();
        iface_lan.flags = 1;
        iface_lan.gateway = Some(netdev::net::device::NetworkDevice::new());

        let mut iface_vpn = netdev::Interface::dummy();
        iface_vpn.flags = 1;
        iface_vpn.name = "tailscale0".to_string();

        let lan_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 117));
        let tailscale_ip = std::net::IpAddr::V4(Ipv4Addr::new(100, 77, 155, 120));

        let p_lan = ip_priority(&iface_lan, lan_ip);
        let p_ts = ip_priority(&iface_vpn, tailscale_ip);

        // LAN IP with gateway should score higher than VPN IP without gateway
        assert!(p_lan > p_ts);
    }
}
