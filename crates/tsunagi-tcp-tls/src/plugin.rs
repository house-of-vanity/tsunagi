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
    let mut ips = Vec::new();
    for iface in netdev::get_interfaces() {
        if iface.is_up() && !iface.is_loopback() {
            for ip in iface.ipv4 {
                let addr = ip.addr();
                if !addr.is_loopback() && !addr.is_unspecified() {
                    ips.push(std::net::IpAddr::V4(addr));
                }
            }
            for ip in iface.ipv6 {
                let addr = ip.addr();
                if !addr.is_loopback() && !addr.is_unspecified() {
                    ips.push(std::net::IpAddr::V6(addr));
                }
            }
        }
    }
    ips.push(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    ips
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
            self.transport
                .set_peer_addr(peer, std::net::SocketAddr::new(*ip, announcement.port));
        }
        self.transport.set_peer_addr(
            peer,
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                announcement.port,
            ),
        );

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
