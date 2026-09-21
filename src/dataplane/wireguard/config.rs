//! The desired local WireGuard configuration, and how it is rendered.
//!
//! Each agent builds its own configuration from the agreed set of
//! participants. For a full mesh of `N` members that is `N - 1` peers locally;
//! nobody hands out a configuration to anybody else.
//!
//! Nothing in here is free-form text taken from the network. Peer keys,
//! endpoints, allowed prefixes and keepalives are typed values that this
//! module re-serialises itself, so a hostile announcement cannot inject a
//! configuration directive or a command argument.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::dataplane::PluginError;
use crate::identity::NetworkId;

use super::keys::{WgPublicKey, WgSecretKey};
use super::overlay::{
    OVERLAY_HOST_PREFIX_LEN, OVERLAY_PREFIX_LEN, overlay_address, overlay_prefix,
};

/// Longest interface name Linux accepts, excluding the terminating NUL.
pub const MAX_INTERFACE_NAME_LEN: usize = 15;

/// Default prefix for interface names this plugin creates.
pub const DEFAULT_INTERFACE_PREFIX: &str = "tsun";

/// An address with a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    /// The address.
    pub addr: IpAddr,
    /// The prefix length in bits.
    pub prefix_len: u8,
}

impl Cidr {
    /// Builds a CIDR, rejecting an impossible prefix length.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, PluginError> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(PluginError::Other(format!(
                "prefix length /{prefix_len} is impossible for {addr}"
            )));
        }
        Ok(Self { addr, prefix_len })
    }

    /// A single host address.
    pub fn host(addr: Ipv6Addr) -> Self {
        Self {
            addr: IpAddr::V6(addr),
            prefix_len: OVERLAY_HOST_PREFIX_LEN,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// One remote participant, as this agent will configure it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// The peer's WireGuard public key.
    pub public_key: WgPublicKey,
    /// Where to send the first packet, when the peer advertised somewhere.
    pub endpoint: Option<SocketAddr>,
    /// Prefixes accepted from and routed to this peer.
    ///
    /// Always derived locally from the peer's key. Never taken from what the
    /// peer claims.
    pub allowed_ips: Vec<Cidr>,
    /// Keepalive interval, needed to hold a NAT mapping open.
    pub persistent_keepalive: Option<u16>,
}

/// The complete local configuration for one network's overlay interface.
#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    /// Interface name this plugin owns.
    pub name: String,
    /// This agent's private key for this network.
    pub private_key: WgSecretKey,
    /// UDP port the interface listens on.
    pub listen_port: u16,
    /// Addresses assigned to the interface.
    pub addresses: Vec<Cidr>,
    /// Interface MTU, when one is configured.
    pub mtu: Option<u32>,
    /// Remote participants.
    pub peers: Vec<PeerConfig>,
}

/// Observable state of a configured interface, without any private key.
///
/// This is what desired and actual are compared on, so reconciliation never
/// needs to move a private key around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceState {
    /// Interface name.
    pub name: String,
    /// Public key currently configured on the interface.
    pub public_key: WgPublicKey,
    /// Port currently listened on.
    pub listen_port: u16,
    /// Addresses currently assigned.
    pub addresses: Vec<Cidr>,
    /// Peers currently configured, sorted by public key.
    pub peers: Vec<PeerState>,
}

/// Observable state of one configured peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerState {
    /// The peer's public key.
    pub public_key: WgPublicKey,
    /// Endpoint currently configured.
    pub endpoint: Option<SocketAddr>,
    /// Allowed prefixes currently configured, sorted.
    pub allowed_ips: Vec<Cidr>,
    /// Keepalive currently configured.
    pub persistent_keepalive: Option<u16>,
}

impl PeerState {
    /// Puts the state in its canonical, comparable form.
    pub fn normalised(mut self) -> Self {
        self.allowed_ips.sort();
        self.allowed_ips.dedup();
        // WireGuard reports a disabled keepalive as zero.
        if self.persistent_keepalive == Some(0) {
            self.persistent_keepalive = None;
        }
        self
    }
}

impl InterfaceState {
    /// Puts the state in its canonical, comparable form.
    pub fn normalised(mut self) -> Self {
        self.addresses.sort();
        self.addresses.dedup();
        self.peers = self.peers.into_iter().map(PeerState::normalised).collect();
        self.peers.sort_by_key(|peer| peer.public_key);
        self
    }
}

impl InterfaceConfig {
    /// The state this configuration is expected to produce.
    pub fn to_state(&self) -> InterfaceState {
        InterfaceState {
            name: self.name.clone(),
            public_key: self.private_key.public(),
            listen_port: self.listen_port,
            addresses: self.addresses.clone(),
            peers: self
                .peers
                .iter()
                .map(|peer| PeerState {
                    public_key: peer.public_key,
                    endpoint: peer.endpoint,
                    allowed_ips: peer.allowed_ips.clone(),
                    persistent_keepalive: peer.persistent_keepalive,
                })
                .collect(),
        }
        .normalised()
    }

    /// Renders the configuration in the format `wg setconf` and `wg syncconf`
    /// read.
    ///
    /// Only WireGuard's own directives appear here. Addresses and MTU are not
    /// part of this format — they belong to the network interface and are
    /// applied separately.
    ///
    /// The result contains the private key and is zeroized on drop.
    pub fn render(&self) -> Zeroizing<String> {
        let mut out = String::with_capacity(256 + self.peers.len() * 192);
        out.push_str("[Interface]\n");
        let _ = writeln!(out, "PrivateKey = {}", self.private_key.encode().as_str());
        let _ = writeln!(out, "ListenPort = {}", self.listen_port);

        let mut peers = self.peers.clone();
        peers.sort_by_key(|peer| peer.public_key);
        for peer in &peers {
            out.push_str("\n[Peer]\n");
            let _ = writeln!(out, "PublicKey = {}", peer.public_key.encode());
            let mut allowed = peer.allowed_ips.clone();
            allowed.sort();
            let rendered: Vec<String> = allowed.iter().map(Cidr::to_string).collect();
            let _ = writeln!(out, "AllowedIPs = {}", rendered.join(", "));
            if let Some(endpoint) = peer.endpoint {
                let _ = writeln!(out, "Endpoint = {endpoint}");
            }
            if let Some(keepalive) = peer.persistent_keepalive {
                let _ = writeln!(out, "PersistentKeepalive = {keepalive}");
            }
        }
        Zeroizing::new(out)
    }
}

/// Derives this plugin's interface name for a network.
///
/// The name is stable across restarts and short enough for the platform. Two
/// agents on the same host in the same network must be given different
/// prefixes, or they would derive the same name.
pub fn interface_name(prefix: &str, network: NetworkId) -> Result<String, PluginError> {
    if prefix.is_empty() {
        return Err(PluginError::Other(
            "interface prefix must not be empty".into(),
        ));
    }
    if !prefix
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(PluginError::Other(
            "interface prefix must be lowercase ASCII letters and digits".into(),
        ));
    }
    if prefix.len() >= MAX_INTERFACE_NAME_LEN {
        return Err(PluginError::Other(format!(
            "interface prefix must be shorter than {MAX_INTERFACE_NAME_LEN} characters"
        )));
    }

    let mut suffix = data_encoding::BASE32_NOPAD.encode(network.as_bytes());
    suffix.make_ascii_lowercase();
    let room = MAX_INTERFACE_NAME_LEN - prefix.len();
    suffix.truncate(room);
    Ok(format!("{prefix}{suffix}"))
}

/// How the plugin chooses its UDP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortPolicy {
    /// Always this port. Only usable with a single network.
    Fixed(u16),
    /// A port derived from the network id inside `base .. base + span`.
    ///
    /// Stable across restarts, so a peer's cached endpoint keeps working, and
    /// different networks on one host land on different ports.
    Derived {
        /// First port of the range.
        base: u16,
        /// How many ports the range covers.
        span: u16,
    },
}

impl Default for PortPolicy {
    fn default() -> Self {
        Self::Derived {
            base: 51820,
            span: 64,
        }
    }
}

impl PortPolicy {
    /// The port to listen on for `network`.
    pub fn port_for(&self, network: NetworkId) -> Result<u16, PluginError> {
        match *self {
            PortPolicy::Fixed(port) => {
                if port == 0 {
                    return Err(PluginError::Other(
                        "a fixed WireGuard port must not be zero".into(),
                    ));
                }
                Ok(port)
            }
            PortPolicy::Derived { base, span } => {
                if base == 0 || span == 0 {
                    return Err(PluginError::Other(
                        "a derived WireGuard port range must not be empty or start at zero".into(),
                    ));
                }
                let room = u16::MAX - base;
                if span - 1 > room {
                    return Err(PluginError::Other(
                        "the derived WireGuard port range runs past port 65535".into(),
                    ));
                }
                let hash = Sha256::digest(network.as_bytes());
                let offset = u16::from_be_bytes([hash[0], hash[1]]) % span;
                Ok(base + offset)
            }
        }
    }
}

/// Everything about the local side of one network's interface.
#[derive(Debug, Clone)]
pub struct InterfaceParams {
    /// The network the interface serves.
    pub network: NetworkId,
    /// Interface name, derived by [`interface_name`].
    pub name: String,
    /// This agent's private key for this network.
    pub private_key: WgSecretKey,
    /// Port to listen on.
    pub listen_port: u16,
    /// Interface MTU.
    pub mtu: Option<u32>,
    /// Keepalive applied to every peer.
    pub keepalive: Option<u16>,
}

/// Builds this agent's interface configuration for one network.
///
/// `peers` is the set of participants the control plane agreed on; `endpoints`
/// supplies whatever reachability each of them advertised.
pub fn build_interface(
    params: InterfaceParams,
    peers: impl IntoIterator<Item = WgPublicKey>,
    endpoints: impl Fn(&WgPublicKey) -> Option<SocketAddr>,
) -> InterfaceConfig {
    let InterfaceParams {
        network,
        name,
        private_key,
        listen_port,
        mtu,
        keepalive,
    } = params;
    let local = overlay_address(network, &private_key.public());

    let mut peer_configs: Vec<PeerConfig> = peers
        .into_iter()
        .filter(|key| !key.is_zero() && *key != private_key.public())
        .map(|key| PeerConfig {
            endpoint: endpoints(&key),
            // Derived locally. This is the whole reason a hostile member
            // cannot route another member's traffic to itself.
            allowed_ips: vec![Cidr::host(overlay_address(network, &key))],
            public_key: key,
            persistent_keepalive: keepalive,
        })
        .collect();
    peer_configs.sort_by_key(|peer| peer.public_key);
    peer_configs.dedup_by(|a, b| a.public_key == b.public_key);

    InterfaceConfig {
        name,
        private_key,
        listen_port,
        addresses: vec![
            Cidr::host(local),
            // The shared /64 gives the interface a route for the overlay.
            Cidr {
                addr: IpAddr::V6(overlay_prefix(network)),
                prefix_len: OVERLAY_PREFIX_LEN,
            },
        ],
        mtu,
        peers: peer_configs,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![5u8; 32]).unwrap(),
        )
        .network_id()
    }

    #[test]
    fn a_full_mesh_of_n_members_yields_n_minus_one_peers() {
        let id = network("mesh");
        let me = WgSecretKey::generate();
        let others: Vec<WgPublicKey> = (0..3).map(|_| WgSecretKey::generate().public()).collect();

        let config = build_interface(
            InterfaceParams {
                network: id,
                name: "tsun0".into(),
                private_key: me.clone(),
                listen_port: 51820,
                mtu: None,
                keepalive: Some(25),
            },
            others.clone().into_iter().chain([me.public()]),
            |_| None,
        );

        assert_eq!(config.peers.len(), 3, "our own key is never a peer");
        for peer in &config.peers {
            assert_eq!(peer.allowed_ips.len(), 1);
            assert_eq!(
                peer.allowed_ips[0],
                Cidr::host(overlay_address(id, &peer.public_key))
            );
            assert_eq!(peer.persistent_keepalive, Some(25));
        }
        assert!(
            config
                .addresses
                .contains(&Cidr::host(overlay_address(id, &me.public())))
        );
    }

    #[test]
    fn duplicate_and_zero_peer_keys_are_dropped() {
        let id = network("dupes");
        let me = WgSecretKey::generate();
        let other = WgSecretKey::generate().public();

        let config = build_interface(
            InterfaceParams {
                network: id,
                name: "tsun0".into(),
                private_key: me,
                listen_port: 51820,
                mtu: None,
                keepalive: None,
            },
            [other, other, WgPublicKey::from_bytes([0u8; 32])],
            |_| None,
        );
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].public_key, other);
    }

    #[test]
    fn the_rendered_config_is_the_wg_setconf_format() {
        let id = network("render");
        let me = WgSecretKey::generate();
        let peer = WgSecretKey::generate().public();
        let config = build_interface(
            InterfaceParams {
                network: id,
                name: "tsun0".into(),
                private_key: me.clone(),
                listen_port: 51820,
                mtu: Some(1380),
                keepalive: Some(25),
            },
            [peer],
            |_| Some("10.0.0.7:51820".parse().unwrap()),
        );

        let rendered = config.render();
        let text = rendered.as_str();
        assert!(text.starts_with("[Interface]\n"));
        assert!(text.contains(&format!("PrivateKey = {}", me.encode().as_str())));
        assert!(text.contains("ListenPort = 51820"));
        assert!(text.contains(&format!("PublicKey = {}", peer.encode())));
        assert!(text.contains("Endpoint = 10.0.0.7:51820"));
        assert!(text.contains("PersistentKeepalive = 25"));
        assert!(text.contains(&format!(
            "AllowedIPs = {}",
            Cidr::host(overlay_address(id, &peer))
        )));
        // Address and MTU belong to the interface, not to wg's own format.
        assert!(!text.contains("Address"));
        assert!(!text.contains("MTU"));
    }

    #[test]
    fn rendering_is_deterministic_regardless_of_peer_order() {
        let id = network("stable");
        let me = WgSecretKey::generate();
        let keys: Vec<WgPublicKey> = (0..5).map(|_| WgSecretKey::generate().public()).collect();

        let forward = build_interface(
            InterfaceParams {
                network: id,
                name: "tsun0".into(),
                private_key: me.clone(),
                listen_port: 51820,
                mtu: None,
                keepalive: None,
            },
            keys.clone(),
            |_| None,
        );
        let reversed = build_interface(
            InterfaceParams {
                network: id,
                name: "tsun0".into(),
                private_key: me,
                listen_port: 51820,
                mtu: None,
                keepalive: None,
            },
            keys.into_iter().rev().collect::<Vec<_>>(),
            |_| None,
        );
        assert_eq!(forward.render().as_str(), reversed.render().as_str());
        assert_eq!(forward.to_state(), reversed.to_state());
    }

    #[test]
    fn interface_names_fit_the_platform_limit_and_are_stable() {
        let id = network("naming");
        let name = interface_name(DEFAULT_INTERFACE_PREFIX, id).unwrap();
        assert_eq!(name.len(), MAX_INTERFACE_NAME_LEN);
        assert!(name.starts_with(DEFAULT_INTERFACE_PREFIX));
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(name, interface_name(DEFAULT_INTERFACE_PREFIX, id).unwrap());
        assert_ne!(
            name,
            interface_name(DEFAULT_INTERFACE_PREFIX, network("other")).unwrap()
        );
        assert_ne!(name, interface_name("wg", id).unwrap());

        assert!(interface_name("", id).is_err());
        assert!(interface_name("has space", id).is_err());
        assert!(interface_name("UPPER", id).is_err());
        assert!(interface_name(&"a".repeat(MAX_INTERFACE_NAME_LEN), id).is_err());
    }

    #[test]
    fn derived_ports_are_stable_and_inside_the_range() {
        let policy = PortPolicy::default();
        let id = network("ports");
        let port = policy.port_for(id).unwrap();
        assert_eq!(port, policy.port_for(id).unwrap());
        assert!(
            (51820..51884).contains(&port),
            "port {port} outside the range"
        );

        assert_eq!(PortPolicy::Fixed(1234).port_for(id).unwrap(), 1234);
        assert!(PortPolicy::Fixed(0).port_for(id).is_err());
        assert!(
            PortPolicy::Derived {
                base: 65500,
                span: 1000
            }
            .port_for(id)
            .is_err()
        );
    }

    #[test]
    fn state_comparison_ignores_ordering_and_a_zero_keepalive() {
        let peer_a = WgSecretKey::generate().public();
        let peer_b = WgSecretKey::generate().public();
        let make = |order: [WgPublicKey; 2], keepalive: Option<u16>| {
            InterfaceState {
                name: "tsun0".into(),
                public_key: peer_a,
                listen_port: 51820,
                addresses: vec![
                    Cidr::host("fd00::2".parse().unwrap()),
                    Cidr::host("fd00::1".parse().unwrap()),
                ],
                peers: order
                    .into_iter()
                    .map(|public_key| PeerState {
                        public_key,
                        endpoint: None,
                        allowed_ips: Vec::new(),
                        persistent_keepalive: keepalive,
                    })
                    .collect(),
            }
            .normalised()
        };
        assert_eq!(
            make([peer_a, peer_b], None),
            make([peer_b, peer_a], Some(0))
        );
    }
}
