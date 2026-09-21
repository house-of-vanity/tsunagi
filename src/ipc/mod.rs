//! The local control interface.
//!
//! This is how a command line tool asks a running agent what it is doing. It
//! is deliberately **an adapter over the public API, not part of the core**:
//! nothing in [`crate::agent`] knows this module exists, so a Windows named
//! pipe or an authenticated loopback socket can be added beside it without
//! touching anything else.
//!
//! It is also a different interface from the peer-to-peer control protocol in
//! [`crate::proto`]. That one is between machines and is authenticated by the
//! network secret; this one is between processes on one machine and is
//! authorised by filesystem permissions.
//!
//! # Access
//!
//! The socket lives inside the agent's state directory, which is owner-only,
//! and the socket itself is created with mode `0600`. There is no
//! unauthenticated listener reachable by other local users, and nothing is
//! exposed on the network.
//!
//! # Wire format
//!
//! Length-prefixed postcard, with the same frame bounds the network protocol
//! uses. The report types here are a stable data transfer format of their own
//! rather than the crate's internal structures, so internal refactors do not
//! silently change what a client sees.

#[cfg(unix)]
pub mod unix;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Largest accepted local control message.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// Where the control socket for a state directory lives.
///
/// A Unix socket path is limited to around 100 bytes, which a state directory
/// nested deeply enough will exceed. So the runtime directory is preferred
/// when the platform provides one — which is also where a runtime socket
/// belongs — with a short name derived from the state directory so that two
/// agents with different state never share a socket. The state directory
/// itself is the fallback.
///
/// Both the agent and the client compute this the same way, so neither has to
/// be told where the other put it.
pub fn control_socket_path(state_dir: &Path) -> PathBuf {
    let digest = Sha256::digest(state_dir.as_os_str().as_encoded_bytes());
    let tag = hex::encode(&digest[..8]);

    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime = PathBuf::from(runtime);
        if runtime.is_absolute() {
            return runtime.join("tsunagi").join(format!("{tag}.sock"));
        }
    }
    state_dir.join("agent.sock")
}

/// What a client asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Request {
    /// Report what the agent is doing.
    Status,
}

/// What the agent answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Response {
    /// A status report.
    Status(Box<StatusReport>),
    /// The request could not be served.
    Error(String),
}

/// Everything the agent is doing, in one snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    /// This device's persistent endpoint id.
    pub endpoint_id: String,
    /// Hostname announced to peers.
    pub hostname: String,
    /// Sockets the endpoint is bound to.
    pub bound_sockets: Vec<String>,
    /// Whether the disposable cache is usable.
    pub cache_healthy: bool,
    /// One entry per configured network.
    pub networks: Vec<NetworkReport>,
}

/// One network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkReport {
    /// Network name.
    pub name: String,
    /// Public network identifier.
    pub network_id: String,
    /// Whether the network is running locally.
    pub active: bool,
    /// Authenticated control plane peers.
    pub peers: Vec<PeerReport>,
    /// Outbound dials that failed.
    pub dial_failures: u64,
    /// Handshakes rejected in either direction.
    pub handshake_failures: u64,
    /// Control messages sent and received.
    pub control_messages: (u64, u64),
    /// The overlay, when an IP plugin is running one.
    pub overlay: Option<OverlayReport>,
}

/// One control plane peer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerReport {
    /// The peer's endpoint id.
    pub endpoint_id: String,
    /// Hostname it announced, if any.
    pub hostname: Option<String>,
    /// `Direct`, `Relay` or `Unknown`, as the transport reports it.
    pub transport: String,
    /// Round-trip time in milliseconds, when a path is selected.
    pub rtt_ms: Option<u64>,
}

/// The WireGuard overlay of one network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayReport {
    /// Packet interface name.
    pub interface: String,
    /// Interface MTU.
    pub mtu: u32,
    /// This agent's overlay address.
    pub address: String,
    /// This agent's IPv4 overlay address, when the overlay is dual stack.
    pub address_v4: Option<String>,
    /// The subnet every member shares.
    pub prefix: String,
    /// Prefix length of that subnet.
    pub prefix_len: u8,
    /// One entry per overlay peer.
    pub peers: Vec<OverlayPeerReport>,
    /// Unicast packets sent to an address no peer owns.
    pub unroutable_packets: u64,
    /// Multicast packets dropped. Expected, not a fault.
    pub multicast_packets: u64,
    /// One destination nobody owned, if there was one.
    pub unroutable_sample: Option<String>,
}

/// One overlay peer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayPeerReport {
    /// The peer's WireGuard public key.
    pub public_key: String,
    /// Its overlay address.
    pub address: String,
    /// Its IPv4 overlay address, when it has one.
    pub address_v4: Option<String>,
    /// Seconds since the last WireGuard handshake.
    ///
    /// `None` means the tunnel has never handshaken and cannot carry traffic.
    pub handshake_secs_ago: Option<u64>,
    /// Packets encrypted and sent to this peer.
    pub tx_packets: u64,
    /// Packets decrypted from this peer.
    pub rx_packets: u64,
    /// Data packets dropped: wrong source address, or too large for the path.
    pub dropped: u64,
    /// WireGuard protocol errors.
    ///
    /// A few are normal while a tunnel is being set up, because both ends
    /// start a handshake at once and one of the two is discarded.
    pub protocol_errors: u64,
    /// What the transport reports about the path in use.
    pub path: String,
}

impl OverlayPeerReport {
    /// Whether the tunnel has handshaken and can carry traffic.
    pub fn is_up(&self) -> bool {
        self.handshake_secs_ago.is_some()
    }
}

impl StatusReport {
    /// Renders the report the way the command line prints it.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "endpoint  {}", self.endpoint_id);
        let _ = writeln!(out, "hostname  {}", self.hostname);
        let _ = writeln!(out, "bound     {}", self.bound_sockets.join(", "));
        if !self.cache_healthy {
            let _ = writeln!(out, "cache     UNAVAILABLE");
        }

        for network in &self.networks {
            let _ = writeln!(
                out,
                "\nnetwork {} ({})  {}",
                network.name,
                network.network_id,
                if network.active { "active" } else { "inactive" }
            );
            if network.peers.is_empty() {
                let _ = writeln!(out, "  no peers");
            }
            for peer in &network.peers {
                let _ = writeln!(
                    out,
                    "  peer {}  {}  {}{}",
                    &peer.endpoint_id[..10.min(peer.endpoint_id.len())],
                    peer.hostname.as_deref().unwrap_or("?"),
                    peer.transport,
                    match peer.rtt_ms {
                        Some(rtt) => format!("  rtt {rtt}ms"),
                        None => String::new(),
                    }
                );
            }
            if network.dial_failures > 0 || network.handshake_failures > 0 {
                let _ = writeln!(
                    out,
                    "  {} dial failure(s), {} handshake failure(s)",
                    network.dial_failures, network.handshake_failures
                );
            }

            if let Some(overlay) = &network.overlay {
                let up = overlay.peers.iter().filter(|peer| peer.is_up()).count();
                let _ = writeln!(
                    out,
                    "  overlay {} {}/{}{} mtu {}  {}/{} tunnel(s) up",
                    overlay.interface,
                    overlay.address,
                    overlay.prefix_len,
                    match &overlay.address_v4 {
                        Some(v4) => format!(" and {v4}"),
                        None => String::new(),
                    },
                    overlay.mtu,
                    up,
                    overlay.peers.len()
                );
                for peer in &overlay.peers {
                    let _ = writeln!(
                        out,
                        "    {}  {}{}  {}  tx {} rx {}{}  {}",
                        &peer.public_key[..8.min(peer.public_key.len())],
                        peer.address,
                        match &peer.address_v4 {
                            Some(v4) => format!(" / {v4}"),
                            None => String::new(),
                        },
                        match peer.handshake_secs_ago {
                            Some(secs) => format!("handshake {secs}s ago"),
                            None => "NOT HANDSHAKEN".to_string(),
                        },
                        peer.tx_packets,
                        peer.rx_packets,
                        if peer.dropped > 0 {
                            format!(" DROPPED {}", peer.dropped)
                        } else {
                            String::new()
                        },
                        peer.path
                    );
                }
                if overlay.unroutable_packets > 0 {
                    let _ = writeln!(
                        out,
                        "    {} packet(s) to addresses nobody owns{}",
                        overlay.unroutable_packets,
                        match &overlay.unroutable_sample {
                            Some(sample) => format!(", most recently {sample}"),
                            None => String::new(),
                        }
                    );
                }
            }
        }
        out
    }
}
