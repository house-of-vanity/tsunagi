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
///
/// `Debug` is written by hand rather than derived: one of these carries a
/// network secret, and a derived one would put it in any log line that
/// printed a request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Request {
    /// Report what the agent is doing.
    Status,
    /// Answer to a different name from now on.
    ///
    /// Applied by the running agent rather than written behind its back, so
    /// the change takes effect and reaches peers immediately instead of
    /// waiting for a restart.
    SetHostname(String),
    /// Leave a network: give up what was claimed, then forget it.
    ///
    /// Asked of the running agent rather than done behind its back, because
    /// only it can publish the release, and only while its sessions are up.
    /// The network is named by its id, in the text form `status` prints.
    Leave(String),
    /// Stop serving a network, or start serving it again.
    ///
    /// Not leaving: the configuration, the secret and the signed state all
    /// stay, so it can be resumed exactly where it was. The network is
    /// named by its id, in the text form `status` prints.
    SetActive {
        /// Which network.
        network_id: String,
        /// Whether it should be running.
        active: bool,
    },
    /// Turn the local resolver on or off, now and for future starts.
    Dns {
        /// Whether it should be serving.
        enable: bool,
        /// The port to serve on. Keeps the stored one when absent.
        port: Option<u16>,
    },
    /// Join a network, or start one that is configured and not running.
    ///
    /// Asked of the running agent because that is the only way to add a
    /// network to an agent that is already up: the state directory belongs
    /// to one live agent, so a second `tsunagi up` cannot.
    Join {
        /// The network name.
        name: String,
        /// The shared secret in its `tsn1…` text form.
        ///
        /// It travels over a socket only its owner can open, to the agent
        /// that stores it anyway, and never appears in `Debug`.
        secret: String,
    },
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Status => f.write_str("Status"),
            Request::SetHostname(name) => write!(f, "SetHostname({name})"),
            Request::Leave(network) => write!(f, "Leave({network})"),
            Request::SetActive { network_id, active } => {
                write!(f, "SetActive {{ {network_id}, active: {active} }}")
            }
            // The name is not a secret; the secret is.
            Request::Dns { enable, port } => {
                write!(f, "Dns {{ enable: {enable}, port: {port:?} }}")
            }
            Request::Join { name, .. } => write!(f, "Join {{ name: {name}, secret: <redacted> }}"),
        }
    }
}

/// What the agent answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Response {
    /// A status report.
    Status(Box<StatusReport>),
    /// The name the agent now answers to, after reducing it to canonical form.
    Hostname(String),
    /// A network was left.
    Left(LeftReport),
    /// A network was joined, or was already there and is now running.
    Joined(JoinedReport),
    /// A network was stopped or started.
    Active(ActiveReport),
    /// What the local resolver is doing, after being changed or asked.
    ///
    /// `None` means it is not serving at all.
    Dns(Option<DnsReport>),
    /// The request could not be served.
    Error(String),
}

/// What happened when a network was stopped or started.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveReport {
    /// The network's name, for the message the user reads.
    pub name: String,
    /// Whether it is running now.
    pub active: bool,
    /// Whether this request is what changed it.
    ///
    /// Stopping something already stopped is not an error — it is the state
    /// asked for — but it is worth saying which happened.
    pub changed: bool,
}

/// What happened when a network was joined.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinedReport {
    /// The network's name, as given.
    pub name: String,
    /// The derived network id, which is what tells two same-named networks
    /// apart.
    pub network_id: String,
    /// Whether this device was already configured for exactly this network.
    ///
    /// Joining is idempotent, so this is the difference between "added" and
    /// "it was already there and is now running".
    pub already_configured: bool,
    /// Another configured network with the same name but a different
    /// secret, if there is one.
    ///
    /// Almost always a mistyped secret, and the one thing that makes two
    /// sections of a report look like one network.
    pub name_shared_with: Option<String>,
}

/// What happened when a network was left.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftReport {
    /// The network's name, for the message the user reads.
    pub name: String,
    /// Whether a signed release was published.
    ///
    /// `false` when the network was not running: nothing could sign or send
    /// it, so this was a local removal and the others keep the old claim.
    pub announced: bool,
    /// How many connected peers it was handed to.
    ///
    /// They pass it on, so this is not the number of members that will
    /// learn of it — but zero means none of them will.
    pub peers_told: u32,
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
    /// The local DNS service, when one was asked for.
    pub dns: Option<DnsReport>,
}

/// The local DNS service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsReport {
    /// The zones it answers for: one per network, named after it.
    pub zones: Vec<String>,
    /// Every address it is listening on, one per family where it could.
    ///
    /// Empty means it answers nowhere, and `bind_error` says why.
    pub listening: Vec<String>,
    /// Why it could not bind, if it did not.
    pub bind_error: Option<String>,
    /// Why the system resolver was not told, if it was not.
    ///
    /// `None` means it was told. The server answers either way, so this is a
    /// degraded overlay rather than a broken one.
    pub publish_error: Option<String>,
    /// What to do about that, when there is something.
    pub publish_remedy: Option<String>,
    /// Anything worth saying about those names, one line each.
    pub zone_warnings: Vec<String>,
    /// How many names it answers for.
    pub names: u32,
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
    /// Members the signed state knows about, connected or not.
    ///
    /// This is what makes "offline" sayable. Without it a member that is away
    /// is indistinguishable from one that never existed, and the only thing
    /// left to report is a dial-failure counter — which describes the symptom
    /// and not the cause.
    pub members: Vec<MemberReport>,
    /// Outbound dials that failed.
    pub dial_failures: u64,
    /// Handshakes rejected in either direction.
    pub handshake_failures: u64,
    /// Control messages sent and received.
    pub control_messages: (u64, u64),
    /// The overlay range this network uses, once it has one.
    pub range: Option<String>,
    /// The range it could not have, because another network on this agent
    /// already holds it.
    pub range_conflict: Option<String>,
    /// The overlay, when a protocol is running one.
    pub overlay: Option<OverlayReport>,
}

/// One member of the network, from signed state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberReport {
    /// The member's device identity.
    pub endpoint_id: String,
    /// The IPv4 overlay address it claimed and signed for.
    pub overlay_address_v4: Option<String>,
    /// Consecutive failed dial attempts, when this agent is trying to reach it.
    pub failed_dials: u32,
}

/// One control plane peer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerReport {
    /// The peer's endpoint id.
    pub endpoint_id: String,
    /// Hostname it announced, if any.
    pub hostname: Option<String>,
    /// How the connection reaches the peer: `direct`, `relay` or `unknown`,
    /// as the transport reports it.
    pub transport: String,
    /// Round-trip time in milliseconds, when a path is selected.
    pub rtt_ms: Option<u64>,
}

/// The WireGuard overlay of one network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayReport {
    /// Packet interface name.
    pub interface: String,
    /// Whether that interface exists on the host.
    ///
    /// `false` under `--no-tun`: tunnels run and packets move between
    /// agents, but the operating system has no interface, no address and no
    /// route, so nothing local reaches the overlay.
    pub on_host: bool,
    /// Interface MTU.
    pub mtu: u32,
    /// This agent's overlay address, once the network has agreed one.
    pub address: Option<String>,
    /// Prefix length of the overlay range every member shares.
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
    /// The peer's control plane identity, so a tunnel can be matched to the
    /// session and the member it belongs to.
    pub endpoint_id: String,
    /// The peer's WireGuard public key.
    pub public_key: String,
    /// The overlay address the network agreed it holds.
    pub address: Option<String>,
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
