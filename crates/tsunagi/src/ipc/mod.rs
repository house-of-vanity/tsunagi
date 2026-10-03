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
#[cfg(windows)]
pub mod windows;

// The one transport this build serves on. The two adapters expose the same
// items, so the rest of the crate — and the client wrappers below — name the
// transport through this alias and never a platform directly.
#[cfg(unix)]
use unix as transport;
#[cfg(windows)]
use windows as transport;

/// Serves the local control interface on this platform's transport.
///
/// A Unix socket on Unix, a named pipe on Windows; the same API either way.
#[cfg(any(unix, windows))]
pub use transport::ControlSocket;

/// Who may open the local control socket.
///
/// The default is owner-only. A system service shares its socket with a GUI or
/// CLI running as another user by granting a group; the agent sets that on the
/// socket when it binds it, so the access is correct from creation rather than
/// patched afterwards.
#[derive(Debug, Clone)]
pub enum ControlSocketAccess {
    /// Owner only — mode `0600`. The per-user agent's default.
    Private,
    /// The owner and members of this group — the socket's group is set to this
    /// gid and the mode to `0660`. The caller resolves a group name to its gid.
    Group(u32),
}

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::BoxFuture;
use crate::error::{Error, Result};

/// Largest accepted local control message.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// A string the control protocol must carry but that must never appear in a
/// log: it serialises transparently (the text crosses the socket intact) but
/// its `Debug` is redacted. Used for a network secret handed back to a local
/// client that asked to copy it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedText(String);

impl RedactedText {
    /// Wraps a string.
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// Unwraps to the plain string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for RedactedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

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

/// Where the default system control socket lives on this platform.
///
/// On Windows, the system-wide `%ProgramData%\tsunagi\agent.sock` is used so that
/// any local user, tray application, or CLI tool can manage the running agent
/// without needing to know which user account or service started it.
/// On macOS the agent runs as a root LaunchDaemon, so a fixed system path under
/// `/var/run` is used for the same reason, and it stays short enough for the
/// Unix socket path limit. On other Unix it derives from the default per-user
/// state directory.
pub fn default_control_socket_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(program_data) = std::env::var_os("ProgramData") {
            let pd = PathBuf::from(program_data);
            if pd.is_absolute() {
                return pd.join("tsunagi").join("agent.sock");
            }
        }
        PathBuf::from(r"C:\ProgramData\tsunagi\agent.sock")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/run/tsunagi/agent.sock")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // Prefer a running system service's socket when it is present, so a
        // GUI or CLI reaches the packaged daemon with no configuration; fall
        // back to the per-user location otherwise.
        let system = PathBuf::from("/run/tsunagi/agent.sock");
        if system.exists() {
            return system;
        }
        if let Ok(paths) = crate::config::StoragePaths::user_default() {
            control_socket_path(&paths.state_dir)
        } else {
            system
        }
    }
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
    /// Set local broadcast participation in one configured network.
    SetBroadcast {
        /// Public network identifier.
        network_id: String,
        /// Whether to originate and accept broadcasts.
        enabled: bool,
    },
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
        /// Explicit choice, or preserve the saved setting.
        #[serde(default)]
        broadcast: Option<bool>,
    },
    /// Ask for a configured network's shared secret, in its `tsn1…` text form,
    /// so a local GUI or script can copy it to re-share. The reply travels only
    /// over the owner/group socket and the secret is never logged.
    Secret {
        /// Which network, by the id text `status` prints.
        network_id: String,
    },
    /// Offer this agent as an exit node in one network, or stop. Off unless
    /// asked.
    SetExitOffer {
        /// Public network identifier.
        network_id: String,
        /// Whether members may send their internet traffic through this agent.
        enabled: bool,
    },
    /// Send all this device's internet traffic through a member of one
    /// network, or back the ordinary way.
    SetExitNode {
        /// Public network identifier.
        network_id: String,
        /// The member's endpoint id, or `None` to stop using an exit node.
        peer: Option<String>,
    },
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Status => f.write_str("Status"),
            Request::SetBroadcast {
                network_id,
                enabled,
            } => write!(f, "SetBroadcast {{ {network_id}, enabled: {enabled} }}"),
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
            Request::Secret { network_id } => write!(f, "Secret {{ {network_id} }}"),
            Request::SetExitOffer {
                network_id,
                enabled,
            } => write!(f, "SetExitOffer {{ {network_id}, enabled: {enabled} }}"),
            Request::SetExitNode { network_id, peer } => {
                write!(f, "SetExitNode {{ {network_id}, peer: {peer:?} }}")
            }
        }
    }
}

/// What the agent answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Response {
    /// A status report.
    Status(Box<StatusReport>),
    /// Accepted local broadcast participation.
    Broadcast(bool),
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
    /// A network's shared secret, redacted in `Debug`.
    Secret(RedactedText),
    /// Whether this agent now offers itself as an exit node.
    ExitOffer(bool),
    /// The member this device now sends its internet traffic through.
    ExitNode(Option<String>),
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
    /// The state directory the agent is actually using.
    ///
    /// A client that was not told one would look in its own default, which is
    /// not the agent's when the agent runs as a service under another user.
    pub state_dir: String,
    /// The cache directory the agent is actually using.
    pub cache_dir: String,
    /// The executable the agent runs, which is what needs the capability.
    pub program: String,
    /// Whether the agent itself can manage the overlay interface.
    ///
    /// It is the agent that creates the interface, so the client's own
    /// capabilities say nothing about it.
    pub privilege: PrivilegeReport,
    /// The version of the agent's software.
    pub version: String,
    /// The data plane protocols it has, each as `name vN` (wire version).
    pub protocols: Vec<String>,
}

/// What the agent found when it checked whether it may manage an interface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeReport {
    /// Not checked.
    #[default]
    Unknown,
    /// It can.
    Available,
    /// It cannot, with what was found.
    Missing(String),
    /// This platform has no provisioner yet.
    Unsupported,
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
    /// Whether this agent participates in LAN broadcasts in this network.
    #[serde(default)]
    pub broadcast: bool,
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
    /// Unverified candidates this network currently knows of.
    ///
    /// Not peers: somewhere to try. Zero of them, with nobody connected,
    /// is the difference between "nobody has joined yet" and "this agent
    /// has no way to reach anybody" — which look identical in a report
    /// that counts only members.
    pub candidates: u32,
    /// Datagrams this agent passed on between two other peers.
    pub relay_forwarded: u64,
    /// Datagrams this agent sent to a peer through somebody else.
    pub relay_sent_via: u64,
    /// Datagrams that reached this agent through somebody else.
    pub relay_received_via: u64,
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
    /// Exit-node settings: whether this agent offers one, and whether it
    /// uses one.
    pub exit: ExitReport,
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
    /// The last hostname this agent saw it announce, kept while it is away.
    pub hostname: Option<String>,
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
    /// The peer offers itself as an exit node in this network.
    pub exit_node: bool,
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
    /// The broadcast route and firewall allowance on this host, when the
    /// agent installed them. `None` means none are installed.
    pub broadcast_rules: Option<HostRulesReport>,
}

/// How one set of exit-node host rules went.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSetReport {
    /// Whether every step took.
    pub ok: bool,
    /// One line: what is in place, or what is missing and why.
    pub detail: String,
}

/// One network's exit-node settings and what they are doing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitReport {
    /// This agent offers itself as an exit node in this network.
    pub offering: bool,
    /// Masquerading and forwarding rules for members' traffic, when offering.
    pub offer_rules: Option<RuleSetReport>,
    /// Whether the kernel forwards packets for the overlay interface.
    /// `Some(false)` means the rules are in place and nothing passes until it
    /// is turned on. `None` when unknown.
    pub forwarding: Option<bool>,
    /// The member this device sends its internet traffic through, as an
    /// endpoint id.
    pub via: Option<String>,
    /// Whether that member is connected and still offering to be one.
    pub via_online: bool,
    /// The routes that send this device's traffic through it.
    pub client_rules: Option<RuleSetReport>,
}

/// What the agent installed on the host so LAN broadcast reaches the overlay.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRulesReport {
    /// Whether both the route and the firewall allowance are in place.
    pub ok: bool,
    /// One line: `ok (route + firewall)`, or what is missing and why.
    pub detail: String,
    /// The overlay address the `255.255.255.255` route is bound to. With
    /// several networks on one interface only one address can be its source.
    pub source: String,
}

/// One overlay peer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayPeerReport {
    /// The peer's control plane identity, so a tunnel can be matched to the
    /// session and the member it belongs to.
    pub endpoint_id: String,
    /// Protocol carrying overlay traffic for this peer (e.g. "tcp-tls", "wg-quic").
    pub protocol: String,
    /// The peer's WireGuard public key (if applicable).
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
    /// Plaintext bytes encrypted and sent to this peer.
    pub tx_bytes: u64,
    /// Plaintext bytes decrypted from this peer.
    pub rx_bytes: u64,
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

// ---------------------------------------------------------------------------
// The transport-agnostic half of the local control interface.
//
// Everything below is the same on every platform: the request/response
// framing, the dispatch of a request onto a [`ReportSource`], and the client
// wrappers that ask one question and read one answer. Only the listener and
// the stream differ, and those live in the per-platform `unix` and `windows`
// adapters. Each adapter drives the shared [`serve_connection`] for its
// accepted streams and offers a `connect`/`is_serving` for the client side,
// so the logic here is written once.
// ---------------------------------------------------------------------------

/// Builds the report that answers a status request, and applies the changes a
/// client asks for.
///
/// Supplied by the caller, because only the caller knows which plugins are
/// running and what they can report or change. That is what keeps this module
/// free of any knowledge of them.
pub trait ReportSource: Send + Sync + 'static {
    /// Produces a fresh report.
    fn report(&self) -> BoxFuture<'_, StatusReport>;

    /// Changes the name the agent answers to, returning the accepted form.
    ///
    /// Defaulted to a refusal so that a source which only reports — the
    /// closure impl below, and every test that uses it — stays valid and
    /// says plainly that it cannot do this, rather than appearing to.
    fn set_hostname(
        &self,
        _hostname: String,
    ) -> BoxFuture<'_, std::result::Result<String, String>> {
        Box::pin(async move { Err("this agent cannot change its hostname".to_string()) })
    }

    /// Leaves a network, publishing a release first.
    ///
    /// Defaulted to a refusal for the same reason as the above: a source
    /// that only reports says so plainly rather than appearing to do it.
    fn leave(&self, _network_id: String) -> BoxFuture<'_, std::result::Result<LeftReport, String>> {
        Box::pin(async move { Err("this agent cannot leave a network".to_string()) })
    }

    /// Joins a network, or starts one that is configured and not running.
    ///
    /// Defaulted to a refusal, like the others: a source that only reports
    /// says so rather than appearing to have done it.
    fn join(
        &self,
        _name: String,
        _secret: String,
        _broadcast: Option<bool>,
    ) -> BoxFuture<'_, std::result::Result<JoinedReport, String>> {
        Box::pin(async move { Err("this agent cannot join a network".to_string()) })
    }

    /// Persists and applies local broadcast participation.
    fn set_broadcast(
        &self,
        _network_id: String,
        _enabled: bool,
    ) -> BoxFuture<'_, std::result::Result<bool, String>> {
        Box::pin(async move { Err("this agent cannot change broadcast participation".into()) })
    }

    /// Stops serving a network, or starts serving it again.
    ///
    /// Defaulted to a refusal, like the others.
    fn set_active(
        &self,
        _network_id: String,
        _active: bool,
    ) -> BoxFuture<'_, std::result::Result<ActiveReport, String>> {
        Box::pin(async move { Err("this agent cannot stop or start a network".to_string()) })
    }

    /// Turns the local resolver on or off while the agent runs.
    ///
    /// Defaulted to a refusal, like the others.
    fn set_dns(
        &self,
        _enable: bool,
        _port: Option<u16>,
    ) -> BoxFuture<'_, std::result::Result<Option<DnsReport>, String>> {
        Box::pin(async move { Err("this agent cannot serve DNS".to_string()) })
    }

    /// Returns a configured network's shared secret in its `tsn1…` text form.
    ///
    /// Defaulted to a refusal, like the others. An implementor reads it from
    /// local state; it must never be logged.
    fn network_secret(
        &self,
        _network_id: String,
    ) -> BoxFuture<'_, std::result::Result<String, String>> {
        Box::pin(async move { Err("this agent cannot read secrets".to_string()) })
    }

    /// Offers this agent as an exit node in a network, or stops.
    ///
    /// Defaulted to a refusal, like the others.
    fn set_exit_offer(
        &self,
        _network_id: String,
        _enabled: bool,
    ) -> BoxFuture<'_, std::result::Result<bool, String>> {
        Box::pin(async move { Err("this agent cannot be an exit node".to_string()) })
    }

    /// Sends this device's internet traffic through a member, or stops.
    ///
    /// Defaulted to a refusal, like the others.
    fn set_exit_node(
        &self,
        _network_id: String,
        _peer: Option<String>,
    ) -> BoxFuture<'_, std::result::Result<Option<String>, String>> {
        Box::pin(async move { Err("this agent cannot use an exit node".to_string()) })
    }
}

impl<F> ReportSource for F
where
    F: Fn() -> BoxFuture<'static, StatusReport> + Send + Sync + 'static,
{
    fn report(&self) -> BoxFuture<'_, StatusReport> {
        (self)()
    }
}

/// How long either end waits for the other.
///
/// A local answer comes from memory, so anything this slow means the agent is
/// wedged rather than busy. Saying so beats waiting: unbounded, one wedged
/// runtime leaves `tsunagi status` hanging with nothing on screen and no way
/// out but Ctrl-C.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Marks the wire format of the local control interface.
///
/// `b"TSN"` followed by the version, so a mismatch is recognised as one
/// instead of being read as a length. The encoding is postcard, which is not
/// self-describing: adding a field to a report changes how the bytes parse,
/// and without this a client one build ahead of its agent reports something
/// like "Found an Option discriminant that wasn't 0 or 1" — which says
/// nothing about the actual problem, that the two are different builds.
///
/// Bump it whenever [`Request`], [`Response`] or anything they contain
/// changes shape.
pub const CONTROL_PROTOCOL: u32 = u32::from_be_bytes([b'T', b'S', b'N', 17]);

/// Reads one request off an accepted stream, answers it, writes the response.
///
/// The per-platform adapters call this for every connection they accept, so
/// the request handling is identical on every transport.
pub(crate) async fn serve_connection<S>(mut stream: S, source: Arc<dyn ReportSource>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Bounded, so a connection that sends nothing cannot hold a task open.
    // Only the wait for the request: building the report afterwards takes as
    // long as it takes, and cutting it off would answer a live client with a
    // closed socket.
    let request: Request =
        match tokio::time::timeout(EXCHANGE_TIMEOUT, read_message(&mut stream)).await {
            Ok(request) => request?,
            Err(_) => {
                return Err(Error::Timeout {
                    what: "a local control connection".to_string(),
                });
            }
        };
    let response = match request {
        Request::Status => Response::Status(Box::new(source.report().await)),
        Request::SetBroadcast {
            network_id,
            enabled,
        } => match source.set_broadcast(network_id, enabled).await {
            Ok(enabled) => Response::Broadcast(enabled),
            Err(error) => Response::Error(error),
        },
        Request::SetHostname(hostname) => match source.set_hostname(hostname).await {
            Ok(accepted) => Response::Hostname(accepted),
            Err(reason) => Response::Error(reason),
        },
        Request::Leave(network_id) => match source.leave(network_id).await {
            Ok(report) => Response::Left(report),
            Err(reason) => Response::Error(reason),
        },
        Request::Join {
            name,
            secret,
            broadcast,
        } => match source.join(name, secret, broadcast).await {
            Ok(report) => Response::Joined(report),
            Err(reason) => Response::Error(reason),
        },
        Request::SetActive { network_id, active } => {
            match source.set_active(network_id, active).await {
                Ok(report) => Response::Active(report),
                Err(reason) => Response::Error(reason),
            }
        }
        Request::Dns { enable, port } => match source.set_dns(enable, port).await {
            Ok(report) => Response::Dns(report),
            Err(reason) => Response::Error(reason),
        },
        Request::Secret { network_id } => match source.network_secret(network_id).await {
            Ok(secret) => Response::Secret(RedactedText::new(secret)),
            Err(reason) => Response::Error(reason),
        },
        Request::SetExitOffer {
            network_id,
            enabled,
        } => match source.set_exit_offer(network_id, enabled).await {
            Ok(enabled) => Response::ExitOffer(enabled),
            Err(reason) => Response::Error(reason),
        },
        Request::SetExitNode { network_id, peer } => {
            match source.set_exit_node(network_id, peer).await {
                Ok(peer) => Response::ExitNode(peer),
                Err(reason) => Response::Error(reason),
            }
        }
    };
    write_message(&mut stream, &response).await
}

/// Connects, sends one request and reads the answer, all within `within`.
///
/// The bound covers the whole exchange rather than each read: an agent that
/// answers the header and then stops is as stuck as one that never answers.
async fn exchange(path: &Path, request: &Request, within: Duration) -> Result<Response> {
    let attempt = async {
        let mut stream = transport::connect(path).await?;
        write_message(&mut stream, request).await?;
        read_message::<Response, _>(&mut stream).await
    };

    match tokio::time::timeout(within, attempt).await {
        Ok(result) => result,
        Err(_) => Err(Error::Timeout {
            what: format!("the agent at {}", path.display()),
        }),
    }
}

/// Whether an agent is serving the control interface at `path`.
///
/// Used to tell a running agent from a leftover: on Unix a socket file with
/// nothing behind it, on Windows nothing at all.
/// A Windows pipe that denies access still counts as present; the subsequent
/// request reports the permission error instead of attempting an offline edit.
pub async fn is_serving(path: impl AsRef<Path>) -> bool {
    transport::probe(path.as_ref()).await
}

/// Asks a running agent for its status.
pub async fn request_status(path: impl AsRef<Path>) -> Result<StatusReport> {
    let path = path.as_ref();
    match exchange(path, &Request::Status, EXCHANGE_TIMEOUT).await? {
        Response::Status(report) => Ok(*report),
        Response::Error(reason) => Err(Error::Storage(reason)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Asks a running agent to answer to a different name.
///
/// Returns the name it accepted, which is the canonical form of what was
/// asked for and may differ from it.
pub async fn set_hostname(path: impl AsRef<Path>, hostname: &str) -> Result<String> {
    let path = path.as_ref();
    let request = Request::SetHostname(hostname.to_string());
    match exchange(path, &request, EXCHANGE_TIMEOUT).await? {
        Response::Hostname(accepted) => Ok(accepted),
        Response::Error(reason) => Err(Error::Storage(reason)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Asks a running agent to leave a network.
///
/// The agent publishes the release and removes the network; this only
/// carries the request and the outcome.
pub async fn leave_network(path: impl AsRef<Path>, network_id: &str) -> Result<LeftReport> {
    let path = path.as_ref();
    let request = Request::Leave(network_id.to_string());
    match exchange(path, &request, EXCHANGE_TIMEOUT).await? {
        Response::Left(report) => Ok(report),
        Response::Error(reason) => Err(Error::Storage(reason)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Asks a running agent to join a network.
///
/// The one way to add a network to an agent that is already up: the state
/// directory belongs to one live agent, so a second `up` cannot.
pub async fn join_network(
    path: impl AsRef<Path>,
    name: &str,
    secret: &str,
) -> Result<JoinedReport> {
    let path = path.as_ref();
    join_network_with_broadcast(path, name, secret, None).await
}

/// Joins with an explicit per-network broadcast choice.
pub async fn join_network_with_broadcast(
    path: impl AsRef<Path>,
    name: &str,
    secret: &str,
    broadcast: Option<bool>,
) -> Result<JoinedReport> {
    let path = path.as_ref();
    let request = Request::Join {
        broadcast,
        name: name.to_string(),
        secret: secret.to_string(),
    };
    match exchange(path, &request, EXCHANGE_TIMEOUT).await? {
        Response::Joined(report) => Ok(report),
        Response::Error(reason) => Err(Error::Storage(reason)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Changes one network's broadcast participation while the agent runs.
pub async fn set_broadcast(
    path: impl AsRef<Path>,
    network_id: &str,
    enabled: bool,
) -> Result<bool> {
    let path = path.as_ref();
    let request = Request::SetBroadcast {
        network_id: network_id.to_owned(),
        enabled,
    };
    match exchange(path, &request, EXCHANGE_TIMEOUT).await? {
        Response::Broadcast(enabled) => Ok(enabled),
        Response::Error(message) => Err(Error::Storage(message)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Asks a running agent to stop serving a network, or to serve it again.
pub async fn set_active(
    path: impl AsRef<Path>,
    network_id: &str,
    active: bool,
) -> Result<ActiveReport> {
    let path = path.as_ref();
    let request = Request::SetActive {
        network_id: network_id.to_string(),
        active,
    };
    match exchange(path, &request, EXCHANGE_TIMEOUT).await? {
        Response::Active(report) => Ok(report),
        Response::Error(reason) => Err(Error::Storage(reason)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Turns the running agent's local resolver on or off.
pub async fn set_dns(
    path: impl AsRef<Path>,
    enable: bool,
    port: Option<u16>,
) -> Result<Option<DnsReport>> {
    let path = path.as_ref();
    match exchange(path, &Request::Dns { enable, port }, EXCHANGE_TIMEOUT).await? {
        Response::Dns(report) => Ok(report),
        Response::Error(reason) => Err(Error::Storage(reason)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Offers the running agent as an exit node in one network, or stops.
pub async fn set_exit_offer(
    path: impl AsRef<Path>,
    network_id: &str,
    enabled: bool,
) -> Result<bool> {
    let request = Request::SetExitOffer {
        network_id: network_id.to_owned(),
        enabled,
    };
    match exchange(path.as_ref(), &request, EXCHANGE_TIMEOUT).await? {
        Response::ExitOffer(enabled) => Ok(enabled),
        Response::Error(message) => Err(Error::Storage(message)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Sends the running agent's internet traffic through a member of one
/// network, or back the ordinary way with `None`.
pub async fn set_exit_node(
    path: impl AsRef<Path>,
    network_id: &str,
    peer: Option<&str>,
) -> Result<Option<String>> {
    let request = Request::SetExitNode {
        network_id: network_id.to_owned(),
        peer: peer.map(str::to_owned),
    };
    match exchange(path.as_ref(), &request, EXCHANGE_TIMEOUT).await? {
        Response::ExitNode(peer) => Ok(peer),
        Response::Error(message) => Err(Error::Storage(message)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Asks a running agent for a configured network's shared secret, in its
/// `tsn1…` text form, so a local client can copy it. The secret is never
/// logged by this path.
pub async fn network_secret(path: impl AsRef<Path>, network_id: &str) -> Result<String> {
    let path = path.as_ref();
    let request = Request::Secret {
        network_id: network_id.to_string(),
    };
    match exchange(path, &request, EXCHANGE_TIMEOUT).await? {
        Response::Secret(secret) => Ok(secret.into_string()),
        Response::Error(reason) => Err(Error::Storage(reason)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

pub(crate) async fn write_message<S, T>(stream: &mut S, value: &T) -> Result<()>
where
    S: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let encoded = postcard::to_stdvec(value)
        .map_err(|err| Error::Storage(format!("cannot encode a control message: {err}")))?;
    if encoded.len() > MAX_MESSAGE_LEN {
        return Err(Error::Storage("control message is too large".into()));
    }
    let len = encoded.len() as u32;
    stream
        .write_all(&CONTROL_PROTOCOL.to_be_bytes())
        .await
        .map_err(io_error)?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(io_error)?;
    stream.write_all(&encoded).await.map_err(io_error)?;
    stream.flush().await.map_err(io_error)
}

pub(crate) async fn read_message<T, S>(stream: &mut S) -> Result<T>
where
    T: for<'de> serde::Deserialize<'de>,
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(io_error)?;
    let version = u32::from_be_bytes(header);
    if version != CONTROL_PROTOCOL {
        return Err(Error::Storage(format!(
            "the other end speaks control protocol {version:#010x} and this build speaks \
             {CONTROL_PROTOCOL:#010x}; they are different builds of tsunagi, so restart the \
             agent with the binary you are running now"
        )));
    }

    stream.read_exact(&mut header).await.map_err(io_error)?;
    let len = u32::from_be_bytes(header) as usize;
    // Checked before allocating, exactly as on the network.
    if len > MAX_MESSAGE_LEN {
        return Err(Error::Storage(format!(
            "control message of {len} bytes exceeds the {MAX_MESSAGE_LEN} byte limit"
        )));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.map_err(io_error)?;
    postcard::from_bytes(&payload)
        .map_err(|err| Error::Storage(format!("cannot decode a control message: {err}")))
}

pub(crate) fn io_error(source: std::io::Error) -> Error {
    Error::Io {
        path: PathBuf::from("<local control socket>"),
        source,
    }
}
