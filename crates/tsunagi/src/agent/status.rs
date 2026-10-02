//! Status snapshots.
//!
//! Metrics are reported at the level they actually belong to. Values that
//! genuinely cannot be attributed to a single network — everything the iroh
//! endpoint aggregates, for instance — stay at the endpoint level rather than
//! being split between networks with invented precision.

use std::time::Duration;

use iroh::{EndpointAddr, EndpointId};

use crate::dataplane::PluginCapability;
use crate::discovery::CandidateSource;
use crate::identity::{NetworkDescriptor, NetworkId, NetworkName};
use crate::net::{ConnectionCounters, PathAddr, PathInfo, TransportKind};
use crate::proto::handshake::Role;
use crate::storage::CacheOutcome;

/// Whether a configured network is running locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkState {
    /// Configured and running.
    Active,
    /// Configured but not running.
    Inactive,
}

/// An unverified candidate as seen by a network runtime.
#[derive(Debug, Clone)]
pub struct CandidateStatus {
    /// Candidate endpoint id.
    pub endpoint_id: EndpointId,
    /// Where it came from.
    pub source: CandidateSource,
    /// Consecutive failed dial attempts since the last success.
    pub consecutive_failures: u32,
}

/// The overlay interface, as the agent sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayStatus {
    /// The interface name the operating system gave.
    pub interface: String,
    /// Whether that interface exists on the host.
    ///
    /// `false` with an in-memory device: the name is real to the agent and
    /// to nothing else. Reported, because everything that would configure
    /// the operating system for this interface must not when it is this.
    pub on_host: bool,
    /// Its MTU.
    pub mtu: u32,
    /// The addresses it should be carrying.
    pub addresses: Vec<crate::overlay::Cidr>,
    /// What has happened on it.
    pub counters: crate::overlay::Counters,
    /// The route and firewall allowance installed for LAN broadcast, when
    /// some network has broadcast on and the interface is on the host.
    /// `None` is "none installed", not "unknown".
    pub broadcast_rules: Option<crate::overlay::BroadcastRulesReport>,
}

/// A member the signed state knows about, connected or not.
///
/// This is the durable roster: it comes from signed records, so a member that
/// went away last month is still here. That is what makes it possible to say
/// "this peer is offline" rather than only "nobody is connected".
///
/// It is not a complete membership list, and cannot be. A member is in signed
/// state once it has claimed something — an address, a name, or both — so a
/// member that has joined but never published is visible only while it is
/// connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberStatus {
    /// The member's device identity.
    pub endpoint_id: EndpointId,
    /// The IPv4 overlay address it claimed and signed for.
    pub overlay_address_v4: Option<std::net::Ipv4Addr>,
    /// The name it claimed, when it holds that name uncontested.
    ///
    /// Signed, so it is still known while the member is away — which is what
    /// lets an absent member be named rather than shown as a bare id.
    pub hostname: Option<String>,
    /// The last name this agent saw it announce, whether or not it is here.
    ///
    /// Not signed, so it is a convenience for naming a member that is away
    /// and never a claim: the zone is served from `hostname`.
    pub last_hostname: Option<String>,
}

/// Status of one authenticated session.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    /// This authenticated peer accepts network broadcasts.
    pub broadcast: bool,
    /// Authenticated endpoint id.
    pub endpoint_id: EndpointId,
    /// Which side this agent played in the handshake.
    pub role: Role,
    /// Hostname the peer announced, if it has announced one yet.
    ///
    /// A mutable binding, not an identity.
    pub hostname: Option<String>,
    /// Protocols agreed with this peer: both sides have them at the same
    /// version.
    ///
    /// Empty means no data plane with that peer, which leaves the control
    /// plane working — messages and state still flow.
    pub protocols: Vec<String>,
    /// Capabilities the peer announced. Payloads stay opaque.
    pub capabilities: Vec<PluginCapability>,
    /// How long the session has been up.
    pub connected_for: Duration,
    /// Verified paths of the underlying connection.
    pub paths: Vec<PathInfo>,
    /// How the connection currently reaches the peer.
    pub transport: TransportKind,
    /// RTT of the selected path, when iroh reported one.
    pub rtt: Option<Duration>,
    /// Per-connection counters.
    pub connection: ConnectionCounters,
    /// Control messages sent on this session.
    pub control_messages_sent: u64,
    /// Control messages received on this session.
    pub control_messages_received: u64,
    /// Control payload bytes queued for this session.
    pub control_bytes_sent: u64,
    /// Control payload bytes read from this session.
    pub control_bytes_received: u64,
}

/// Counters scoped to one logical network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkMetrics {
    /// Outbound dial attempts started.
    pub dial_attempts: u64,
    /// Outbound dials that failed before or during the handshake.
    pub dial_failures: u64,
    /// Handshakes rejected, in either direction.
    pub handshake_failures: u64,
    /// Sessions that reached the authenticated state.
    pub sessions_established: u64,
    /// Sessions that ended.
    pub disconnects: u64,
    /// Control messages sent in this network.
    pub control_messages_sent: u64,
    /// Control messages received in this network.
    pub control_messages_received: u64,
    /// Control bytes sent in this network, payload only.
    pub control_bytes_sent: u64,
    /// Control bytes received in this network, payload only.
    pub control_bytes_received: u64,
    /// Messages or sessions rejected for protocol violations.
    pub protocol_violations: u64,
    /// Errors reported by IP plugins. Never fatal.
    pub plugin_errors: u64,
    /// Data plane links that were established.
    pub data_links_established: u64,
    /// Attempts to open a data plane link that failed.
    pub data_link_failures: u64,
}

/// Status of one network.
#[derive(Debug, Clone)]
pub struct NetworkStatus {
    /// Local broadcast participation in this network.
    pub broadcast: bool,
    /// Immutable deterministic description of the network space.
    pub descriptor: NetworkDescriptor,
    /// Network name, for convenience.
    pub name: NetworkName,
    /// Public network identifier.
    pub network_id: NetworkId,
    /// Whether the network is running locally.
    pub state: NetworkState,
    /// Authenticated sessions.
    pub peers: Vec<PeerStatus>,
    /// Unverified candidates currently known. Not peers.
    pub candidates: Vec<CandidateStatus>,
    /// Members the signed state knows about, whether connected or not.
    pub members: Vec<MemberStatus>,
    /// The overlay range this network uses, once it has one.
    pub range: Option<crate::state::Ipv4Range>,
    /// The range it could not have, because another network on this agent
    /// already holds it.
    ///
    /// One agent has one interface, so an address belongs to one network.
    /// This network waits to adopt whatever its members settle on instead of
    /// proposing something it could not route.
    pub range_conflict: Option<crate::state::Ipv4Range>,
    /// Per-network counters.
    pub metrics: NetworkMetrics,
    /// What has gone through a peer in the middle, in both directions.
    pub relay: crate::dataplane::relay::RelayCounters,
}

impl NetworkStatus {
    /// Endpoint ids of peers with an authenticated session.
    pub fn connected_peers(&self) -> Vec<EndpointId> {
        self.peers.iter().map(|peer| peer.endpoint_id).collect()
    }
}

/// Status of the whole agent.
#[derive(Debug, Clone)]
pub struct AgentStatus {
    /// This device's persistent endpoint id.
    pub endpoint_id: EndpointId,
    /// Hostname announced to peers.
    pub hostname: String,
    /// Sockets actually bound.
    pub bound_sockets: Vec<std::net::SocketAddr>,
    /// Addresses iroh believes this endpoint has. Observed, not verified.
    pub observed_addrs: Vec<PathAddr>,
    /// The dialable address of this endpoint, as iroh currently reports it.
    pub endpoint_addr: EndpointAddr,
    /// What happened to the disposable cache at startup.
    pub cache_outcome: CacheOutcome,
    /// Whether the cache is currently usable.
    pub cache_healthy: bool,
    /// Per-network status, including configured but inactive networks.
    pub networks: Vec<NetworkStatus>,
}

impl AgentStatus {
    /// Looks up one network's status.
    pub fn network(&self, network_id: &NetworkId) -> Option<&NetworkStatus> {
        self.networks
            .iter()
            .find(|status| &status.network_id == network_id)
    }
}
