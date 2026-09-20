//! Events published by a running agent.
//!
//! Events are delivered through a bounded [`tokio::sync::broadcast`] channel.
//! A slow subscriber is lagged, never allowed to stall the runtime.
//!
//! Nothing here ever carries a secret, a derived key or a handshake proof.

use std::time::Duration;

use iroh::EndpointId;

use crate::identity::NetworkId;
use crate::net::TransportKind;
use crate::proto::ControlMessage;
use crate::proto::handshake::Role;

/// Something that happened inside the agent.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    /// A network was activated locally.
    NetworkActivated {
        /// The network.
        network: NetworkId,
    },
    /// A network was deactivated locally.
    ///
    /// This is a local deactivation only. It is not a signed revocation of
    /// membership, and it says nothing about the network's other participants.
    NetworkDeactivated {
        /// The network.
        network: NetworkId,
    },
    /// A peer completed the handshake and has an authenticated session.
    PeerConnected {
        /// The network the session belongs to.
        network: NetworkId,
        /// Authenticated peer endpoint id.
        peer: EndpointId,
        /// Which side this agent played.
        role: Role,
        /// How the connection currently reaches the peer.
        transport: TransportKind,
        /// RTT of the selected path, if iroh reported one.
        rtt: Option<Duration>,
    },
    /// A peer's session ended.
    PeerDisconnected {
        /// The network the session belonged to.
        network: NetworkId,
        /// The peer.
        peer: EndpointId,
        /// Why the session ended. Free of secrets.
        reason: String,
    },
    /// A control message arrived on an authenticated session.
    MessageReceived {
        /// The network.
        network: NetworkId,
        /// The peer that sent it.
        peer: EndpointId,
        /// The message.
        message: ControlMessage,
    },
    /// An outbound dial failed.
    ///
    /// A dead candidate produces these and nothing else; other peers keep
    /// connecting normally.
    DialFailed {
        /// The network.
        network: NetworkId,
        /// The candidate that could not be reached.
        peer: EndpointId,
        /// Why it failed.
        reason: String,
    },
    /// A handshake was rejected.
    ///
    /// The network is `None` when the failure happened before the peer's
    /// requested network could be resolved.
    HandshakeRejected {
        /// The network, when known.
        network: Option<NetworkId>,
        /// The peer, when known.
        peer: Option<EndpointId>,
        /// Why it was rejected.
        reason: String,
    },
    /// A message or session was rejected for violating the protocol.
    ProtocolViolation {
        /// The network, when known.
        network: Option<NetworkId>,
        /// The peer, when known.
        peer: Option<EndpointId>,
        /// What was wrong.
        reason: String,
    },
    /// The disposable cache was discarded and recreated at startup.
    CacheReset {
        /// Why it was discarded. Free of secrets.
        reason: String,
    },
    /// An IP plugin reported an error. Never fatal.
    PluginError {
        /// The network the call was scoped to.
        network: NetworkId,
        /// Plugin protocol id.
        protocol: String,
        /// The reported error.
        reason: String,
    },
}
