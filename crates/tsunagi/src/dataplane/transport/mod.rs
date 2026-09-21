//! The data plane transport boundary.
//!
//! This is the seam that keeps the control protocol and the data plane
//! independent. An [`IpPlugin`] never learns how its packets are moved: it is
//! handed a [`PacketLink`] to a peer and writes datagrams into it. Whether
//! that link runs over iroh today, a raw UDP socket, or something else
//! entirely tomorrow is the transport's business alone.
//!
//! [`IpPlugin`]: crate::dataplane::IpPlugin
//!
//! # Why the transport may use iroh
//!
//! The separation between control and data is **logical**, not a ban on
//! sharing technology. Refusing to use iroh for data would throw away exactly
//! what iroh is good at — hole punching a direct path between two peers behind
//! NAT, with a relay as fallback — and force the data plane to reimplement it.
//! So the default transport is [`iroh_link::IrohTransport`], which gives every
//! plugin that connectivity for free.
//!
//! What the separation does buy is that the control protocol in
//! [`crate::proto`] knows nothing about packets, and this module knows nothing
//! about WireGuard. Either side can be replaced on its own.
//!
//! # Semantics
//!
//! A link is an **unreliable, unordered datagram** channel, because that is
//! what a tunnelled UDP protocol needs: no retransmission, no head-of-line
//! blocking, loss is normal rather than an error. It is authenticated and
//! encrypted by the transport, and scoped to exactly one network, one peer and
//! one plugin protocol.

pub mod iroh_link;

use bytes::Bytes;
use iroh::EndpointId;

use crate::BoxFuture;
use crate::identity::NetworkId;

/// Why a data plane link failed.
///
/// None of these ever stop the control plane.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The peer is not reachable for the data plane right now.
    #[error("peer is unreachable: {0}")]
    Unreachable(String),
    /// The peer declined to open a channel for this protocol.
    #[error("peer declined a data channel for protocol `{0}`")]
    Declined(String),
    /// The link is closed.
    #[error("data link is closed")]
    Closed,
    /// A datagram was larger than the link can carry.
    #[error("datagram of {size} bytes exceeds the {limit} byte link limit")]
    TooLarge {
        /// Size that was attempted.
        size: usize,
        /// Largest datagram this link accepts.
        limit: usize,
    },
    /// Anything else.
    #[error("data transport error: {0}")]
    Other(String),
}

/// An authenticated datagram channel to one peer, for one plugin protocol.
///
/// Dropping the link closes it.
pub trait PacketLink: Send + Sync + std::fmt::Debug + 'static {
    /// The network this link belongs to.
    fn network(&self) -> NetworkId;

    /// The authenticated peer on the other end.
    fn peer(&self) -> EndpointId;

    /// The largest datagram this link can carry, in bytes.
    ///
    /// A plugin must size its own packets to fit, because there is no
    /// fragmentation here.
    fn max_datagram_size(&self) -> usize;

    /// Sends one datagram.
    ///
    /// Delivery is not guaranteed. Returning `Ok` means the datagram was
    /// handed to the transport, nothing more.
    fn send(&self, payload: Bytes) -> Result<(), TransportError>;

    /// Receives the next datagram, or `None` once the link is finished.
    fn recv(&self) -> BoxFuture<'_, Option<Bytes>>;

    /// Resolves once the link is closed, for whatever reason.
    fn closed(&self) -> BoxFuture<'_, ()>;

    /// Whether the link is already closed.
    ///
    /// Lets the owner notice a dead link and ask for a new one without
    /// keeping a task parked on [`PacketLink::closed`].
    fn is_closed(&self) -> bool;

    /// A short description of the path in use, for diagnostics.
    ///
    /// Reports what the transport actually knows. It must not invent a value.
    fn path_description(&self) -> String;
}

/// A shared handle to a link.
pub type SharedLink = std::sync::Arc<dyn PacketLink>;

/// An inbound link a peer opened towards us.
#[derive(Debug)]
pub struct InboundLink {
    /// The network it belongs to.
    pub network: NetworkId,
    /// The peer that opened it.
    pub peer: EndpointId,
    /// The plugin protocol it carries.
    pub protocol: String,
    /// The link itself.
    pub link: SharedLink,
}

/// Opens and accepts data plane links.
///
/// The agent owns one of these and hands links to plugins; plugins never call
/// it directly.
pub trait PacketTransport: Send + Sync + std::fmt::Debug + 'static {
    /// A short name used in diagnostics.
    fn name(&self) -> &str;

    /// Lets the agent recover the concrete transport to drive its accept side.
    ///
    /// Accepting is inherently transport-specific — it starts from whatever
    /// the transport's own listener produced — so it is not part of this
    /// trait's uniform interface.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Opens a link to `peer` in `network` for `protocol`.
    fn open<'a>(
        &'a self,
        network: NetworkId,
        peer: EndpointId,
        protocol: &'a str,
    ) -> BoxFuture<'a, Result<SharedLink, TransportError>>;
}
