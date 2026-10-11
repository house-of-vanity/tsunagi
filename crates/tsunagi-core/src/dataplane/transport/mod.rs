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

mod fragments;
pub(crate) mod health;
pub mod iroh_link;

use std::sync::Arc;

use bytes::Bytes;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

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
    /// This is the logical payload limit. A transport can fragment underneath
    /// it so path MTU changes do not force a plugin to resize the host interface.
    fn max_datagram_size(&self) -> usize;

    /// Sends one datagram.
    ///
    /// Delivery is not guaranteed. Returning `Ok` means the datagram was
    /// handed to the transport, nothing more.
    fn send(&self, payload: Bytes) -> Result<(), TransportError>;

    /// Sends a datagram with an opaque stable flow identifier. Plugins derive
    /// this before encryption; transports that do not route can ignore it.
    fn send_flow(
        &self,
        payload: Bytes,
        _flow: super::routing::FlowId,
    ) -> Result<(), TransportError> {
        self.send(payload)
    }

    /// Receives the next datagram, or `None` once the link is finished.
    fn recv(&self) -> BoxFuture<'_, Option<Bytes>>;

    /// Resolves once the link is closed, for whatever reason.
    fn closed(&self) -> BoxFuture<'_, ()>;

    /// Whether the link is already closed.
    ///
    /// Lets the owner notice a dead link and ask for a new one without
    /// keeping a task parked on [`PacketLink::closed`].
    fn is_closed(&self) -> bool;

    /// Explicitly retires a physical link. Implementations should wake readers.
    fn close(&self) {}

    /// Observed reason for retiring this link, if available.
    fn failure_reason(&self) -> Option<String> {
        None
    }

    /// A short description of the path in use, for diagnostics.
    ///
    /// Reports what the transport actually knows. It must not invent a value.
    fn path_description(&self) -> String;
}

/// A shared handle to a link.
pub type SharedLink = std::sync::Arc<dyn PacketLink>;

/// Maximum opaque pair-negotiation payload.
pub const MAX_TRANSPORT_PAYLOAD: usize = 4096;

/// Private transport bytes, never included in Debug output.
#[derive(Clone, PartialEq, Eq, Serialize, zeroize::ZeroizeOnDrop)]
pub struct TransportPayload(Vec<u8>);

impl<'de> Deserialize<'de> for TransportPayload {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = TransportPayload;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "at most {MAX_TRANSPORT_PAYLOAD} private transport bytes")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                if sequence
                    .size_hint()
                    .is_some_and(|size| size > MAX_TRANSPORT_PAYLOAD)
                {
                    return Err(serde::de::Error::custom("transport payload too large"));
                }
                let mut payload = TransportPayload(Vec::with_capacity(
                    sequence.size_hint().unwrap_or(0).min(MAX_TRANSPORT_PAYLOAD),
                ));
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if payload.0.len() == MAX_TRANSPORT_PAYLOAD {
                        return Err(serde::de::Error::custom("transport payload too large"));
                    }
                    payload.0.push(byte);
                }
                Ok(payload)
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}
impl TransportPayload {
    /// Wraps bytes for one authenticated control session.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Borrows private bytes; callers must not log them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for TransportPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportPayload([REDACTED])")
    }
}

/// Private control-plane sender for transports. Contains no network secret.
pub trait ControlSender: Send + Sync + std::fmt::Debug + 'static {
    /// Queues a bounded message to one authenticated member of one network.
    fn send<'a>(
        &'a self,
        network: NetworkId,
        peer: EndpointId,
        protocol: &'a str,
        payload: TransportPayload,
    ) -> BoxFuture<'a, Result<(), TransportError>>;
}

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
    /// Supplies a private sender before network activation.
    fn attach_control(&self, _control: Arc<dyn ControlSender>) {}
    /// Validates and queues private negotiation received from an authenticated member.
    fn on_control(
        &self,
        _network: NetworkId,
        _peer: EndpointId,
        _protocol: &str,
        _payload: &[u8],
    ) -> Result<(), TransportError> {
        Err(TransportError::Declined(self.name().into()))
    }
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

/// A composite packet transport that dispatches requests by protocol id.
#[derive(Debug)]
pub struct MultiPacketTransport {
    default: Arc<dyn PacketTransport>,
    by_protocol: std::collections::HashMap<String, Arc<dyn PacketTransport>>,
}

impl MultiPacketTransport {
    /// Creates a new composite transport with a default fallback transport.
    pub fn new(
        default: Arc<dyn PacketTransport>,
        by_protocol: std::collections::HashMap<String, Arc<dyn PacketTransport>>,
    ) -> Self {
        Self {
            default,
            by_protocol,
        }
    }

    /// Access the default underlying transport.
    pub fn default_transport(&self) -> &Arc<dyn PacketTransport> {
        &self.default
    }
}

impl PacketTransport for MultiPacketTransport {
    fn attach_control(&self, control: Arc<dyn ControlSender>) {
        self.default.attach_control(control.clone());
        for transport in self.by_protocol.values() {
            transport.attach_control(control.clone());
        }
    }
    fn on_control(
        &self,
        network: NetworkId,
        peer: EndpointId,
        protocol: &str,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        match self.by_protocol.get(protocol) {
            Some(transport) => transport.on_control(network, peer, protocol, payload),
            None => Err(TransportError::Declined(protocol.into())),
        }
    }
    fn name(&self) -> &str {
        "multi"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn open<'a>(
        &'a self,
        network: NetworkId,
        peer: EndpointId,
        protocol: &'a str,
    ) -> BoxFuture<'a, Result<SharedLink, TransportError>> {
        if let Some(transport) = self.by_protocol.get(protocol) {
            transport.open(network, peer, protocol)
        } else {
            self.default.open(network, peer, protocol)
        }
    }
}
