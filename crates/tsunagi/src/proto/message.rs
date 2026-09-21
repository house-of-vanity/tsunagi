//! Control message formats.
//!
//! This is deliberately a small, closed set of messages, not a general RPC
//! framework. Bodies are encoded with [postcard], a compact, deterministic,
//! non-self-describing serde format.
//!
//! Every message that arrives from the network passes [`validate`] against the
//! configured [`Limits`] before it reaches anything else.
//!
//! [postcard]: https://docs.rs/postcard

use serde::{Deserialize, Serialize};

use crate::config::Limits;
use crate::dataplane::{MAX_PROTOCOL_ID_LEN, PluginCapability};
use crate::error::ProtocolError;

/// ALPN of the tsunagi control plane.
///
/// The version in the ALPN is the wire-compatibility version of the control
/// protocol. It is independent of the network identity scheme version, so
/// bumping it must not change any existing [`crate::NetworkId`].
pub const ALPN: &[u8] = b"tsunagi/ctrl/1";

/// ALPN of the tsunagi data plane.
///
/// Data plane connections are deliberately separate from control plane ones.
/// They carry one IP plugin's packets for one network and nothing else, so a
/// saturated or broken data plane cannot disturb control traffic, and the
/// transport underneath can be replaced without touching the control protocol.
pub const DATA_ALPN: &[u8] = b"tsunagi/data/1";

/// Largest plugin protocol identifier accepted when opening a data channel.
pub const MAX_DATA_PROTOCOL_LEN: usize = 32;

/// Largest accepted signature on a signed record, in bytes.
pub const MAX_SIGNATURE_LEN: usize = 64;

/// Control protocol version carried inside the handshake.
pub const PROTOCOL_VERSION: u16 = 1;

/// First message of the handshake, sent by the initiator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Control protocol version the initiator speaks.
    pub version: u16,
    /// Public network identifier the initiator wants to join.
    pub network_id: [u8; 32],
    /// Initiator's fresh handshake nonce.
    pub nonce: [u8; 16],
}

/// Responder's reply to [`Hello`]. Carries no proof yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    /// Control protocol version the responder speaks.
    pub version: u16,
    /// Responder's fresh handshake nonce.
    pub nonce: [u8; 16],
}

/// A handshake proof, i.e. one HMAC tag over a role-specific transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProof {
    /// HMAC-SHA256 tag.
    pub proof: [u8; 32],
}

/// What this agent tells a peer about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    /// Human-readable hostname. A mutable binding, not an identity.
    pub hostname: String,
    /// Announced IP plugin capabilities. Opaque to the core.
    pub capabilities: Vec<PluginCapability>,
}

/// Opens a data channel, sent by the initiator right after the membership
/// handshake on a [`DATA_ALPN`] connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataOpen {
    /// Which IP plugin's packets this channel will carry.
    pub protocol: String,
}

/// The responder's answer to [`DataOpen`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataOpenAck {
    /// Whether the channel was accepted.
    ///
    /// A channel is refused when the responder has no plugin for that
    /// protocol in that network. That is an ordinary outcome, not an error.
    pub accepted: bool,
    /// Largest datagram the responder is willing to receive, in bytes.
    pub max_datagram: u32,
}

/// A control message exchanged after a successful handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ControlMessage {
    /// Hostname and capability announcement.
    Announce(Announcement),
    /// A small request used to verify that the exchange works.
    Ping {
        /// Caller-chosen sequence number, echoed back.
        seq: u64,
        /// Opaque bounded payload, echoed back.
        payload: Vec<u8>,
    },
    /// The reply to a [`ControlMessage::Ping`].
    Pong {
        /// Sequence number of the request being answered.
        seq: u64,
        /// Echoed payload.
        payload: Vec<u8>,
    },
    /// A snapshot of signed records this agent holds for the network.
    ///
    /// A snapshot is merged into what the receiver already has, never
    /// substituted for it: an author missing from the batch is left alone,
    /// because absence is not deletion.
    State {
        /// The records. Bounded by [`crate::config::Limits::max_state_records`].
        records: Vec<crate::state::SignedRecord>,
    },
    /// Graceful goodbye.
    ///
    /// A peer going away is not a revocation of anything.
    Bye {
        /// Short free-text reason.
        reason: String,
    },
}

/// A control message together with the network it belongs to.
///
/// Every session is bound to exactly one network at handshake time. The
/// `network_id` here is re-checked on every message, so an authenticated
/// session for network A can never be used to speak to network B, even over a
/// shared physical connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Network this message belongs to.
    pub network_id: [u8; 32],
    /// The message itself.
    pub message: ControlMessage,
}

/// Encodes a value into a postcard byte vector.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    postcard::to_stdvec(value).map_err(|_| ProtocolError::Malformed("cannot encode message"))
}

/// Decodes a value from postcard bytes.
pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ProtocolError> {
    postcard::from_bytes(bytes).map_err(|_| ProtocolError::Malformed("cannot decode message"))
}

fn check_len(field: &'static str, len: usize, limit: usize) -> Result<(), ProtocolError> {
    if len > limit {
        return Err(ProtocolError::FieldTooLarge { field, len, limit });
    }
    Ok(())
}

/// Validates a decoded capability against the configured limits.
pub fn validate_capability(
    capability: &PluginCapability,
    limits: &Limits,
) -> Result<(), ProtocolError> {
    if capability.protocol.is_empty() {
        return Err(ProtocolError::Malformed("empty plugin protocol id"));
    }
    check_len(
        "capability.protocol",
        capability.protocol.len(),
        MAX_PROTOCOL_ID_LEN,
    )?;
    check_len(
        "capability.data",
        capability.data.len(),
        limits.max_capability_data_len,
    )?;
    Ok(())
}

/// Validates a decoded control message against the configured limits.
///
/// Returning an error rejects that single message. It never stops the session's
/// network, the other networks or the agent.
pub fn validate(message: &ControlMessage, limits: &Limits) -> Result<(), ProtocolError> {
    match message {
        ControlMessage::Announce(announcement) => {
            check_len(
                "announce.hostname",
                announcement.hostname.len(),
                limits.max_hostname_len,
            )?;
            check_len(
                "announce.capabilities",
                announcement.capabilities.len(),
                limits.max_capabilities,
            )?;
            for capability in &announcement.capabilities {
                validate_capability(capability, limits)?;
            }
        }
        ControlMessage::Ping { payload, .. } | ControlMessage::Pong { payload, .. } => {
            check_len("echo.payload", payload.len(), limits.max_echo_payload_len)?;
        }
        ControlMessage::State { records } => {
            check_len("state.records", records.len(), limits.max_state_records)?;
            for record in records {
                check_len("state.signature", record.signature.len(), MAX_SIGNATURE_LEN)?;
            }
        }
        ControlMessage::Bye { reason } => {
            check_len("bye.reason", reason.len(), limits.max_reason_len)?;
        }
    }
    Ok(())
}

/// A short, stable label for a message kind, for metrics and diagnostics.
pub fn kind(message: &ControlMessage) -> &'static str {
    match message {
        ControlMessage::Announce(_) => "announce",
        ControlMessage::Ping { .. } => "ping",
        ControlMessage::Pong { .. } => "pong",
        ControlMessage::State { .. } => "state",
        ControlMessage::Bye { .. } => "bye",
    }
}
