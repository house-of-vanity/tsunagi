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
pub const ALPN: &[u8] = b"tsunagi/ctrl/8";

/// ALPN of the tsunagi data plane.
///
/// Data plane connections are deliberately separate from control plane ones.
/// They carry one IP plugin's packets for one network and nothing else, so a
/// saturated or broken data plane cannot disturb control traffic, and the
/// transport underneath can be replaced without touching the control protocol.
///
/// Version 4 adds source, destination, hop limit and stable flow id above
/// transport fragmentation. Version 5 adds the end-to-end protocol to that
/// envelope, so a tunnel no longer depends on the kind of link under it, and
/// a first-claimed time to a signed hostname claim. All members must upgrade
/// together. Version 6 uses one fixed inner WireGuard channel and independent
/// external carrier capabilities. Control authentication, persistent identities
/// and network configuration do not change.
pub const DATA_ALPN: &[u8] = b"tsunagi/data/6";

/// Largest plugin protocol identifier accepted when opening a data channel.
pub const MAX_DATA_PROTOCOL_LEN: usize = 32;

/// Largest accepted signature on a signed record, in bytes.
pub const MAX_SIGNATURE_LEN: usize = 64;

/// Control protocol version carried inside the handshake.
pub const PROTOCOL_VERSION: u16 = 8;

pub use crate::dataplane::transport::{MAX_TRANSPORT_PAYLOAD, TransportPayload};

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
    /// Local opt-in to receive LAN broadcasts in this network.
    pub broadcast: bool,
    /// This agent offers itself as an exit node in this network: members may
    /// send all their internet traffic through it. Off unless its owner
    /// turned it on, and only said once the rules that make it work are in
    /// place.
    pub exit_node: bool,
    /// Human-readable hostname. A mutable binding, not an identity.
    pub hostname: String,
    /// Announced IP plugin capabilities. Opaque to the core.
    pub capabilities: Vec<PluginCapability>,
    /// Software release reported by this peer for display after authentication.
    /// Keep this trailer last: original v8 readers stop after the capabilities.
    #[serde(default, deserialize_with = "read_agent_version")]
    pub agent_version: Option<String>,
}

fn read_agent_version<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    // A frame contains exactly one envelope. EOF here is a legacy announcement.
    // An unreadable display hint can also be discarded without losing the
    // hostname or capabilities. Borrow the frame until the label is bounded.
    let version = Option::<&str>::deserialize(d).ok().flatten().filter(|s| {
        !s.is_empty()
            && s.len() <= crate::config::MAX_AGENT_VERSION_LEN
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
    });
    Ok(version.map(str::to_owned))
}

/// Opens a data channel, sent by the initiator right after the membership
/// handshake on a [`DATA_ALPN`] connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataOpen {
    /// Which IP plugin's packets this channel will carry.
    pub protocol: String,
    /// Maximum reassembled payload the initiator is willing to receive.
    pub max_datagram: u32,
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
    /// Private transport negotiation; never persisted or rebroadcast.
    Transport {
        /// Transport protocol id; the payload stays opaque to the core.
        protocol: String,
        /// Secret negotiation data, redacted in diagnostics.
        payload: TransportPayload,
    },
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
    /// Members this sender knows of, and where it has seen them.
    ///
    /// An introduction, not a vouching: everything here is an unverified
    /// candidate, and membership is still decided by the handshake. It is
    /// what turns a star around whoever was named on the command line into
    /// a mesh — a device that was told about one member ends up talking to
    /// all of them — and it is the same shape a lookup in a distributed
    /// hash table would return.
    Peers {
        /// The members, with whatever addresses the sender has for them.
        peers: Vec<PeerHint>,
    },
    /// Which peers this sender has a live data link with, right now.
    ///
    /// First-hand and nothing else: a sender speaks only for itself, never
    /// about what somebody else can reach. That is what makes it usable
    /// without weighing hearsay — the claim is proved or disproved by
    /// sending through it.
    ///
    /// A snapshot rather than a change, because a snapshot is idempotent
    /// and repairs itself; and volatile, so it lives here and not in
    /// signed state, which is for what has to survive a member being away.
    Reachable {
        /// Direct links, scoped to the plugin protocol they actually carry.
        links: Vec<ReachableLink>,
    },
    /// Graceful goodbye.
    ///
    /// A peer going away is not a revocation of anything.
    Bye {
        /// Short free-text reason.
        reason: String,
    },
    /// One complete signed VIP field snapshot, merged atomically.
    Vips {
        /// Signed registers bounded by the per-VIP field limit.
        entries: Vec<crate::vip::VipEntry>,
    },
    /// Signed cleanup markers, each proving the retired claim version.
    Retirements {
        /// Bounded by the per-message signed-state limit.
        markers: Vec<crate::state::SignedRetirement>,
    },
}

/// Somewhere a member has been seen.
///
/// Addresses are in iroh's own text form, which is what the endpoint takes
/// back: this is a hint to try, never a fact about where anybody is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHint {
    /// The member's endpoint key.
    pub endpoint: [u8; 32],
    /// Where the sender has seen it, as `ip:<socket>` or `relay:<url>`.
    ///
    /// The same spelling the disposable cache uses, so one decoder serves
    /// both and neither can drift from the other. An empty list is still
    /// worth sending: an id alone is enough for a receiver whose endpoint
    /// can resolve it.
    pub addrs: Vec<String>,
}

/// One directly observed edge, advertised only by its authenticated source.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReachableLink {
    /// The other end of this transport link.
    pub peer: [u8; 32],
    /// Protocol carried by the link.
    pub protocol: String,
}

/// Longest address text accepted in a hint.
pub const MAX_HINT_ADDR_LEN: usize = 128;

/// Most addresses accepted for one member in a hint.
pub const MAX_HINT_ADDRS: usize = 8;

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
        ControlMessage::Vips { entries } => {
            check_len("vip.fields", entries.len(), limits.max_vip_fields)?;
            for e in entries {
                check_len("vip.id", e.vip.len(), 32)?;
                check_len("vip.key", e.key.len(), 160)?;
                check_len("vip.value", e.value.as_ref().map_or(0, Vec::len), 256)?;
                check_len("vip.signature", e.signature.len(), 64)?;
            }
        }
        ControlMessage::Retirements { markers } => {
            check_len("retirements", markers.len(), limits.max_state_records)?;
            for marker in markers {
                check_len(
                    "retirement.signature",
                    marker.signature.len(),
                    MAX_SIGNATURE_LEN,
                )?;
                check_len(
                    "retirement.target.signature",
                    marker.target.signature.len(),
                    MAX_SIGNATURE_LEN,
                )?;
                if let Some(name) = marker.target.body.hostname() {
                    check_len(
                        "retirement.target.hostname",
                        name.len(),
                        limits.max_hostname_len,
                    )?;
                }
            }
        }
        ControlMessage::Transport { protocol, payload } => {
            if protocol.is_empty() {
                return Err(ProtocolError::Malformed("empty transport protocol"));
            }
            check_len("transport.protocol", protocol.len(), MAX_PROTOCOL_ID_LEN)?;
            check_len(
                "transport.payload",
                payload.as_bytes().len(),
                limits.max_transport_payload_len.min(MAX_TRANSPORT_PAYLOAD),
            )?;
        }
        ControlMessage::Peers { peers } => {
            check_len("peers", peers.len(), limits.max_state_records)?;
            for hint in peers {
                check_len("peers.addrs", hint.addrs.len(), MAX_HINT_ADDRS)?;
                for addr in &hint.addrs {
                    check_len("peers.addr", addr.len(), MAX_HINT_ADDR_LEN)?;
                }
            }
        }
        ControlMessage::Reachable { links } => {
            check_len("reachable.links", links.len(), limits.max_state_records)?;
            for link in links {
                if link.protocol.is_empty() {
                    return Err(ProtocolError::Malformed("empty routing protocol"));
                }
                check_len(
                    "reachable.protocol",
                    link.protocol.len(),
                    MAX_PROTOCOL_ID_LEN,
                )?;
            }
        }
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
        ControlMessage::Transport { .. } => "transport",
        ControlMessage::Announce(_) => "announce",
        ControlMessage::Ping { .. } => "ping",
        ControlMessage::Pong { .. } => "pong",
        ControlMessage::State { .. } => "state",
        ControlMessage::Retirements { .. } => "retirements",
        ControlMessage::Vips { .. } => "vips",
        ControlMessage::Reachable { .. } => "reachable",
        ControlMessage::Peers { .. } => "peers",
        ControlMessage::Bye { .. } => "bye",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn v8_announcements_interoperate_with_and_without_a_software_version() {
        // The original v8 frame ends with the capability list. Decode the
        // new frame using exactly those fields as an older receiver would.
        type OldFrame = ([u8; 32], u8, bool, bool, String, Vec<PluginCapability>);
        let old: OldFrame = ([7; 32], 1, true, false, "lab".into(), vec![]);
        let legacy = encode(&old).unwrap();
        assert!(decode::<Envelope>(&legacy[..legacy.len() - 1]).is_err());
        let read = |bytes: &[u8]| match decode::<Envelope>(bytes).unwrap().message {
            ControlMessage::Announce(a) => a,
            _ => panic!("expected announcement"),
        };
        let mut a = read(&legacy);
        assert_eq!(a.agent_version, None);
        a.agent_version = Some("2.1.0-rc.2+android".into());
        let wire = encode(&Envelope {
            network_id: old.0,
            message: ControlMessage::Announce(a.clone()),
        })
        .unwrap();
        assert_eq!(decode::<OldFrame>(&wire).unwrap(), old);
        assert_eq!(read(&wire), a);

        for invalid in ["", "1.2.3\nforged", &"1".repeat(256)] {
            let mut wire = legacy.clone();
            wire.extend(encode(&Some(invalid)).unwrap());
            let a = read(&wire);
            assert_eq!(a.agent_version, None);
            assert_eq!(a.hostname, "lab");
        }
    }
}
