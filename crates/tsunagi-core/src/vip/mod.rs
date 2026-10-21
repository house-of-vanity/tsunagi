//! Named, shared virtual services. Signed field registers converge without an
//! owner; routing, health and connection state remain local to each client.
use crate::Limits;
use crate::error::{Error, Result};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
pub(crate) mod packet;
pub(crate) mod router;
pub use crate::state::vip::{VipEntry, VipSet};
pub(crate) use router::VipRouter;
#[cfg(test)]
mod tests;

/// IP transport carried by a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}
impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}
impl std::str::FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err("protocol must be tcp or udp".into()),
        }
    }
}
/// A node identity and its application port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    /// Full device identity, resolved when editing.
    pub peer: String,
    /// Destination port.
    pub port: u16,
}
/// One independently routed port of a VIP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    /// Stable listener generation; prevents removed backend fields resurfacing on re-creation.
    pub id: String,
    /// TCP or UDP.
    pub protocol: Protocol,
    /// Client-facing port.
    pub port: u16,
    /// Enable active TCP connect checks; UDP uses path checks and ICMP errors.
    pub port_check: bool,
    /// Period between checks in milliseconds.
    pub check_interval_ms: u32,
    /// Deadline of a port check in milliseconds.
    pub check_timeout_ms: u32,
    /// Consecutive failed checks before exclusion.
    pub failure_threshold: u8,
    /// Consecutive successes before recovery.
    pub recovery_threshold: u8,
    /// Idle expiry for this listener's flows, in seconds.
    pub idle_timeout_secs: u32,
    /// Allowed destination nodes and ports.
    pub backends: Vec<Backend>,
}
impl Listener {
    /// Creates a listener with automatic recovery and bounded checks.
    pub fn new(protocol: Protocol, port: u16) -> Self {
        Self {
            id: hex::encode(rand::random::<[u8; 16]>()),
            protocol,
            port,
            port_check: true,
            check_interval_ms: 3000,
            check_timeout_ms: 2000,
            failure_threshold: 2,
            recovery_threshold: 1,
            idle_timeout_secs: if protocol == Protocol::Tcp { 7200 } else { 120 },
            backends: vec![],
        }
    }
}
/// Entire editable service; its address is an internal derived reservation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VipConfig {
    /// Stable random 128-bit id in hexadecimal.
    pub id: String,
    /// One DNS label, unique within the network.
    pub name: String,
    /// Independent listeners.
    pub listeners: Vec<Listener>,
}
impl VipConfig {
    /// Creates an empty named service with a fresh stable identity.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: hex::encode(rand::random::<[u8; 16]>()),
            name: name.into(),
            listeners: vec![],
        }
    }
    /// Validates a complete draft before any state is changed.
    pub fn validate(&self, limits: &Limits) -> Result<()> {
        if self.id.len() != 32 || hex::decode(&self.id).is_err() {
            return Err(invalid("invalid VIP id"));
        }
        if self.name.is_empty()
            || self.name.len() > 63
            || self.name.starts_with('-')
            || self.name.ends_with('-')
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(invalid(
                "VIP name must be a lowercase DNS label (letters, digits and hyphens)",
            ));
        }
        if self.listeners.len() > limits.max_vip_listeners {
            return Err(invalid("too many VIP listeners"));
        }
        let mut seen = BTreeSet::new();
        for l in &self.listeners {
            if l.id.len() != 32 || hex::decode(&l.id).is_err() {
                return Err(invalid("invalid listener identity"));
            }
            if l.port == 0 || !seen.insert((l.protocol, l.port)) {
                return Err(invalid(
                    "listener ports must be nonzero and unique per protocol",
                ));
            }
            if !(250..=3_600_000).contains(&l.check_interval_ms)
                || !(100..=60_000).contains(&l.check_timeout_ms)
                || l.failure_threshold == 0
                || l.recovery_threshold == 0
                || !(1..=604800).contains(&l.idle_timeout_secs)
            {
                return Err(invalid(
                    "invalid check interval, timeout, thresholds or flow idle timeout",
                ));
            }
            if l.backends.len() > limits.max_vip_backends {
                return Err(invalid("too many listener backends"));
            }
            let mut backends = BTreeSet::new();
            for b in &l.backends {
                if b.port == 0 || b.peer.parse::<EndpointId>().is_err() || !backends.insert(b) {
                    return Err(invalid(
                        "backend must have a unique node identity and a nonzero port",
                    ));
                }
            }
        }
        if crate::state::vip::flatten(self)?.len() > limits.max_vip_fields {
            return Err(invalid("VIP configuration exceeds signed field capacity"));
        }
        Ok(())
    }
}
pub(crate) fn invalid(reason: impl Into<String>) -> Error {
    Error::Rejected {
        reason: reason.into(),
    }
}
/// Cumulative IP traffic, excluding probes. Reset on agent restart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    /// Outbound packets.
    pub tx_packets: u64,
    /// Outbound bytes.
    pub tx_bytes: u64,
    /// Inbound packets.
    pub rx_packets: u64,
    /// Inbound bytes.
    pub rx_bytes: u64,
    /// Created flow bindings.
    pub flows: u64,
    /// UDP failovers.
    pub failovers: u64,
    /// Packets rejected or lacking an eligible backend.
    pub dropped: u64,
}
/// One backend, as seen by this client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendStatus {
    /// Configured endpoint.
    pub backend: Backend,
    /// Eligibility and reason.
    pub state: String,
    /// Smoothed full data-plane RTT, microseconds; unknown stays absent.
    pub rtt_us: Option<u64>,
    /// Last successful path measurement age.
    pub measurement_age_ms: Option<u64>,
    /// Current bindings.
    pub active_flows: u32,
    /// Local traffic counters.
    pub counters: Counters,
}
/// Runtime view of one listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerStatus {
    /// Protocol.
    pub protocol: Protocol,
    /// Frontend port.
    pub port: u16,
    /// Best backend for a new flow, if measured and eligible.
    pub selected: Option<Backend>,
    /// Configured and draining endpoints.
    pub backends: Vec<BackendStatus>,
    /// Local counters.
    pub counters: Counters,
}
/// Configuration and local diagnostics returned through the same API to CLI and GUI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VipStatus {
    /// Persisted configuration.
    pub config: VipConfig,
    /// Opaque revision used when saving a draft.
    pub revision: String,
    /// Internal service address.
    pub address: Option<Ipv4Addr>,
    /// Conflict or allocation issue, if any.
    pub error: Option<String>,
    /// Local listener status.
    pub listeners: Vec<ListenerStatus>,
}
