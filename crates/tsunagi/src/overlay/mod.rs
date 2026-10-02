//! The overlay interface: the one network interface an agent owns.
//!
//! One agent, one interface. It belongs to the system level rather than to
//! any protocol, and that is the whole point: a packet leaving it is routed
//! to whichever peer owns its destination address, over whichever protocol
//! currently has a link to that peer. Several protocols can be live at once
//! without arguing over who holds the address, because neither of them
//! holds it — the agent does.
//!
//! What lives here:
//!
//! * [`provision`] creates the interface and configures it, and removes it
//!   again. Platform mechanics behind one decision function.
//! * [`hostrules`] installs the route and firewall allowance that let a
//!   game's LAN discovery reach the interface, while broadcast is on.
//! * [`tun`] is the packet interface itself, real or in memory.
//! * [`packet`] reads just enough of an IP header to route by it.
//! * [`config`] names interfaces and describes addresses.
//!
//! What does not live here: encryption, peer discovery, and how a packet
//! actually reaches another machine. Those belong to a protocol plugin,
//! which this level hands packets to and takes packets from.

/// Why the overlay interface cannot be brought into the state asked for.
///
/// Its own error rather than the plugin one it used to borrow: this level
/// owns the interface now, and a plugin failing is a different event from
/// the interface failing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OverlayError {
    /// The interface cannot be created or configured right now, with the
    /// reason and, where there is one, what to do about it.
    #[error("overlay unavailable: {0}")]
    Unavailable(String),
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

pub mod broadcast;
pub mod config;
pub mod hostrules;
pub mod interface;
pub mod packet;
pub mod provision;
pub mod router;
pub mod tun;

pub use config::{Cidr, DEFAULT_INTERFACE_PREFIX, MAX_INTERFACE_NAME_LEN, interface_name};
pub use hostrules::{
    BroadcastHostRules, BroadcastRulesPlan, BroadcastRulesReport, MockHostRules, RuleOutcome,
    UnsupportedHostRules,
};
pub use interface::{Counters, Interface, PacketCarrier, Rejected};
pub use packet::IpHeader;
pub use provision::{
    Changes, InterfacePlan, InterfaceProvisioner, InterfaceState, LinkKind, ManagedTunFactory,
    MockHost, MockProvisioner, Privilege, Provisioned, UnsupportedProvisioner, plan_changes,
    probe_net_admin,
};
pub use router::{NetworkRoutes, Route, RouteError, RoutingTable};
pub use tun::{MemoryTun, MemoryTunFactory, TunDevice, TunFactory, TunRequest, address_is_local};

#[cfg(all(feature = "tun-device", target_os = "linux"))]
pub use hostrules::LinuxHostRules;
#[cfg(all(feature = "tun-device", target_os = "macos"))]
pub use hostrules::MacosHostRules;
#[cfg(all(feature = "tun-device", target_os = "windows"))]
pub use hostrules::WindowsHostRules;
#[cfg(all(feature = "tun-device", target_os = "linux"))]
pub use provision::NetlinkProvisioner;

#[cfg(all(feature = "tun-device", target_os = "macos"))]
pub use provision::UtunProvisioner;

#[cfg(all(feature = "tun-device", target_os = "windows"))]
pub use provision::WintunProvisioner;
