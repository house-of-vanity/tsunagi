//! The WireGuard protocol plugin.
//!
//! The first of them. It carries IP packets between participants; deciding
//! who is in the network, what addresses they hold and which interface those
//! sit on belongs to the system level, which configures this and then leaves
//! it to get on with it.
//!
//! Where the line falls:
//!
//! * **The plugin knows nothing about reachability.** It is handed a
//!   [`PacketLink`](crate::dataplane::transport::PacketLink) per peer and
//!   moves datagrams over it. Hole punching and relaying belong to the
//!   transport.
//! * **The plugin knows nothing about addresses either.** They are allocated
//!   and signed at the system level, the same ones whichever protocol is
//!   moving the packets. Nothing here derives one.
//! * **The announcement says who, not where.** A public key and the network
//!   it is for, so there is nothing about reachability for a peer to lie
//!   about.
//! * **The core never parses these announcements.** It moves a bounded
//!   opaque blob; only [`announcement`] interprets it.
//! * **Keys are separate.** One key per network, in its own store, unrelated
//!   to the iroh device key and to the network secret.
//! * **WireGuard's own crypto is untouched.** The handshake and encryption
//!   run end to end between the two ends of a tunnel.
//!
//! WireGuard itself is [`boringtun`]'s protocol state machine, running in
//! this process: no kernel module, no `wg` tool, the same code on every
//! platform. [`device::WireguardDevice`] drives one tunnel per peer.
//!
//! The interface underneath comes from [`crate::overlay`], and with its
//! in-memory implementation the whole data plane — handshake, encryption,
//! routing, address ownership — runs and is tested with no privileges at
//! all.
//!
//! See `docs/wireguard.md` for the full picture.

pub mod announcement;
pub mod device;
pub mod keys;
pub mod plugin;
pub mod store;

pub use crate::state::Ipv4Range;
pub use announcement::{ANNOUNCEMENT_VERSION, ValidatedAnnouncement, WgAnnouncement};
// The interface, its addresses and how it is created belong to the system
// level now: one agent has one interface, and no protocol owns it. Re-exported
// here while callers are moved over.
pub use crate::overlay::provision::{
    Changes, InterfacePlan, InterfaceProvisioner, InterfaceState, LinkKind, ManagedTunFactory,
    MockHost, MockProvisioner, Privilege, Provisioned, UnsupportedProvisioner, plan_changes,
    probe_net_admin,
};
pub use crate::overlay::{
    Cidr, DEFAULT_INTERFACE_PREFIX, IpHeader, MAX_INTERFACE_NAME_LEN, MemoryTun, MemoryTunFactory,
    TunDevice, TunFactory, TunRequest, address_is_local, interface_name,
};
pub use device::{PeerHealth, PeerStats, PeerSummary, WireguardDevice};
pub use keys::{WgPublicKey, WgSecretKey};
pub use plugin::{
    DEFAULT_MTU, MIN_MTU, NetworkOverview, PeerOverview, WIREGUARD_OVERHEAD, WIREGUARD_PROTOCOL,
    WireguardConfig, WireguardPlugin,
};
pub use store::WgKeyStore;

#[cfg(all(feature = "tun-device", target_os = "linux"))]
pub use crate::overlay::NetlinkProvisioner;
