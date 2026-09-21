//! The WireGuard data plane plugin.
//!
//! WireGuard is the first IP plugin. It creates real IP connectivity between
//! participants, while the control plane keeps doing what it does: agreeing on
//! who is in the network and carrying each participant's opaque announcement.
//!
//! The two planes stay separate:
//!
//! * **The plugin knows nothing about reachability.** It is handed a
//!   [`PacketLink`](crate::dataplane::transport::PacketLink) per peer and
//!   bridges the kernel WireGuard device onto it. Hole punching and relaying
//!   belong to the transport.
//! * **The announcement says who, not where.** It carries a public key, so
//!   there is no address for a peer to lie about.
//! * **The core never parses these announcements.** It moves a bounded opaque
//!   blob; only [`announcement`] interprets it.
//! * **Keys are separate.** The plugin has its own key per network, in its own
//!   store, unrelated to the iroh device key and to the network secret.
//! * **WireGuard's own crypto is untouched.** The bridge is a pipe; the
//!   handshake and encryption run end to end between the two kernels.
//!
//! # How a mesh forms
//!
//! Every participant derives its own overlay address from the network id and
//! its own WireGuard public key ([`overlay`]), so no coordinator hands out
//! addresses. Because that derivation is public, each agent computes every
//! peer's `AllowedIPs` itself instead of believing what the peer claims — a
//! member cannot route another member's traffic to itself.
//!
//! WireGuard itself is [`boringtun`]'s protocol state machine, running in this
//! process: no kernel module, no `wg` tool, the same code on every platform.
//! [`device::WireguardDevice`] drives one tunnel per peer and routes packets
//! between them and a [`tun::TunDevice`].
//!
//! The only part that needs privileges is the packet interface. With
//! [`tun::MemoryTunFactory`] the whole data plane — handshake, encryption,
//! routing, address ownership — runs and is tested with no privileges at all.
//! For real traffic there is [`provision::ManagedTunFactory`], where the
//! agent creates and configures the interface itself over netlink and
//! removes it again on exit.
//!
//! See `docs/wireguard.md` for the full picture.

pub mod announcement;
pub mod device;
pub mod keys;
pub mod overlay;
pub mod plugin;
pub mod store;

pub use crate::state::Ipv4Range;
pub use announcement::{ValidatedAnnouncement, WgAnnouncement};
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
pub use overlay::{OVERLAY_PREFIX_LEN, overlay_address, overlay_address_v4, overlay_prefix};
pub use plugin::{
    DEFAULT_MTU, MIN_MTU, NetworkOverview, PeerOverview, WIREGUARD_OVERHEAD, WIREGUARD_PROTOCOL,
    WireguardConfig, WireguardPlugin,
};
pub use store::WgKeyStore;

#[cfg(all(feature = "tun-device", target_os = "linux"))]
pub use crate::overlay::NetlinkProvisioner;
