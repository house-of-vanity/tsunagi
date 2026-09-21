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
//! routing, address ownership — runs and is tested with no privileges at all;
//! `SystemTunFactory` swaps in a real interface when you want traffic to
//! reach the operating system.
//!
//! See `docs/wireguard.md` for the full picture.

pub mod announcement;
pub mod config;
pub mod device;
pub mod keys;
pub mod overlay;
pub mod packet;
pub mod plugin;
pub mod store;
pub mod tun;

pub use announcement::{ValidatedAnnouncement, WgAnnouncement};
pub use config::{Cidr, DEFAULT_INTERFACE_PREFIX, MAX_INTERFACE_NAME_LEN, interface_name};
pub use device::{PeerHealth, PeerStats, PeerSummary, WireguardDevice};
pub use keys::{WgPublicKey, WgSecretKey};
pub use overlay::{OVERLAY_PREFIX_LEN, overlay_address, overlay_prefix};
pub use packet::IpHeader;
pub use plugin::{
    DEFAULT_MTU, NetworkOverview, PeerOverview, WIREGUARD_PROTOCOL, WireguardConfig,
    WireguardPlugin,
};
pub use store::WgKeyStore;
pub use tun::{MemoryTun, MemoryTunFactory, TunDevice, TunFactory, TunRequest};

#[cfg(feature = "tun-device")]
pub use tun::{SystemTunFactory, interface_exists, interface_has_address, setup_commands};
