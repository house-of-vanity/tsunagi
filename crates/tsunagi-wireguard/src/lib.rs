//! The pure WireGuard protocol plugin for Tsunagi: WireGuard cryptography over direct UDP.
//!
//! Deliberately a separate crate from the core, ensuring clear boundaries:
//! - Direct UDP datagram transport without QUIC encapsulation or double-encryption.
//! - Standard WireGuard cryptography via `boringtun`.
//! - Peer discovery and key exchange managed through the Tsunagi control plane.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod announcement;
pub mod device;
pub mod keys;
pub mod plugin;
pub mod store;
pub mod transport;

pub use announcement::{
    ANNOUNCEMENT_VERSION, ValidatedAnnouncement, WG_PROTOCOL, WG_WIRE_VERSION, WgAnnouncement,
};
pub use device::{PeerHealth, PeerStats, PeerSummary, WireguardDevice};
pub use keys::{WgPublicKey, WgSecretKey};
pub use plugin::{
    DEFAULT_MTU, MIN_MTU, NetworkOverview, PeerOverview, WIREGUARD_OVERHEAD, WireguardConfig,
    WireguardPlugin, local_ip_candidates,
};
pub use store::WgKeyStore;
pub use transport::{DEFAULT_PORT, MAX_UDP_DATAGRAM_SIZE, WireguardLink, WireguardTransport};
