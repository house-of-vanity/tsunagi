//! The `wg-quic` protocol: WireGuard's cryptography in iroh's QUIC datagrams.
//!
//! A crate of its own, so the line between a protocol and the system level
//! is drawn by the compiler rather than by discipline: nothing here can
//! reach into `tsunagi` beyond what it makes public. It also carries its own
//! version, which is **not** the version peers compare — that is
//! [`ANNOUNCEMENT_VERSION`], and it moves only when the bytes on the wire
//! do, so two peers on different releases keep working.
//!
//! That it uses iroh is a convenience, not a requirement of the design: the
//! system level already has an iroh endpoint that crosses NAT, and plain
//! WireGuard is blocked on some networks where this is not.
//!
//! Where the line falls:
//!
//! * **It knows nothing about reachability.** It is handed a
//!   [`PacketLink`](tsunagi::dataplane::transport::PacketLink) per peer and
//!   moves datagrams over it. Hole punching and relaying are the transport's.
//! * **It knows nothing about addresses, and owns no interface.** One agent
//!   has one interface at the system level, and every protocol carries
//!   traffic for the same addresses on it. A packet arrives here already
//!   routed and leaves here already decrypted, to be checked against the
//!   signed claim by the level that holds those.
//! * **Its announcement says who, not where.** A public key and the network
//!   it is for, so there is nothing about reachability to lie about.
//! * **The core never parses that announcement.** It moves a bounded opaque
//!   blob; only [`announcement`] reads it.
//! * **Its keys are its own.** One per network, in its own store, unrelated
//!   to the iroh device key and to the network secret — which it never sees.
//! * **WireGuard's own crypto is untouched.** The handshake and encryption
//!   run end to end between the two ends of a tunnel, via [`boringtun`]'s
//!   state machine in this process: no kernel module, no `wg` tool, the same
//!   code on every platform.
//!
//! See `docs/wireguard.md` for the full picture.

pub mod announcement;
pub mod device;
pub mod keys;
pub mod plugin;
pub mod store;

pub use announcement::{ANNOUNCEMENT_VERSION, ValidatedAnnouncement, WgAnnouncement};
pub use device::{PeerHealth, PeerStats, PeerSummary, WireguardDevice};
pub use keys::{WgPublicKey, WgSecretKey};
pub use plugin::{
    DEFAULT_MTU, MIN_MTU, NetworkOverview, PeerOverview, WIREGUARD_OVERHEAD, WIREGUARD_PROTOCOL,
    WireguardConfig, WireguardPlugin,
};
pub use store::WgKeyStore;
