//! Authenticated, per-neighbour WireGuard UDP carriers. IP encryption is independent.
#![deny(unsafe_code)]
#![warn(missing_docs)]
mod addresses;
mod masking;
mod plugin;
pub mod profile;
mod session;
mod stun;
mod transport;
pub use addresses::{local_ip_candidates, prioritize_local_subnet};
pub use plugin::AwgPlugin as UdpCarrier;
pub use transport::{AwgTransport as UdpTransport, PairOverview};
/// External ordinary WireGuard carrier identifier.
pub const WG_PROTOCOL: &str = "wg";
/// Wire version of the private UDP negotiation and carrier frames.
pub const WG_WIRE_VERSION: u16 = 2;
/// Masked carrier identifier used by the shared pair engine.
pub const AWG_PROTOCOL: &str = "awg";
/// Wire version of masked carrier frames and private negotiation.
pub const AWG_WIRE_VERSION: u16 = 2;
