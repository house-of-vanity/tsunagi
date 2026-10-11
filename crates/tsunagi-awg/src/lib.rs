//! Pairwise, ephemeral Amnezia packet transport with independent end-to-end tunnels.
//! All negotiation travels over authenticated Tsunagi control sessions.
mod masking;
mod plugin;
pub mod profile;
mod session;
mod stun;
mod transport;

pub use plugin::AwgPlugin;
pub use transport::{AwgTransport, PairOverview};

/// Protocol identifier and default second-choice direct transport.
pub const AWG_PROTOCOL: &str = "awg";
/// Tsunagi AWG wire version, independent of software releases.
pub const AWG_WIRE_VERSION: u16 = 1;
