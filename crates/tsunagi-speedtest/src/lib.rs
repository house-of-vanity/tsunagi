//! Directional goodput measurements for an authenticated peer on its existing IPv4 tunnel.
//!
//! The host advertises and negotiates this crate's wire version, admits at most one
//! test at a time, and delivers control messages over its reliable authenticated
//! channel. Probe packets take the same encrypted IPv4 path as application traffic.

mod engine;
mod measurement;
mod packet;
mod wire;

pub use engine::{Config, Handle, Io, Session, initiate, respond};
pub use packet::{Datagram, decode_packet, is_test_packet};
pub use wire::{Control, Direction, Feedback, Progress, Quality, Reading, Start, State};

/// Capability negotiated by peers for this protocol.
pub const PROTOCOL: &str = "speedtest";
/// Wire version of the control records and IPv4 payload, independent of software versions.
pub const VERSION: u16 = 1;
/// Absolute per-direction diagnostic IPv4 traffic budget.
pub const NORMAL_BYTES: u32 = 96 * 1024 * 1024;
/// Suggested per-direction budget on metered paths.
pub const METERED_BYTES: u32 = 8 * 1024 * 1024;
