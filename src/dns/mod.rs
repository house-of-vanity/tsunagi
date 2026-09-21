//! A DNS view of the overlay.
//!
//! The names and addresses of a network, served to the host that runs the
//! agent, so members can be reached by name. Answered from signed state, so a
//! member that is switched off still resolves.
//!
//! Three parts, kept apart on purpose:
//!
//! * [`zone`] decides what the answer is. Pure, and knows nothing about
//!   packets or sockets.
//! * [`server`] puts that on the wire.
//! * `publish` tells the operating system where to send its questions,
//!   which is the only part that differs between platforms.

pub mod server;
pub mod zone;

pub use server::{DnsServer, SharedZone};
pub use zone::{Answer, Query, Zone, ZoneError, ZoneName};
