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

pub mod publish;
pub mod server;
pub mod zone;

pub use publish::{DnsPublisher, PublishError, Published};

use std::net::{Ipv4Addr, SocketAddr};

/// Where the server should try to listen, best first.
///
/// The overlay address comes first: that is what the system resolver is
/// pointed at, and it is reachable only over the overlay interface, so a
/// question for these names cannot arrive from anywhere else.
///
/// Loopback second, and it is not merely a fallback for having no overlay
/// address. An address this agent has been *allocated* is not necessarily an
/// address that is *on an interface* — with no privileges, with `--no-tun`,
/// or in the moment before the interface is configured, it is not — and
/// binding to one that is not there fails. Trying loopback afterwards is
/// what keeps the promise that the port comes up regardless.
pub fn listen_addresses(overlay: Option<Ipv4Addr>, port: u16) -> Vec<SocketAddr> {
    let mut candidates = Vec::with_capacity(2);
    if let Some(overlay) = overlay {
        candidates.push(SocketAddr::from((overlay, port)));
    }
    candidates.push(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    candidates
}

pub use server::{DnsServer, SharedZone};
pub use zone::{Answer, Query, Zone, ZoneError, ZoneName};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_overlay_is_preferred_and_loopback_is_always_offered() {
        // Loopback is in the list even when there is an overlay address,
        // because being allocated one is not the same as it being on an
        // interface — and binding to one that is not there fails.
        assert_eq!(
            listen_addresses(Some(Ipv4Addr::new(10, 13, 37, 69)), 5354),
            vec![
                "10.13.37.69:5354".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:5354".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert_eq!(
            listen_addresses(None, 5354),
            vec!["127.0.0.1:5354".parse::<SocketAddr>().unwrap()]
        );
    }
}
