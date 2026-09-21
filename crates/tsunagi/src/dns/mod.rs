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

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Where the server should try to listen, one list per address family.
///
/// Both families are served, and independently: a question arrives over
/// whichever one the resolver happens to use, and on a host where one of
/// them is switched off the other must still answer. So neither list failing
/// says anything about the other, and a listener is opened from each.
///
/// Within a list the order is best first. The overlay address comes first:
/// that is what the system resolver is pointed at, and it is reachable only
/// over the overlay interface, so a question for these names cannot arrive
/// from anywhere else.
///
/// Loopback second, and it is not merely a fallback for having no overlay
/// address. An address this agent has been *allocated* is not necessarily an
/// address that is *on an interface* — with no privileges, with `--no-tun`,
/// or in the moment before the interface is configured, it is not — and
/// binding to one that is not there fails. Trying loopback afterwards is
/// what keeps the promise that the port comes up regardless.
///
/// The overlay itself is IPv4, so there is no overlay address to offer for
/// IPv6 and that list is loopback alone. That is a property of the overlay
/// and not of this: a listening address is disposable, unlike an address a
/// member holds in signed state, so serving one family over loopback and the
/// other over the overlay costs nothing and loses nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenPlan {
    /// IPv4 candidates, best first.
    pub v4: Vec<SocketAddr>,
    /// IPv6 candidates, best first.
    pub v6: Vec<SocketAddr>,
}

impl ListenPlan {
    /// The two lists, so a caller can bind one listener from each.
    pub fn families(&self) -> [&[SocketAddr]; 2] {
        [&self.v4, &self.v6]
    }
}

/// Builds the listen plan for one port.
pub fn listen_plan(overlay: Option<Ipv4Addr>, port: u16) -> ListenPlan {
    let mut v4 = Vec::with_capacity(2);
    if let Some(overlay) = overlay {
        v4.push(SocketAddr::from((overlay, port)));
    }
    v4.push(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    ListenPlan {
        v4,
        v6: vec![SocketAddr::from((Ipv6Addr::LOCALHOST, port))],
    }
}

pub use server::{DnsServer, SharedZone};
pub use zone::{Answer, Query, Zone, ZoneError, ZoneName};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn both_families_are_planned_for_and_the_overlay_is_preferred() {
        let plan = listen_plan(Some(Ipv4Addr::new(10, 13, 37, 69)), 5354);
        // Loopback is in the list even when there is an overlay address,
        // because being allocated one is not the same as it being on an
        // interface — and binding to one that is not there fails.
        assert_eq!(
            plan.v4,
            vec![
                "10.13.37.69:5354".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:5354".parse::<SocketAddr>().unwrap(),
            ]
        );
        // IPv6 is served too, over loopback: the overlay has no IPv6
        // address to offer, and that is no reason to answer only one family.
        assert_eq!(plan.v6, vec!["[::1]:5354".parse::<SocketAddr>().unwrap()]);
        assert_eq!(plan.families().len(), 2);
    }

    #[test]
    fn with_no_overlay_address_each_family_still_has_somewhere_to_listen() {
        let plan = listen_plan(None, 5354);
        assert_eq!(
            plan.v4,
            vec!["127.0.0.1:5354".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(plan.v6, vec!["[::1]:5354".parse::<SocketAddr>().unwrap()]);
    }
}
