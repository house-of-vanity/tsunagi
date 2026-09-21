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

/// Where the server listens, one list per address family.
///
/// Loopback, and only loopback. The zones are a view *for the host running
/// the agent*: it is that host's resolver that is pointed at them. Binding
/// an overlay address instead would put them in front of the whole mesh —
/// and an agent in several networks would then answer one network's
/// questions about another's names, which is precisely what separate
/// networks are for.
///
/// Both families, and independently: a question arrives over whichever one
/// the resolver happens to use, and on a host with one of them switched off
/// the other must still answer. So neither list failing says anything about
/// the other, and a listener is opened from each.
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
pub fn listen_plan(port: u16) -> ListenPlan {
    ListenPlan {
        v4: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))],
        v6: vec![SocketAddr::from((Ipv6Addr::LOCALHOST, port))],
    }
}

pub use server::{DnsServer, SharedZone};
pub use zone::{Answer, Query, Zone, ZoneError, ZoneName, Zones};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn both_families_are_planned_for_and_neither_is_reachable_off_this_host() {
        let plan = listen_plan(5354);
        assert_eq!(
            plan.v4,
            vec!["127.0.0.1:5354".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(plan.v6, vec!["[::1]:5354".parse::<SocketAddr>().unwrap()]);
        assert_eq!(plan.families().len(), 2);
        // Nothing here is reachable from another member: the zones are a
        // view for this host, and an agent in two networks must not answer
        // one network's questions about the other's names.
        for address in plan.families().concat() {
            assert!(address.ip().is_loopback(), "{address} is not loopback");
        }
    }
}
