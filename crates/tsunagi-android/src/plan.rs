//! All addresses and routes installed in the one Android VPN.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tsunagi::overlay::Cidr;

/// An exhaustive VpnService configuration, derived from local core policy.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct VpnPlan {
    /// One address in each active, non-overlapping network.
    pub addresses: Vec<Cidr>,
    /// Payload MTU for every attached network.
    pub mtu: u32,
    /// Capture IPv4 traffic outside the mesh.
    pub full_tunnel: bool,
    /// Preferred IPv4 source for the default route.
    pub exit: Option<IpAddr>,
    /// Capture the limited broadcast when requested by the core.
    pub broadcast: bool,
}

impl VpnPlan {
    /// Device-local DNS endpoint. Never take an address from a joined mesh.
    pub fn dns_address(&self) -> Option<Ipv4Addr> {
        if self.addresses.is_empty() {
            return None;
        }
        [
            Ipv4Addr::new(192, 0, 2, 53),
            Ipv4Addr::new(198, 51, 100, 53),
            Ipv4Addr::new(203, 0, 113, 53),
        ]
        .into_iter()
        .find(|candidate| {
            !self.addresses.iter().any(|cidr| {
                let IpAddr::V4(base) = cidr.addr else {
                    return false;
                };
                tsunagi::state::Ipv4Range {
                    base,
                    prefix_len: cidr.prefix_len,
                }
                .contains(*candidate)
            })
        })
    }

    /// Android uses the first address as primary for unscoped IPv4 traffic.
    pub fn addresses_in_order(&self) -> Vec<Cidr> {
        let mut ordered = self.addresses.clone();
        ordered.sort_by_key(|cidr| (Some(cidr.addr) != self.exit, *cidr));
        ordered
    }

    /// Explicitly route the entire agreed subnet, including its virtual services.
    pub fn routes(&self) -> Vec<String> {
        let mut routes: Vec<_> = self
            .addresses
            .iter()
            .map(|cidr| {
                let p = cidr.prefix_len;
                let base = match cidr.addr {
                    IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(
                        u32::from(a) & u32::MAX.checked_shl(u32::from(32 - p)).unwrap_or(0),
                    )),
                    IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(
                        u128::from(a) & u128::MAX.checked_shl(u32::from(128 - p)).unwrap_or(0),
                    )),
                };
                format!("{base}/{p}")
            })
            .collect();
        if let Some(dns) = self.dns_address() {
            routes.push(format!("{dns}/32"));
        }
        if self.full_tunnel {
            routes.push("0.0.0.0/0".into());
        }
        if self.broadcast {
            routes.push("255.255.255.255/32".into());
        }
        routes.sort();
        routes.dedup();
        routes
    }
}
