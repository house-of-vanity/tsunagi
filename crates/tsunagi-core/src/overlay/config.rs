//! The desired local WireGuard configuration, and how it is rendered.
//!
//! Each agent builds its own configuration from the agreed set of
//! participants. For a full mesh of `N` members that is `N - 1` peers locally;
//! nobody hands out a configuration to anybody else.
//!
//! Nothing in here is free-form text taken from the network. Peer keys,
//! endpoints, allowed prefixes and keepalives are typed values that this
//! module re-serialises itself, so a hostile announcement cannot inject a
//! configuration directive or a command argument.

use std::net::{IpAddr, Ipv6Addr};

use crate::identity::NetworkId;
use crate::overlay::OverlayError;

/// Prefix length of a single IPv6 host address.
const HOST_PREFIX_LEN: u8 = 128;

/// Longest interface name Linux accepts, excluding the terminating NUL.
pub const MAX_INTERFACE_NAME_LEN: usize = 15;

/// Default prefix for interface names this plugin creates.
pub const DEFAULT_INTERFACE_PREFIX: &str = "tsun";

/// An address with a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    /// The address.
    pub addr: IpAddr,
    /// The prefix length in bits.
    pub prefix_len: u8,
}

impl Cidr {
    /// Builds a CIDR, rejecting an impossible prefix length.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, OverlayError> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(OverlayError::Other(format!(
                "prefix length /{prefix_len} is impossible for {addr}"
            )));
        }
        Ok(Self { addr, prefix_len })
    }

    /// A single host address.
    pub fn host(addr: Ipv6Addr) -> Self {
        Self {
            addr: IpAddr::V6(addr),
            prefix_len: HOST_PREFIX_LEN,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// Derives this plugin's interface name for a network.
///
/// The name is stable across restarts and short enough for the platform. Two
/// agents on the same host in the same network must be given different
/// prefixes, or they would derive the same name.
pub fn interface_name(prefix: &str, network: NetworkId) -> Result<String, OverlayError> {
    if prefix.is_empty() {
        return Err(OverlayError::Other(
            "interface prefix must not be empty".into(),
        ));
    }
    if !prefix
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(OverlayError::Other(
            "interface prefix must be lowercase ASCII letters and digits".into(),
        ));
    }
    if prefix.len() >= MAX_INTERFACE_NAME_LEN {
        return Err(OverlayError::Other(format!(
            "interface prefix must be shorter than {MAX_INTERFACE_NAME_LEN} characters"
        )));
    }

    let mut suffix = data_encoding::BASE32_NOPAD.encode(network.as_bytes());
    suffix.make_ascii_lowercase();
    let room = MAX_INTERFACE_NAME_LEN - prefix.len();
    suffix.truncate(room);
    Ok(format!("{prefix}{suffix}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![5u8; 32]).unwrap(),
        )
        .network_id()
    }

    #[test]
    fn interface_names_fit_the_platform_limit_and_are_stable() {
        let id = network("naming");
        let name = interface_name(DEFAULT_INTERFACE_PREFIX, id).unwrap();
        assert_eq!(name.len(), MAX_INTERFACE_NAME_LEN);
        assert!(name.starts_with(DEFAULT_INTERFACE_PREFIX));
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(name, interface_name(DEFAULT_INTERFACE_PREFIX, id).unwrap());
        assert_ne!(
            name,
            interface_name(DEFAULT_INTERFACE_PREFIX, network("other")).unwrap()
        );
        assert_ne!(name, interface_name("wg", id).unwrap());

        assert!(interface_name("", id).is_err());
        assert!(interface_name("has space", id).is_err());
        assert!(interface_name("UPPER", id).is_err());
        assert!(interface_name(&"a".repeat(MAX_INTERFACE_NAME_LEN), id).is_err());
    }

    #[test]
    fn a_cidr_rejects_an_impossible_prefix_length() {
        assert!(Cidr::new("10.0.0.1".parse().unwrap(), 33).is_err());
        assert!(Cidr::new("fd00::1".parse().unwrap(), 129).is_err());
        assert_eq!(
            Cidr::host("fd00::1".parse().unwrap()).to_string(),
            "fd00::1/128"
        );
    }
}
