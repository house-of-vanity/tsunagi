//! Telling the operating system where to send its questions.
//!
//! The server answers whether or not this works. That is the whole reason it
//! is a separate thing: if the resolver cannot be configured — no
//! systemd-resolved, an unwilling polkit, a platform nobody has written this
//! for — the port is still up and the user can point something at it by
//! hand. A failure here is a degraded overlay, not a broken one.
//!
//! Only the *mechanics* differ between systems. What has to be arranged is
//! the same everywhere: send questions for these suffixes to this address,
//! through this interface, and do not make it the resolver for anything
//! else. That is [`Published`]; the rest is behind [`DnsPublisher`].

use std::net::SocketAddr;

use crate::BoxFuture;

mod mock;
pub use mock::MockPublisher;

#[cfg(all(feature = "dns-publish", target_os = "linux"))]
mod resolved;
#[cfg(all(feature = "dns-publish", target_os = "linux"))]
pub use resolved::ResolvedPublisher;

mod unsupported;
pub use unsupported::UnsupportedPublisher;

/// What the operating system is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The interface questions should be sent through.
    ///
    /// The server listens on an overlay address, which is only reachable
    /// over the overlay interface, so the two travel together.
    pub interface: String,
    /// Where the server is listening.
    pub server: SocketAddr,
    /// The suffixes that belong to this server.
    ///
    /// Routing suffixes only: they say *which questions* come here, never
    /// that this is the resolver for anything else.
    pub domains: Vec<String>,
}

/// Why the resolver could not be told.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublishError {
    /// There is nothing here that can be configured this way.
    #[error("{0}")]
    Unavailable(String),
    /// Something is there, and it declined.
    ///
    /// Separate from a plain failure because the answer is different: this
    /// one is about who the agent is running as, not about whether the thing
    /// works.
    #[error("{0}")]
    Refused(String),
    /// It was there, it accepted the request, and it went wrong anyway.
    #[error("{0}")]
    Failed(String),
}

impl PublishError {
    /// What the user can do about it, when there is something.
    pub fn remedy(&self) -> Option<&'static str> {
        match self {
            PublishError::Refused(_) => Some(
                "systemd-resolved asks polkit before accepting this, and polkit \
                 decides by user. Run the agent as a system service, or install a \
                 polkit rule allowing this user the `org.freedesktop.resolve1.set-*` \
                 actions.",
            ),
            _ => None,
        }
    }
}

/// Arranges for the operating system to ask this server.
pub trait DnsPublisher: Send + Sync + std::fmt::Debug + 'static {
    /// A short name used in diagnostics.
    fn name(&self) -> &str;

    /// Applies the setting, replacing whatever this publisher set before.
    fn apply<'a>(&'a self, published: &'a Published) -> BoxFuture<'a, Result<(), PublishError>>;

    /// Undoes it.
    ///
    /// Reverting something that was never applied succeeds: this runs on the
    /// shutdown path, where the setting being gone is the point.
    fn revert(&self) -> BoxFuture<'_, Result<(), PublishError>>;
}

/// The kernel's index for an interface.
///
/// From sysfs, which needs no privileges and no netlink round trip.
#[cfg(target_os = "linux")]
pub fn interface_index(name: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(not(target_os = "linux"))]
pub fn interface_index(_name: &str) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn only_a_refusal_suggests_what_to_do_about_it() {
        // The other two are conditions of the host, not of the user.
        assert!(PublishError::Refused("no".into()).remedy().is_some());
        assert!(PublishError::Unavailable("none".into()).remedy().is_none());
        assert!(PublishError::Failed("bang".into()).remedy().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_interface_index_is_read_from_the_running_kernel() {
        assert_eq!(interface_index("lo"), Some(1));
        assert_eq!(interface_index("tsunagi-no-such-interface"), None);
    }
}
