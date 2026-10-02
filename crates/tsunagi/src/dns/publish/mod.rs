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

#[cfg(all(feature = "dns-publish", target_os = "windows"))]
mod windows;
#[cfg(all(feature = "dns-publish", target_os = "windows"))]
pub use windows::NrptPublisher;

#[cfg(all(feature = "dns-publish", target_os = "macos"))]
mod macos;
#[cfg(all(feature = "dns-publish", target_os = "macos"))]
pub use macos::ResolverDirPublisher;

mod unsupported;
pub use unsupported::UnsupportedPublisher;

/// What the operating system is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The interface questions should be sent through.
    ///
    /// The server listens on an overlay address, which is only reachable
    /// over the overlay interface, so the two travel together. It must be an
    /// interface this agent created: configuring one it did not is
    /// configuring somebody else's.
    pub interface: String,
    /// Every address the server is listening on, best first.
    ///
    /// One per address family, so a resolver reaches it over whichever it
    /// uses. All of them are published together and none is preferred by
    /// this: which one a resolver picks is its business.
    pub servers: Vec<SocketAddr>,
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
    /// Whether waiting will fix it.
    ///
    /// A refusal will not change on its own — somebody has to grant
    /// permission — so retrying it at the pace of everything else is just
    /// noise. Anything else might be a service still starting.
    pub fn needs_a_human(&self) -> bool {
        matches!(self, PublishError::Refused(_))
    }

    /// One line for a status table.
    pub fn remedy(&self) -> Option<&'static str> {
        match self {
            PublishError::Refused(_) => Some(
                "grant this user the `org.freedesktop.resolve1.set-*` actions in \
                 /etc/polkit-1/rules.d, or run the agent as a system service",
            ),
            _ => None,
        }
    }
}

/// The polkit rule that lets this user configure the resolver.
///
/// Printed in full rather than described, because the point of this feature
/// is that the user has as little to do as possible, and "write a polkit
/// rule" is a great deal more work than pasting one.
///
/// It grants exactly the four actions this agent calls and nothing else.
/// polkit decides by user id — a capability does not help here — so there is
/// no way to do this from inside the process.
pub fn polkit_recipe(user: &str) -> String {
    format!(
        "sudo tee /etc/polkit-1/rules.d/50-tsunagi-resolved.rules > /dev/null <<'RULE'\n\
         polkit.addRule(function(action, subject) {{\n\
         \x20   var allowed = [\n\
         \x20       \"org.freedesktop.resolve1.set-dns-servers\",\n\
         \x20       \"org.freedesktop.resolve1.set-domains\",\n\
         \x20       \"org.freedesktop.resolve1.set-default-route\",\n\
         \x20       \"org.freedesktop.resolve1.revert\"\n\
         \x20   ];\n\
         \x20   if (allowed.indexOf(action.id) >= 0 && subject.user == \"{user}\") {{\n\
         \x20       return polkit.Result.YES;\n\
         \x20   }}\n\
         }});\n\
         RULE"
    )
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

/// The kernel's index for an interface.
///
/// Only the systemd-resolved publisher needs one, so off Linux there is
/// nothing to look up and this is always `None`.
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

    #[test]
    fn only_a_refusal_waits_for_a_person() {
        // The rest may come right on their own, so they are worth retrying
        // at the ordinary pace; a refusal is not.
        assert!(PublishError::Refused("no".into()).needs_a_human());
        assert!(!PublishError::Unavailable("none".into()).needs_a_human());
        assert!(!PublishError::Failed("bang".into()).needs_a_human());
    }

    #[test]
    fn the_polkit_recipe_grants_what_is_called_and_no_more() {
        let recipe = polkit_recipe("ab");
        for action in [
            "set-dns-servers",
            "set-domains",
            "set-default-route",
            "revert",
        ] {
            assert!(recipe.contains(action), "{action} missing from:\n{recipe}");
        }
        // Nothing beyond what the agent calls: a rule that granted the lot
        // would be handing out more than this feature needs.
        for other in ["set-dnssec", "set-mdns", "register-service", "set-llmnr"] {
            assert!(!recipe.contains(other), "{other} should not be granted");
        }
        assert!(recipe.contains("subject.user == \"ab\""));
        // ES5: the rules engine is duktape and has no `startsWith`.
        assert!(!recipe.contains("startsWith"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_interface_index_is_read_from_the_running_kernel() {
        assert_eq!(interface_index("lo"), Some(1));
        assert_eq!(interface_index("tsunagi-no-such-interface"), None);
    }
}
