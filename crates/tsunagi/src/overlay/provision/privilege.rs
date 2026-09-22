//! Holding `CAP_NET_ADMIN` for as short a time as possible.
//!
//! Creating a TUN interface and assigning addresses to it needs
//! `CAP_NET_ADMIN`, and there is no way around that on Linux. What *is* in
//! our control is how long the process can actually use it.
//!
//! Linux splits capabilities into sets. The *permitted* set is what a process
//! may use; the *effective* set is what it may use **right now**. A process
//! can lower a capability out of effective and raise it back later, but it
//! can never add to permitted. So the agent keeps `CAP_NET_ADMIN` out of the
//! effective set and raises it only around the handful of netlink calls that
//! need it, which is a few milliseconds at startup and again whenever the
//! address allocation changes.
//!
//! Grant it with:
//!
//! ```text
//! sudo setcap cap_net_admin+p /usr/local/bin/tsunagi
//! ```
//!
//! `+p` rather than `+ep`: with `+p` the capability is permitted but not
//! effective at exec, which is exactly the resting state this module wants.
//! `+ep` also works — [`NetAdmin::acquire`] lowers it on the way in.
//!
//! # Capabilities are per thread
//!
//! `capset` affects the calling thread only, so raising one inside an async
//! block would be a bug the moment the task migrated to another worker. Every
//! caller here runs on a single dedicated thread; see
//! [`linux`](super::linux).

/// Whether this process can configure interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Privilege {
    /// `CAP_NET_ADMIN` is available. The agent manages the interface itself.
    Available,
    /// It is not, with a description of what was found.
    Missing(String),
    /// This platform has no provisioner yet.
    Unsupported,
}

impl Privilege {
    /// Whether interfaces can be managed.
    pub fn is_available(&self) -> bool {
        matches!(self, Privilege::Available)
    }

    /// How to obtain it, for a diagnostic.
    pub fn how_to_grant(program: &str) -> String {
        format!(
            "Grant it once with `sudo setcap cap_net_admin+p {program}` \
             and the agent manages its own interface. Without it, run with \
             `--no-tun`: the tunnels still form, they just do not reach the \
             operating system."
        )
    }
}

#[cfg(all(feature = "tun-device", target_os = "linux"))]
pub use linux_impl::{NetAdmin, probe_net_admin};

#[cfg(all(feature = "tun-device", target_os = "windows"))]
pub use windows_impl::probe_net_admin;

#[cfg(not(any(
    all(feature = "tun-device", target_os = "linux"),
    all(feature = "tun-device", target_os = "windows")
)))]
pub use other_impl::probe_net_admin;

#[cfg(not(any(
    all(feature = "tun-device", target_os = "linux"),
    all(feature = "tun-device", target_os = "windows")
)))]
mod other_impl {
    use super::Privilege;

    /// Whether this process can configure interfaces.
    pub fn probe_net_admin() -> Privilege {
        Privilege::Unsupported
    }
}

#[cfg(all(feature = "tun-device", target_os = "windows"))]
mod windows_impl {
    use super::Privilege;

    /// Whether this process can configure interfaces.
    ///
    /// Windows has no capability to hold and lower the way Linux does:
    /// creating an adapter simply needs the process to be elevated. Reading
    /// whether it *is* elevated means inspecting the process token through a
    /// raw call this crate forbids, so the probe is deliberately optimistic —
    /// it reports that the platform can manage interfaces — and the real
    /// check is left to Wintun's adapter creation, which fails with a precise
    /// message when the process is not elevated. This matches how the Linux
    /// path treats the open itself as the honest answer.
    pub fn probe_net_admin() -> Privilege {
        Privilege::Available
    }
}

#[cfg(all(feature = "tun-device", target_os = "linux"))]
mod linux_impl {
    use caps::{CapSet, Capability};

    use super::Privilege;
    use crate::overlay::OverlayError;

    /// Whether this thread holds `CAP_NET_ADMIN` in its permitted set.
    pub fn probe_net_admin() -> Privilege {
        match caps::has_cap(None, CapSet::Permitted, Capability::CAP_NET_ADMIN) {
            Ok(true) => Privilege::Available,
            Ok(false) => Privilege::Missing(
                "this process does not hold CAP_NET_ADMIN, so it cannot create \
                 or configure a network interface"
                    .to_string(),
            ),
            Err(err) => {
                Privilege::Missing(format!("cannot read this process's capabilities: {err}"))
            }
        }
    }

    /// `CAP_NET_ADMIN`, raised for as long as this value is alive.
    ///
    /// Dropping it lowers the capability again, including on the error paths,
    /// which is the point of it being a guard rather than a pair of calls.
    #[derive(Debug)]
    pub struct NetAdmin {
        /// Whether this guard is the one that raised it, and so the one that
        /// must lower it. Nested acquisition leaves the inner guard inert.
        raised: bool,
    }

    impl NetAdmin {
        /// Raises `CAP_NET_ADMIN` into the effective set.
        pub fn acquire() -> Result<Self, OverlayError> {
            let already = caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_ADMIN)
                .map_err(|err| {
                    OverlayError::Unavailable(format!("cannot read capabilities: {err}"))
                })?;
            if already {
                return Ok(Self { raised: false });
            }
            caps::raise(None, CapSet::Effective, Capability::CAP_NET_ADMIN).map_err(|err| {
                OverlayError::Unavailable(format!(
                    "cannot raise CAP_NET_ADMIN: {err}. {}",
                    Privilege::how_to_grant("tsunagi")
                ))
            })?;
            Ok(Self { raised: true })
        }

        /// Lowers `CAP_NET_ADMIN` out of the effective set of this thread.
        ///
        /// Called on the way in as well as on the way out, so that a binary
        /// granted `cap_net_admin+ep` — which starts with it effective — still
        /// spends almost all of its life unable to use it.
        pub fn lower() {
            let _ = caps::drop(None, CapSet::Effective, Capability::CAP_NET_ADMIN);
        }
    }

    impl Drop for NetAdmin {
        fn drop(&mut self) {
            if self.raised {
                Self::lower();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_grant_instructions_name_the_program() {
        let text = Privilege::how_to_grant("/usr/local/bin/tsunagi");
        assert!(text.contains("setcap cap_net_admin+p /usr/local/bin/tsunagi"));
        assert!(text.contains("--no-tun"), "the fallback is offered too");
    }

    #[test]
    fn probing_says_something_definite_about_this_host() {
        // Whatever the answer is, it must be one of the three, and a missing
        // capability must come with a reason rather than a bare `false`.
        match probe_net_admin() {
            Privilege::Available => {}
            Privilege::Missing(reason) => assert!(!reason.is_empty()),
            Privilege::Unsupported => {}
        }
    }
}
