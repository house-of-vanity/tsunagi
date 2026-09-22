//! Bringing a host interface into the state the overlay needs.
//!
//! The agent used to print a list of `ip` commands and ask a human to run
//! them. That is fragile in exactly the way hand-held setup always is: the
//! interface does not survive a reboot, a changed address allocation needs
//! another manual round, and a crashed run leaves a half-configured interface
//! that the next run then trips over.
//!
//! So the agent does it itself, and the shape of that is a *reconciliation*:
//! it is handed an [`InterfacePlan`] describing what the interface should look
//! like, it observes what is actually there, and it applies the difference.
//! Running it twice changes nothing the second time, and running it after a
//! crash repairs whatever was left behind.
//!
//! # Why this is a trait
//!
//! Every platform does this differently — netlink on Linux, `SystemConfiguration`
//! on macOS, the Windows IP Helper API — while the *decision* of what to change
//! is the same everywhere. So the decision lives in [`plan_changes`], which is
//! pure and tested on every platform, and only the execution is behind
//! [`InterfaceProvisioner`].
//!
//! Four implementations:
//!
//! * `NetlinkProvisioner` on Linux, which needs `CAP_NET_ADMIN`.
//! * `WintunProvisioner` on Windows, a Wintun adapter configured with `netsh`,
//!   which needs an elevated process.
//! * [`MockProvisioner`], an in-memory host used by the tests.
//! * [`UnsupportedProvisioner`] elsewhere, which fails with an explanation
//!   and a pointer at the manual route rather than pretending to work.
//!
//! # What it is not allowed to do
//!
//! Nothing here takes a name, an address or a command from the network. The
//! interface name is derived from the network id, the addresses come from the
//! local plugin, and an interface this agent did not create is never deleted
//! or reconfigured — see [`plan_changes`].

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::BoxFuture;
use crate::overlay::OverlayError;

use super::config::Cidr;
use super::tun::TunDevice;

mod mock;
pub use mock::{MockHost, MockProvisioner};

#[cfg(all(feature = "tun-device", target_os = "linux"))]
mod linux;
#[cfg(all(feature = "tun-device", target_os = "linux"))]
pub use linux::NetlinkProvisioner;

#[cfg(all(feature = "tun-device", target_os = "windows"))]
mod windows;
#[cfg(all(feature = "tun-device", target_os = "windows"))]
pub use windows::WintunProvisioner;

mod privilege;
pub use privilege::{Privilege, probe_net_admin};

mod unsupported;
pub use unsupported::UnsupportedProvisioner;

mod factory;
pub use factory::ManagedTunFactory;

/// What an interface should look like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfacePlan {
    /// Interface name. Derived from the network id, never from the network.
    pub name: String,
    /// Interface MTU.
    pub mtu: u32,
    /// Every address the interface should carry, and no others.
    pub addresses: Vec<Cidr>,
}

impl InterfacePlan {
    /// Builds a plan, normalising the address list.
    pub fn new(name: impl Into<String>, mtu: u32, addresses: Vec<Cidr>) -> Self {
        let unique: BTreeSet<Cidr> = addresses.into_iter().collect();
        Self {
            name: name.into(),
            mtu,
            addresses: unique.into_iter().collect(),
        }
    }
}

/// What kind of link is sitting on a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkKind {
    /// Nothing is there.
    Absent,
    /// A TUN interface.
    Tun,
    /// Something else entirely — a bridge, a physical device, a VPN from
    /// another program. Never ours to touch.
    Foreign(String),
}

/// What an interface currently looks like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceState {
    /// What kind of link holds the name.
    pub kind: LinkKind,
    /// Whether a process is attached to the TUN, which the kernel reports as
    /// carrier. A leftover interface from a crashed run has none.
    pub attached: bool,
    /// Whether the link is administratively up.
    pub up: bool,
    /// The current MTU.
    pub mtu: u32,
    /// The addresses currently assigned.
    pub addresses: Vec<Cidr>,
}

impl InterfaceState {
    /// The state of a name nothing is using.
    pub fn absent() -> Self {
        Self {
            kind: LinkKind::Absent,
            attached: false,
            up: false,
            mtu: 0,
            addresses: Vec::new(),
        }
    }
}

/// The steps that turn an [`InterfaceState`] into an [`InterfacePlan`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    /// Remove a stale interface left behind by an earlier run.
    pub delete_link: bool,
    /// Create the interface.
    pub create_link: bool,
    /// Set the MTU, when it is not already right.
    pub set_mtu: Option<u32>,
    /// Bring the link up.
    pub bring_up: bool,
    /// Addresses to add.
    pub add: Vec<Cidr>,
    /// Addresses to remove, because the plan no longer contains them.
    pub remove: Vec<Cidr>,
}

impl Changes {
    /// Whether anything at all needs doing.
    pub fn is_empty(&self) -> bool {
        !self.delete_link
            && !self.create_link
            && self.set_mtu.is_none()
            && !self.bring_up
            && self.add.is_empty()
            && self.remove.is_empty()
    }

    /// A one-line summary for a log line.
    pub fn summary(&self) -> String {
        if self.is_empty() {
            return "already as planned".to_string();
        }
        let mut parts = Vec::new();
        if self.delete_link {
            parts.push("remove a stale interface".to_string());
        }
        if self.create_link {
            parts.push("create the interface".to_string());
        }
        if let Some(mtu) = self.set_mtu {
            parts.push(format!("set mtu {mtu}"));
        }
        if self.bring_up {
            parts.push("bring it up".to_string());
        }
        for address in &self.add {
            parts.push(format!("add {address}"));
        }
        for address in &self.remove {
            parts.push(format!("remove {address}"));
        }
        parts.join(", ")
    }
}

/// Decides what to change, or refuses.
///
/// `ours` says whether this process created the interface in its current run.
/// It is the whole reason this can be safe: an interface we made is adjusted
/// in place, and an interface we did not make is only ever *replaced* when it
/// is plainly abandoned.
///
/// The refusals matter more than the changes:
///
/// * A link that is not a TUN is never touched. Deriving the name from the
///   network id makes a collision with a real device unlikely, not impossible,
///   and destroying somebody's bridge because it happened to share a name is
///   not a recoverable mistake.
/// * A TUN with a process attached to it is never deleted. It is somebody
///   else's working interface — most likely another agent on this host — and
///   yanking it out from under them would break a running overlay.
///
/// What is left is a TUN with nothing attached, which is precisely the
/// footprint of a run that died: those are removed and rebuilt.
pub fn plan_changes(
    current: &InterfaceState,
    plan: &InterfacePlan,
    ours: bool,
) -> Result<Changes, OverlayError> {
    let mut changes = Changes::default();

    match &current.kind {
        LinkKind::Foreign(kind) => {
            return Err(OverlayError::Unavailable(format!(
                "`{}` already exists and is a {kind} interface, not one of ours. \
                 Refusing to touch it. Run with a different interface prefix.",
                plan.name
            )));
        }
        LinkKind::Tun if !ours && current.attached => {
            return Err(OverlayError::Unavailable(format!(
                "`{}` already exists and another process is attached to it. \
                 That is most likely a second agent on this host in the same \
                 network; give one of them a different interface prefix.",
                plan.name
            )));
        }
        LinkKind::Tun if !ours => {
            // Abandoned: a TUN with no carrier is one nothing holds open. It
            // is either a leftover from a run that died or an interface made
            // by the old manual recipe. Either way it is replaced, which also
            // discards whatever stale addresses it carried.
            changes.delete_link = true;
            changes.create_link = true;
        }
        LinkKind::Tun => {}
        LinkKind::Absent => changes.create_link = true,
    }

    if changes.create_link {
        // A fresh interface starts down, with the kernel default MTU and no
        // addresses, so everything in the plan has to be applied.
        changes.set_mtu = Some(plan.mtu);
        changes.bring_up = true;
        changes.add = plan.addresses.clone();
        return Ok(changes);
    }

    if current.mtu != plan.mtu {
        changes.set_mtu = Some(plan.mtu);
    }
    if !current.up {
        changes.bring_up = true;
    }

    let wanted: BTreeSet<Cidr> = plan.addresses.iter().copied().collect();
    let present: BTreeSet<Cidr> = current.addresses.iter().copied().collect();
    changes.add = wanted.difference(&present).copied().collect();
    changes.remove = present.difference(&wanted).copied().collect();

    Ok(changes)
}

/// The result of a reconciliation.
pub struct Provisioned {
    /// What was changed to get here.
    pub changes: Changes,
    /// The packet interface, when this call is what created it.
    ///
    /// Creating the interface and configuring it are the same privileged act
    /// and belong together, so the provisioner owns both. A reconciliation
    /// that only adjusted an interface already in place returns `None`.
    pub device: Option<Arc<dyn TunDevice>>,
}

impl std::fmt::Debug for Provisioned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provisioned")
            .field("changes", &self.changes)
            .field("device", &self.device.as_ref().map(|device| device.name()))
            .finish()
    }
}

/// Applies an [`InterfacePlan`] to the host.
///
/// Implementations are expected to be idempotent: calling [`reconcile`] twice
/// with the same plan changes nothing the second time.
///
/// [`reconcile`]: InterfaceProvisioner::reconcile
pub trait InterfaceProvisioner: Send + Sync + std::fmt::Debug + 'static {
    /// A short name used in diagnostics.
    fn name(&self) -> &str;

    /// Brings the interface in line with the plan, and reports what it did.
    fn reconcile<'a>(
        &'a self,
        plan: &'a InterfacePlan,
    ) -> BoxFuture<'a, Result<Provisioned, OverlayError>>;

    /// Removes an interface this provisioner created.
    ///
    /// Removing one that is already gone succeeds: this runs on the shutdown
    /// path, where the interface having vanished is the desired outcome.
    fn remove<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), OverlayError>>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v6(last: u16) -> Cidr {
        Cidr {
            addr: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last)),
            prefix_len: 64,
        }
    }

    fn v4(last: u8) -> Cidr {
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 13, 37, last)),
            prefix_len: 24,
        }
    }

    fn plan() -> InterfacePlan {
        InterfacePlan::new("tsuntest", 1280, vec![v6(1), v4(69)])
    }

    #[test]
    fn an_absent_interface_is_created_and_fully_configured() {
        let changes = plan_changes(&InterfaceState::absent(), &plan(), false).unwrap();
        assert!(changes.create_link);
        assert!(!changes.delete_link);
        assert_eq!(changes.set_mtu, Some(1280));
        assert!(changes.bring_up);
        assert_eq!(changes.add, vec![v4(69), v6(1)]);
        assert!(changes.remove.is_empty());
    }

    #[test]
    fn an_abandoned_tun_from_a_crashed_run_is_replaced() {
        // The footprint of a run that died: the interface is still there, it
        // still has its old addresses, and nothing holds it open.
        let current = InterfaceState {
            kind: LinkKind::Tun,
            attached: false,
            up: true,
            mtu: 1280,
            addresses: vec![v4(178)],
        };
        let changes = plan_changes(&current, &plan(), false).unwrap();
        assert!(changes.delete_link, "the stale interface goes");
        assert!(changes.create_link);
        // Replacing it discards the stale address, so it need not be removed
        // one by one.
        assert_eq!(changes.add, vec![v4(69), v6(1)]);
        assert!(changes.remove.is_empty());
    }

    #[test]
    fn a_foreign_interface_is_never_touched() {
        let current = InterfaceState {
            kind: LinkKind::Foreign("bridge".into()),
            attached: true,
            up: true,
            mtu: 1500,
            addresses: vec![v4(1)],
        };
        let err = plan_changes(&current, &plan(), false).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("bridge"), "{message}");
        assert!(message.contains("Refusing to touch it"), "{message}");
    }

    #[test]
    fn a_tun_another_process_is_using_is_never_deleted() {
        let current = InterfaceState {
            kind: LinkKind::Tun,
            attached: true,
            up: true,
            mtu: 1280,
            addresses: vec![v6(1)],
        };
        let err = plan_changes(&current, &plan(), false).unwrap_err();
        assert!(err.to_string().contains("another process"), "{err}");
    }

    #[test]
    fn our_own_interface_is_adjusted_in_place() {
        // The live case: our address allocation changed while running. The
        // interface must not be recreated, or every tunnel on it would drop.
        let current = InterfaceState {
            kind: LinkKind::Tun,
            attached: true,
            up: true,
            mtu: 1280,
            addresses: vec![v6(1), v4(178)],
        };
        let changes = plan_changes(&current, &plan(), true).unwrap();
        assert!(!changes.delete_link && !changes.create_link);
        assert_eq!(changes.add, vec![v4(69)]);
        assert_eq!(changes.remove, vec![v4(178)]);
    }

    #[test]
    fn reconciling_an_interface_that_already_matches_changes_nothing() {
        let current = InterfaceState {
            kind: LinkKind::Tun,
            attached: true,
            up: true,
            mtu: 1280,
            addresses: vec![v4(69), v6(1)],
        };
        let changes = plan_changes(&current, &plan(), true).unwrap();
        assert!(changes.is_empty(), "{changes:?}");
        assert_eq!(changes.summary(), "already as planned");
    }

    #[test]
    fn a_wrong_mtu_or_a_down_link_is_corrected() {
        let current = InterfaceState {
            kind: LinkKind::Tun,
            attached: true,
            up: false,
            mtu: 1500,
            addresses: vec![v4(69), v6(1)],
        };
        let changes = plan_changes(&current, &plan(), true).unwrap();
        assert_eq!(changes.set_mtu, Some(1280));
        assert!(changes.bring_up);
        assert!(changes.add.is_empty() && changes.remove.is_empty());
    }

    #[test]
    fn a_plan_deduplicates_and_orders_its_addresses() {
        let plan = InterfacePlan::new("x", 1280, vec![v6(1), v4(69), v6(1)]);
        assert_eq!(plan.addresses, vec![v4(69), v6(1)]);
    }
}
