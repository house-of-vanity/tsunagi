//! Managing the overlay interface on macOS, through utun and `ifconfig`/`route`.
//!
//! The shape is the same as the Linux and Windows provisioners: observe what
//! is there, [`plan_changes`](super::plan_changes) to decide what to do, apply
//! the difference. Only the mechanisms differ.
//!
//! # Creating the interface
//!
//! The interface is a `utun` device, created through the `tun` dependency's
//! safe wrapper — [`open_tun`](super::super::tun) — over the in-kernel
//! `com.apple.net.utun_control` control socket. No kernel extension and no
//! Network Extension entitlement is involved; what it needs is root. The
//! device is not made persistent, so closing the last file descriptor removes
//! the interface — it goes away when the agent does, however the agent ends.
//!
//! # The kernel names the interface, not us
//!
//! Unlike Linux and Windows, a utun interface cannot be given an arbitrary
//! name: it is always `utunN`, and the unit number is assigned by the kernel.
//! So the name derived from the network id (`tsun…`) is only ever a *request*;
//! the real name is read back off the device after it is opened, and
//! everything downstream — the host rules, the resolver publication — uses the
//! real one. The agent adopts it as soon as the device is created (see
//! [`Interface`](crate::overlay::Interface)).
//!
//! # Configuring it
//!
//! Addresses, MTU and routes are applied with `ifconfig` and `route`. On Linux
//! the same work is done in process over a netlink socket; here there is no
//! equivalent this crate may call, because the in-process route is raw `ioctl`
//! and `PF_ROUTE` and that is `unsafe`. The tools are invoked by absolute path
//! from `/sbin`, so nothing on `PATH` can stand in for them, and every value
//! handed to them is one this agent derived — an interface name chosen by the
//! kernel, an address it allocated — never anything a peer said.
//!
//! # Observing it
//!
//! The interface table is read through `netdev`, a safe wrapper over
//! `getifaddrs`. An interface is matched by its real `utunN` name, which only
//! matters on reconfiguration: the first create always makes a fresh device.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use crate::BoxFuture;
use crate::overlay::OverlayError;

use super::super::config::Cidr;
use super::super::tun::{TunDevice, TunRequest, open_tun};
use super::privilege::{Privilege, probe_net_admin};
use super::{
    InterfacePlan, InterfaceProvisioner, InterfaceState, LinkKind, Provisioned, plan_changes,
};

/// Manages the overlay interface with utun and `ifconfig`/`route`.
#[derive(Debug)]
pub struct UtunProvisioner {
    /// Interfaces this process created, by their real `utunN` name, so a
    /// reconfiguration adjusts them rather than trying to create them again.
    ours: Mutex<Vec<String>>,
    /// Devices kept alive for as long as the interface should exist. Dropping
    /// one closes the last descriptor, which removes the utin interface.
    held: Mutex<Vec<(String, Arc<dyn TunDevice>)>>,
}

impl UtunProvisioner {
    /// Creates the provisioner, after checking the platform supports one.
    ///
    /// Whether the process is actually root is not checked here — reading the
    /// effective uid needs a libc call this crate forbids — so a missing
    /// privilege surfaces at utun creation with a precise message, the same
    /// way the Linux and Windows paths treat the open itself as the honest
    /// answer.
    pub fn new() -> Result<Self, OverlayError> {
        match probe_net_admin() {
            Privilege::Available => {}
            Privilege::Missing(reason) => return Err(OverlayError::Unavailable(reason)),
            Privilege::Unsupported => {
                return Err(OverlayError::Unavailable(
                    "interface management is not compiled in".to_string(),
                ));
            }
        }
        Ok(Self {
            ours: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
        })
    }

    fn is_ours(&self, name: &str) -> bool {
        lock(&self.ours).iter().any(|owned| owned == name)
    }

    /// Opens the utun device, which is what creates it. The kernel assigns the
    /// name, so the returned device reports a `utunN` that is not `plan.name`.
    fn create_device(&self, plan: &InterfacePlan) -> Result<Arc<dyn TunDevice>, OverlayError> {
        let request = TunRequest::bare(plan.name.clone(), plan.mtu);
        open_tun(&request)
    }
}

impl InterfaceProvisioner for UtunProvisioner {
    fn name(&self) -> &str {
        "utun"
    }

    fn reconcile<'a>(
        &'a self,
        plan: &'a InterfacePlan,
    ) -> BoxFuture<'a, Result<Provisioned, OverlayError>> {
        Box::pin(async move {
            // A reconfiguration: the plan carries the real `utunN` name the
            // agent adopted after the first create, so the interface is there
            // and only the addresses and MTU need bringing into line.
            if self.is_ours(&plan.name) {
                let current = observe(&plan.name).await;
                let changes = plan_changes(&current, plan, true)?;
                configure(&plan.name, &changes).await?;
                return Ok(Provisioned {
                    changes,
                    device: None,
                });
            }

            // The first create. The kernel assigns the unit, so the device is
            // opened first and its real name used for everything after.
            let device = self.create_device(plan)?;
            let real = device.name().to_string();

            // A fresh interface starts with nothing on it, so the whole plan is
            // applied. `plan_changes` against an absent interface is exactly
            // that decision; its `create_link` flag is already satisfied by the
            // open above, so `configure` ignores it and only applies the rest.
            let changes = plan_changes(&InterfaceState::absent(), plan, false)?;

            // A failure here leaves an interface that exists but cannot carry
            // traffic. Drop the device so the utun closes, and report, rather
            // than leave a trap behind.
            if let Err(err) = configure(&real, &changes).await {
                drop(device);
                return Err(err);
            }

            lock(&self.ours).push(real.clone());
            lock(&self.held).push((real, Arc::clone(&device)));
            Ok(Provisioned {
                changes,
                device: Some(device),
            })
        })
    }

    fn remove<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), OverlayError>> {
        Box::pin(async move {
            // Dropping the device closes the last descriptor, which removes the
            // utun interface and the routes that were bound to it. There is
            // nothing to flush: a utun never outlives the process that holds it.
            lock(&self.held).retain(|(held, _)| held != name);
            lock(&self.ours).retain(|owned| owned != name);
            Ok(())
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// `fe80::/10` and `169.254.0.0/16`, which macOS assigns on its own.
fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => addr.is_link_local(),
        IpAddr::V6(addr) => (addr.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// What the interface named `name` currently looks like.
///
/// Never fails: a name nothing is using reads as [`InterfaceState::absent`],
/// which is what the plan then acts on.
async fn observe(name: &str) -> InterfaceState {
    let name = name.to_string();
    let found = tokio::task::spawn_blocking(move || {
        netdev::get_interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
    })
    .await
    .ok()
    .flatten();

    let Some(iface) = found else {
        return InterfaceState::absent();
    };

    let mut addresses: Vec<Cidr> = Vec::new();
    for net in &iface.ipv4 {
        if let Ok(cidr) = Cidr::new(IpAddr::V4(net.addr()), net.prefix_len())
            && !is_link_local(cidr.addr)
        {
            addresses.push(cidr);
        }
    }
    for net in &iface.ipv6 {
        if let Ok(cidr) = Cidr::new(IpAddr::V6(net.addr()), net.prefix_len())
            && !is_link_local(cidr.addr)
        {
            addresses.push(cidr);
        }
    }
    addresses.sort();

    InterfaceState {
        // Only ever reached for an interface this agent created (see
        // `reconcile`), so it is ours and a TUN by construction.
        kind: LinkKind::Tun,
        attached: iface.is_up(),
        up: iface.is_up(),
        mtu: iface.mtu.unwrap_or(0),
        addresses,
    }
}

/// Applies MTU, link state, addresses and the on-link routes they imply.
async fn configure(name: &str, changes: &super::Changes) -> Result<(), OverlayError> {
    if let Some(mtu) = changes.set_mtu {
        set_mtu(name, mtu).await?;
    }
    for cidr in &changes.remove {
        // Best effort: an address that is already gone is the outcome wanted.
        if let Err(err) = address_del(name, *cidr).await {
            tracing::debug!(interface = %name, %cidr, %err, "could not remove address");
        }
        if let Err(err) = route_del(name, *cidr).await {
            tracing::debug!(interface = %name, %cidr, %err, "could not remove route");
        }
    }
    for cidr in &changes.add {
        address_add(name, *cidr).await?;
        // The subnet route makes the whole overlay range reach the interface;
        // a point-to-point utun does not install one from the address alone. A
        // host address (/32 or /128) needs none. Best effort: a route that is
        // already there is the outcome wanted.
        if let Err(err) = route_add(name, *cidr).await {
            tracing::debug!(interface = %name, %cidr, %err, "could not add route");
        }
    }
    if changes.bring_up {
        // Best effort: a utun with a descriptor open is up already, and a
        // failure to nudge it is not a reason to fail the whole reconcile.
        if let Err(err) = set_up(name).await {
            tracing::debug!(interface = %name, %err, "could not enable the interface");
        }
    }
    Ok(())
}

/// The network address of a CIDR, with the host bits cleared.
fn network_of(cidr: Cidr) -> IpAddr {
    match cidr.addr {
        IpAddr::V4(addr) => {
            let bits = u32::from(addr);
            let mask = if cidr.prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(cidr.prefix_len))
            };
            IpAddr::V4(Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(addr) => {
            let bits = u128::from(addr);
            let mask = if cidr.prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(cidr.prefix_len))
            };
            IpAddr::V6(Ipv6Addr::from(bits & mask))
        }
    }
}

/// Whether a CIDR is a single host address, which needs no subnet route.
fn is_host_route(cidr: Cidr) -> bool {
    match cidr.addr {
        IpAddr::V4(_) => cidr.prefix_len >= 32,
        IpAddr::V6(_) => cidr.prefix_len >= 128,
    }
}

/// The `ifconfig` arguments that add an address to a utun interface.
///
/// A utun is point-to-point, so the IPv4 form names the address as its own
/// peer; `alias` lets several coexist on the one interface.
fn address_add_args(name: &str, cidr: Cidr) -> Vec<String> {
    match cidr.addr {
        IpAddr::V4(addr) => vec![
            name.into(),
            "inet".into(),
            format!("{addr}/{}", cidr.prefix_len),
            addr.to_string(),
            "alias".into(),
        ],
        IpAddr::V6(addr) => vec![
            name.into(),
            "inet6".into(),
            format!("{addr}/{}", cidr.prefix_len),
            "alias".into(),
        ],
    }
}

/// The `ifconfig` arguments that remove an address from a utun interface.
fn address_del_args(name: &str, cidr: Cidr) -> Vec<String> {
    let family = match cidr.addr {
        IpAddr::V4(_) => "inet",
        IpAddr::V6(_) => "inet6",
    };
    vec![
        name.into(),
        family.into(),
        cidr.addr.to_string(),
        "-alias".into(),
    ]
}

/// The `route` arguments that point a CIDR's subnet at the interface.
fn route_add_args(name: &str, cidr: Cidr) -> Vec<String> {
    let family = match cidr.addr {
        IpAddr::V4(_) => "-inet",
        IpAddr::V6(_) => "-inet6",
    };
    vec![
        "-q".into(),
        "-n".into(),
        "add".into(),
        family.into(),
        "-net".into(),
        format!("{}/{}", network_of(cidr), cidr.prefix_len),
        "-interface".into(),
        name.into(),
    ]
}

/// The `route` arguments that remove that subnet route.
fn route_del_args(name: &str, cidr: Cidr) -> Vec<String> {
    let family = match cidr.addr {
        IpAddr::V4(_) => "-inet",
        IpAddr::V6(_) => "-inet6",
    };
    vec![
        "-q".into(),
        "-n".into(),
        "delete".into(),
        family.into(),
        "-net".into(),
        format!("{}/{}", network_of(cidr), cidr.prefix_len),
        "-interface".into(),
        name.into(),
    ]
}

async fn address_add(name: &str, cidr: Cidr) -> Result<(), OverlayError> {
    ifconfig(address_add_args(name, cidr)).await
}

async fn address_del(name: &str, cidr: Cidr) -> Result<(), OverlayError> {
    ifconfig(address_del_args(name, cidr)).await
}

async fn route_add(name: &str, cidr: Cidr) -> Result<(), OverlayError> {
    if is_host_route(cidr) {
        return Ok(());
    }
    route(route_add_args(name, cidr)).await
}

async fn route_del(name: &str, cidr: Cidr) -> Result<(), OverlayError> {
    if is_host_route(cidr) {
        return Ok(());
    }
    route(route_del_args(name, cidr)).await
}

async fn set_mtu(name: &str, mtu: u32) -> Result<(), OverlayError> {
    ifconfig(vec![name.into(), "mtu".into(), mtu.to_string()]).await
}

async fn set_up(name: &str) -> Result<(), OverlayError> {
    ifconfig(vec![name.into(), "up".into()]).await
}

/// Runs `/sbin/ifconfig`, turning a non-zero exit into an error with its text.
async fn ifconfig(args: Vec<String>) -> Result<(), OverlayError> {
    run("/sbin/ifconfig", args).await
}

/// Runs `/sbin/route`, turning a non-zero exit into an error with its text.
async fn route(args: Vec<String>) -> Result<(), OverlayError> {
    run("/sbin/route", args).await
}

/// Runs a system tool by absolute path, so nothing on `PATH` can stand in for
/// it, and turns a non-zero exit into an error carrying what it said.
async fn run(program: &'static str, args: Vec<String>) -> Result<(), OverlayError> {
    let display = format!("{program} {}", args.join(" "));
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(program).args(&args).output()
    })
    .await
    .map_err(|err| OverlayError::Other(format!("could not run {display}: {err}")))?
    .map_err(|err| OverlayError::Unavailable(format!("could not run {display}: {err}")))?;

    if output.status.success() {
        return Ok(());
    }
    let message = {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let text = if stderr.trim().is_empty() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        if text.is_empty() {
            format!("exit code {}", output.status)
        } else {
            text
        }
    };
    Err(OverlayError::Unavailable(format!(
        "{display} failed: {message}"
    )))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn v4(last: u8, prefix: u8) -> Cidr {
        Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 13, 37, last)), prefix).unwrap()
    }

    fn v6(last: u16, prefix: u8) -> Cidr {
        Cidr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last)),
            prefix,
        )
        .unwrap()
    }

    #[test]
    fn a_v4_address_is_added_point_to_point_with_an_alias() {
        let args = address_add_args("utun5", v4(69, 24));
        assert_eq!(
            args,
            vec!["utun5", "inet", "10.13.37.69/24", "10.13.37.69", "alias"]
        );
    }

    #[test]
    fn a_v6_address_is_added_with_a_prefix_and_an_alias() {
        let args = address_add_args("utun5", v6(1, 128));
        assert_eq!(args, vec!["utun5", "inet6", "fd00::1/128", "alias"]);
    }

    #[test]
    fn deleting_an_address_names_the_family_and_removes_the_alias() {
        let args = address_del_args("utun5", v4(69, 24));
        assert_eq!(args, vec!["utun5", "inet", "10.13.37.69", "-alias"]);
        let args = address_del_args("utun5", v6(1, 128));
        assert_eq!(args, vec!["utun5", "inet6", "fd00::1", "-alias"]);
    }

    #[test]
    fn a_subnet_route_points_the_masked_network_at_the_interface() {
        let args = route_add_args("utun5", v4(69, 24));
        assert_eq!(
            args,
            vec![
                "-q",
                "-n",
                "add",
                "-inet",
                "-net",
                "10.13.37.0/24",
                "-interface",
                "utun5"
            ]
        );
    }

    #[test]
    fn a_host_address_installs_no_subnet_route() {
        assert!(is_host_route(v4(69, 32)));
        assert!(is_host_route(v6(1, 128)));
        assert!(!is_host_route(v4(69, 24)));
        assert!(!is_host_route(v6(1, 64)));
    }

    #[test]
    fn the_network_address_clears_the_host_bits() {
        assert_eq!(
            network_of(v4(69, 24)),
            IpAddr::V4(Ipv4Addr::new(10, 13, 37, 0))
        );
        assert_eq!(
            network_of(Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 69)), 16).unwrap()),
            IpAddr::V4(Ipv4Addr::new(10, 13, 0, 0))
        );
        assert_eq!(
            network_of(v6(0x1234, 64)),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0))
        );
    }

    #[test]
    fn link_local_addresses_are_not_ours_to_manage() {
        assert!(is_link_local(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_link_local(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_link_local(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 1))));
        assert!(!is_link_local(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
    }
}
