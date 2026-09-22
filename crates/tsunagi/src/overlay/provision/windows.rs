//! Managing the overlay interface on Windows, through Wintun and `netsh`.
//!
//! The shape is the same as the Linux provisioner: observe what is there,
//! [`plan_changes`](super::plan_changes) to decide what to do, apply the
//! difference. Only the two mechanisms differ.
//!
//! # Creating the interface
//!
//! The interface is a Wintun adapter, created through the `tun` dependency's
//! safe wrapper — [`open_tun`](super::super::tun) — because loading
//! `wintun.dll` is an `unsafe` call and this crate forbids `unsafe`. The
//! adapter is created, not made persistent: closing the last handle to it
//! removes it, so it goes away when the agent does, however the agent ends.
//! The reader and writer inside the device hold that handle, so the adapter
//! lives exactly as long as the device does.
//!
//! # Configuring it
//!
//! Addresses and MTU are applied with `netsh`. On Linux the same work is done
//! in process over a netlink socket; here there is no equivalent that this
//! crate may call, because the in-process route is the IP Helper API and that
//! is `unsafe`. `netsh` is the supported tool for the job, it is invoked by
//! absolute path from `%SystemRoot%` so nothing on `PATH` can stand in for it,
//! and every value handed to it is one this agent derived — an interface name
//! from the network id, an address it allocated — never anything a peer said.
//!
//! # Observing it
//!
//! The interface table is read through `netdev`, whose enumeration is a safe
//! wrapper over the same IP Helper API. An adapter is matched by the friendly
//! name it was created with. A match that carries a default gateway is treated
//! as foreign and left alone: a tsunagi overlay interface never has one, so a
//! gateway is the mark of a real device that happens to share the name.
//!
//! # What Windows cannot do that Linux can
//!
//! Wintun exposes no way to delete an adapter this process did not create, so
//! a leftover from a run that was killed is *reused* rather than replaced: its
//! addresses are flushed and the planned ones applied, which reaches the same
//! end state. A reused adapter is not removed on exit, only closed — that is a
//! Wintun limitation, and the common case of a clean start and a clean stop is
//! unaffected.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use crate::BoxFuture;
use crate::overlay::OverlayError;

use super::super::config::Cidr;
use super::super::tun::{TunDevice, TunRequest, open_tun};
use super::privilege::{Privilege, probe_net_admin};
use super::{
    InterfacePlan, InterfaceProvisioner, InterfaceState, LinkKind, Provisioned, plan_changes,
};

/// Manages the overlay interface with Wintun and `netsh`.
#[derive(Debug)]
pub struct WintunProvisioner {
    /// Interfaces this process created, so they are adjusted rather than
    /// replaced. See [`plan_changes`].
    ours: Mutex<Vec<String>>,
    /// Devices kept alive for as long as the interface should exist. Dropping
    /// one closes the adapter, which removes it if this process created it.
    held: Mutex<Vec<(String, Arc<dyn TunDevice>)>>,
}

impl WintunProvisioner {
    /// Creates the provisioner, after checking the platform supports one.
    ///
    /// Whether the process is actually elevated is not checked here — that
    /// cannot be read without an `unsafe` call — so a missing privilege
    /// surfaces at adapter creation with a precise message, the same way the
    /// Linux path treats the open itself as the honest answer.
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
        lock(&self.ours)
            .iter()
            .any(|owned| owned.eq_ignore_ascii_case(name))
    }

    /// Opens the Wintun adapter, which is what creates it.
    fn create_device(&self, plan: &InterfacePlan) -> Result<Arc<dyn TunDevice>, OverlayError> {
        let request = TunRequest::bare(plan.name.clone(), plan.mtu);
        open_tun(&request)
    }
}

impl InterfaceProvisioner for WintunProvisioner {
    fn name(&self) -> &str {
        "wintun"
    }

    fn reconcile<'a>(
        &'a self,
        plan: &'a InterfacePlan,
    ) -> BoxFuture<'a, Result<Provisioned, OverlayError>> {
        Box::pin(async move {
            let current = observe(&plan.name).await;
            let changes = plan_changes(&current, plan, self.is_ours(&plan.name))?;

            // Wintun cannot delete an adapter this process did not create, so a
            // "delete then create" from `plan_changes` becomes "flush then
            // reuse": clear the stale addresses off the interface that is
            // there, and let the create step below reopen the same adapter.
            // The end state — an adapter carrying exactly the plan's addresses
            // — is identical.
            let flush: Vec<Cidr> = if changes.delete_link {
                tracing::info!(
                    interface = %plan.name,
                    "reusing an abandoned interface left by an earlier run"
                );
                current.addresses.clone()
            } else {
                Vec::new()
            };

            for cidr in flush.iter().chain(changes.remove.iter()) {
                // Best effort: an address that is already gone is the outcome
                // wanted, and refusing to start over one is not worth it.
                if let Err(err) = address_del(&plan.name, *cidr).await {
                    tracing::debug!(interface = %plan.name, %cidr, %err, "could not remove address");
                }
            }

            let device = if changes.create_link {
                let device = self.create_device(plan)?;
                lock(&self.ours).push(plan.name.clone());
                lock(&self.held).push((plan.name.clone(), Arc::clone(&device)));
                Some(device)
            } else {
                None
            };

            // A failure past this point leaves an interface that exists but
            // cannot carry traffic. Undo the bookkeeping for one we just
            // created so it is not mistaken for a working interface, and drop
            // the device so the adapter closes.
            let configured = configure(plan, &changes).await;
            if let Err(err) = configured {
                if changes.create_link {
                    lock(&self.held).retain(|(held, _)| held != &plan.name);
                    lock(&self.ours).retain(|owned| owned != &plan.name);
                }
                return Err(err);
            }

            Ok(Provisioned { changes, device })
        })
    }

    fn remove<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), OverlayError>> {
        Box::pin(async move {
            // Dropping the device closes the adapter, which removes it if this
            // process created it. A reused adapter is only closed, not removed;
            // flushing its addresses first keeps no stale configuration behind.
            let current = observe(name).await;
            for cidr in &current.addresses {
                if let Err(err) = address_del(name, *cidr).await {
                    tracing::debug!(interface = %name, %cidr, %err, "could not remove address");
                }
            }
            lock(&self.held).retain(|(held, _)| !held.eq_ignore_ascii_case(name));
            lock(&self.ours).retain(|owned| !owned.eq_ignore_ascii_case(name));
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

/// `fe80::/10` and `169.254.0.0/16`, which Windows assigns on its own.
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
            .find(|iface| match &iface.friendly_name {
                Some(friendly) => friendly.eq_ignore_ascii_case(&name),
                None => false,
            })
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

    // A tsunagi overlay interface only ever carries the addresses it was given
    // and no gateway. One that has a gateway is a real device sharing the name,
    // so it is foreign and never touched.
    let kind = if iface.gateway.is_some() {
        LinkKind::Foreign("gatewayed".to_string())
    } else {
        LinkKind::Tun
    };

    InterfaceState {
        kind,
        // Wintun reports an adapter with a live session as up and an abandoned
        // one as down, so "up" doubles as "some process is holding it".
        attached: iface.is_up(),
        up: iface.is_up(),
        mtu: iface.mtu.unwrap_or(0),
        addresses,
    }
}

/// Applies MTU, link state and addresses.
async fn configure(plan: &InterfacePlan, changes: &super::Changes) -> Result<(), OverlayError> {
    if let Some(mtu) = changes.set_mtu {
        set_mtu(&plan.name, mtu).await?;
    }
    for cidr in &changes.add {
        address_add(&plan.name, *cidr).await?;
    }
    if changes.bring_up {
        // Best effort: a Wintun adapter with a session is up already, and a
        // failure to nudge it is not a reason to fail the whole reconcile.
        if let Err(err) = set_up(&plan.name).await {
            tracing::debug!(interface = %plan.name, %err, "could not enable the interface");
        }
    }
    Ok(())
}

/// The dotted netmask for an IPv4 prefix length.
fn ipv4_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(u32::MAX << (32 - u32::from(prefix_len)))
    }
}

/// The `netsh` arguments that add an address to an interface.
fn address_add_args(name: &str, cidr: Cidr) -> Vec<String> {
    match cidr.addr {
        IpAddr::V4(addr) => vec![
            "interface".into(),
            "ipv4".into(),
            "add".into(),
            "address".into(),
            format!("name={name}"),
            format!("address={addr}"),
            format!("mask={}", ipv4_mask(cidr.prefix_len)),
            "store=active".into(),
        ],
        IpAddr::V6(addr) => vec![
            "interface".into(),
            "ipv6".into(),
            "add".into(),
            "address".into(),
            format!("interface={name}"),
            format!("address={addr}/{}", cidr.prefix_len),
            "store=active".into(),
        ],
    }
}

/// The `netsh` arguments that remove an address from an interface.
fn address_del_args(name: &str, cidr: Cidr) -> Vec<String> {
    match cidr.addr {
        IpAddr::V4(addr) => vec![
            "interface".into(),
            "ipv4".into(),
            "delete".into(),
            "address".into(),
            format!("name={name}"),
            format!("address={addr}"),
            "store=active".into(),
        ],
        IpAddr::V6(addr) => vec![
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "address".into(),
            format!("interface={name}"),
            format!("address={addr}"),
            "store=active".into(),
        ],
    }
}

/// The `netsh` arguments that set an interface's MTU, one call per family.
fn mtu_args(name: &str, family: &str, mtu: u32) -> Vec<String> {
    vec![
        "interface".into(),
        family.into(),
        "set".into(),
        "subinterface".into(),
        name.into(),
        format!("mtu={mtu}"),
        "store=active".into(),
    ]
}

async fn address_add(name: &str, cidr: Cidr) -> Result<(), OverlayError> {
    netsh(address_add_args(name, cidr)).await
}

async fn address_del(name: &str, cidr: Cidr) -> Result<(), OverlayError> {
    netsh(address_del_args(name, cidr)).await
}

/// Sets the MTU on both families.
///
/// A family that is turned off on the adapter cannot take an MTU, so this
/// fails only when *neither* would — one family carrying the plan's MTU is
/// enough, and refusing the whole interface because the other is disabled
/// would be wrong.
async fn set_mtu(name: &str, mtu: u32) -> Result<(), OverlayError> {
    let v4 = netsh(mtu_args(name, "ipv4", mtu)).await;
    let v6 = netsh(mtu_args(name, "ipv6", mtu)).await;
    match (&v4, &v6) {
        (Err(_), Err(_)) => v4,
        _ => {
            if let Err(err) = &v4 {
                tracing::debug!(interface = %name, %err, "could not set the IPv4 MTU");
            }
            if let Err(err) = &v6 {
                tracing::debug!(interface = %name, %err, "could not set the IPv6 MTU");
            }
            Ok(())
        }
    }
}

async fn set_up(name: &str) -> Result<(), OverlayError> {
    netsh(vec![
        "interface".into(),
        "set".into(),
        "interface".into(),
        format!("name={name}"),
        "admin=enabled".into(),
    ])
    .await
}

/// Runs `netsh` from `%SystemRoot%\System32`, so nothing on `PATH` can stand
/// in for it, and turns a non-zero exit into an error carrying what it said.
async fn netsh(args: Vec<String>) -> Result<(), OverlayError> {
    let program = system32("netsh.exe");
    let display = format!("netsh {}", args.join(" "));
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

/// The absolute path to a program in `System32`.
fn system32(exe: &str) -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    std::path::Path::new(&root).join("System32").join(exe)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::net::Ipv6Addr;

    fn v4(last: u8, prefix: u8) -> Cidr {
        Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 13, 37, last)), prefix).unwrap()
    }

    fn v6(last: u16) -> Cidr {
        Cidr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last)),
            64,
        )
        .unwrap()
    }

    #[test]
    fn a_prefix_length_becomes_the_right_dotted_mask() {
        assert_eq!(ipv4_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(ipv4_mask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(ipv4_mask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(ipv4_mask(0), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn a_v4_address_is_added_by_name_with_a_dotted_mask() {
        let args = address_add_args("tsun0", v4(69, 24));
        assert!(args.contains(&"ipv4".to_string()));
        assert!(args.contains(&"add".to_string()));
        assert!(args.contains(&"name=tsun0".to_string()));
        assert!(args.contains(&"address=10.13.37.69".to_string()));
        assert!(args.contains(&"mask=255.255.255.0".to_string()));
    }

    #[test]
    fn a_v6_address_is_added_by_interface_with_a_prefix() {
        let args = address_add_args("tsun0", v6(1));
        assert!(args.contains(&"ipv6".to_string()));
        assert!(args.contains(&"interface=tsun0".to_string()));
        assert!(args.contains(&"address=fd00::1/64".to_string()));
    }

    #[test]
    fn deleting_an_address_names_no_mask() {
        let args = address_del_args("tsun0", v4(69, 24));
        assert!(args.contains(&"delete".to_string()));
        assert!(args.contains(&"address=10.13.37.69".to_string()));
        assert!(!args.iter().any(|arg| arg.starts_with("mask=")));
    }

    #[test]
    fn the_mtu_is_set_per_family_on_the_subinterface() {
        let args = mtu_args("tsun0", "ipv4", 1280);
        assert!(args.contains(&"subinterface".to_string()));
        assert!(args.contains(&"tsun0".to_string()));
        assert!(args.contains(&"mtu=1280".to_string()));
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

    #[test]
    fn system32_is_absolute_and_ends_with_the_program() {
        let path = system32("netsh.exe");
        assert!(path.is_absolute(), "{path:?}");
        assert!(path.ends_with("netsh.exe"), "{path:?}");
    }
}
