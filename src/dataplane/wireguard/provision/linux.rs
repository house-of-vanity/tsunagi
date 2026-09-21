//! Managing the overlay interface on Linux, through netlink.
//!
//! Everything the old printed recipe did — `ip tuntap add`, `ip link set`,
//! `ip address add` — happens here instead, in this process, over a netlink
//! socket. No `ip` binary is invoked, so nothing this module does can be
//! influenced by `PATH`, by a shell, or by anything a remote peer said.
//!
//! # The interface cleans up after itself
//!
//! The TUN interface is created by opening `/dev/net/tun` and is **not**
//! made persistent, so the kernel destroys it the moment the last file
//! descriptor closes. That covers the ordinary exit, a panic, a `SIGKILL`
//! and a power loss equally: there is no path by which a dead agent leaves an
//! interface behind, because keeping it alive is what needs an action, not
//! removing it.
//!
//! It also means the interface has carrier for its whole life, which removes
//! the two settings the manual recipe needed. `keep_addr_on_down` was only
//! needed because an interface nobody held open lost carrier and had its IPv6
//! addresses flushed; `nodad` only because duplicate address detection cannot
//! finish without carrier.
//!
//! What can still be left behind is an interface from *before* this change —
//! one created persistent by the old recipe — or one from a run killed in the
//! window between `TUNSETIFF` and this module recording it. Those are found
//! at startup and replaced; see
//! [`plan_changes`](super::plan_changes) for the rules that decide it.
//!
//! # Threads
//!
//! Capabilities on Linux are per thread, and netlink checks the credentials
//! of whichever thread calls `sendmsg` — which, with an async netlink client,
//! is the connection task rather than the caller. Raising `CAP_NET_ADMIN`
//! around an `await` would therefore be both wrong and unsound in the "works
//! until the scheduler moves the task" sense.
//!
//! So all netlink work happens on one dedicated thread running a
//! current-thread runtime. Nothing is polled outside a `block_on`, the
//! capability is raised immediately before that call and lowered immediately
//! after, and the connection task lives and dies inside it.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, mpsc};

use futures_util::TryStreamExt;
// Through rtnetlink's own re-export, so the packet types can never drift out
// of step with the client that sends them.
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage};
use rtnetlink::{LinkMessageBuilder, LinkUnspec};

use crate::BoxFuture;
use crate::dataplane::PluginError;

use super::super::config::Cidr;
use super::super::tun::{TunDevice, TunRequest};
use super::privilege::{NetAdmin, Privilege, probe_net_admin};
use super::{
    InterfacePlan, InterfaceProvisioner, InterfaceState, LinkKind, Provisioned, plan_changes,
};

/// A request to the netlink thread.
enum Command {
    /// What does this interface look like right now?
    Observe(String, Reply<InterfaceState>),
    /// Remove this interface.
    Delete(String, Reply<()>),
    /// Apply MTU, link state and addresses.
    Configure(Box<Configure>, Reply<()>),
    /// Stop the thread.
    Stop,
}

type Reply<T> = mpsc::Sender<Result<T, PluginError>>;

/// The configuration half of a reconciliation.
struct Configure {
    name: String,
    mtu: Option<u32>,
    bring_up: bool,
    add: Vec<Cidr>,
    remove: Vec<Cidr>,
}

/// Manages the overlay interface with netlink.
#[derive(Debug)]
pub struct NetlinkProvisioner {
    commands: mpsc::Sender<Command>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Interfaces this process created, so they are adjusted rather than
    /// replaced. See [`plan_changes`].
    ours: Mutex<Vec<String>>,
    /// Devices kept alive for as long as the interface should exist. Dropping
    /// one is what removes the interface from the kernel.
    held: Mutex<Vec<(String, Arc<dyn TunDevice>)>>,
}

impl NetlinkProvisioner {
    /// Starts the netlink thread, after checking this process can use it.
    pub fn new() -> Result<Self, PluginError> {
        match probe_net_admin() {
            Privilege::Available => {}
            Privilege::Missing(reason) => {
                return Err(PluginError::Unavailable(format!(
                    "{reason}. {}",
                    Privilege::how_to_grant(&current_program())
                )));
            }
            Privilege::Unsupported => {
                return Err(PluginError::Unavailable(
                    "interface management is not compiled in".to_string(),
                ));
            }
        }

        let (commands, requests) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("tsunagi-netlink".to_string())
            .spawn(move || netlink_thread(requests))
            .map_err(|err| {
                PluginError::Unavailable(format!("cannot start the netlink thread: {err}"))
            })?;

        Ok(Self {
            commands,
            worker: Mutex::new(Some(worker)),
            ours: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
        })
    }

    fn call<T: Send + 'static>(
        &self,
        make: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, PluginError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.commands
            .send(make(reply_tx))
            .map_err(|_| PluginError::Unavailable("the netlink thread has stopped".to_string()))?;
        reply_rx.recv().map_err(|_| {
            PluginError::Unavailable("the netlink thread stopped mid-request".to_string())
        })?
    }

    fn is_ours(&self, name: &str) -> bool {
        lock(&self.ours).iter().any(|owned| owned == name)
    }

    /// Opens the TUN interface, which is what creates it.
    ///
    /// Synchronous on purpose: the capability guard is raised and lowered
    /// without an `await` in between, so it cannot outlive this thread.
    fn create_device(&self, plan: &InterfacePlan) -> Result<Arc<dyn TunDevice>, PluginError> {
        let request = TunRequest::bare(plan.name.clone(), plan.mtu);
        let _guard = NetAdmin::acquire()?;
        super::super::tun::open_tun(&request, false)
    }
}

impl Drop for NetlinkProvisioner {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(worker) = lock(&self.worker).take() {
            let _ = worker.join();
        }
    }
}

impl InterfaceProvisioner for NetlinkProvisioner {
    fn name(&self) -> &str {
        "netlink"
    }

    fn reconcile<'a>(
        &'a self,
        plan: &'a InterfacePlan,
    ) -> BoxFuture<'a, Result<Provisioned, PluginError>> {
        Box::pin(async move {
            let current = self.call(|reply| Command::Observe(plan.name.clone(), reply))?;
            let changes = plan_changes(&current, plan, self.is_ours(&plan.name))?;

            if changes.delete_link {
                tracing::info!(
                    interface = %plan.name,
                    "removing an abandoned interface left by an earlier run"
                );
                self.call(|reply| Command::Delete(plan.name.clone(), reply))?;
            }

            let device = if changes.create_link {
                let device = self.create_device(plan)?;
                lock(&self.ours).push(plan.name.clone());
                lock(&self.held).push((plan.name.clone(), Arc::clone(&device)));
                Some(device)
            } else {
                None
            };

            if changes.set_mtu.is_some()
                || changes.bring_up
                || !changes.add.is_empty()
                || !changes.remove.is_empty()
            {
                let configure = Box::new(Configure {
                    name: plan.name.clone(),
                    mtu: changes.set_mtu,
                    bring_up: changes.bring_up,
                    add: changes.add.clone(),
                    remove: changes.remove.clone(),
                });
                // A failure here leaves an interface that exists but cannot
                // carry traffic, which is worse than none at all, so it is
                // taken back down rather than left as a trap.
                if let Err(err) = self.call(move |reply| Command::Configure(configure, reply)) {
                    if changes.create_link {
                        lock(&self.held).retain(|(held, _)| held != &plan.name);
                        lock(&self.ours).retain(|owned| owned != &plan.name);
                    }
                    return Err(err);
                }
            }

            Ok(Provisioned { changes, device })
        })
    }

    fn remove<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), PluginError>> {
        Box::pin(async move {
            // Dropping the device is what removes the interface; the explicit
            // delete is only so it is gone by the time this returns rather
            // than whenever the last reader lets go.
            lock(&self.held).retain(|(held, _)| held != name);
            lock(&self.ours).retain(|owned| owned != name);
            self.call(|reply| Command::Delete(name.to_string(), reply))
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn current_program() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.to_str().map(str::to_string))
        .unwrap_or_else(|| "tsunagi".to_string())
}

/// The netlink thread.
///
/// It owns a current-thread runtime, so nothing is polled except inside the
/// `block_on` below — which is what makes the capability window exact.
fn netlink_thread(requests: mpsc::Receiver<Command>) {
    // A binary granted `cap_net_admin+ep` starts with the capability
    // effective. Lower it immediately so that even this thread only has it
    // during the calls that need it.
    NetAdmin::lower();

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            // Answer every request with the reason rather than hanging.
            while let Ok(command) = requests.recv() {
                let message = format!("the netlink thread has no runtime: {err}");
                match command {
                    Command::Observe(_, reply) => {
                        let _ = reply.send(Err(PluginError::Unavailable(message)));
                    }
                    Command::Delete(_, reply) | Command::Configure(_, reply) => {
                        let _ = reply.send(Err(PluginError::Unavailable(message)));
                    }
                    Command::Stop => return,
                }
            }
            return;
        }
    };

    while let Ok(command) = requests.recv() {
        match command {
            Command::Stop => return,
            // Reading the interface list needs no privilege at all.
            Command::Observe(name, reply) => {
                let _ = reply.send(runtime.block_on(observe(&name)));
            }
            Command::Delete(name, reply) => {
                let result = NetAdmin::acquire().and_then(|guard| {
                    let result = runtime.block_on(delete_link(&name));
                    drop(guard);
                    result
                });
                let _ = reply.send(result);
            }
            Command::Configure(configure, reply) => {
                let result = NetAdmin::acquire().and_then(|guard| {
                    let result = runtime.block_on(configure_link(&configure));
                    drop(guard);
                    result
                });
                let _ = reply.send(result);
            }
        }
    }
}

/// Opens a netlink connection and runs one unit of work over it.
async fn with_netlink<T, F>(work: impl FnOnce(rtnetlink::Handle) -> F) -> Result<T, PluginError>
where
    F: std::future::Future<Output = Result<T, PluginError>>,
{
    let (connection, handle, _messages) = rtnetlink::new_connection()
        .map_err(|err| PluginError::Unavailable(format!("cannot open netlink: {err}")))?;
    let pump = tokio::spawn(connection);
    let result = work(handle).await;
    pump.abort();
    result
}

/// `fe80::/10`, which the kernel assigns on its own.
fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => addr.is_link_local(),
        IpAddr::V6(addr) => (addr.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Whether a name belongs to a TUN interface, from sysfs.
///
/// A fallback for the case where the kernel does not report `IFLA_LINKINFO`
/// for the link. Reading sysfs needs no privileges.
fn is_tun_in_sysfs(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}/tun_flags")).exists()
}

fn link_kind(message: &LinkMessage, name: &str) -> LinkKind {
    for attribute in &message.attributes {
        if let LinkAttribute::LinkInfo(infos) = attribute {
            for info in infos {
                if let LinkInfo::Kind(kind) = info {
                    return match kind {
                        InfoKind::Tun => LinkKind::Tun,
                        other => LinkKind::Foreign(format!("{other:?}").to_lowercase()),
                    };
                }
            }
        }
    }
    if is_tun_in_sysfs(name) {
        LinkKind::Tun
    } else {
        // No `IFLA_LINKINFO` and no `tun_flags`: a plain device such as an
        // ethernet port. Unknown rather than ours, so it is left alone.
        LinkKind::Foreign("non-tun".to_string())
    }
}

async fn observe(name: &str) -> Result<InterfaceState, PluginError> {
    with_netlink(|handle| async move {
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        let message = match links.try_next().await {
            Ok(Some(message)) => message,
            Ok(None) => return Ok(InterfaceState::absent()),
            Err(err) => {
                // "No such device" is the expected answer on a clean host, so
                // it is not an error; anything else is.
                if !std::path::Path::new(&format!("/sys/class/net/{name}")).exists() {
                    return Ok(InterfaceState::absent());
                }
                return Err(PluginError::Unavailable(format!(
                    "cannot read interface `{name}`: {err}"
                )));
            }
        };

        let index = message.header.index;
        let flags = message.header.flags;
        let mtu = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::Mtu(mtu) => Some(*mtu),
                _ => None,
            })
            .unwrap_or(0);

        let mut addresses = Vec::new();
        let mut stream = handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        while let Some(message) = stream.try_next().await.map_err(|err| {
            PluginError::Unavailable(format!("cannot read the addresses of `{name}`: {err}"))
        })? {
            if let Some(cidr) = address_of(&message)
                && !is_link_local(cidr.addr)
            {
                addresses.push(cidr);
            }
        }
        addresses.sort();

        Ok(InterfaceState {
            kind: link_kind(&message, name),
            // `IFF_LOWER_UP` is carrier, and a TUN has carrier exactly while
            // a process holds it open.
            attached: flags.contains(LinkFlags::LowerUp),
            up: flags.contains(LinkFlags::Up),
            mtu,
            addresses,
        })
    })
    .await
}

/// The address a message carries, preferring `IFA_LOCAL`.
///
/// For a point-to-point interface `IFA_ADDRESS` is the *peer* address, so
/// taking it would compare the wrong thing.
fn address_of(message: &AddressMessage) -> Option<Cidr> {
    let mut address = None;
    for attribute in &message.attributes {
        match attribute {
            AddressAttribute::Local(addr) => return cidr(*addr, message.header.prefix_len),
            AddressAttribute::Address(addr) => address = Some(*addr),
            _ => {}
        }
    }
    address.and_then(|addr| cidr(addr, message.header.prefix_len))
}

fn cidr(addr: IpAddr, prefix_len: u8) -> Option<Cidr> {
    Cidr::new(addr, prefix_len).ok()
}

async fn delete_link(name: &str) -> Result<(), PluginError> {
    with_netlink(|handle| async move {
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        let index = match links.try_next().await {
            Ok(Some(message)) => message.header.index,
            // Already gone, which is the outcome asked for.
            Ok(None) | Err(_) => return Ok(()),
        };
        handle.link().del(index).execute().await.map_err(|err| {
            PluginError::Unavailable(format!("cannot remove interface `{name}`: {err}"))
        })
    })
    .await
}

async fn configure_link(configure: &Configure) -> Result<(), PluginError> {
    let name = configure.name.as_str();
    with_netlink(|handle| async move {
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        let index = links
            .try_next()
            .await
            .ok()
            .flatten()
            .map(|message| message.header.index)
            .ok_or_else(|| {
                PluginError::Unavailable(format!(
                    "interface `{name}` disappeared before it could be configured"
                ))
            })?;

        if configure.mtu.is_some() || configure.bring_up {
            let mut builder = LinkMessageBuilder::<LinkUnspec>::new().index(index);
            if let Some(mtu) = configure.mtu {
                builder = builder.mtu(mtu);
            }
            if configure.bring_up {
                builder = builder.up();
            }
            handle
                .link()
                .set(builder.build())
                .execute()
                .await
                .map_err(|err| {
                    PluginError::Unavailable(format!("cannot configure interface `{name}`: {err}"))
                })?;
        }

        for cidr in &configure.remove {
            // Delete the exact message the kernel holds rather than a
            // reconstruction of it, so the family and flags always match.
            let mut stream = handle
                .address()
                .get()
                .set_link_index_filter(index)
                .execute();
            let mut target: Option<AddressMessage> = None;
            while let Ok(Some(message)) = stream.try_next().await {
                if address_of(&message) == Some(*cidr) {
                    target = Some(message);
                    break;
                }
            }
            drop(stream);
            if let Some(message) = target {
                handle
                    .address()
                    .del(message)
                    .execute()
                    .await
                    .map_err(|err| {
                        PluginError::Unavailable(format!(
                            "cannot remove {cidr} from interface `{name}`: {err}"
                        ))
                    })?;
            }
        }

        for cidr in &configure.add {
            handle
                .address()
                .add(index, cidr.addr, cidr.prefix_len)
                .execute()
                .await
                .map_err(|err| {
                    PluginError::Unavailable(format!(
                        "cannot add {cidr} to interface `{name}`: {err}"
                    ))
                })?;
        }

        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn link_local_addresses_are_not_ours_to_manage() {
        // The kernel assigns these itself when the link comes up. Treating
        // them as unplanned would make every reconciliation try to delete one.
        assert!(is_link_local(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_link_local(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_link_local(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_link_local(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 1))));
    }

    #[tokio::test]
    async fn observing_a_name_nothing_uses_reports_it_absent() {
        let state = observe("tsunagi-no-such-interface").await.unwrap();
        assert_eq!(state.kind, LinkKind::Absent);
        assert!(state.addresses.is_empty());
    }

    #[tokio::test]
    async fn observing_the_loopback_interface_decodes_what_the_kernel_reports() {
        // Reading the interface table needs no privileges, so this runs
        // everywhere and checks the netlink decoding against a real kernel
        // rather than against a fixture.
        let state = observe("lo").await.unwrap();
        assert!(
            matches!(state.kind, LinkKind::Foreign(_)),
            "loopback is not a tun: {:?}",
            state.kind
        );
        assert!(state.up, "loopback is up");
        assert!(state.mtu >= 1280, "decoded an mtu: {}", state.mtu);
        assert!(
            state
                .addresses
                .iter()
                .any(|cidr| cidr.addr == IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "127.0.0.1 is decoded: {:?}",
            state.addresses
        );
        assert!(
            !state.addresses.iter().any(|cidr| is_link_local(cidr.addr)),
            "link-local addresses are filtered out: {:?}",
            state.addresses
        );
    }

    #[test]
    fn an_interface_that_is_not_a_tun_is_reported_foreign() {
        let message = LinkMessage::default();
        // No `IFLA_LINKINFO` and a name with no `tun_flags` in sysfs.
        assert!(matches!(
            link_kind(&message, "definitely-not-an-interface"),
            LinkKind::Foreign(_)
        ));
    }
}
