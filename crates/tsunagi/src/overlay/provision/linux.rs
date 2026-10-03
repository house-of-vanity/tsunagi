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

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, mpsc};

use futures_util::TryStreamExt;
// Through rtnetlink's own re-export, so the packet types can never drift out
// of step with the client that sends them.
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage};
use rtnetlink::packet_route::route::RouteScope;
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage, RuleUidRange};
use rtnetlink::{IpVersion, LinkMessageBuilder, LinkUnspec, RouteMessageBuilder};

use crate::BoxFuture;
use crate::overlay::OverlayError;

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
    /// Route `255.255.255.255/32` through this interface from this address.
    SetBroadcastRoute(String, Ipv4Addr, Reply<()>),
    /// Remove that route from this interface.
    DelBroadcastRoute(String, Reply<()>),
    /// Send the host's default traffic through this interface, except what
    /// this user id sends.
    SetExitClient(String, u32, Reply<()>),
    /// Take those routing rules away again.
    ClearExitClient(Reply<()>),
    /// Stop the thread.
    Stop,
}

type Reply<T> = mpsc::Sender<Result<T, OverlayError>>;

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
    pub fn new() -> Result<Self, OverlayError> {
        match probe_net_admin() {
            Privilege::Available => {}
            Privilege::Missing(reason) => {
                return Err(OverlayError::Unavailable(format!(
                    "{reason}. {}",
                    Privilege::how_to_grant(&current_program())
                )));
            }
            Privilege::Unsupported => {
                return Err(OverlayError::Unavailable(
                    "interface management is not compiled in".to_string(),
                ));
            }
        }

        let (commands, requests) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("tsunagi-netlink".to_string())
            .spawn(move || netlink_thread(requests))
            .map_err(|err| {
                OverlayError::Unavailable(format!("cannot start the netlink thread: {err}"))
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
    ) -> Result<T, OverlayError> {
        call_thread(&self.commands, make)
    }

    /// The broadcast host rules for this host.
    ///
    /// The route is added by this provisioner's netlink thread, because it is
    /// the only one that ever holds `CAP_NET_ADMIN`, and only for the duration
    /// of a call. Keep the provisioner alive for as long as the rules are used.
    pub fn host_rules(&self) -> crate::overlay::hostrules::LinuxHostRules {
        crate::overlay::hostrules::LinuxHostRules::new(RouteHandle {
            commands: self.commands.clone(),
        })
    }

    fn is_ours(&self, name: &str) -> bool {
        lock(&self.ours).iter().any(|owned| owned == name)
    }

    /// Opens the TUN interface, which is what creates it.
    ///
    /// Synchronous on purpose: the capability guard is raised and lowered
    /// without an `await` in between, so it cannot outlive this thread.
    fn create_device(&self, plan: &InterfacePlan) -> Result<Arc<dyn TunDevice>, OverlayError> {
        let request = TunRequest::bare(plan.name.clone(), plan.mtu);
        let _guard = NetAdmin::acquire()?;
        super::super::tun::open_tun(&request)
    }
}

fn call_thread<T: Send + 'static>(
    commands: &mpsc::Sender<Command>,
    make: impl FnOnce(Reply<T>) -> Command,
) -> Result<T, OverlayError> {
    let (reply_tx, reply_rx) = mpsc::channel();
    commands
        .send(make(reply_tx))
        .map_err(|_| OverlayError::Unavailable("the netlink thread has stopped".to_string()))?;
    reply_rx.recv().map_err(|_| {
        OverlayError::Unavailable("the netlink thread stopped mid-request".to_string())
    })?
}

/// Adds and removes the limited-broadcast route on the netlink thread.
#[derive(Debug, Clone)]
pub(crate) struct RouteHandle {
    commands: mpsc::Sender<Command>,
}

impl RouteHandle {
    /// Routes `255.255.255.255/32` through `interface`, preferring `source`.
    /// Replaces a route this agent added earlier, so it can be repeated.
    pub(crate) fn set(&self, interface: &str, source: Ipv4Addr) -> Result<(), OverlayError> {
        let interface = interface.to_string();
        call_thread(&self.commands, |reply| {
            Command::SetBroadcastRoute(interface, source, reply)
        })
    }

    /// Removes the route. Succeeds when it, or the interface, is gone.
    pub(crate) fn clear(&self, interface: &str) -> Result<(), OverlayError> {
        let interface = interface.to_string();
        call_thread(&self.commands, |reply| {
            Command::DelBroadcastRoute(interface, reply)
        })
    }

    /// Sends the host's default traffic through `interface`, except what the
    /// user id `uid` sends. Replaces what an earlier call set up.
    pub(crate) fn set_exit_client(&self, interface: &str, uid: u32) -> Result<(), OverlayError> {
        let interface = interface.to_string();
        call_thread(&self.commands, |reply| {
            Command::SetExitClient(interface, uid, reply)
        })
    }

    /// Removes those rules. Succeeds when none are there.
    pub(crate) fn clear_exit_client(&self) -> Result<(), OverlayError> {
        call_thread(&self.commands, Command::ClearExitClient)
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
    ) -> BoxFuture<'a, Result<Provisioned, OverlayError>> {
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

    fn remove<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), OverlayError>> {
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
                        let _ = reply.send(Err(OverlayError::Unavailable(message)));
                    }
                    Command::Delete(_, reply)
                    | Command::Configure(_, reply)
                    | Command::SetBroadcastRoute(_, _, reply)
                    | Command::DelBroadcastRoute(_, reply)
                    | Command::SetExitClient(_, _, reply) => {
                        let _ = reply.send(Err(OverlayError::Unavailable(message)));
                    }
                    Command::ClearExitClient(reply) => {
                        let _ = reply.send(Err(OverlayError::Unavailable(message)));
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
            Command::SetBroadcastRoute(name, source, reply) => {
                let result = NetAdmin::acquire().and_then(|guard| {
                    let result = runtime.block_on(set_broadcast_route(&name, source));
                    drop(guard);
                    result
                });
                let _ = reply.send(result);
            }
            Command::DelBroadcastRoute(name, reply) => {
                let result = NetAdmin::acquire().and_then(|guard| {
                    let result = runtime.block_on(del_broadcast_route(&name));
                    drop(guard);
                    result
                });
                let _ = reply.send(result);
            }
            Command::SetExitClient(name, uid, reply) => {
                let result = NetAdmin::acquire().and_then(|guard| {
                    let result = runtime.block_on(set_exit_client(&name, uid));
                    drop(guard);
                    result
                });
                let _ = reply.send(result);
            }
            Command::ClearExitClient(reply) => {
                let result = NetAdmin::acquire().and_then(|guard| {
                    let result = runtime.block_on(clear_exit_client());
                    drop(guard);
                    result
                });
                let _ = reply.send(result);
            }
        }
    }
}

/// Opens a netlink connection and runs one unit of work over it.
async fn with_netlink<T, F>(work: impl FnOnce(rtnetlink::Handle) -> F) -> Result<T, OverlayError>
where
    F: std::future::Future<Output = Result<T, OverlayError>>,
{
    let (connection, handle, _messages) = rtnetlink::new_connection()
        .map_err(|err| OverlayError::Unavailable(format!("cannot open netlink: {err}")))?;
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

async fn observe(name: &str) -> Result<InterfaceState, OverlayError> {
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
                return Err(OverlayError::Unavailable(format!(
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
            OverlayError::Unavailable(format!("cannot read the addresses of `{name}`: {err}"))
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

async fn delete_link(name: &str) -> Result<(), OverlayError> {
    with_netlink(|handle| async move {
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        let index = match links.try_next().await {
            Ok(Some(message)) => message.header.index,
            // Already gone, which is the outcome asked for.
            Ok(None) | Err(_) => return Ok(()),
        };
        handle.link().del(index).execute().await.map_err(|err| {
            OverlayError::Unavailable(format!("cannot remove interface `{name}`: {err}"))
        })
    })
    .await
}

/// The message that names the limited-broadcast route on an interface.
///
/// On-link scope is what the kernel requires of a route with no gateway, and
/// what `ip route add 255.255.255.255/32 dev <if>` produces. Deleting needs the
/// same scope or the kernel finds no match.
fn broadcast_route_message(
    index: u32,
    source: Option<Ipv4Addr>,
) -> rtnetlink::packet_route::route::RouteMessage {
    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::BROADCAST, 32)
        .output_interface(index)
        .scope(RouteScope::Link);
    if let Some(source) = source {
        builder = builder.pref_source(source);
    }
    builder.build()
}

async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Option<u32> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    links
        .try_next()
        .await
        .ok()
        .flatten()
        .map(|message| message.header.index)
}

async fn set_broadcast_route(name: &str, source: Ipv4Addr) -> Result<(), OverlayError> {
    with_netlink(|handle| async move {
        let index = link_index(&handle, name).await.ok_or_else(|| {
            OverlayError::Unavailable(format!(
                "interface `{name}` disappeared before its broadcast route could be added"
            ))
        })?;
        handle
            .route()
            .add(broadcast_route_message(index, Some(source)))
            .replace()
            .execute()
            .await
            .map_err(|err| {
                OverlayError::Unavailable(format!(
                    "cannot route 255.255.255.255 through `{name}` from {source}: {err}"
                ))
            })
    })
    .await
}

async fn del_broadcast_route(name: &str) -> Result<(), OverlayError> {
    with_netlink(|handle| async move {
        // An interface that is gone took its routes with it.
        let Some(index) = link_index(&handle, name).await else {
            return Ok(());
        };
        match handle
            .route()
            .del(broadcast_route_message(index, None))
            .execute()
            .await
        {
            Ok(()) => Ok(()),
            // "No such process": there was no such route, which is the goal.
            Err(err) if err.to_string().contains("No such process") => Ok(()),
            Err(err) => Err(OverlayError::Unavailable(format!(
                "cannot remove the 255.255.255.255 route from `{name}`: {err}"
            ))),
        }
    })
    .await
}

/// The routing table that holds the exit node's default route: `tsun` in
/// ASCII-ish hex, and nothing else uses it.
const EXIT_TABLE: u32 = 0x7473;
/// The main table.
const MAIN_TABLE: u32 = 254;
/// Where the exit rules sit, after Tailscale's 5270.
const EXIT_BYPASS_PRIORITY: u32 = 5280;
const EXIT_SPECIFIC_PRIORITY: u32 = 5290;
const EXIT_DEFAULT_PRIORITY: u32 = 5300;

/// The table a rule looks up.
fn rule_table(rule: &RuleMessage) -> u32 {
    rule.attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(rule.header.table))
}

fn rule_priority(rule: &RuleMessage) -> Option<u32> {
    rule.attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Priority(priority) => Some(*priority),
            _ => None,
        })
}

/// Whether a rule is one of the three this agent adds for an exit node.
///
/// Recognised by shape as well as priority: those numbers are not reserved,
/// and a rule somebody else put at one of them must not be removed.
fn is_exit_rule(rule: &RuleMessage) -> bool {
    let table = rule_table(rule);
    match rule_priority(rule) {
        Some(EXIT_BYPASS_PRIORITY) => {
            table == MAIN_TABLE
                && rule
                    .attributes
                    .iter()
                    .any(|attribute| matches!(attribute, RuleAttribute::UidRange(_)))
        }
        Some(EXIT_SPECIFIC_PRIORITY) => {
            table == MAIN_TABLE
                && rule
                    .attributes
                    .iter()
                    .any(|attribute| matches!(attribute, RuleAttribute::SuppressPrefixLen(0)))
        }
        Some(EXIT_DEFAULT_PRIORITY) => table == EXIT_TABLE,
        _ => false,
    }
}

fn exit_default_route(index: Option<u32>) -> rtnetlink::packet_route::route::RouteMessage {
    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .table_id(EXIT_TABLE);
    if let Some(index) = index {
        builder = builder.output_interface(index).scope(RouteScope::Link);
    }
    builder.build()
}

/// The exit table's IPv6 default: nothing is reachable through it.
///
/// There is no IPv6 through an exit node, and what the ordinary route would do
/// is send it out in the clear. This turns it into an immediate refusal, which
/// is what makes applications fall back to IPv4.
fn exit_blocking_route_v6() -> rtnetlink::packet_route::route::RouteMessage {
    RouteMessageBuilder::<std::net::Ipv6Addr>::new()
        .destination_prefix(std::net::Ipv6Addr::UNSPECIFIED, 0)
        .table_id(EXIT_TABLE)
        .kind(rtnetlink::packet_route::route::RouteType::Unreachable)
        .build()
}

/// A host with no IPv6 at all has nothing to block, and says so this way.
fn family_unsupported(err: &impl std::fmt::Display) -> bool {
    let text = err.to_string();
    text.contains("not supported") || text.contains("Address family")
}

/// Removes the exit node's routing rules and its tables. Nothing there is
/// success: it also runs once at startup, for what a crashed run left.
async fn clear_exit_client() -> Result<(), OverlayError> {
    with_netlink(|handle| async move { remove_exit_client(&handle).await }).await
}

/// Deletes this agent's exit rules of one address family.
async fn remove_exit_rules(
    handle: &rtnetlink::Handle,
    version: IpVersion,
) -> Result<(), OverlayError> {
    let mut rules = handle.rule().get(version).execute();
    let mut ours = Vec::new();
    while let Some(rule) = rules
        .try_next()
        .await
        .map_err(|err| OverlayError::Unavailable(format!("cannot read the routing rules: {err}")))?
    {
        if is_exit_rule(&rule) {
            ours.push(rule);
        }
    }
    for rule in ours {
        match handle.rule().del(rule).execute().await {
            Ok(()) => {}
            // Gone already.
            Err(err) if err.to_string().contains("No such") => {}
            Err(err) => {
                return Err(OverlayError::Unavailable(format!(
                    "cannot remove an exit node routing rule: {err}"
                )));
            }
        }
    }
    Ok(())
}

async fn remove_exit_client(handle: &rtnetlink::Handle) -> Result<(), OverlayError> {
    remove_exit_rules(handle, IpVersion::V4).await?;
    match handle.route().del(exit_default_route(None)).execute().await {
        Ok(()) => {}
        // "No such process": no such route, which is the goal.
        Err(err) if err.to_string().contains("No such") => {}
        Err(err) => {
            return Err(OverlayError::Unavailable(format!(
                "cannot remove the exit node default route: {err}"
            )));
        }
    }

    match remove_exit_rules(handle, IpVersion::V6).await {
        Ok(()) => {}
        Err(OverlayError::Unavailable(reason)) if family_unsupported(&reason) => return Ok(()),
        Err(err) => return Err(err),
    }
    match handle.route().del(exit_blocking_route_v6()).execute().await {
        Ok(()) => Ok(()),
        Err(err) if err.to_string().contains("No such") || family_unsupported(&err) => Ok(()),
        Err(err) => Err(OverlayError::Unavailable(format!(
            "cannot remove the exit node IPv6 block: {err}"
        ))),
    }
}

/// Sets up the using side of an exit node.
///
/// ```text
/// ip route replace default dev <if> table 0x7473
/// ip rule add priority 5280 uidrange <uid>-<uid> lookup main
/// ip rule add priority 5290 lookup main suppress_prefixlength 0
/// ip rule add priority 5300 lookup 0x7473
/// ```
///
/// and the same for IPv6 with `ip -6 route replace unreachable default table
/// 0x7473`, so that IPv6 is refused instead of leaving the ordinary way.
///
/// What an earlier call left is removed first, so repeating it is safe, and
/// the rules go in last, so a failure part way never leaves a rule that
/// sends traffic to a table with no route in it.
async fn set_exit_client(name: &str, uid: u32) -> Result<(), OverlayError> {
    with_netlink(|handle| async move {
        let index = link_index(&handle, name).await.ok_or_else(|| {
            OverlayError::Unavailable(format!(
                "interface `{name}` disappeared before the exit node routes could be added"
            ))
        })?;
        remove_exit_client(&handle).await?;
        let fail = |what: &str, err: rtnetlink::Error| {
            OverlayError::Unavailable(format!("cannot add the exit node {what}: {err}"))
        };
        handle
            .route()
            .add(exit_default_route(Some(index)))
            .replace()
            .execute()
            .await
            .map_err(|err| fail("default route", err))?;

        let mut bypass = handle
            .rule()
            .add()
            .v4()
            .table_id(MAIN_TABLE)
            .action(RuleAction::ToTable)
            .priority(EXIT_BYPASS_PRIORITY);
        bypass
            .message_mut()
            .attributes
            .push(RuleAttribute::UidRange(RuleUidRange {
                start: uid,
                end: uid,
            }));
        bypass
            .execute()
            .await
            .map_err(|err| fail("rule for the agent's own traffic", err))?;

        let mut specific = handle
            .rule()
            .add()
            .v4()
            .table_id(MAIN_TABLE)
            .action(RuleAction::ToTable)
            .priority(EXIT_SPECIFIC_PRIORITY);
        specific
            .message_mut()
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(0));
        specific
            .execute()
            .await
            .map_err(|err| fail("rule for the specific routes", err))?;

        handle
            .rule()
            .add()
            .v4()
            .table_id(EXIT_TABLE)
            .action(RuleAction::ToTable)
            .priority(EXIT_DEFAULT_PRIORITY)
            .execute()
            .await
            .map_err(|err| fail("rule for the default route", err))?;

        set_exit_block_v6(&handle, uid).await
    })
    .await
}

/// The IPv6 half: an unreachable default for everything but the agent's own
/// connections and the specific routes, which keep working.
async fn set_exit_block_v6(handle: &rtnetlink::Handle, uid: u32) -> Result<(), OverlayError> {
    let fail = |what: &str, err: rtnetlink::Error| {
        OverlayError::Unavailable(format!("cannot add the exit node IPv6 {what}: {err}"))
    };
    if let Err(err) = handle
        .route()
        .add(exit_blocking_route_v6())
        .replace()
        .execute()
        .await
    {
        // Without IPv6 there is nothing to leak.
        return if family_unsupported(&err) {
            Ok(())
        } else {
            Err(fail("block", err))
        };
    }

    let mut bypass = handle
        .rule()
        .add()
        .v6()
        .table_id(MAIN_TABLE)
        .action(RuleAction::ToTable)
        .priority(EXIT_BYPASS_PRIORITY);
    bypass
        .message_mut()
        .attributes
        .push(RuleAttribute::UidRange(RuleUidRange {
            start: uid,
            end: uid,
        }));
    bypass
        .execute()
        .await
        .map_err(|err| fail("rule for the agent's own traffic", err))?;

    let mut specific = handle
        .rule()
        .add()
        .v6()
        .table_id(MAIN_TABLE)
        .action(RuleAction::ToTable)
        .priority(EXIT_SPECIFIC_PRIORITY);
    specific
        .message_mut()
        .attributes
        .push(RuleAttribute::SuppressPrefixLen(0));
    specific
        .execute()
        .await
        .map_err(|err| fail("rule for the specific routes", err))?;

    handle
        .rule()
        .add()
        .v6()
        .table_id(EXIT_TABLE)
        .action(RuleAction::ToTable)
        .priority(EXIT_DEFAULT_PRIORITY)
        .execute()
        .await
        .map_err(|err| fail("rule for the default route", err))
}

async fn configure_link(configure: &Configure) -> Result<(), OverlayError> {
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
                OverlayError::Unavailable(format!(
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
                    OverlayError::Unavailable(format!("cannot configure interface `{name}`: {err}"))
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
                        OverlayError::Unavailable(format!(
                            "cannot remove {cidr} from interface `{name}`: {err}"
                        ))
                    })?;
            }
        }

        for cidr in &configure.add {
            let res = handle
                .address()
                .add(index, cidr.addr, cidr.prefix_len)
                .execute()
                .await;
            if let Err(err) = res {
                let err_str = err.to_string();
                if !err_str.contains("File exists") && !err_str.contains("os error 17") {
                    return Err(OverlayError::Unavailable(format!(
                        "cannot add {cidr} to interface `{name}`: {err}"
                    )));
                }
            }
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

    fn rule(priority: u32, table: u32, extra: Vec<RuleAttribute>) -> RuleMessage {
        let mut message = RuleMessage::default();
        message.attributes.push(RuleAttribute::Priority(priority));
        if table > 255 {
            message.attributes.push(RuleAttribute::Table(table));
        } else {
            message.header.table = table as u8;
        }
        message.attributes.extend(extra);
        message
    }

    #[test]
    fn only_the_three_exit_rules_are_recognised_as_ours() {
        let uid = RuleAttribute::UidRange(RuleUidRange { start: 5, end: 5 });
        assert!(is_exit_rule(&rule(5280, 254, vec![uid.clone()])));
        assert!(is_exit_rule(&rule(
            5290,
            254,
            vec![RuleAttribute::SuppressPrefixLen(0)]
        )));
        assert!(is_exit_rule(&rule(5300, EXIT_TABLE, vec![])));

        // Same priorities, somebody else's rules.
        assert!(!is_exit_rule(&rule(5280, 254, vec![])));
        assert!(!is_exit_rule(&rule(5290, 254, vec![])));
        assert!(!is_exit_rule(&rule(5300, 52, vec![])));
        assert!(!is_exit_rule(&rule(5270, 52, vec![])));
        assert!(!is_exit_rule(&rule(5280, 100, vec![uid])));
    }

    #[test]
    fn the_ipv6_default_of_the_exit_table_refuses_instead_of_routing() {
        let route = exit_blocking_route_v6();
        assert_eq!(route.header.destination_prefix_length, 0);
        let debug = format!("{route:?}");
        assert!(debug.contains("Unreachable"), "{debug}");
        assert!(debug.contains(&format!("Table({EXIT_TABLE})")), "{debug}");
        assert!(!debug.contains("Oif"), "{debug}");
    }

    #[test]
    fn a_host_without_ipv6_is_not_a_failure() {
        assert!(family_unsupported(
            &"Address family not supported by protocol"
        ));
        assert!(family_unsupported(&"Operation not supported"));
        assert!(!family_unsupported(&"Operation not permitted"));
    }

    #[test]
    fn the_default_route_of_the_exit_table_names_the_table_and_the_interface() {
        let route = exit_default_route(Some(7));
        assert_eq!(route.header.destination_prefix_length, 0);
        let debug = format!("{route:?}");
        assert!(debug.contains(&format!("Table({EXIT_TABLE})")), "{debug}");
        assert!(debug.contains("Oif(7)"), "{debug}");
        // Deleting names no interface, so it matches whatever it was added on.
        assert!(!format!("{:?}", exit_default_route(None)).contains("Oif"));
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
