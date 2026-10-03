//! The one interface an agent owns, and the loop that moves packets across it.
//!
//! Outbound, a packet read from the interface is looked up in the
//! [`RoutingTable`] and handed to whatever can carry it to that peer.
//! Inbound, a packet a protocol has decrypted is checked against the same
//! table and written to the interface.
//!
//! Neither direction knows which protocol is involved, and that is the
//! point: the interface, the addresses on it and the decision of whose
//! packet this is all belong here, so several protocols can be carrying
//! traffic at once without any of them owning the thing they are carrying it
//! for.
//!
//! # What is counted rather than hidden
//!
//! A packet with nowhere to go, a packet from a peer that does not hold its
//! source address, a multicast packet the operating system emitted anyway:
//! each is dropped and counted, with a sample kept for the first kind,
//! because "the overlay is quiet" and "the overlay is dropping everything"
//! look identical without them.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use iroh::EndpointId;
use tokio::task::JoinHandle;

use crate::identity::NetworkId;

use super::exit::{ExitRulesReport, RuleSetReport};
use super::hostrules::{
    BroadcastHostRules, BroadcastRulesPlan, BroadcastRulesReport, ExitHostPlan, ExitHostReport,
    RuleOutcome, offer_detail,
};
use super::packet::IpHeader;
use super::router::{Route, RoutingTable};
use super::tun::{TunDevice, TunFactory, TunRequest};
use super::{Cidr, OverlayError};

/// Carries one packet to a peer, by whatever protocol currently can.
///
/// Implemented by the layer that knows which protocols are live for which
/// peers. The interface does not: it asks for a packet to reach a peer and
/// is told whether that was possible.
pub trait PacketCarrier: Send + Sync + 'static {
    /// Carries a packet, answering `false` if nothing can right now.
    fn carry(&self, route: Route, packet: Bytes) -> bool;
}

/// Why a decrypted packet was not written to the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// It was not a packet this agent could read.
    Malformed,
    /// The overlay is IPv4; anything else has no owner here.
    WrongFamily,
    /// The sending peer does not hold the source address it used.
    WrongSource,
    /// Broadcast disabled, outside this domain, or malformed/non-UDP.
    BroadcastDenied,
    /// The packet terminates outside this host's network address/domain.
    WrongDestination,
}

/// Counters for one interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    /// Packets handed to a protocol.
    pub sent: u64,
    /// Broadcast copies handed to recipient tunnels.
    pub broadcast_sent: u64,
    /// Broadcast packets admitted to this host.
    pub broadcast_received: u64,
    /// Broadcasts refused by domain policy or packet validation.
    pub broadcast_dropped: u64,
    /// Packets written to the operating system.
    pub received: u64,
    /// Packets for an address nobody in any network holds.
    pub unroutable: u64,
    /// One such destination, so the number can be acted on.
    pub unroutable_sample: Option<IpAddr>,
    /// Packets nothing could carry, though their destination was known.
    pub undeliverable: u64,
    /// Unsupported multicast or unspecified-destination packets.
    pub multicast: u64,
    /// Packets from a peer that does not hold the source address used.
    pub wrong_source: u64,
    /// Decrypted packets addressed outside the receiving network's local host.
    pub wrong_destination: u64,
    /// Packets that could not be read at all.
    pub malformed: u64,
}

#[derive(Debug, Default)]
struct Tally {
    sent: AtomicU64,
    broadcast_sent: AtomicU64,
    broadcast_received: AtomicU64,
    broadcast_dropped: AtomicU64,
    received: AtomicU64,
    unroutable: AtomicU64,
    undeliverable: AtomicU64,
    multicast: AtomicU64,
    wrong_source: AtomicU64,
    wrong_destination: AtomicU64,
    malformed: AtomicU64,
    sample: std::sync::Mutex<Option<IpAddr>>,
}

impl Tally {
    fn snapshot(&self) -> Counters {
        Counters {
            sent: self.sent.load(Ordering::Relaxed),
            broadcast_sent: self.broadcast_sent.load(Ordering::Relaxed),
            broadcast_received: self.broadcast_received.load(Ordering::Relaxed),
            broadcast_dropped: self.broadcast_dropped.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            unroutable: self.unroutable.load(Ordering::Relaxed),
            unroutable_sample: match self.sample.lock() {
                Ok(guard) => *guard,
                Err(poisoned) => *poisoned.into_inner(),
            },
            undeliverable: self.undeliverable.load(Ordering::Relaxed),
            multicast: self.multicast.load(Ordering::Relaxed),
            wrong_source: self.wrong_source.load(Ordering::Relaxed),
            wrong_destination: self.wrong_destination.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
        }
    }

    fn note_unroutable(&self, destination: IpAddr) {
        self.unroutable.fetch_add(1, Ordering::Relaxed);
        // The first one is kept. A later sample would keep overwriting the
        // one a reader is looking at.
        let mut guard = match self.sample.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.is_none() {
            *guard = Some(destination);
        }
    }
}

/// The overlay interface.
#[derive(Debug)]
pub struct Interface {
    device: Arc<dyn TunDevice>,
    factory: Arc<dyn TunFactory>,
    name: String,
    mtu: u32,
    routes: Arc<RoutingTable>,
    tally: Arc<Tally>,
    /// What was last applied to the host, so an unchanged table is not
    /// re-applied on every pass.
    applied: std::sync::Mutex<Vec<Cidr>>,
    task: std::sync::Mutex<Option<JoinHandle<()>>>,
    sync_lock: Arc<tokio::sync::Mutex<()>>,
    /// The host rules for this interface, when the factory manages the host.
    host_rules: Option<Arc<dyn BroadcastHostRules>>,
    /// What those rules last reported, `None` while none are installed.
    rules_report: std::sync::Mutex<Option<BroadcastRulesReport>>,
    /// What the exit-node rules were last asked for, and what came of it.
    exit_state: std::sync::Mutex<ExitState>,
    /// Where each network's runtime reaches its peers and relays outside the
    /// overlay; read only by hosts that cannot exempt the agent from the
    /// exit node's default route.
    underlay: std::sync::Mutex<std::collections::HashMap<NetworkId, Underlay>>,
}

/// Underlay destinations one network's runtime currently depends on.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Underlay {
    addresses: std::collections::BTreeSet<std::net::Ipv4Addr>,
    hosts: std::collections::BTreeSet<String>,
}

/// The exit-node host rules as this interface last left them.
#[derive(Debug, Default)]
struct ExitState {
    /// Whether what an earlier run left behind has been taken away. Done once,
    /// at the first sync, whether or not anything is wanted now: a firewall
    /// rule that forwards a range must not outlive the switch that offered it.
    cleaned: bool,
    /// What was last applied, `None` while nothing is.
    plan: Option<ExitHostPlan>,
    /// What came of it.
    report: Option<ExitHostReport>,
}

impl ExitState {
    /// Whether every step of the last apply took.
    fn is_ok(&self) -> bool {
        self.report.as_ref().is_some_and(|report| {
            report.offer.iter().all(|(_, outcome)| outcome.is_applied())
                && report.client.as_ref().is_none_or(RuleOutcome::is_applied)
        })
    }
}

impl Interface {
    /// Creates the interface and starts moving packets.
    pub async fn start(
        factory: Arc<dyn TunFactory>,
        name: impl Into<String>,
        mtu: u32,
        routes: Arc<RoutingTable>,
        carrier: Arc<dyn PacketCarrier>,
    ) -> Result<Self, OverlayError> {
        let name = name.into();
        let host_rules = factory.host_rules();
        let device = factory.create(TunRequest::bare(name.clone(), mtu)).await?;
        // The name the operating system actually gave the interface. On Linux
        // and Windows that is the one we asked for; on macOS the kernel assigns
        // the utun unit, so the real name differs and everything that
        // configures the host for this interface afterwards — the broadcast
        // route and firewall, the reconfigure on an address change — has to use
        // the real one, not the requested `tsun…`.
        let name = device.name().to_string();
        let tally = Arc::new(Tally::default());

        let task = {
            let device = Arc::clone(&device);
            let routes = Arc::clone(&routes);
            let tally = Arc::clone(&tally);
            tokio::spawn(async move {
                while let Some(packet) = device.recv().await {
                    let Some(header) = IpHeader::parse(&packet) else {
                        tally.malformed.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let destination = header.destination();
                    if let (IpAddr::V4(source), IpAddr::V4(destination)) =
                        (header.source(), destination)
                        && routes.is_broadcast(destination)
                    {
                        let recipients = super::broadcast::valid_udp(&packet)
                            .then(|| routes.broadcast_recipients(source, destination))
                            .flatten();
                        if let Some(recipients) = recipients {
                            for &route in recipients.iter() {
                                if carrier.carry(route, packet.clone()) {
                                    tally.sent.fetch_add(1, Ordering::Relaxed);
                                    tally.broadcast_sent.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    tally.undeliverable.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        } else {
                            tally.broadcast_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                    if is_multicast_or_broadcast(destination) {
                        // The operating system emits these on any interface.
                        // The overlay is a set of point-to-point tunnels and
                        // has nowhere to put them; expected, not a fault.
                        tally.multicast.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let Some(route) = routes.route_v4(destination) else {
                        tally.note_unroutable(destination);
                        continue;
                    };
                    if carrier.carry(route, packet) {
                        tally.sent.fetch_add(1, Ordering::Relaxed);
                    } else {
                        tally.undeliverable.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        };

        Ok(Self {
            device,
            factory,
            name,
            mtu,
            routes,
            tally,
            applied: std::sync::Mutex::new(Vec::new()),
            task: std::sync::Mutex::new(Some(task)),
            sync_lock: Arc::new(tokio::sync::Mutex::new(())),
            host_rules,
            rules_report: std::sync::Mutex::new(None),
            exit_state: std::sync::Mutex::new(ExitState::default()),
            underlay: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Brings the broadcast route and firewall allowance in line with the
    /// routing table: installed while some network has broadcast on and an
    /// address, removed when none does.
    ///
    /// Called after the addresses are synced, because the route's preferred
    /// source has to be on the interface already. A plan that has not changed
    /// is not re-applied, so this is cheap to call whenever the table moves.
    /// It never fails: the outcome is kept for [`Self::broadcast_rules`].
    pub async fn sync_broadcast_rules(&self) {
        let Some(rules) = &self.host_rules else {
            return;
        };
        let _guard = self.sync_lock.lock().await;
        let desired =
            self.routes
                .broadcast_host_target()
                .map(|(source, range)| BroadcastRulesPlan {
                    interface: self.name.clone(),
                    source,
                    range,
                });
        let current = self.current_rules_report();
        match (desired, current) {
            (None, None) => {}
            (None, Some(_)) => {
                rules.clear(&self.name).await;
                self.store_rules_report(None);
                tracing::info!(interface = %self.name, "broadcast host rules removed");
            }
            (Some(plan), Some(report)) if report.plan == plan => {}
            (Some(plan), _) => {
                let report = rules.apply(&plan).await;
                if report.is_ok() {
                    tracing::info!(
                        interface = %self.name,
                        source = %plan.source,
                        "broadcast host rules applied"
                    );
                } else {
                    tracing::warn!(
                        interface = %self.name,
                        "broadcast host rules are incomplete: {}",
                        report.summary()
                    );
                }
                self.store_rules_report(Some(report));
            }
        }
    }

    /// Brings the host's exit-node rules in line with the routing table.
    ///
    /// Idempotent, and cheap when nothing changed. It never fails: the
    /// outcome is kept for [`Self::exit_rules`]. The first call also takes
    /// away whatever an earlier run left, even when nothing is wanted now.
    pub async fn sync_exit_rules(&self) {
        let Some(exit) = self
            .host_rules
            .as_ref()
            .and_then(|rules| rules.exit_rules())
        else {
            return;
        };
        let _guard = self.sync_lock.lock().await;
        let mut ranges: Vec<_> = self
            .routes
            .exit_offers()
            .into_iter()
            .map(|(_, range)| range)
            .collect();
        ranges.sort_by_key(|range| (range.base, range.prefix_len));
        ranges.dedup();
        let client = self.routes.exit_via().is_some();
        let overlay = self.routes.overlay_ranges();
        let (bypass, bypass_hosts) = if client && exit.needs_bypass() {
            self.underlay_targets(&overlay)
        } else {
            (Vec::new(), Vec::new())
        };
        let wanted = ExitHostPlan {
            interface: self.name.clone(),
            offer: ranges,
            client,
            overlay,
            bypass,
            bypass_hosts,
        };

        let first = !std::mem::replace(&mut self.exit_state().cleaned, true);
        if first {
            exit.clear(&self.name).await;
        }
        let (planned, ok) = {
            let state = self.exit_state();
            (state.plan.clone(), state.is_ok())
        };
        if wanted.is_empty() {
            if planned.is_some() {
                exit.clear(&self.name).await;
                let mut state = self.exit_state();
                state.plan = None;
                state.report = None;
                tracing::info!(interface = %self.name, "exit node host rules removed");
            }
            return;
        }
        if planned.as_ref() == Some(&wanted) && ok {
            return;
        }
        let report = exit.apply(&wanted).await;
        for (range, outcome) in &report.offer {
            match outcome {
                RuleOutcome::Applied => tracing::info!(
                    interface = %self.name,
                    %range,
                    "exit node firewall rules applied"
                ),
                RuleOutcome::Failed(reason) => tracing::warn!(
                    interface = %self.name,
                    %range,
                    "exit node firewall rules are incomplete: {reason}"
                ),
            }
        }
        if report.offer.iter().any(|(_, outcome)| outcome.is_applied())
            && report.forwarding == Some(false)
        {
            tracing::warn!(
                interface = %self.name,
                "kernel forwarding is off for this interface, so nothing is forwarded for the \
                 exit node yet: {}",
                if cfg!(target_os = "windows") {
                    "`Set-NetIPInterface -Forwarding Enabled` on the interfaces involved"
                } else if cfg!(target_os = "macos") {
                    "`sysctl -w net.inet.ip.forwarding=1`, set again after every reboot"
                } else {
                    "`sysctl -w net.ipv4.ip_forward=1` (or `net.ipv4.conf.<interface>.forwarding=1`), \
                     and set it in sysctl.d to keep it"
                }
            );
        }
        match &report.client {
            Some(RuleOutcome::Applied) => tracing::info!(
                interface = %self.name,
                "this device's traffic is routed through its exit node"
            ),
            Some(RuleOutcome::Failed(reason)) => tracing::warn!(
                interface = %self.name,
                "cannot route this device's traffic through the exit node: {reason}"
            ),
            None => {}
        }
        let mut state = self.exit_state();
        state.plan = Some(wanted);
        state.report = Some(report);
    }

    /// Tells the interface where a network's runtime reaches peers and
    /// relays outside the overlay. When the host needs those kept out of the
    /// exit node's default route and the set changed, the rules follow.
    pub async fn set_underlay(
        &self,
        network: NetworkId,
        addresses: impl IntoIterator<Item = std::net::Ipv4Addr>,
        hosts: impl IntoIterator<Item = String>,
    ) {
        let new = Underlay {
            addresses: addresses.into_iter().collect(),
            hosts: hosts.into_iter().collect(),
        };
        let changed = {
            let mut map = match self.underlay.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if new == Underlay::default() {
                map.remove(&network).is_some()
            } else {
                map.insert(network, new.clone()) != Some(new)
            }
        };
        let needed = changed
            && self.routes.exit_via().is_some()
            && self
                .host_rules
                .as_ref()
                .and_then(|rules| rules.exit_rules())
                .is_some_and(|exit| exit.needs_bypass());
        if needed {
            self.sync_exit_rules().await;
        }
    }

    /// Every underlay destination worth keeping direct, minus anything that
    /// is the overlay itself, loopback or link-local.
    fn underlay_targets(
        &self,
        overlay: &[crate::state::Ipv4Range],
    ) -> (Vec<std::net::Ipv4Addr>, Vec<String>) {
        let map = match self.underlay.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut addresses = std::collections::BTreeSet::new();
        let mut hosts = std::collections::BTreeSet::new();
        for underlay in map.values() {
            addresses.extend(underlay.addresses.iter().copied().filter(|address| {
                !address.is_loopback()
                    && !address.is_link_local()
                    && !address.is_multicast()
                    && !address.is_unspecified()
                    && !address.is_broadcast()
                    && !overlay.iter().any(|range| range.contains(*address))
            }));
            hosts.extend(underlay.hosts.iter().cloned());
        }
        (addresses.into_iter().collect(), hosts.into_iter().collect())
    }

    fn exit_state(&self) -> std::sync::MutexGuard<'_, ExitState> {
        match self.exit_state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// What the exit-node rules of a network are doing now.
    ///
    /// `offer` is `Some` while the network offers this agent as an exit node,
    /// `client` while this device sends its traffic through a member of it.
    pub fn exit_rules(&self, network: NetworkId) -> ExitRulesReport {
        let Some((policy, range)) = self.routes.exit_settings(network) else {
            return ExitRulesReport::default();
        };
        let unavailable = match self
            .host_rules
            .as_ref()
            .map(|rules| rules.exit_rules().is_some())
        {
            None => Some(
                "this overlay interface is not on the host (no TUN device), so there is \
                 nothing to forward to",
            ),
            Some(false) => Some("exit nodes are not supported on this platform yet"),
            Some(true) => None,
        };
        let failed = |detail: &str| RuleSetReport {
            ok: false,
            detail: detail.to_string(),
        };
        let state = self.exit_state();
        let mut out = ExitRulesReport::default();
        if policy.offer {
            out.offer = Some(match (unavailable, range) {
                (Some(why), _) => failed(why),
                (None, None) => failed("waiting for the network to agree an address range"),
                (None, Some(range)) => {
                    match state
                        .report
                        .as_ref()
                        .and_then(|report| report.offer.iter().find(|(r, _)| *r == range))
                    {
                        Some((_, outcome)) => RuleSetReport {
                            ok: outcome.is_applied(),
                            detail: offer_detail(outcome, &range),
                        },
                        None => failed("not applied yet"),
                    }
                }
            });
            if unavailable.is_none() {
                out.forwarding = state.report.as_ref().and_then(|report| report.forwarding);
            }
        }
        if policy.via.is_some()
            && self
                .routes
                .exit_via()
                .is_some_and(|(selected, _)| selected == network)
        {
            out.client = Some(match unavailable {
                Some(why) => failed(why),
                None => match state
                    .report
                    .as_ref()
                    .and_then(|report| report.client.as_ref())
                {
                    Some(RuleOutcome::Applied) => RuleSetReport {
                        ok: true,
                        detail: "this device's traffic is routed through the exit node".to_string(),
                    },
                    Some(RuleOutcome::Failed(reason)) => failed(reason),
                    None => failed("not applied yet"),
                },
            });
        }
        out
    }

    /// Whether this agent can really act as an exit node in a network: the
    /// rules members' traffic needs are in place. Kernel forwarding is not
    /// part of it, because the agent never turns that on itself.
    pub fn exit_offer_ready(&self, network: NetworkId) -> bool {
        let Some((policy, Some(range))) = self.routes.exit_settings(network) else {
            return false;
        };
        policy.offer
            && self.exit_state().report.as_ref().is_some_and(|report| {
                report
                    .offer
                    .iter()
                    .any(|(r, outcome)| *r == range && outcome.is_applied())
            })
    }

    /// What the broadcast host rules achieved, `None` when none are installed
    /// or this interface has no host to configure.
    pub fn broadcast_rules(&self) -> Option<BroadcastRulesReport> {
        self.current_rules_report()
    }

    fn current_rules_report(&self) -> Option<BroadcastRulesReport> {
        match self.rules_report.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn store_rules_report(&self, report: Option<BroadcastRulesReport>) {
        match self.rules_report.lock() {
            Ok(mut guard) => *guard = report,
            Err(poisoned) => *poisoned.into_inner() = report,
        }
    }

    /// Brings the addresses on the host in line with the routing table.
    ///
    /// Called whenever a network agrees a different address for this agent.
    /// The interface is never recreated for it: that would drop every tunnel
    /// riding on it for the sake of one address.
    pub async fn sync_addresses(&self) -> Result<(), OverlayError> {
        let _guard = self.sync_lock.lock().await;
        let wanted = self.wanted_addresses();
        {
            let applied = match self.applied.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            };
            if applied == wanted {
                return Ok(());
            }
        }

        // Every address this agent holds, in every network it is in. The
        // plan is exhaustive by contract, so this is also what takes an
        // address off the interface when a network is left or stopped.
        let request = TunRequest {
            name: self.name.clone(),
            addresses: wanted.clone(),
            mtu: self.mtu,
        };
        self.factory.reconfigure(request).await?;
        match self.applied.lock() {
            Ok(mut guard) => *guard = wanted,
            Err(poisoned) => *poisoned.into_inner() = wanted,
        }
        Ok(())
    }

    /// The interface name the operating system gave.
    pub fn name(&self) -> &str {
        self.device.name()
    }

    /// The interface MTU.
    pub fn mtu(&self) -> u32 {
        self.device.mtu()
    }

    /// Whether this interface exists on the host.
    ///
    /// `false` with an in-memory device, where tunnels run and packets move
    /// but the operating system knows nothing about any of it. Anything that
    /// would configure the host — a route, a resolver setting, a complaint
    /// that an address is missing from a link — has to ask first.
    pub fn on_host(&self) -> bool {
        self.factory.on_host()
    }

    /// Removes the interface from the host.
    pub async fn remove(&self) {
        // The route goes with the interface; the firewall rule does not, so
        // it is taken out explicitly while the interface is still known.
        if let Some(rules) = &self.host_rules {
            rules.clear(&self.name).await;
            self.store_rules_report(None);
            let touched = {
                let state = self.exit_state();
                state.cleaned || state.plan.is_some()
            };
            if let (true, Some(exit)) = (touched, rules.exit_rules()) {
                exit.clear(&self.name).await;
                let mut state = self.exit_state();
                state.plan = None;
                state.report = None;
            }
        }
        // The packet loop holds the device open, and it ends only when the
        // device reports end of stream — which a real interface never does
        // while it exists. Stop it directly before destroying the interface.
        let task = match self.task.lock() {
            Ok(mut guard) => guard.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        self.factory.destroy(self.device.name()).await;
    }

    /// The counters as they stand.
    pub fn counters(&self) -> Counters {
        self.tally.snapshot()
    }

    /// Writes a packet a protocol decrypted to the operating system.
    ///
    /// The source is checked against what the network agreed that peer
    /// holds. A protocol proved *who* sent the packet; only this level knows
    /// what that member is entitled to say.
    pub async fn deliver(
        &self,
        network: NetworkId,
        peer: EndpointId,
        packet: Bytes,
    ) -> Result<(), Rejected> {
        let Some(header) = IpHeader::parse(&packet) else {
            self.tally.malformed.fetch_add(1, Ordering::Relaxed);
            return Err(Rejected::Malformed);
        };
        let IpAddr::V4(source) = header.source() else {
            self.tally.wrong_source.fetch_add(1, Ordering::Relaxed);
            return Err(Rejected::WrongFamily);
        };
        if !self.routes.may_send_from(network, peer, source) {
            self.tally.wrong_source.fetch_add(1, Ordering::Relaxed);
            return Err(Rejected::WrongSource);
        }
        let broadcast = match header.destination() {
            IpAddr::V4(destination) if self.routes.is_broadcast(destination) => {
                if !super::broadcast::valid_udp(&packet)
                    || !self.routes.accepts_broadcast(network, peer, destination)
                {
                    self.tally.broadcast_dropped.fetch_add(1, Ordering::Relaxed);
                    return Err(Rejected::BroadcastDenied);
                }
                true
            }
            IpAddr::V4(destination) if self.routes.is_local_destination(network, destination) => {
                false
            }
            // This agent is an exit node of this network: a member's packet
            // for the internet goes to the host, which masquerades it.
            IpAddr::V4(destination) if self.routes.accepts_exit_traffic(network, destination) => {
                false
            }
            _ => {
                self.tally.wrong_destination.fetch_add(1, Ordering::Relaxed);
                return Err(Rejected::WrongDestination);
            }
        };
        // Remote broadcasts terminate here. Only local TUN ingress can fan out.
        if self.device.send(packet).await.is_ok() {
            if broadcast {
                self.tally
                    .broadcast_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.tally.received.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// The addresses the interface should be carrying, from the table.
    pub fn wanted_addresses(&self) -> Vec<Cidr> {
        self.routes
            .local_addresses()
            .into_iter()
            .filter_map(|(address, prefix_len)| Cidr::new(address.into(), prefix_len).ok())
            .collect()
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.task.lock()
            && let Some(task) = guard.take()
        {
            task.abort();
        }
    }
}

impl RoutingTable {
    /// The route for a destination, when it is one the overlay carries.
    fn route_v4(&self, destination: IpAddr) -> Option<Route> {
        match destination {
            IpAddr::V4(address) => self.route(address),
            // The overlay is IPv4. An IPv6 packet has no owner here, and
            // counting it as unroutable is the truth rather than a fault.
            IpAddr::V6(_) => None,
        }
    }
}

/// Whether an address is one the overlay has nowhere to send.
fn is_multicast_or_broadcast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_multicast() || address.is_broadcast() || address == Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(address) => address.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[tokio::test]
    async fn an_in_memory_interface_says_it_is_not_on_the_host() {
        // Everything that would configure the operating system for this
        // interface asks first, and the answer here is no: the name is real
        // to the agent and to nothing else. A real `tsun0` belonging to
        // another agent looks identical from here, so acting on the name
        // alone would configure that one.
        let interface = Interface::start(
            Arc::new(crate::overlay::MemoryTunFactory::new()),
            "tsun0",
            1280,
            Arc::new(RoutingTable::new()),
            Arc::new(Recorder::default()),
        )
        .await
        .unwrap();

        assert_eq!(interface.name(), "tsun0");
        assert!(!interface.on_host());
        interface.remove().await;
    }
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};
    use crate::overlay::broadcast::BroadcastPolicy;
    use crate::overlay::hostrules::{MockHostRules, RuleOutcome};
    use crate::overlay::provision::{ManagedTunFactory, MockProvisioner};
    use crate::overlay::router::{ExitPolicy, NetworkRoutes};
    use crate::overlay::tun::{MemoryTun, MemoryTunFactory};

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![7u8; 32]).unwrap(),
        )
        .network_id()
    }

    fn peer(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn addr(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 13, 37, last)
    }

    fn ipv4(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Bytes {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        let total = (20 + payload.len()) as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet.extend_from_slice(payload);
        Bytes::from(packet)
    }

    #[tokio::test]
    async fn broadcast_ingress_is_validated_and_remote_delivery_never_refloods() {
        use super::super::broadcast::BroadcastPolicy;
        use std::collections::HashSet;
        let (interface, device, routes, carrier, id) = interface(false).await;
        let enabled = BroadcastPolicy {
            enabled: true,
            peers: HashSet::from([peer(2)]),
        };
        routes.set_broadcast(id, enabled.clone());
        let packet = ipv4(addr(2), Ipv4Addr::BROADCAST, &[0, 1, 0, 2, 0, 8, 0, 0]);
        interface
            .deliver(id, peer(2), packet.clone())
            .await
            .unwrap();
        assert_eq!(device.pop_to_os().await.unwrap(), packet);
        assert!(
            carrier.carried().is_empty(),
            "remote ingress never originates a fanout"
        );
        assert_eq!(
            interface.deliver(id, peer(3), packet.clone()).await,
            Err(Rejected::WrongSource)
        );
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(addr(2), Ipv4Addr::BROADCAST, b"bad"))
                .await,
            Err(Rejected::BroadcastDenied)
        );
        routes.set_broadcast(
            id,
            BroadcastPolicy {
                enabled: false,
                ..enabled
            },
        );
        assert_eq!(
            interface.deliver(id, peer(2), packet).await,
            Err(Rejected::BroadcastDenied)
        );
        // An authenticated sender cannot use TUN as a gateway to a physical LAN.
        assert_eq!(
            interface
                .deliver(
                    id,
                    peer(2),
                    ipv4(
                        addr(2),
                        "192.168.1.255".parse().unwrap(),
                        &[0, 1, 0, 2, 0, 8, 0, 0]
                    )
                )
                .await,
            Err(Rejected::WrongDestination)
        );
        device.push_from_os(ipv4(
            addr(1),
            Ipv4Addr::BROADCAST,
            &[0, 1, 0, 2, 0, 8, 0, 0],
        ));
        wait_for(&interface, |c| c.broadcast_dropped.saturating_sub(2)).await;
        assert!(carrier.carried().is_empty());
        assert_eq!(interface.counters().received, 1);
        interface.remove().await;
    }

    /// Records what it was asked to carry, and can refuse.
    #[derive(Debug, Default)]
    struct Recorder {
        carried: std::sync::Mutex<Vec<(Route, Bytes)>>,
        refuse: bool,
    }

    impl PacketCarrier for Recorder {
        fn carry(&self, route: Route, packet: Bytes) -> bool {
            if self.refuse {
                return false;
            }
            match self.carried.lock() {
                Ok(mut guard) => guard.push((route, packet)),
                Err(poisoned) => poisoned.into_inner().push((route, packet)),
            }
            true
        }
    }

    impl Recorder {
        fn carried(&self) -> Vec<(Route, Bytes)> {
            match self.carried.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }
    }

    async fn interface(
        refuse: bool,
    ) -> (
        Interface,
        Arc<MemoryTun>,
        Arc<RoutingTable>,
        Arc<Recorder>,
        NetworkId,
    ) {
        let id = network("interface");
        let routes = Arc::new(RoutingTable::new());
        routes
            .set_network(
                id,
                NetworkRoutes {
                    exit: Default::default(),
                    broadcast: Default::default(),
                    range: Some("10.13.37.0/24".parse().unwrap()),
                    local: Some(addr(1)),
                    peers: vec![(addr(2), peer(2)), (addr(3), peer(3))],
                },
            )
            .unwrap();
        let carrier = Arc::new(Recorder {
            carried: std::sync::Mutex::new(Vec::new()),
            refuse,
        });
        let factory = Arc::new(MemoryTunFactory::new());
        let interface = Interface::start(
            Arc::clone(&factory) as Arc<dyn TunFactory>,
            "tsuntest",
            1280,
            Arc::clone(&routes),
            Arc::clone(&carrier) as Arc<dyn PacketCarrier>,
        )
        .await
        .unwrap();
        // The factory keeps what it made, which is how a test reaches the
        // device the interface is using without exposing it.
        let device = factory.device("tsuntest").expect("the device was created");
        (interface, device, routes, carrier, id)
    }

    /// Waits for a counter to move, so the interface's own task has run.
    async fn wait_for(interface: &Interface, pick: impl Fn(&Counters) -> u64) {
        for _ in 0..400 {
            if pick(&interface.counters()) > 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("the counter never moved: {:?}", interface.counters());
    }

    #[tokio::test]
    async fn a_packet_leaving_the_interface_goes_to_the_peer_that_owns_it() {
        let (interface, device, _routes, carrier, id) = interface(false).await;
        device.push_from_os(ipv4(addr(1), addr(2), b"hello"));

        wait_for(&interface, |counters| counters.sent).await;
        let carried = carrier.carried();
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].0.peer, peer(2));
        assert_eq!(carried[0].0.network, id);
        assert_eq!(&carried[0].1[20..], b"hello");
    }

    #[tokio::test]
    async fn a_packet_for_nobody_is_counted_with_a_sample_and_not_sent() {
        // Counted rather than dropped quietly: without the number and an
        // example of it, "the overlay is quiet" and "the overlay is dropping
        // everything" look the same.
        let (interface, device, _routes, carrier, _id) = interface(false).await;
        let nowhere = Ipv4Addr::new(10, 13, 37, 200);
        device.push_from_os(ipv4(addr(1), nowhere, b"lost"));

        wait_for(&interface, |counters| counters.unroutable).await;
        assert_eq!(
            interface.counters().unroutable_sample,
            Some(IpAddr::V4(nowhere))
        );
        assert!(carrier.carried().is_empty(), "nothing was flooded");
    }

    #[tokio::test]
    async fn multicast_is_expected_and_never_carried() {
        let (interface, device, _routes, carrier, _id) = interface(false).await;
        device.push_from_os(ipv4(addr(1), Ipv4Addr::new(224, 0, 0, 251), b"mdns"));

        wait_for(&interface, |counters| counters.multicast).await;
        assert_eq!(interface.counters().unroutable, 0, "not a routing failure");
        assert!(carrier.carried().is_empty());
    }

    #[tokio::test]
    async fn a_packet_nothing_can_carry_is_counted_separately() {
        // Distinct from unroutable: the destination is known, there is just
        // no live protocol for it. The two want different answers.
        let (interface, device, _routes, _carrier, _id) = interface(true).await;
        device.push_from_os(ipv4(addr(1), addr(2), b"no link"));

        wait_for(&interface, |counters| counters.undeliverable).await;
        let counters = interface.counters();
        assert_eq!(counters.sent, 0);
        assert_eq!(counters.unroutable, 0);
    }

    #[tokio::test]
    async fn a_decrypted_packet_from_its_owner_reaches_the_operating_system() {
        let (interface, device, _routes, _carrier, id) = interface(false).await;
        interface
            .deliver(id, peer(2), ipv4(addr(2), addr(1), b"inbound"))
            .await
            .unwrap();

        let written = tokio::time::timeout(std::time::Duration::from_secs(5), device.pop_to_os())
            .await
            .expect("the packet reaches the interface")
            .unwrap();
        assert_eq!(&written[20..], b"inbound");
        assert_eq!(interface.counters().received, 1);
    }

    #[tokio::test]
    async fn a_peer_cannot_send_from_an_address_it_does_not_hold() {
        let (interface, _device, _routes, _carrier, id) = interface(false).await;

        // Another member's address.
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(addr(3), addr(1), b"spoofed"))
                .await,
            Err(Rejected::WrongSource)
        );
        // And this agent's own.
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(addr(1), addr(1), b"spoofed"))
                .await,
            Err(Rejected::WrongSource)
        );
        assert_eq!(interface.counters().wrong_source, 2);
        assert_eq!(interface.counters().received, 0);
    }

    #[tokio::test]
    async fn an_unreadable_or_wrong_family_packet_is_refused_without_panicking() {
        let (interface, _device, _routes, _carrier, id) = interface(false).await;

        assert_eq!(
            interface.deliver(id, peer(2), Bytes::new()).await,
            Err(Rejected::Malformed)
        );
        assert_eq!(
            interface
                .deliver(id, peer(2), Bytes::from_static(&[0xff; 8]))
                .await,
            Err(Rejected::Malformed)
        );

        // An IPv6 packet: readable, but the overlay has no owner for it.
        let mut six = vec![0u8; 40];
        six[0] = 0x60;
        assert_eq!(
            interface.deliver(id, peer(2), Bytes::from(six)).await,
            Err(Rejected::WrongFamily)
        );
    }

    #[tokio::test]
    async fn the_wanted_addresses_follow_the_table() {
        let (interface, _device, routes, _carrier, id) = interface(false).await;
        assert_eq!(
            interface.wanted_addresses(),
            vec![Cidr::new(addr(1).into(), 24).unwrap()]
        );

        // The network agreed a different address for us.
        routes
            .set_network(
                id,
                NetworkRoutes {
                    exit: Default::default(),
                    broadcast: Default::default(),
                    range: Some("10.13.37.0/24".parse().unwrap()),
                    local: Some(addr(9)),
                    peers: vec![(addr(2), peer(2))],
                },
            )
            .unwrap();
        assert_eq!(
            interface.wanted_addresses(),
            vec![Cidr::new(addr(9).into(), 24).unwrap()]
        );
    }

    async fn managed_interface(
        rules: &MockHostRules,
        broadcast_enabled: bool,
    ) -> (Interface, Arc<RoutingTable>, NetworkId) {
        let id = network("rules");
        let routes = Arc::new(RoutingTable::new());
        routes
            .set_network(
                id,
                NetworkRoutes {
                    exit: Default::default(),
                    broadcast: BroadcastPolicy {
                        enabled: broadcast_enabled,
                        ..Default::default()
                    },
                    range: Some("10.13.37.0/24".parse().unwrap()),
                    local: Some(addr(1)),
                    peers: vec![(addr(2), peer(2))],
                },
            )
            .unwrap();
        let factory = Arc::new(
            ManagedTunFactory::new(Arc::new(MockProvisioner::default()))
                .with_host_rules(Arc::new(rules.clone())),
        );
        let interface = Interface::start(
            factory as Arc<dyn TunFactory>,
            "tsunrules",
            1280,
            Arc::clone(&routes),
            Arc::new(Recorder::default()) as Arc<dyn PacketCarrier>,
        )
        .await
        .unwrap();
        (interface, routes, id)
    }

    #[tokio::test]
    async fn host_rules_follow_broadcast_policy_address_and_interface_lifetime() {
        let rules = MockHostRules::new();
        let (interface, routes, id) = managed_interface(&rules, true).await;
        assert!(
            interface.broadcast_rules().is_none(),
            "nothing before a sync"
        );

        interface.sync_broadcast_rules().await;
        let installed = rules.installed();
        assert_eq!(installed["tsunrules"].source, addr(1));
        assert_eq!(
            installed["tsunrules"].range,
            "10.13.37.0/24".parse().unwrap()
        );
        assert!(interface.broadcast_rules().unwrap().is_ok());

        // Unchanged: not applied a second time.
        interface.sync_broadcast_rules().await;
        interface.sync_broadcast_rules().await;
        assert_eq!(rules.calls(), ["apply:tsunrules"]);

        // A new address replaces the plan, it does not stack a second one.
        routes
            .set_network(
                id,
                NetworkRoutes {
                    exit: Default::default(),
                    broadcast: BroadcastPolicy::default(),
                    range: Some("10.13.37.0/24".parse().unwrap()),
                    local: Some(addr(9)),
                    peers: vec![(addr(2), peer(2))],
                },
            )
            .unwrap();
        interface.sync_broadcast_rules().await;
        assert_eq!(rules.installed()["tsunrules"].source, addr(9));
        assert_eq!(rules.installed().len(), 1);

        // Turning broadcast off takes the rules away.
        routes.set_broadcast(
            id,
            BroadcastPolicy {
                enabled: false,
                ..Default::default()
            },
        );
        interface.sync_broadcast_rules().await;
        assert!(rules.installed().is_empty());
        assert!(interface.broadcast_rules().is_none());

        // And on again puts them back; leaving the agent removes them once more.
        routes.set_broadcast(id, BroadcastPolicy::default());
        interface.sync_broadcast_rules().await;
        assert_eq!(rules.installed().len(), 1);
        interface.remove().await;
        assert!(rules.installed().is_empty(), "shutdown clears the host");
        assert!(interface.broadcast_rules().is_none());
    }

    #[tokio::test]
    async fn host_rules_are_not_installed_while_broadcast_is_off() {
        let rules = MockHostRules::new();
        let (interface, _routes, _id) = managed_interface(&rules, false).await;
        interface.sync_broadcast_rules().await;
        assert!(rules.installed().is_empty());
        assert!(rules.calls().is_empty(), "the host was not even asked");
        interface.remove().await;
    }

    #[tokio::test]
    async fn a_failed_firewall_step_is_reported_and_does_not_undo_the_route() {
        let rules = MockHostRules::new();
        rules.fail_firewall("iptables not found");
        let (interface, _routes, _id) = managed_interface(&rules, true).await;
        interface.sync_broadcast_rules().await;
        let report = interface.broadcast_rules().unwrap();
        assert!(report.route.is_applied());
        assert_eq!(
            report.firewall,
            RuleOutcome::Failed("iptables not found".into())
        );
        assert!(!report.is_ok());
        // Not retried on every sync: the plan is the same.
        interface.sync_broadcast_rules().await;
        assert_eq!(rules.calls(), ["apply:tsunrules"]);
        interface.remove().await;
    }

    #[tokio::test]
    async fn an_interface_without_a_host_has_no_host_rules() {
        let (interface, _device, _routes, _carrier, _id) = interface(false).await;
        interface.sync_broadcast_rules().await;
        assert!(interface.broadcast_rules().is_none());
        interface.remove().await;
    }

    const INTERNET: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    fn offering() -> ExitPolicy {
        ExitPolicy {
            offer: true,
            via: None,
        }
    }

    fn using(exit: EndpointId) -> ExitPolicy {
        ExitPolicy {
            offer: false,
            via: Some(exit),
        }
    }

    #[tokio::test]
    async fn internet_traffic_goes_to_the_exit_node_and_only_once_one_is_chosen() {
        let (interface, device, routes, carrier, id) = interface(false).await;
        device.push_from_os(ipv4(addr(1), INTERNET, b"before"));
        wait_for(&interface, |counters| counters.unroutable).await;
        assert!(carrier.carried().is_empty(), "no exit node, no route");

        routes.set_exit(id, using(peer(2)));
        device.push_from_os(ipv4(addr(1), INTERNET, b"after"));
        wait_for(&interface, |counters| counters.sent).await;
        let carried = carrier.carried();
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].0.peer, peer(2));
        assert_eq!(&carried[0].1[20..], b"after");
    }

    #[tokio::test]
    async fn the_exit_node_may_answer_with_any_source_and_nobody_else_may() {
        let (interface, device, routes, _carrier, id) = interface(false).await;
        routes.set_exit(id, using(peer(2)));

        interface
            .deliver(id, peer(2), ipv4(INTERNET, addr(1), b"reply"))
            .await
            .unwrap();
        let written = tokio::time::timeout(std::time::Duration::from_secs(5), device.pop_to_os())
            .await
            .expect("the reply reaches the interface")
            .unwrap();
        assert_eq!(&written[20..], b"reply");

        // Another member cannot use the internet's addresses.
        assert_eq!(
            interface
                .deliver(id, peer(3), ipv4(INTERNET, addr(1), b"spoof"))
                .await,
            Err(Rejected::WrongSource)
        );
        // Nor can the exit node speak for a member.
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(addr(3), addr(1), b"spoof"))
                .await,
            Err(Rejected::WrongSource)
        );
        // And what it sends still has to be for this agent.
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(INTERNET, addr(200), b"elsewhere"))
                .await,
            Err(Rejected::WrongDestination)
        );
        assert_eq!(interface.counters().received, 1);
    }

    #[tokio::test]
    async fn an_exit_node_hands_a_members_internet_packet_to_the_host_only_while_offering() {
        let (interface, device, routes, _carrier, id) = interface(false).await;

        // Not offering: dropped exactly as before.
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(addr(2), INTERNET, b"request"))
                .await,
            Err(Rejected::WrongDestination)
        );
        assert_eq!(interface.counters().received, 0);

        routes.set_exit(id, offering());
        interface
            .deliver(id, peer(2), ipv4(addr(2), INTERNET, b"request"))
            .await
            .unwrap();
        let written = tokio::time::timeout(std::time::Duration::from_secs(5), device.pop_to_os())
            .await
            .expect("the request reaches the interface")
            .unwrap();
        assert_eq!(&written[20..], b"request");

        // The source must still be the sender's own address.
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(addr(3), INTERNET, b"spoof"))
                .await,
            Err(Rejected::WrongSource)
        );
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(INTERNET, INTERNET, b"spoof"))
                .await,
            Err(Rejected::WrongSource)
        );
        // Offering does not make this a door to the overlay or to this host.
        for destination in [addr(3), addr(200), Ipv4Addr::LOCALHOST] {
            assert_eq!(
                interface
                    .deliver(id, peer(2), ipv4(addr(2), destination, b"no"))
                    .await,
                Err(Rejected::WrongDestination),
                "{destination}"
            );
        }
        assert_eq!(interface.counters().received, 1);
    }

    #[tokio::test]
    async fn the_underlay_reaches_the_rules_only_for_hosts_that_need_it_and_only_while_using_one() {
        let rules = MockHostRules::new();
        let (interface, routes, id) = managed_interface(&rules, false).await;
        let relay = || vec!["relay.example".to_string()];
        let direct = || {
            vec![
                Ipv4Addr::new(138, 201, 61, 182),
                Ipv4Addr::new(10, 13, 37, 9), // the overlay itself
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::new(169, 254, 1, 1),
            ]
        };

        // A host that does not ask never gets them, so Linux and macOS do not
        // re-apply their rules whenever a path moves.
        routes.set_exit(id, using(peer(2)));
        interface.set_underlay(id, direct(), relay()).await;
        interface.sync_exit_rules().await;
        let plan = rules.exit().installed().unwrap();
        assert!(plan.client);
        assert!(plan.bypass.is_empty() && plan.bypass_hosts.is_empty());

        // A host that does gets the usable ones, and follows changes.
        rules.exit().set_needs_bypass(true);
        interface.set_underlay(id, direct(), relay()).await;
        interface.sync_exit_rules().await;
        let plan = rules.exit().installed().unwrap();
        assert_eq!(plan.bypass, vec![Ipv4Addr::new(138, 201, 61, 182)]);
        assert_eq!(plan.bypass_hosts, relay());
        let applies = || {
            rules
                .exit()
                .calls()
                .iter()
                .filter(|c| c.starts_with("apply"))
                .count()
        };
        let before = applies();
        interface.set_underlay(id, direct(), relay()).await;
        assert_eq!(applies(), before, "an unchanged set is not applied again");
        interface
            .set_underlay(id, vec![Ipv4Addr::new(5, 6, 7, 8)], relay())
            .await;
        assert_eq!(applies(), before + 1);
        assert_eq!(
            rules.exit().installed().unwrap().bypass,
            vec![Ipv4Addr::new(5, 6, 7, 8)]
        );

        // Not using an exit node: nothing to keep direct.
        routes.set_exit(id, Default::default());
        interface.sync_exit_rules().await;
        interface
            .set_underlay(id, vec![Ipv4Addr::new(1, 1, 1, 1)], relay())
            .await;
        assert!(rules.exit().installed().is_none());
    }

    #[tokio::test]
    async fn the_exit_rules_follow_the_routing_table_and_leave_with_the_interface() {
        let rules = MockHostRules::new();
        let (interface, routes, id) = managed_interface(&rules, false).await;
        let range: crate::state::Ipv4Range = "10.13.37.0/24".parse().unwrap();

        // Nothing wanted: nothing installed, but what a crashed run left is
        // taken away once.
        interface.sync_exit_rules().await;
        interface.sync_exit_rules().await;
        assert_eq!(rules.exit().calls(), ["clear:tsunrules"]);
        assert!(rules.exit().installed().is_none());
        assert!(!interface.exit_offer_ready(id));
        assert_eq!(interface.exit_rules(id), ExitRulesReport::default());

        // Offering: the range is masqueraded, and the agent can say so.
        routes.set_exit(id, offering());
        assert!(!interface.exit_offer_ready(id), "not applied yet");
        let waiting = interface.exit_rules(id).offer.unwrap();
        assert!(!waiting.ok);
        assert!(waiting.detail.contains("not applied yet"), "{waiting:?}");
        interface.sync_exit_rules().await;
        assert_eq!(rules.exit().installed().unwrap().offer, vec![range]);
        assert!(interface.exit_offer_ready(id));
        let report = interface.exit_rules(id);
        assert!(report.offer.as_ref().unwrap().ok);
        assert_eq!(report.forwarding, Some(true));
        assert!(report.client.is_none());

        // Unchanged: not applied again.
        interface.sync_exit_rules().await;
        assert_eq!(
            rules
                .exit()
                .calls()
                .iter()
                .filter(|call| call.starts_with("apply"))
                .count(),
            1
        );

        // Forwarding off in the kernel: still installed, still ready, and said.
        rules.exit().set_forwarding(Some(false));
        routes.set_exit(
            id,
            ExitPolicy {
                offer: true,
                via: Some(peer(2)),
            },
        );
        interface.sync_exit_rules().await;
        assert!(rules.exit().installed().unwrap().client);
        assert!(interface.exit_offer_ready(id));
        let report = interface.exit_rules(id);
        assert_eq!(report.forwarding, Some(false));
        assert!(report.offer.unwrap().ok);
        assert!(report.client.unwrap().ok);

        // Turned off: removed, and no longer announced as ready.
        routes.set_exit(id, ExitPolicy::default());
        interface.sync_exit_rules().await;
        assert!(rules.exit().installed().is_none());
        assert!(!interface.exit_offer_ready(id));
        assert_eq!(interface.exit_rules(id), ExitRulesReport::default());

        routes.set_exit(id, offering());
        interface.sync_exit_rules().await;
        assert!(rules.exit().installed().is_some());
        interface.remove().await;
        assert!(
            rules.exit().installed().is_none(),
            "gone with the interface"
        );
    }

    #[tokio::test]
    async fn a_failed_exit_step_is_reported_and_the_agent_does_not_claim_to_be_an_exit_node() {
        let rules = MockHostRules::new();
        rules.exit().fail_with(Some("iptables needs root".into()));
        let (interface, routes, id) = managed_interface(&rules, false).await;
        routes.set_exit(id, offering());
        interface.sync_exit_rules().await;

        assert!(!interface.exit_offer_ready(id));
        let offer = interface.exit_rules(id).offer.unwrap();
        assert!(!offer.ok);
        assert!(offer.detail.contains("iptables needs root"), "{offer:?}");

        // It is tried again, not given up on, the next time it is asked.
        rules.exit().fail_with(None);
        interface.sync_exit_rules().await;
        assert!(interface.exit_offer_ready(id));
        interface.remove().await;
    }

    #[tokio::test]
    async fn an_interface_without_a_host_cannot_be_an_exit_node_and_says_why() {
        let (interface, _device, routes, _carrier, id) = interface(false).await;
        routes.set_exit(
            id,
            ExitPolicy {
                offer: true,
                via: Some(peer(2)),
            },
        );
        interface.sync_exit_rules().await;
        assert!(!interface.exit_offer_ready(id));
        let report = interface.exit_rules(id);
        let offer = report.offer.unwrap();
        assert!(!offer.ok);
        assert!(offer.detail.contains("not on the host"), "{offer:?}");
        assert!(!report.client.unwrap().ok);
        interface.remove().await;
    }

    #[tokio::test]
    async fn a_network_waiting_for_its_range_has_nothing_to_masquerade_yet() {
        let rules = MockHostRules::new();
        let (interface, routes, _id) = managed_interface(&rules, false).await;
        let waiting = network("waiting");
        routes
            .set_network(
                waiting,
                NetworkRoutes {
                    exit: offering(),
                    ..Default::default()
                },
            )
            .unwrap();
        interface.sync_exit_rules().await;
        assert!(rules.exit().installed().is_none());
        let offer = interface.exit_rules(waiting).offer.unwrap();
        assert!(offer.detail.contains("address range"), "{offer:?}");
        interface.remove().await;
    }
}
