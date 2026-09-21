//! The per-network runtime.
//!
//! One of these runs for every locally active network. It owns that network's
//! sessions, its dial loop and its counters. Everything it touches carries an
//! explicit [`NetworkId`], so deactivating or breaking one network cannot
//! disturb another and cannot stop the agent.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::{Limits, ReconnectPolicy};
use crate::dataplane::transport::{InboundLink, PacketTransport, SharedLink};
use crate::dataplane::{PluginCapability, SharedPlugin};
use crate::discovery::{Candidate, CandidateSource, NetworkDiscovery};
use crate::error::{Error, Result};
use crate::identity::{NetworkId, NetworkKeys};
use crate::net::{EndpointAdapter, PathAddr, snapshot_connection};
use crate::proto::handshake::{self, HandshakeOutcome, Role};
use crate::proto::message::{Announcement, ControlMessage, Envelope, encode, kind};
use crate::state::allocator::allocate;
use crate::state::{Ipv4Range, Merged, RecordBody, SignedRecord, StateSet};
use crate::storage::Storage;

use super::events::Event;
use super::session::{self, Session, SessionEvent};
use super::shutdown::Shutdown;
use super::status::{
    CandidateStatus, MemberStatus, NetworkMetrics, NetworkState, NetworkStatus, PeerStatus,
};

/// An inbound connection that already passed the handshake.
#[derive(Debug)]
pub(crate) struct InboundSession {
    pub(crate) conn: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
    pub(crate) outcome: HandshakeOutcome,
}

/// Commands accepted by a network runtime.
pub(crate) enum NetCommand {
    Inbound(Box<InboundSession>),
    Send {
        peer: EndpointId,
        message: ControlMessage,
        reply: oneshot::Sender<Result<()>>,
    },
    Broadcast {
        message: ControlMessage,
        reply: oneshot::Sender<usize>,
    },
    /// A peer opened a data plane link towards us.
    InboundLink(Box<InboundLink>),
    Status {
        reply: oneshot::Sender<Box<NetworkStatus>>,
    },
    Recheck,
    /// Resend this agent's announcement to every peer of this network.
    Reannounce,
    /// Answer to a different name from now on.
    SetHostname(String),
    /// An IP plugin reported an error from one of its own tasks.
    PluginError {
        /// Plugin protocol id.
        protocol: String,
        /// Human readable reason, free of secrets.
        reason: String,
    },
}

impl std::fmt::Debug for NetCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetCommand::Inbound(_) => f.write_str("Inbound"),
            NetCommand::InboundLink(link) => write!(f, "InboundLink({})", link.protocol),
            NetCommand::Send { peer, message, .. } => {
                write!(f, "Send({}, {})", peer.fmt_short(), kind(message))
            }
            NetCommand::Broadcast { message, .. } => write!(f, "Broadcast({})", kind(message)),
            NetCommand::Status { .. } => f.write_str("Status"),
            NetCommand::Recheck => f.write_str("Recheck"),
            NetCommand::Reannounce => f.write_str("Reannounce"),
            NetCommand::SetHostname(_) => f.write_str("SetHostname"),
            NetCommand::PluginError { protocol, .. } => write!(f, "PluginError({protocol})"),
        }
    }
}

/// Handle to a running network runtime.
#[derive(Debug)]
pub(crate) struct NetworkHandle {
    pub(crate) keys: NetworkKeys,
    pub(crate) commands: mpsc::Sender<NetCommand>,
    shutdown: Shutdown,
    task: JoinHandle<()>,
}

impl NetworkHandle {
    /// Stops the runtime and waits for its task to finish.
    pub(crate) async fn stop(self) {
        self.shutdown.trigger();
        let _ = self.task.await;
    }
}

/// Everything a network runtime needs to run.
pub(crate) struct RuntimeParams {
    pub(crate) keys: NetworkKeys,
    pub(crate) adapter: EndpointAdapter,
    pub(crate) storage: Storage,
    pub(crate) events: broadcast::Sender<Event>,
    pub(crate) limits: Arc<Limits>,
    pub(crate) reconnect: ReconnectPolicy,
    pub(crate) discovery: Option<Arc<dyn NetworkDiscovery>>,
    pub(crate) discovery_interval: Duration,
    pub(crate) plugins: Vec<SharedPlugin>,
    /// Who holds which overlay address, shared with every other network.
    pub(crate) routes: Arc<crate::overlay::RoutingTable>,
    /// The one interface, when the agent has one.
    pub(crate) interface: Option<Arc<crate::overlay::Interface>>,
    pub(crate) hostname: String,
    /// Signing key for this agent's own records.
    pub(crate) device_secret: iroh::SecretKey,
    /// The IPv4 overlay range this agent would use, if the network has not
    /// already settled on another one.
    pub(crate) ipv4_range: Option<Ipv4Range>,
    /// How data plane links are opened. `None` disables the data plane.
    pub(crate) transport: Option<Arc<dyn PacketTransport>>,
}

/// Outcome of one attempt to open a data plane link.
struct LinkOutcome {
    peer: EndpointId,
    protocol: String,
    result: Result<SharedLink, String>,
}

/// Outcome of one outbound dial.
enum DialOutcome {
    Established(Box<InboundSession>),
    Failed {
        peer: EndpointId,
        reason: String,
        during_handshake: bool,
    },
}

/// Backoff bookkeeping for one candidate.
#[derive(Debug)]
struct DialState {
    consecutive_failures: u32,
    next_attempt: Instant,
    in_flight: bool,
    source: CandidateSource,
}

impl DialState {
    fn new(source: CandidateSource) -> Self {
        Self {
            consecutive_failures: 0,
            next_attempt: Instant::now(),
            in_flight: false,
            source,
        }
    }
}

/// Starts a network runtime.
pub(crate) fn spawn(params: RuntimeParams) -> NetworkHandle {
    let keys = params.keys.clone();
    let shutdown = Shutdown::new();
    let (commands_tx, commands_rx) = mpsc::channel(64);

    let runtime_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        let mut runtime = Runtime::new(params, runtime_shutdown);
        runtime.run(commands_rx).await;
    });

    NetworkHandle {
        keys,
        commands: commands_tx,
        shutdown,
        task,
    }
}

struct Runtime {
    params: RuntimeParams,
    network_id: NetworkId,
    local_id: EndpointId,
    shutdown: Shutdown,
    sessions: HashMap<EndpointId, Session>,
    dial_states: HashMap<EndpointId, DialState>,
    candidate_addrs: HashMap<EndpointId, iroh::EndpointAddr>,
    metrics: NetworkMetrics,
    session_events_tx: mpsc::Sender<SessionEvent>,
    session_events_rx: mpsc::Receiver<SessionEvent>,
    dial_results_tx: mpsc::Sender<DialOutcome>,
    dial_results_rx: mpsc::Receiver<DialOutcome>,
    /// Live data plane links, keyed by peer and plugin protocol.
    links: HashMap<(EndpointId, String), SharedLink>,
    /// Links currently being opened, so we do not start two.
    opening: HashSet<(EndpointId, String)>,
    link_results_tx: mpsc::Sender<LinkOutcome>,
    link_results_rx: mpsc::Receiver<LinkOutcome>,
    /// Peers already told about a protocol version that cannot match, so it
    /// is said once rather than on every announcement.
    reported_mismatch: HashSet<(EndpointId, String)>,
    /// The address last reported as absent from the interface, so it is said
    /// once rather than for ever.
    reported_missing: Option<std::net::Ipv4Addr>,
    /// Signed records, merged from every replica we have talked to.
    state: StateSet,
    /// Snapshots received while dispatching, handled on the next loop pass.
    pending_state: Vec<(EndpointId, Vec<SignedRecord>)>,
    /// The highest version this agent has ever published for this network.
    own_version: u64,
}

impl Runtime {
    fn new(params: RuntimeParams, shutdown: Shutdown) -> Self {
        let network_id = params.keys.network_id();
        let local_id = params.adapter.endpoint_id();
        let (session_events_tx, session_events_rx) = mpsc::channel(256);
        let (dial_results_tx, dial_results_rx) = mpsc::channel(64);
        let (link_results_tx, link_results_rx) = mpsc::channel(64);
        Self {
            params,
            network_id,
            local_id,
            shutdown,
            sessions: HashMap::new(),
            dial_states: HashMap::new(),
            candidate_addrs: HashMap::new(),
            metrics: NetworkMetrics::default(),
            session_events_tx,
            session_events_rx,
            dial_results_tx,
            dial_results_rx,
            links: HashMap::new(),
            opening: HashSet::new(),
            link_results_tx,
            link_results_rx,
            reported_mismatch: HashSet::new(),
            reported_missing: None,
            state: StateSet::new(),
            pending_state: Vec::new(),
            own_version: 0,
        }
    }

    fn emit(&self, event: Event) {
        // A broadcast with no subscribers is not an error.
        let _ = self.params.events.send(event);
    }

    async fn run(&mut self, mut commands: mpsc::Receiver<NetCommand>) {
        // Everything this agent knew before it restarted, including the
        // address it holds.
        self.load_state().await;

        let mut ticker = tokio::time::interval(self.params.discovery_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.wait() => break,
                command = commands.recv() => match command {
                    Some(command) => self.handle_command(command).await,
                    None => break,
                },
                event = self.session_events_rx.recv() => {
                    if let Some(event) = event {
                        self.handle_session_event(event).await;
                        self.drain_pending_state().await;
                    }
                }
                result = self.dial_results_rx.recv() => {
                    if let Some(result) = result {
                        self.handle_dial_result(result).await;
                    }
                }
                result = self.link_results_rx.recv() => {
                    if let Some(result) = result {
                        self.handle_link_result(result);
                    }
                }
                _ = ticker.tick() => {
                    self.discovery_round().await;
                    self.ensure_links();
                }
            }
        }

        self.teardown().await;
    }

    async fn teardown(&mut self) {
        // Stop accepting session events first: nothing is going to act on them
        // any more, and a sender blocked on a full queue would stall shutdown.
        self.session_events_rx.close();
        if let Some(discovery) = &self.params.discovery {
            let _ = discovery
                .unpublish(self.params.keys.discovery_key(), self.local_id)
                .await;
        }
        self.links.clear();
        let peers: Vec<EndpointId> = self.sessions.keys().copied().collect();
        for peer in peers {
            if let Some(session) = self.sessions.remove(&peer) {
                session.stop().await;
            }
        }
        self.emit(Event::NetworkDeactivated {
            network: self.network_id,
        });
    }

    // ---------------------------------------------------------------- commands

    async fn handle_command(&mut self, command: NetCommand) {
        match command {
            NetCommand::Inbound(inbound) => {
                self.install_session(*inbound).await;
            }
            NetCommand::InboundLink(inbound) => self.install_link(*inbound),
            NetCommand::Send {
                peer,
                message,
                reply,
            } => {
                let _ = reply.send(self.send_to(peer, message));
            }
            NetCommand::Broadcast { message, reply } => {
                let peers: Vec<EndpointId> = self.sessions.keys().copied().collect();
                let mut delivered = 0;
                for peer in peers {
                    if self.send_to(peer, message.clone()).is_ok() {
                        delivered += 1;
                    }
                }
                let _ = reply.send(delivered);
            }
            NetCommand::Status { reply } => {
                let _ = reply.send(Box::new(self.status()));
            }
            NetCommand::Recheck => self.discovery_round().await,
            NetCommand::Reannounce => self.reannounce(),
            NetCommand::SetHostname(hostname) => {
                if self.params.hostname != hostname {
                    self.params.hostname = hostname;
                    // Publishing the claim is the revocation: one record per
                    // author, so the new version replaces the old name
                    // rather than sitting beside it.
                    self.ensure_own_claim().await;
                    self.broadcast_state();
                }
                // Told to peers regardless, so a session that missed the
                // earlier announcement is not left with a stale name.
                self.reannounce();
            }
            NetCommand::PluginError { protocol, reason } => {
                // Counted here so that the per-network metric and the event
                // always agree, wherever the error came from.
                self.metrics.plugin_errors += 1;
                self.emit(Event::PluginError {
                    network: self.network_id,
                    protocol,
                    reason,
                });
            }
        }
    }

    /// Rebuilds this agent's announcement and pushes it to every session.
    ///
    /// Used when a plugin's capability changed, so peers do not have to wait
    /// for a reconnect to learn about it.
    fn reannounce(&mut self) {
        let announcement = ControlMessage::Announce(self.local_announcement());
        let peers: Vec<EndpointId> = self.sessions.keys().copied().collect();
        for peer in peers {
            if let Err(err) = self.send_to(peer, announcement.clone()) {
                tracing::debug!(%err, "could not queue re-announcement");
            }
        }
    }

    /// Queues a message without blocking the runtime loop.
    ///
    /// The envelope is encoded here so that the exact number of control bytes
    /// handed to the transport is known and can be reported honestly.
    ///
    /// A full queue is backpressure: the send fails rather than stalling every
    /// other peer in this network.
    fn send_to(&mut self, peer: EndpointId, message: ControlMessage) -> Result<()> {
        let network = self.network_id;
        let envelope = Envelope {
            network_id: *network.as_bytes(),
            message,
        };
        let encoded = encode(&envelope)?;
        let bytes = encoded.len() as u64;

        let session = self.sessions.get_mut(&peer).ok_or(Error::NoSuchPeer {
            network,
            peer: peer.fmt_short().to_string(),
        })?;

        match session.outbound.try_send(encoded) {
            Ok(()) => {
                session.messages_sent += 1;
                session.bytes_sent += bytes;
                self.metrics.control_messages_sent += 1;
                self.metrics.control_bytes_sent += bytes;
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => Err(Error::Storage(format!(
                "outbound queue for peer {} is full",
                peer.fmt_short()
            ))),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::NoSuchPeer {
                network,
                peer: peer.fmt_short().to_string(),
            }),
        }
    }

    // ------------------------------------------------------------- discovery

    async fn discovery_round(&mut self) {
        if self.shutdown.is_triggered() {
            return;
        }

        let mut candidates: Vec<Candidate> = Vec::new();

        if let Some(discovery) = self.params.discovery.clone() {
            let key = self.params.keys.discovery_key();
            // Publishing every round keeps a restarted agent reachable at its
            // new local port without any special case.
            if let Err(err) = discovery.publish(key, self.params.adapter.addr()).await {
                tracing::debug!(%err, "discovery publish failed");
            }
            if let Err(err) = discovery
                .publish(key, self.params.adapter.loopback_addr())
                .await
            {
                tracing::debug!(%err, "discovery publish of bound sockets failed");
            }
            match discovery.resolve(key).await {
                Ok(found) => candidates.extend(found),
                Err(err) => tracing::debug!(%err, "discovery resolve failed"),
            }
        }

        // A stale or missing cache only changes which candidates we try first.
        // It never bypasses authentication.
        for hint in self.params.storage.hints_for_network(self.network_id).await {
            let Ok(endpoint_id) = EndpointId::from_bytes(&hint.endpoint_id) else {
                continue;
            };
            let Some(addr) = decode_hint(endpoint_id, &hint.addr) else {
                continue;
            };
            candidates.push(Candidate::new(addr, CandidateSource::Cache));
        }

        for candidate in candidates {
            let peer = candidate.endpoint_id();
            if peer == self.local_id {
                continue;
            }
            self.candidate_addrs
                .entry(peer)
                .and_modify(|existing| merge_addr(existing, &candidate.addr))
                .or_insert_with(|| candidate.addr.clone());
            self.dial_states
                .entry(peer)
                .or_insert_with(|| DialState::new(candidate.source));
        }

        self.start_dials();
    }

    fn start_dials(&mut self) {
        let now = Instant::now();
        let in_flight = self
            .dial_states
            .values()
            .filter(|state| state.in_flight)
            .count();
        let mut budget = self
            .params
            .limits
            .max_concurrent_dials
            .saturating_sub(in_flight);
        if budget == 0 || self.sessions.len() >= self.params.limits.max_sessions_per_network {
            return;
        }

        let ready: Vec<EndpointId> = self
            .dial_states
            .iter()
            .filter(|(peer, state)| {
                !state.in_flight && state.next_attempt <= now && !self.sessions.contains_key(*peer)
            })
            .map(|(peer, _)| *peer)
            .collect();

        for peer in ready {
            if budget == 0 {
                break;
            }
            let Some(addr) = self.candidate_addrs.get(&peer).cloned() else {
                continue;
            };
            if let Some(state) = self.dial_states.get_mut(&peer) {
                state.in_flight = true;
            }
            budget -= 1;
            self.metrics.dial_attempts += 1;

            let adapter = self.params.adapter.clone();
            let keys = self.params.keys.clone();
            let limits = Arc::clone(&self.params.limits);
            let results = self.dial_results_tx.clone();
            let local_id = self.local_id;
            let shutdown = self.shutdown.clone();

            tokio::spawn(async move {
                let outcome = tokio::select! {
                    biased;
                    _ = shutdown.wait() => DialOutcome::Failed {
                        peer,
                        reason: "network deactivated".into(),
                        during_handshake: false,
                    },
                    outcome = dial(adapter, addr, keys, limits, local_id, peer) => outcome,
                };
                let _ = results.send(outcome).await;
            });
        }
    }

    async fn handle_dial_result(&mut self, result: DialOutcome) {
        match result {
            DialOutcome::Established(inbound) => {
                let peer = inbound.outcome.peer;
                if let Some(state) = self.dial_states.get_mut(&peer) {
                    state.in_flight = false;
                    state.consecutive_failures = 0;
                    state.next_attempt = Instant::now();
                }
                self.install_session(*inbound).await;
            }
            DialOutcome::Failed {
                peer,
                reason,
                during_handshake,
            } => {
                self.metrics.dial_failures += 1;
                if during_handshake {
                    self.metrics.handshake_failures += 1;
                }
                let give_up = {
                    let policy = &self.params.reconnect;
                    let state = self
                        .dial_states
                        .entry(peer)
                        .or_insert_with(|| DialState::new(CandidateSource::Discovery));
                    state.in_flight = false;
                    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                    let delay = policy.delay_for(state.consecutive_failures);
                    state.next_attempt = Instant::now() + delay;
                    policy
                        .max_consecutive_failures
                        .is_some_and(|max| state.consecutive_failures >= max)
                };
                if give_up {
                    // Keep the backoff entry but push it far out; discovery
                    // seeing the peer again resets it.
                    if let Some(state) = self.dial_states.get_mut(&peer) {
                        state.next_attempt = Instant::now() + self.params.reconnect.max_delay;
                    }
                }
                self.emit(Event::DialFailed {
                    network: self.network_id,
                    peer,
                    reason,
                });
            }
        }
    }

    // ----------------------------------------------------------- agreed state

    /// Reads back what this agent already knew before it restarted.
    ///
    /// Records are verified again on load: the database is not a trust
    /// boundary, because a restored backup or a copied file could hold
    /// anything.
    async fn load_state(&mut self) {
        let stored = self
            .params
            .storage
            .signed_records(self.network_id)
            .await
            .unwrap_or_default();
        let (_, errors) = self.state.merge_all(self.network_id, stored);
        for err in errors {
            tracing::warn!(%err, "discarding an unusable stored record");
        }
        self.own_version = self
            .params
            .storage
            .own_record_version(self.network_id, self.local_id)
            .await
            .unwrap_or(0);

        self.ensure_own_claim().await;
        self.publish_allocations().await;
    }

    /// The range this network uses: whatever it has already settled on, else
    /// what this agent was configured with.
    ///
    /// Adopting the agreed one is what lets a participant join without being
    /// told the range out of band.
    fn effective_range(&self) -> Option<Ipv4Range> {
        if let Some(agreed) = self.state.agreed_range() {
            return Some(agreed);
        }
        // Nobody has settled one yet, so this agent would be proposing its
        // own. It must not propose a range it cannot route: one agent has
        // one interface, and claiming an address in a range another network
        // already owns would spread the collision rather than contain it —
        // "the lowest author's range wins" would carry it to everybody.
        // Better to hold off and adopt whatever the network settles on.
        let wanted = self.params.ipv4_range?;
        match self.params.routes.would_overlap(self.network_id, wanted) {
            None => Some(wanted),
            Some(_) => None,
        }
    }

    /// Makes sure this agent holds an address, claiming one if it does not.
    ///
    /// Called after anything that could change the picture: startup, and
    /// every time another replica's records arrive.
    async fn ensure_own_claim(&mut self) {
        let wanted_hostname = {
            let hostname = crate::state::sanitise_hostname(&self.params.hostname);
            (!hostname.is_empty()).then_some(hostname)
        };
        let range = self.effective_range();

        let wanted_address = match range {
            None => None,
            Some(range) => {
                let holders = self.state.address_holders();
                // An address we still hold is kept; this is what makes a
                // returning participant get its old address back.
                match self.state.address_of(&self.local_id) {
                    Some(mine) if range.contains(mine) => Some(mine),
                    _ => {
                        let taken: std::collections::HashSet<std::net::Ipv4Addr> = holders
                            .iter()
                            .filter(|(_, holder)| **holder != self.local_id)
                            .map(|(address, _)| *address)
                            .collect();
                        match allocate(
                            self.network_id,
                            self.local_id,
                            range,
                            &taken,
                            self.state
                                .get(&self.local_id)
                                .and_then(|record| record.body.claimed_address()),
                        ) {
                            Ok(address) => Some(address),
                            Err(err) => {
                                self.metrics.plugin_errors += 1;
                                self.emit(Event::PluginError {
                                    network: self.network_id,
                                    protocol: "overlay".into(),
                                    reason: err.to_string(),
                                });
                                None
                            }
                        }
                    }
                }
            }
        };

        let body = RecordBody::Claim {
            address: wanted_address,
            // The range only travels with an address, so a member of an
            // IPv6-only network does not assert one.
            range: wanted_address.and(range),
            hostname: wanted_hostname,
        };

        // Nothing to say is not the same as saying nothing changed: a member
        // that claims neither an address nor a name has no reason to occupy a
        // record at all.
        if matches!(
            &body,
            RecordBody::Claim {
                address: None,
                hostname: None,
                ..
            }
        ) {
            return;
        }

        // Republishing an unchanged claim would bump the version for no
        // reason and make every replica store it again.
        if self
            .state
            .get(&self.local_id)
            .is_some_and(|record| record.body == body)
        {
            return;
        }

        self.publish_record(body).await;
    }

    /// Signs, stores and announces one of this agent's own records.
    ///
    /// Stored before it is announced, in one transaction with the version
    /// counter, so a crash can never let us reuse a version we already put on
    /// the wire.
    async fn publish_record(&mut self, body: RecordBody) {
        let version = self.own_version.saturating_add(1);
        let record = SignedRecord::sign(&self.params.device_secret, self.network_id, version, body);

        if let Err(err) = self.params.storage.publish_own_record(record.clone()).await {
            self.emit(Event::PluginError {
                network: self.network_id,
                protocol: "overlay".into(),
                reason: format!("cannot store our own record: {err}"),
            });
            return;
        }
        self.own_version = version;

        match self.state.merge(self.network_id, record) {
            Ok(_) => {}
            Err(err) => {
                tracing::error!(%err, "our own record did not verify");
                return;
            }
        }
        self.broadcast_state();
    }

    /// Handles snapshots collected while dispatching messages.
    async fn drain_pending_state(&mut self) {
        for (peer, records) in std::mem::take(&mut self.pending_state) {
            self.receive_state(peer, records).await;
        }
    }

    /// Sends everything we know to every peer.
    fn broadcast_state(&mut self) {
        let mut records = self.state.records();
        records.truncate(self.params.limits.max_state_records);
        if records.is_empty() {
            return;
        }
        let message = ControlMessage::State { records };
        let peers: Vec<EndpointId> = self.sessions.keys().copied().collect();
        for peer in peers {
            if let Err(err) = self.send_to(peer, message.clone()) {
                tracing::debug!(%err, "could not queue a state snapshot");
            }
        }
    }

    /// Merges a snapshot from a peer.
    async fn receive_state(&mut self, peer: EndpointId, records: Vec<SignedRecord>) {
        let before = self.state.records();
        let (outcomes, errors) = self.state.merge_all(self.network_id, records);

        for err in errors {
            self.metrics.protocol_violations += 1;
            self.emit(Event::ProtocolViolation {
                network: Some(self.network_id),
                peer: Some(peer),
                reason: format!("unusable signed record: {err}"),
            });
        }
        for outcome in &outcomes {
            if *outcome == Merged::Conflicted {
                self.emit(Event::PluginError {
                    network: self.network_id,
                    protocol: "overlay".into(),
                    reason: "two different records from one author at the same version; \
                             a device key appears to be in use in two places"
                        .into(),
                });
            }
        }

        let changed = outcomes.iter().any(|outcome| {
            matches!(
                outcome,
                Merged::Added | Merged::Updated | Merged::Conflicted
            )
        });
        if !changed {
            return;
        }

        for record in self.state.records() {
            if record.author == *self.local_id.as_bytes() {
                continue;
            }
            if let Err(err) = self.params.storage.put_signed_record(record).await {
                tracing::debug!(%err, "cannot persist a record");
            }
        }

        // Somebody may have taken the address we were using.
        self.ensure_own_claim().await;
        self.publish_allocations().await;
        if self.state.records() != before {
            self.broadcast_state();
        }
    }

    /// Tells the plugins who holds which overlay address.
    async fn publish_allocations(&mut self) {
        let Some(range) = self.effective_range() else {
            return;
        };
        let mut allocations: Vec<(EndpointId, std::net::Ipv4Addr)> = self
            .state
            .address_holders()
            .into_iter()
            .map(|(address, holder)| (holder, address))
            .collect();
        allocations.sort_by_key(|(holder, _)| *holder.as_bytes());

        for plugin in &self.params.plugins {
            plugin.on_address_allocation(self.network_id, range, &allocations);
        }

        // And the system level's own view, which is what decides whose
        // packet is whose. The local address is kept out of the peer list:
        // a packet for ourselves does not go over a tunnel.
        let local = self.state.address_of(&self.local_id);
        let routes = crate::overlay::NetworkRoutes {
            range: Some(range),
            local,
            peers: allocations
                .iter()
                .filter(|(holder, _)| *holder != self.local_id)
                .map(|(holder, address)| (*address, *holder))
                .collect(),
        };
        if let Err(err) = self.params.routes.set_network(self.network_id, routes) {
            // Reported once per change rather than swallowed: two networks
            // wanting the same addresses is a thing the user has to settle.
            self.metrics.plugin_errors += 1;
            self.emit(Event::PluginError {
                network: self.network_id,
                protocol: "overlay".into(),
                reason: err.to_string(),
            });
            return;
        }
        let Some(interface) = self.params.interface.clone() else {
            return;
        };
        if let Err(err) = interface.sync_addresses().await {
            self.emit(Event::PluginError {
                network: self.network_id,
                protocol: "overlay".into(),
                reason: err.to_string(),
            });
            return;
        }

        // The agent assigns this address itself, so finding it absent means
        // the assignment did not take — something outside removed it, or the
        // provisioner reported a success it did not achieve. Left unsaid it
        // looks like a broken network: packets would leave with the wrong
        // source and every peer would drop them. Checked rather than
        // assumed, because the assumption is exactly the kind that has been
        // wrong here before. Said once per address, not every round.
        let missing = match local {
            Some(address) if !crate::overlay::address_is_local(std::net::IpAddr::V4(address)) => {
                let already = self.reported_missing == Some(address);
                self.reported_missing = Some(address);
                (!already).then_some(address)
            }
            _ => {
                self.reported_missing = None;
                None
            }
        };
        if let Some(address) = missing {
            self.emit(Event::PluginError {
                network: self.network_id,
                protocol: "overlay".into(),
                reason: format!(
                    "this agent was allocated {address}/{} but the address is not on any \
                     interface, so the overlay cannot work: packets would leave with the \
                     wrong source and every peer would drop them. It should have been \
                     assigned to `{}` automatically; check whether something else removed \
                     it.",
                    range.prefix_len,
                    interface.name()
                ),
            });
        }
    }

    // ------------------------------------------------------------ data plane

    /// The protocols this agent speaks, with the version it speaks them at.
    fn served_protocols(&self) -> Vec<(String, u16)> {
        self.params
            .plugins
            .iter()
            .map(|plugin| (plugin.protocol_id().to_string(), plugin.protocol_version()))
            .collect()
    }

    /// Opens whatever data plane links are missing, and forgets dead ones.
    ///
    /// Only one side dials, chosen by a rule both sides compute the same way,
    /// so two agents never open two links for the same thing.
    fn ensure_links(&mut self) {
        let Some(transport) = self.params.transport.clone() else {
            return;
        };
        let served = self.served_protocols();
        if served.is_empty() {
            return;
        }

        let mut dead: Vec<(EndpointId, String)> = Vec::new();
        for (key, link) in &self.links {
            if link.is_closed() {
                dead.push(key.clone());
            }
        }
        for (peer, protocol) in dead {
            self.links.remove(&(peer, protocol.clone()));
            self.emit(Event::DataLinkDown {
                network: self.network_id,
                peer,
                protocol,
                reason: "link closed".into(),
            });
        }

        // Both the name and the version have to match. A peer offering
        // `wg-quic` at a version this build does not speak is not a peer to
        // carry traffic with, and a link opened anyway would fail later and
        // say less about why.
        let wanted: Vec<(EndpointId, String)> = self
            .sessions
            .values()
            .flat_map(|session| {
                let peer = session.peer;
                session
                    .capabilities
                    .iter()
                    .filter(|capability| capability.enabled)
                    .map(move |capability| (peer, capability.protocol.clone(), capability.version))
            })
            .filter(|(_, protocol, version)| {
                served
                    .iter()
                    .any(|(name, ours)| name == protocol && ours == version)
            })
            .map(|(peer, protocol, _)| (peer, protocol))
            .collect();

        for (peer, protocol) in wanted {
            let key = (peer, protocol.clone());
            if self.links.contains_key(&key) || self.opening.contains(&key) {
                continue;
            }
            // The smaller endpoint id dials; the other side accepts. Both
            // compute this identically, so exactly one link is created.
            if self.local_id.as_bytes() >= peer.as_bytes() {
                continue;
            }
            self.opening.insert(key);

            let results = self.link_results_tx.clone();
            let transport = Arc::clone(&transport);
            let network = self.network_id;
            let shutdown = self.shutdown.clone();
            tokio::spawn(async move {
                let result = tokio::select! {
                    biased;
                    _ = shutdown.wait() => Err("network deactivated".to_string()),
                    result = transport.open(network, peer, &protocol) => {
                        result.map_err(|err| err.to_string())
                    }
                };
                let _ = results
                    .send(LinkOutcome {
                        peer,
                        protocol,
                        result,
                    })
                    .await;
            });
        }
    }

    fn handle_link_result(&mut self, outcome: LinkOutcome) {
        let key = (outcome.peer, outcome.protocol.clone());
        self.opening.remove(&key);
        match outcome.result {
            Ok(link) => self.adopt_link(outcome.peer, outcome.protocol, link),
            Err(reason) => {
                // A data plane that cannot be set up is reported, never fatal.
                self.metrics.data_link_failures += 1;
                self.emit(Event::DataLinkDown {
                    network: self.network_id,
                    peer: outcome.peer,
                    protocol: outcome.protocol,
                    reason,
                });
            }
        }
    }

    fn install_link(&mut self, inbound: InboundLink) {
        self.adopt_link(inbound.peer, inbound.protocol, inbound.link);
    }

    /// Hands a link to the plugin that owns its protocol.
    fn adopt_link(&mut self, peer: EndpointId, protocol: String, link: SharedLink) {
        let Some(plugin) = self
            .params
            .plugins
            .iter()
            .find(|plugin| plugin.protocol_id() == protocol)
            .cloned()
        else {
            return;
        };

        let path = link.path_description();
        let max_datagram = link.max_datagram_size();
        self.links
            .insert((peer, protocol.clone()), Arc::clone(&link));
        plugin.on_peer_link(self.network_id, peer, link);
        self.metrics.data_links_established += 1;
        self.emit(Event::DataLinkUp {
            network: self.network_id,
            peer,
            protocol,
            path,
            max_datagram,
        });
    }

    /// Drops every link to a peer.
    fn drop_links_for(&mut self, peer: EndpointId) {
        let keys: Vec<(EndpointId, String)> = self
            .links
            .keys()
            .filter(|(id, _)| *id == peer)
            .cloned()
            .collect();
        for key in keys {
            self.links.remove(&key);
            self.emit(Event::DataLinkDown {
                network: self.network_id,
                peer,
                protocol: key.1,
                reason: "peer session ended".into(),
            });
        }
    }

    // --------------------------------------------------------------- sessions

    async fn install_session(&mut self, inbound: InboundSession) {
        let InboundSession {
            conn,
            send,
            recv,
            outcome,
        } = inbound;
        let peer = outcome.peer;

        if self.sessions.len() >= self.params.limits.max_sessions_per_network
            && !self.sessions.contains_key(&peer)
        {
            conn.close(1u32.into(), b"session limit reached");
            self.emit(Event::ProtocolViolation {
                network: Some(self.network_id),
                peer: Some(peer),
                reason: "session limit for this network reached".into(),
            });
            return;
        }

        // Two agents may dial each other at the same time. Both sides apply the
        // same deterministic rule, so they converge on the same session.
        if let Some(existing) = self.sessions.get(&peer) {
            let existing_initiator = initiator_of(existing.role, self.local_id, peer);
            let new_initiator = initiator_of(outcome.role, self.local_id, peer);
            if existing_initiator.as_bytes() <= new_initiator.as_bytes() {
                conn.close(0u32.into(), b"duplicate session");
                return;
            }
            if let Some(old) = self.sessions.remove(&peer) {
                old.abort();
                old.conn
                    .close(0u32.into(), b"replaced by preferred session");
            }
        }

        self.record_hints(&conn).await;

        let session = session::spawn(
            self.network_id,
            peer,
            outcome.role,
            conn.clone(),
            send,
            recv,
            Arc::clone(&self.params.limits),
            self.session_events_tx.clone(),
            self.shutdown.clone(),
        );

        let snapshot = snapshot_connection(&conn);
        self.sessions.insert(peer, session);
        self.metrics.sessions_established += 1;

        // Announce ourselves straight away so the peer learns our hostname and
        // capabilities without another round of discovery.
        let announcement = ControlMessage::Announce(self.local_announcement());
        if let Err(err) = self.send_to(peer, announcement) {
            tracing::debug!(%err, "could not queue initial announcement");
        }

        self.broadcast_state();

        self.emit(Event::PeerConnected {
            network: self.network_id,
            peer,
            role: outcome.role,
            transport: snapshot.transport,
            rtt: snapshot.rtt,
        });
    }

    fn local_announcement(&mut self) -> Announcement {
        let mut capabilities = Vec::new();
        let mut errors = Vec::new();
        for plugin in &self.params.plugins {
            match plugin.local_capability(self.network_id) {
                Ok(Some(capability)) => capabilities.push(capability),
                Ok(None) => {}
                Err(err) => errors.push((plugin.protocol_id().to_string(), err.to_string())),
            }
        }
        for (protocol, reason) in errors {
            self.metrics.plugin_errors += 1;
            self.emit(Event::PluginError {
                network: self.network_id,
                protocol,
                reason,
            });
        }
        capabilities.truncate(self.params.limits.max_capabilities);
        Announcement {
            hostname: self.params.hostname.clone(),
            capabilities,
        }
    }

    async fn record_hints(&self, conn: &Connection) {
        let snapshot = snapshot_connection(conn);
        let peer_bytes = *snapshot.remote_id.as_bytes();
        for path in &snapshot.paths {
            if let Some(encoded) = encode_hint(&path.remote) {
                self.params
                    .storage
                    .record_hint(
                        self.network_id,
                        peer_bytes,
                        encoded,
                        self.params.limits.max_hints_per_peer,
                    )
                    .await;
            }
        }
    }

    async fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::Message {
                session_id,
                peer,
                message,
                bytes,
            } => {
                let current = self.sessions.get(&peer).map(|session| session.id);
                if current != Some(session_id) {
                    return;
                }
                self.metrics.control_messages_received += 1;
                self.metrics.control_bytes_received += bytes as u64;
                if let Some(session) = self.sessions.get_mut(&peer) {
                    session.messages_received += 1;
                    session.bytes_received += bytes as u64;
                }
                self.dispatch_message(peer, message);
            }
            SessionEvent::Violation {
                session_id,
                peer,
                error,
            } => {
                let current = self.sessions.get(&peer).map(|session| session.id);
                if current != Some(session_id) {
                    return;
                }
                self.metrics.protocol_violations += 1;
                self.emit(Event::ProtocolViolation {
                    network: Some(self.network_id),
                    peer: Some(peer),
                    reason: error.to_string(),
                });
            }
            SessionEvent::Closed {
                session_id,
                peer,
                reason,
            } => {
                let current = self.sessions.get(&peer).map(|session| session.id);
                if current != Some(session_id) {
                    return;
                }
                if let Some(session) = self.sessions.remove(&peer) {
                    session.abort();
                    session.conn.close(0u32.into(), b"session ended");
                }
                self.metrics.disconnects += 1;
                self.drop_links_for(peer);
                for plugin in &self.params.plugins {
                    plugin.on_peer_gone(self.network_id, peer);
                }
                // Retry promptly, then back off if it keeps failing.
                let policy = &self.params.reconnect;
                let state = self
                    .dial_states
                    .entry(peer)
                    .or_insert_with(|| DialState::new(CandidateSource::Discovery));
                state.in_flight = false;
                state.next_attempt = Instant::now() + policy.initial_delay;
                self.emit(Event::PeerDisconnected {
                    network: self.network_id,
                    peer,
                    reason,
                });
            }
        }
    }

    fn dispatch_message(&mut self, peer: EndpointId, message: ControlMessage) {
        match &message {
            ControlMessage::Announce(announcement) => {
                let capabilities = announcement.capabilities.clone();
                if let Some(session) = self.sessions.get_mut(&peer) {
                    session.hostname = Some(announcement.hostname.clone());
                    session.capabilities = capabilities.clone();
                }
                self.dispatch_capabilities(peer, &capabilities);
                self.ensure_links();
            }
            ControlMessage::Ping { seq, payload } => {
                let pong = ControlMessage::Pong {
                    seq: *seq,
                    payload: payload.clone(),
                };
                if let Err(err) = self.send_to(peer, pong) {
                    tracing::debug!(%err, "could not queue pong");
                }
            }
            ControlMessage::State { records } => {
                self.pending_state.push((peer, records.clone()));
            }
            ControlMessage::Pong { .. } | ControlMessage::Bye { .. } => {}
        }

        self.emit(Event::MessageReceived {
            network: self.network_id,
            peer,
            message,
        });
    }

    fn dispatch_capabilities(&mut self, peer: EndpointId, capabilities: &[PluginCapability]) {
        let mut errors = Vec::new();
        for capability in capabilities {
            for plugin in &self.params.plugins {
                if plugin.protocol_id() != capability.protocol {
                    continue;
                }
                if plugin.protocol_version() != capability.version {
                    // Said once per peer and protocol. A version that will
                    // not match this build will not match it on the next
                    // announcement either, and repeating it every round
                    // would bury everything else.
                    let key = (peer, capability.protocol.clone());
                    if self.reported_mismatch.insert(key) {
                        errors.push((
                            capability.protocol.clone(),
                            format!(
                                "peer speaks {} version {} and this build speaks {}, so there \
                                 is no data plane with it; the control plane is unaffected",
                                capability.protocol,
                                capability.version,
                                plugin.protocol_version()
                            ),
                        ));
                    }
                    continue;
                }
                // The core hands the opaque payload over without interpreting it.
                if let Err(err) = plugin.on_peer_capability(self.network_id, peer, capability) {
                    errors.push((plugin.protocol_id().to_string(), err.to_string()));
                }
            }
        }
        for (protocol, reason) in errors {
            self.metrics.plugin_errors += 1;
            self.emit(Event::PluginError {
                network: self.network_id,
                protocol,
                reason,
            });
        }
    }

    // ----------------------------------------------------------------- status

    fn status(&self) -> NetworkStatus {
        let served = self.served_protocols();
        let mut peers: Vec<PeerStatus> = self
            .sessions
            .values()
            .map(|session| {
                let snapshot = snapshot_connection(&session.conn);
                PeerStatus {
                    endpoint_id: session.peer,
                    role: session.role,
                    hostname: session.hostname.clone(),
                    protocols: session
                        .capabilities
                        .iter()
                        .filter(|capability| capability.enabled)
                        .filter(|capability| {
                            served.iter().any(|(name, ours)| {
                                *name == capability.protocol && *ours == capability.version
                            })
                        })
                        .map(|capability| capability.protocol.clone())
                        .collect(),
                    capabilities: session.capabilities.clone(),
                    connected_for: session.established.elapsed(),
                    paths: snapshot.paths,
                    transport: snapshot.transport,
                    rtt: snapshot.rtt,
                    connection: snapshot.counters,
                    control_messages_sent: session.messages_sent,
                    control_messages_received: session.messages_received,
                    control_bytes_sent: session.bytes_sent,
                    control_bytes_received: session.bytes_received,
                }
            })
            .collect();
        peers.sort_by(|a, b| a.endpoint_id.as_bytes().cmp(b.endpoint_id.as_bytes()));

        let mut candidates: Vec<CandidateStatus> = self
            .dial_states
            .iter()
            .map(|(peer, state)| CandidateStatus {
                endpoint_id: *peer,
                source: state.source,
                consecutive_failures: state.consecutive_failures,
            })
            .collect();
        candidates.sort_by(|a, b| a.endpoint_id.as_bytes().cmp(b.endpoint_id.as_bytes()));

        // The durable roster. Every author of a signed record is a member,
        // including this agent and including members that are not here.
        let mut members: Vec<MemberStatus> = self
            .state
            .records()
            .into_iter()
            .filter_map(|record| {
                let endpoint_id = record.author_id().ok()?;
                Some(MemberStatus {
                    endpoint_id,
                    // Only uncontested claims are reported as held: two
                    // members may have claimed the same thing, and saying
                    // both hold it would be untrue on one of them.
                    overlay_address_v4: self.state.address_of(&endpoint_id),
                    hostname: self.state.hostname_of(&endpoint_id).map(str::to_string),
                })
            })
            .collect();
        members.sort_by(|a, b| a.endpoint_id.as_bytes().cmp(b.endpoint_id.as_bytes()));
        members.dedup_by(|a, b| a.endpoint_id == b.endpoint_id);

        NetworkStatus {
            descriptor: self.params.keys.descriptor(),
            name: self.params.keys.name().clone(),
            network_id: self.network_id,
            state: NetworkState::Active,
            peers,
            candidates,
            members,
            metrics: self.metrics.clone(),
        }
    }
}

/// Which side dialled, given a role and the two identities.
fn initiator_of(role: Role, local: EndpointId, peer: EndpointId) -> EndpointId {
    match role {
        Role::Initiator => local,
        Role::Responder => peer,
    }
}

/// Performs one dial and handshake.
async fn dial(
    adapter: EndpointAdapter,
    addr: iroh::EndpointAddr,
    keys: NetworkKeys,
    limits: Arc<Limits>,
    local_id: EndpointId,
    peer: EndpointId,
) -> DialOutcome {
    let connect = tokio::time::timeout(limits.dial_timeout, adapter.connect(addr)).await;
    let (conn, mut send, mut recv) = match connect {
        Ok(Ok(parts)) => parts,
        Ok(Err(err)) => {
            return DialOutcome::Failed {
                peer,
                reason: err.to_string(),
                during_handshake: false,
            };
        }
        Err(_) => {
            return DialOutcome::Failed {
                peer,
                reason: "dial timed out".into(),
                during_handshake: false,
            };
        }
    };

    match handshake::initiate(&conn, &mut send, &mut recv, local_id, &keys, &limits).await {
        Ok(outcome) => DialOutcome::Established(Box::new(InboundSession {
            conn,
            send,
            recv,
            outcome,
        })),
        Err(err) => {
            conn.close(2u32.into(), b"handshake failed");
            DialOutcome::Failed {
                peer,
                reason: err.to_string(),
                during_handshake: true,
            }
        }
    }
}

/// Encodes a path address as a cache hint.
fn encode_hint(addr: &PathAddr) -> Option<String> {
    match addr {
        PathAddr::Ip(socket) => Some(format!("ip:{socket}")),
        PathAddr::Relay(url) => Some(format!("relay:{url}")),
        PathAddr::Other(_) => None,
    }
}

/// Decodes a cache hint back into an address. Malformed hints are ignored.
fn decode_hint(endpoint_id: EndpointId, hint: &str) -> Option<iroh::EndpointAddr> {
    if let Some(rest) = hint.strip_prefix("ip:") {
        let socket: std::net::SocketAddr = rest.parse().ok()?;
        return Some(iroh::EndpointAddr::new(endpoint_id).with_ip_addr(socket));
    }
    if let Some(rest) = hint.strip_prefix("relay:") {
        let url: iroh::RelayUrl = rest.parse().ok()?;
        return Some(iroh::EndpointAddr::new(endpoint_id).with_relay_url(url));
    }
    None
}

/// Folds newly learned addresses into a known candidate address.
fn merge_addr(existing: &mut iroh::EndpointAddr, incoming: &iroh::EndpointAddr) {
    if existing.id != incoming.id {
        *existing = incoming.clone();
        return;
    }
    for addr in &incoming.addrs {
        existing.addrs.insert(addr.clone());
    }
}
