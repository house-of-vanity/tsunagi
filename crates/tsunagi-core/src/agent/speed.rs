//! Local ownership of one bounded throughput diagnostic. Control carries
//! negotiation and receiver feedback. Every data packet uses the current cipher and carrier.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use iroh::EndpointId;
use tsunagi_speedtest as wire;

use super::{Agent, DataPath, Inner, PeerStatus};
use crate::dataplane::PluginCapability;
use crate::error::{Error, Result};
use crate::identity::NetworkId;
use crate::ipc::{SpeedBatchReport, SpeedPeerReport, SpeedPhase, SpeedRate, SpeedReport};
use crate::overlay::router::DiagnosticPeer;
use crate::proto::message::{ControlMessage, TransportPayload};

type Key = (NetworkId, EndpointId);

/// A batch can spend at most this many IPv4 bytes in *each* direction.
/// Every remaining peer gets an equal reservation even when earlier probes are lost.
const BATCH_BYTES: u32 = 128 * 1024 * 1024;
const METERED_BATCH_BYTES: u32 = 16 * 1024 * 1024;

pub(super) fn capability() -> PluginCapability {
    PluginCapability {
        protocol: wire::PROTOCOL.into(),
        version: wire::VERSION,
        enabled: true,
        data: Vec::new(),
    }
}

pub(super) fn supported(caps: &[PluginCapability]) -> bool {
    caps.iter()
        .any(|c| c.enabled && c.protocol == wire::PROTOCOL && c.version == wire::VERSION)
}

fn envelope(message: &wire::Control) -> Option<ControlMessage> {
    Some(ControlMessage::Transport {
        protocol: wire::PROTOCOL.into(),
        payload: TransportPayload::new(message.encode().ok()?),
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct Channel {
    key: Key,
    id: u64,
    limit: u32,
    addresses: DiagnosticPeer,
    handle: wire::Handle,
}

struct Job {
    generation: u64,
    network: NetworkId,
    batch: Option<SpeedBatchReport>,
}

#[derive(Default)]
struct Jobs {
    job: Option<Job>,
    history: BTreeMap<Key, SpeedPeerReport>,
}

#[derive(Default)]
pub(super) struct SpeedTests {
    // Admission, completion and cancellation serialize here. Decrypted packets
    // only read the active channel and its receiver counter.
    jobs: Mutex<Jobs>,
    active: ArcSwapOption<Channel>,
    metered: AtomicBool,
}

impl std::fmt::Debug for SpeedTests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpeedTests").finish_non_exhaustive()
    }
}

impl SpeedTests {
    fn lock(&self) -> MutexGuard<'_, Jobs> {
        self.jobs.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn clear_channel(&self, key: Key, id: u64) {
        // Called with the jobs lock held so an old task cannot clear its successor.
        if self
            .active
            .load()
            .as_ref()
            .is_some_and(|c| c.key == key && c.id == id)
        {
            self.active.store(None);
        }
    }

    pub(super) fn report(
        &self,
        network: NetworkId,
        peers: &[PeerStatus],
        enabled: bool,
    ) -> SpeedReport {
        let jobs = self.lock();
        SpeedReport {
            batch: jobs
                .job
                .as_ref()
                .filter(|j| j.network == network)
                .and_then(|j| j.batch),
            peers: jobs
                .history
                .iter()
                .filter(|((net, _), _)| *net == network)
                .map(|((_, peer), report)| (peer.to_string(), report.clone()))
                .collect(),
            capable: peers
                .iter()
                .filter(|p| enabled && supported(&p.capabilities))
                .map(|p| p.endpoint_id.to_string())
                .collect(),
        }
    }

    pub(super) fn disconnected(&self, network: NetworkId, peer: EndpointId) {
        if let Some(c) = self
            .active
            .load()
            .as_ref()
            .filter(|c| c.key == (network, peer))
        {
            c.handle.cancel();
        }
    }

    fn cancel_locked(&self, jobs: &mut Jobs, network: NetworkId) {
        if let Some(c) = self.active.load().as_ref().filter(|c| c.key.0 == network) {
            c.handle.cancel();
        }
        if jobs.job.as_ref().is_some_and(|job| job.network == network) {
            jobs.job = None;
            for ((net, _), report) in &mut jobs.history {
                if *net == network
                    && matches!(
                        report.phase,
                        SpeedPhase::Queued
                            | SpeedPhase::Preparing
                            | SpeedPhase::Download
                            | SpeedPhase::Upload
                    )
                {
                    match report.phase {
                        SpeedPhase::Download => report.down = None,
                        SpeedPhase::Upload => report.up = None,
                        _ => {}
                    }
                    report.phase = SpeedPhase::Cancelled;
                    report.measured_at_unix_secs = now();
                }
            }
        }
    }

    pub(super) fn remove_network(&self, network: NetworkId) {
        let mut jobs = self.lock();
        self.cancel_locked(&mut jobs, network);
        jobs.history.retain(|(net, _), _| *net != network);
    }

    pub(super) fn shutdown(&self) {
        let mut jobs = self.lock();
        jobs.job = None;
        if let Some(channel) = self.active.swap(None) {
            channel.handle.cancel();
        }
    }
}

/// Recognized probe frames never go to a host socket. Admission is stricter
/// than exit traffic: both addresses must be the current signed overlay pair.
pub(super) fn receive_packet(
    inner: &Inner,
    network: NetworkId,
    peer: EndpointId,
    packet: &[u8],
) -> bool {
    if !wire::is_test_packet(packet) {
        return false;
    }
    if let Some(channel) = inner.speed.active.load().as_ref()
        && channel.key == (network, peer)
        && let Some(data) = wire::decode_packet(packet)
        && data.id == channel.id
        && (data.destination, data.source) == (channel.addresses.local, channel.addresses.remote)
        && channel.addresses.is_current(&inner.routes)
    {
        inner
            .routes
            .traffic
            .packet(network, peer, crate::traffic::Direction::Rx, packet, || {
                crate::traffic::Role::SpeedTest
            })
            .record();
        channel.handle.data(data);
    }
    true
}

fn config(
    inner: &Inner,
    key: Key,
    id: u64,
    bytes: u32,
    rtt: Option<Duration>,
) -> Option<(wire::Config, DiagnosticPeer)> {
    let addresses = inner.routes.diagnostic_peer(key.0, key.1)?;
    let ceiling = if inner.speed.metered.load(Ordering::Relaxed) {
        wire::METERED_BYTES
    } else {
        wire::NORMAL_BYTES
    };
    let cfg = wire::Config {
        id,
        local: addresses.local,
        remote: addresses.remote,
        mtu: u16::try_from(inner.config.interface_mtu).unwrap_or(u16::MAX),
        byte_limit: bytes.min(ceiling),
        rtt: rtt.unwrap_or(Duration::from_millis(100)),
    };
    Some((cfg, addresses))
}

pub(super) fn receive_control(
    inner: &Arc<Inner>,
    network: NetworkId,
    peer: EndpointId,
    message: wire::Control,
    rtt: impl FnOnce() -> Option<Duration>,
) -> Option<ControlMessage> {
    let key = (network, peer);
    let id = message.id();
    if let wire::Control::Start(request) = message {
        let jobs = inner.speed.lock();
        if inner.shutdown.is_triggered()
            || jobs.job.is_some()
            || inner.speed.active.load().is_some()
        {
            return envelope(&wire::Control::Busy { id });
        }
        let (cfg, addresses) = config(inner, key, id, request.byte_limit, rtt())?;
        let limit = cfg.byte_limit;
        let (handle, session) = wire::respond(cfg, request);
        inner.speed.active.store(Some(Arc::new(Channel {
            key,
            id,
            limit,
            addresses,
            handle,
        })));
        drop(jobs);
        let io = TestIo::new(inner, key, None);
        tokio::spawn(async move {
            let owner = io.inner.clone();
            session.run(io).await;
            if let Some(inner) = owner.upgrade() {
                let _guard = inner.speed.lock();
                inner.speed.clear_channel(key, id);
            }
        });
    } else if let Some(c) = inner
        .speed
        .active
        .load()
        .as_ref()
        .filter(|c| c.key == key && c.id == id)
    {
        c.handle.control(message);
    }
    None
}

struct TestIo {
    inner: Weak<Inner>,
    key: Key,
    generation: Option<u64>,
    started: Instant,
}

impl TestIo {
    fn new(inner: &Arc<Inner>, key: Key, generation: Option<u64>) -> Self {
        Self {
            inner: Arc::downgrade(inner),
            key,
            generation,
            started: Instant::now(),
        }
    }
}

impl wire::Io for TestIo {
    async fn control(&self, message: wire::Control) -> bool {
        let (Some(inner), Some(message)) = (self.inner.upgrade(), envelope(&message)) else {
            return false;
        };
        Agent { inner }
            .send(self.key.0, self.key.1, message)
            .await
            .is_ok()
    }

    fn packet(&self, packet: Bytes) -> bool {
        self.inner.upgrade().is_some_and(|inner| {
            let observation = inner.routes.traffic.packet(
                self.key.0,
                self.key.1,
                crate::traffic::Direction::Tx,
                &packet,
                || crate::traffic::Role::SpeedTest,
            );
            let sent = inner
                .config
                .tunnel
                .as_ref()
                .is_some_and(|t| t.carry(self.key.0, self.key.1, packet));
            if sent {
                observation.record();
            }
            sent
        })
    }

    fn progress(&self, update: wire::Progress) {
        if !matches!(
            update.state,
            wire::State::Starting | wire::State::Download | wire::State::Upload
        ) {
            return; // Publish terminal results together with releasing the slot.
        }
        if let Some(generation) = self.generation
            && let Some(inner) = self.inner.upgrade()
        {
            let mut jobs = inner.speed.lock();
            if jobs
                .job
                .as_ref()
                .is_some_and(|j| j.generation == generation)
                && let Some(report) = jobs.history.get_mut(&self.key)
            {
                update_report(report, update, self.started);
            }
        }
    }
}

fn update_report(report: &mut SpeedPeerReport, progress: wire::Progress, started: Instant) {
    let live = matches!(progress.state, wire::State::Download | wire::State::Upload);
    let rate = |reading: wire::Reading| {
        reading
            .bps
            .filter(|_| match reading.quality {
                wire::Quality::Measured | wire::Quality::AtLeast => true,
                wire::Quality::Measuring => live,
                wire::Quality::Insufficient => false,
            })
            .map(|bps| SpeedRate {
                bps,
                lower_bound: reading.quality == wire::Quality::AtLeast,
            })
    };
    report.down = rate(progress.down);
    report.up = rate(progress.up);
    report.bytes = u64::from(progress.down.bytes) + u64::from(progress.up.bytes);
    report.elapsed_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
    report.measured_at_unix_secs = now();
    report.phase = match progress.state {
        wire::State::Starting => SpeedPhase::Preparing,
        wire::State::Download => SpeedPhase::Download,
        wire::State::Upload => SpeedPhase::Upload,
        wire::State::Complete if report.down.is_some() || report.up.is_some() => SpeedPhase::Done,
        wire::State::Complete => SpeedPhase::Failed("Insufficient data for a reliable rate".into()),
        wire::State::Busy => SpeedPhase::Failed("Peer is already running a speed test".into()),
        wire::State::TimedOut => {
            SpeedPhase::Failed("Peer did not finish the speed test in time".into())
        }
        wire::State::Cancelled => SpeedPhase::Cancelled,
        wire::State::Failed => {
            SpeedPhase::Failed("The data path could not complete the speed test".into())
        }
    };
}

fn describe_path(peer: &PeerStatus) -> Option<String> {
    match &peer.data_path {
        DataPath::None => None,
        DataPath::Direct { transport } => Some(match &peer.data_transport_detail {
            Some(detail) => format!("{transport} · {detail}"),
            None => transport.clone(),
        }),
        DataPath::Relayed { hops, via } => Some(format!("{hops} hops via {}", via.fmt_short())),
    }
}

impl Agent {
    /// Runs one peer diagnostic, or sequentially tests the capable exit nodes in the network.
    pub async fn start_speed_test(
        &self,
        network: NetworkId,
        peer: Option<EndpointId>,
        metered: bool,
    ) -> Result<()> {
        let status = self.network_status(network).await?;
        let targets: Vec<_> = status
            .peers
            .iter()
            .filter(|p| {
                peer.map_or(p.exit_node, |selected| p.endpoint_id == selected)
                    && status.speed.capable.contains(&p.endpoint_id.to_string())
            })
            .map(|p| p.endpoint_id)
            .collect();
        if targets.is_empty() {
            return Err(Error::SpeedTest(
                if peer.is_some() {
                    "Peer is offline or does not support this speed-test version"
                } else {
                    "No online exit nodes support speed tests in this network"
                }
                .into(),
            ));
        }
        let cap = self.inner.limits.max_speed_results;
        if targets.len() > cap {
            return Err(Error::SpeedTest("Too many peers for one test batch".into()));
        }
        let generation = rand::random();
        let mut jobs = self.inner.speed.lock();
        if self.inner.shutdown.is_triggered() {
            return Err(Error::Stopped);
        }
        if jobs.job.is_some() || self.inner.speed.active.load().is_some() {
            return Err(Error::SpeedTest(
                "Another speed test is already running".into(),
            ));
        }
        // Make room before inserting the queue, preserving results of other networks when possible.
        for target in &targets {
            jobs.history.remove(&(network, *target));
        }
        while jobs.history.len() + targets.len() > cap {
            let Some(oldest) = jobs
                .history
                .iter()
                .min_by_key(|(_, r)| r.measured_at_unix_secs)
                .map(|(k, _)| *k)
            else {
                break;
            };
            jobs.history.remove(&oldest);
        }
        let count = targets.len() as u32;
        jobs.job = Some(Job {
            generation,
            network,
            batch: peer.is_none().then_some(SpeedBatchReport {
                done: 0,
                total: count,
            }),
        });
        for target in &targets {
            jobs.history.insert(
                (network, *target),
                SpeedPeerReport {
                    measured_at_unix_secs: now(),
                    ..Default::default()
                },
            );
        }
        let owner = Arc::downgrade(&self.inner);
        let metered = metered || self.inner.speed.metered.load(Ordering::Relaxed);
        let per_peer = if metered {
            wire::METERED_BYTES
        } else {
            wire::NORMAL_BYTES
        };
        let limit = if peer.is_none() {
            per_peer.min(
                if metered {
                    METERED_BATCH_BYTES
                } else {
                    BATCH_BYTES
                } / count,
            )
        } else {
            per_peer
        };
        tokio::spawn(async move {
            for (index, target) in targets.into_iter().enumerate() {
                let key = (network, target);
                let Some(inner) = owner.upgrade() else {
                    return;
                };
                let result = run_outgoing(&inner, key, generation, limit, peer.is_none()).await;
                let mut jobs = inner.speed.lock();
                if let Some((id, _, _)) = &result {
                    inner.speed.clear_channel(key, *id);
                }
                if jobs.job.as_ref().is_none_or(|j| j.generation != generation) {
                    return;
                }
                if let Some(report) = jobs.history.get_mut(&key) {
                    match result {
                        Some((_, update, started)) => update_report(report, update, started),
                        None => {
                            report.phase = SpeedPhase::Failed(
                                "Peer is no longer eligible or its overlay address is unavailable"
                                    .into(),
                            )
                        }
                    }
                }
                if index + 1 == count as usize {
                    jobs.job = None;
                } else if let Some(batch) = jobs.job.as_mut().and_then(|j| j.batch.as_mut()) {
                    batch.done += 1;
                }
            }
        });
        Ok(())
    }

    /// Cancels the current test and any queued peers in this network.
    pub fn stop_speed_test(&self, network: NetworkId) {
        let mut jobs = self.inner.speed.lock();
        self.inner.speed.cancel_locked(&mut jobs, network);
    }

    /// Applies the host's actual metered-link policy to incoming and outgoing measurements.
    pub fn set_speed_test_metered(&self, metered: bool) {
        if self.inner.speed.metered.swap(metered, Ordering::Relaxed) || !metered {
            return;
        }
        let mut jobs = self.inner.speed.lock();
        if let Some(network) = jobs.job.as_ref().map(|j| j.network) {
            self.inner.speed.cancel_locked(&mut jobs, network);
        } else if let Some(c) = self
            .inner
            .speed
            .active
            .load()
            .as_ref()
            .filter(|c| c.limit > wire::METERED_BYTES)
        {
            c.handle.cancel();
        }
    }
}

async fn run_outgoing(
    inner: &Arc<Inner>,
    key: Key,
    generation: u64,
    limit: u32,
    exits_only: bool,
) -> Option<(u64, wire::Progress, Instant)> {
    let agent = Agent {
        inner: Arc::clone(inner),
    };
    let status = agent.network_status(key.0).await.ok()?;
    let peer = status.peers.iter().find(|p| {
        p.endpoint_id == key.1 && (!exits_only || p.exit_node) && supported(&p.capabilities)
    })?;
    let id = rand::random();
    let (cfg, addresses) = config(inner, key, id, limit, peer.data_rtt.or(peer.rtt))?;
    let limit = cfg.byte_limit;
    let (handle, session) = wire::initiate(cfg);
    let io = TestIo::new(inner, key, Some(generation));
    {
        let mut jobs = inner.speed.lock();
        if jobs.job.as_ref().is_none_or(|j| j.generation != generation) {
            return None;
        }
        let report = jobs.history.get_mut(&key)?;
        report.phase = SpeedPhase::Preparing;
        report.path = describe_path(peer);
        inner.speed.active.store(Some(Arc::new(Channel {
            key,
            id,
            limit,
            addresses,
            handle,
        })));
    }
    let started = io.started;
    let update = session.run(io).await;
    Some((id, update, started))
}
