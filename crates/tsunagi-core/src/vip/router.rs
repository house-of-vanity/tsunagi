//! Client-side flow NAT, data-plane probes and local service observations.
use super::packet::{self, Tuple};
use super::{Backend, BackendStatus, Counters, Listener, ListenerStatus, Protocol, VipStatus};
use crate::overlay::Route;
use crate::{Limits, NetworkId};
use bytes::Bytes;
use iroh::EndpointId;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};
const PROBE: &[u8; 16] = b"tsunagi-vip-rtt1";
#[derive(Debug)]
pub(crate) enum Decision {
    Pass,
    Send(Route, Bytes),
    Local(Bytes),
    Drop,
}
#[derive(Debug)]
enum Guard {
    Tcp { _socket: tokio::net::TcpSocket },
    Udp { _socket: std::net::UdpSocket },
}
fn reserve(protocol: Protocol) -> Option<(u16, Guard)> {
    match protocol {
        Protocol::Tcp => {
            let socket = tokio::net::TcpSocket::new_v4().ok()?;
            socket
                .bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                .ok()?;
            Some((
                socket.local_addr().ok()?.port(),
                Guard::Tcp { _socket: socket },
            ))
        }
        Protocol::Udp => {
            let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
            Some((
                socket.local_addr().ok()?.port(),
                Guard::Udp { _socket: socket },
            ))
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    network: NetworkId,
    vip: String,
    protocol: Protocol,
    port: u16,
}
#[derive(Debug)]
struct Flow {
    key: Key,
    backend: Backend,
    peer: EndpointId,
    wire: Tuple,
    at: Instant,
    idle: Duration,
    local: bool,
    initial_syn: Option<u32>,
    established: bool,
    _guard: Guard,
}
#[derive(Debug, Default)]
struct Path {
    address: Option<Ipv4Addr>,
    available: bool,
    rtt: Option<u64>,
    heard: Option<Instant>,
    last_probe: Option<Instant>,
    pending: Option<(u64, Instant)>,
    misses: u8,
}
#[derive(Debug, Default)]
struct Check {
    at: Option<Instant>,
    pending: bool,
    ever_ok: bool,
    good: u8,
    bad: u8,
    negative_until: Option<Instant>,
}
#[derive(Debug)]
struct Network {
    local: EndpointId,
    address: Option<Ipv4Addr>,
    vips: Vec<VipStatus>,
}
type CheckKey = (NetworkId, EndpointId, Ipv4Addr, Protocol, u16);
/// A bounded TCP connect check prepared off the packet path.
pub(crate) struct CheckJob {
    key: CheckKey,
    source: Ipv4Addr,
    timeout: Duration,
}
impl CheckJob {
    pub async fn run(
        self,
        bind: impl FnOnce(&tokio::net::TcpSocket, Ipv4Addr) -> std::io::Result<()>,
    ) -> (Self, bool) {
        let connect = async {
            let socket = tokio::net::TcpSocket::new_v4()?;
            bind(&socket, self.source)?;
            socket.connect((self.key.2, self.key.4).into()).await
        };
        let ok = matches!(tokio::time::timeout(self.timeout, connect).await, Ok(Ok(_)));
        (self, ok)
    }
}
#[derive(Debug, Default)]
struct State {
    networks: HashMap<NetworkId, Network>,
    paths: HashMap<(NetworkId, EndpointId), Path>,
    checks: HashMap<CheckKey, Check>,
    flows: HashMap<Tuple, Flow>,
    reverse: HashMap<(NetworkId, EndpointId, Tuple), Tuple>,
    retired: HashMap<(NetworkId, EndpointId, Tuple), (Instant, Guard)>,
    counters: HashMap<(Key, Option<Backend>), Counters>,
    fragments: HashMap<NetworkId, packet::Reassembly>,
    limits: Limits,
    sequence: u64,
    check_cursor: usize,
}
#[derive(Debug, Default)]
pub(crate) struct VipRouter {
    state: Mutex<State>,
}
impl VipRouter {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn configure(
        &self,
        network: NetworkId,
        local: EndpointId,
        address: Option<Ipv4Addr>,
        vips: Vec<VipStatus>,
        peers: Vec<(EndpointId, Ipv4Addr, bool)>,
        limits: &Limits,
    ) {
        let mut s = self.lock();
        s.limits = limits.clone();
        let mut present = HashSet::new();
        for (peer, address, available) in peers {
            present.insert(peer);
            let p = s.paths.entry((network, peer)).or_default();
            if p.address != Some(address) {
                p.rtt = None;
                p.heard = None;
                p.pending = None;
            }
            p.address = Some(address);
            p.available = available;
        }
        for ((n, peer), p) in &mut s.paths {
            if *n == network && !present.contains(peer) {
                p.available = false;
            }
        }
        if let Some(address) = address {
            let p = s.paths.entry((network, local)).or_default();
            p.address = Some(address);
            p.available = true;
            p.rtt = Some(0);
            p.heard = Some(Instant::now());
        }
        s.networks.insert(
            network,
            Network {
                local,
                address,
                vips,
            },
        );
    }
    pub fn remove_network(&self, network: NetworkId) {
        let mut s = self.lock();
        s.networks.remove(&network);
        s.fragments.remove(&network);
        s.paths.retain(|(n, _), _| *n != network);
        s.checks.retain(|(n, _, _, _, _), _| *n != network);
        s.flows.retain(|_, f| f.key.network != network);
        s.reverse.retain(|(n, _, _), _| *n != network);
        s.retired.retain(|(n, _, _), _| *n != network);
        s.counters.retain(|(k, _), _| k.network != network);
    }
    pub fn statuses(&self, network: NetworkId) -> Vec<VipStatus> {
        let s = self.lock();
        let Some(n) = s.networks.get(&network) else {
            return vec![];
        };
        let mut views = n.vips.clone();
        for v in &mut views {
            v.listeners = v
                .config
                .listeners
                .iter()
                .map(|l| {
                    let key = Key {
                        network,
                        vip: v.config.id.clone(),
                        protocol: l.protocol,
                        port: l.port,
                    };
                    let mut backends: Vec<_> = l
                        .backends
                        .iter()
                        .map(|b| {
                            let (state, rtt, age) = eligibility(&s, network, n.local, l, b);
                            BackendStatus {
                                backend: b.clone(),
                                state,
                                rtt_us: rtt,
                                measurement_age_ms: age,
                                active_flows: s
                                    .flows
                                    .values()
                                    .filter(|f| f.key == key && f.backend == *b)
                                    .count() as u32,
                                counters: s
                                    .counters
                                    .get(&(key.clone(), Some(b.clone())))
                                    .cloned()
                                    .unwrap_or_default(),
                            }
                        })
                        .collect();
                    for f in s.flows.values().filter(|f| f.key == key) {
                        if !backends.iter().any(|b| b.backend == f.backend) {
                            backends.push(BackendStatus {
                                backend: f.backend.clone(),
                                state: "draining".into(),
                                rtt_us: None,
                                measurement_age_ms: None,
                                active_flows: s
                                    .flows
                                    .values()
                                    .filter(|x| x.key == key && x.backend == f.backend)
                                    .count() as u32,
                                counters: s
                                    .counters
                                    .get(&(key.clone(), Some(f.backend.clone())))
                                    .cloned()
                                    .unwrap_or_default(),
                            });
                        }
                    }
                    let selected = if v.error.is_none() {
                        select(&s, network, n.local, l).map(|(b, _)| b)
                    } else {
                        None
                    };
                    ListenerStatus {
                        protocol: l.protocol,
                        port: l.port,
                        selected,
                        backends,
                        counters: s.counters.get(&(key, None)).cloned().unwrap_or_default(),
                    }
                })
                .collect();
            // A removed listener can still own draining flows; keep them observable.
            let mut draining: BTreeMap<(Protocol, u16), Vec<Backend>> = BTreeMap::new();
            for f in s
                .flows
                .values()
                .filter(|f| f.key.network == network && f.key.vip == v.config.id)
            {
                if !v
                    .listeners
                    .iter()
                    .any(|l| l.protocol == f.key.protocol && l.port == f.key.port)
                {
                    draining
                        .entry((f.key.protocol, f.key.port))
                        .or_default()
                        .push(f.backend.clone());
                }
            }
            for ((protocol, port), mut backends) in draining {
                backends.sort();
                backends.dedup();
                let key = Key {
                    network,
                    vip: v.config.id.clone(),
                    protocol,
                    port,
                };
                let backends = backends
                    .into_iter()
                    .map(|backend| BackendStatus {
                        state: "draining".into(),
                        rtt_us: None,
                        measurement_age_ms: None,
                        active_flows: s
                            .flows
                            .values()
                            .filter(|f| f.key == key && f.backend == backend)
                            .count() as u32,
                        counters: s
                            .counters
                            .get(&(key.clone(), Some(backend.clone())))
                            .cloned()
                            .unwrap_or_default(),
                        backend,
                    })
                    .collect();
                v.listeners.push(ListenerStatus {
                    protocol,
                    port,
                    selected: None,
                    backends,
                    counters: s.counters.get(&(key, None)).cloned().unwrap_or_default(),
                });
            }
        }
        views
    }
    pub fn check_capacity(&self) -> usize {
        self.lock().limits.max_vip_checks
    }
    pub fn tick(&self, capacity: usize) -> (Vec<(Route, Bytes)>, Vec<CheckJob>) {
        let mut s = self.lock();
        let now = Instant::now();
        for fragments in s.fragments.values_mut() {
            fragments.expire(now);
        }
        let expired: Vec<_> = s
            .flows
            .iter()
            .filter(|(_, f)| now.duration_since(f.at) >= f.idle)
            .map(|(t, _)| *t)
            .collect();
        for t in expired {
            remove_flow(&mut s, t);
        }
        s.retired.retain(|_, (until, _)| now < *until);
        let live: HashSet<_> = s.flows.keys().copied().collect();
        s.reverse.retain(|_, t| live.contains(t));
        let mut probes = Vec::new();
        let mut jobs = Vec::new();
        let mut targets = BTreeMap::new();
        for (n, net) in &s.networks {
            for v in &net.vips {
                if v.error.is_some() {
                    continue;
                }
                for l in &v.config.listeners {
                    for b in &l.backends {
                        if let Ok(peer) = b.peer.parse::<EndpointId>() {
                            targets
                                .entry((*n, peer))
                                .or_insert_with(Vec::new)
                                .push((l.clone(), b.clone()));
                        }
                    }
                }
            }
        }
        let mut wanted_checks = HashSet::new();
        for ((network, peer), listeners) in targets {
            let Some(net) = s.networks.get(&network) else {
                continue;
            };
            let (local, source) = (net.local, net.address);
            let sequence = s.sequence.wrapping_add(1);
            s.sequence = sequence;
            let Some(path) = s.paths.get_mut(&(network, peer)) else {
                continue;
            };
            let Some(address) = path.address else {
                continue;
            };
            if peer == local {
                path.rtt = Some(0);
                path.heard = Some(now);
            } else if path.available {
                if path
                    .pending
                    .is_some_and(|(_, at)| now.duration_since(at) >= Duration::from_secs(3))
                {
                    path.pending = None;
                    path.misses = path.misses.saturating_add(1);
                }
                if path.pending.is_none()
                    && path
                        .last_probe
                        .is_none_or(|at| now.duration_since(at) >= Duration::from_secs(1))
                    && let Some(source) = source
                {
                    path.pending = Some((sequence, now));
                    path.last_probe = Some(now);
                    probes.push((Route { network, peer }, probe(source, address, 1, sequence)));
                }
            }
            for (l, b) in listeners {
                let key = (network, peer, address, l.protocol, b.port);
                wanted_checks.insert(key);
                let Some(source) = source else { continue };
                if l.protocol != Protocol::Tcp || !l.port_check {
                    continue;
                }
                let path = s.paths.get(&(network, peer));
                if !path.is_some_and(|p| p.available) {
                    continue;
                }
                let check = s.checks.entry(key).or_default();
                if !check.pending
                    && check.at.is_none_or(|at| {
                        now.duration_since(at)
                            >= Duration::from_millis(u64::from(l.check_interval_ms))
                    })
                {
                    jobs.push(CheckJob {
                        key,
                        source,
                        timeout: Duration::from_millis(u64::from(l.check_timeout_ms)),
                    });
                }
            }
        }
        s.checks.retain(|key, _| wanted_checks.contains(key));
        let mut unique = HashSet::new();
        jobs.retain(|job| unique.insert(job.key));
        if !jobs.is_empty() {
            let offset = s.check_cursor % jobs.len();
            jobs.rotate_left(offset);
            s.check_cursor = s.check_cursor.wrapping_add(capacity.min(jobs.len()));
        }
        jobs.truncate(capacity);
        for job in &jobs {
            if let Some(check) = s.checks.get_mut(&job.key) {
                check.pending = true;
                check.at = Some(now);
            }
        }
        (probes, jobs)
    }
    pub fn checked(&self, job: CheckJob, ok: bool) {
        let mut s = self.lock();
        if let Some(c) = s.checks.get_mut(&job.key) {
            c.pending = false;
            if ok {
                c.ever_ok = true;
                c.good = c.good.saturating_add(1);
                c.bad = 0;
            } else {
                c.bad = c.bad.saturating_add(1);
                c.good = 0;
            }
        }
    }
    pub fn outgoing(&self, packet: Bytes) -> Decision {
        let mut s = self.lock();
        let Some((src, dst)) = packet::addresses(&packet) else {
            return Decision::Pass;
        };
        let fragment = packet::header(&packet)
            .is_some_and(|_| u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0);
        let fragment_network = if fragment {
            s.networks
                .iter()
                .find(|(_, n)| n.vips.iter().any(|v| v.address == Some(dst)))
                .map(|(id, _)| *id)
                .or_else(|| {
                    s.flows
                        .iter()
                        .find(|(t, f)| t.dst == dst || f.local && f.wire.src == dst)
                        .map(|(_, f)| f.key.network)
                })
        } else {
            None
        };
        let packet = if let Some(network) = fragment_network {
            let max = s.limits.max_vip_fragments;
            let Some(p) = s
                .fragments
                .entry(network)
                .or_default()
                .accept(packet, max, None)
            else {
                return Decision::Drop;
            };
            p
        } else {
            packet
        };
        if let Some(quote) = packet::icmp_quote(&packet) {
            let original = s
                .networks
                .iter()
                .find_map(|(id, n)| s.reverse.get(&(*id, n.local, quote.reverse())).copied());
            if let Some(original) = original {
                if let Some(f) = s.flows.get(&original) {
                    let check_key = (
                        f.key.network,
                        f.peer,
                        quote.dst,
                        quote.protocol,
                        f.backend.port,
                    );
                    if packet::header(&packet).is_some_and(|n| packet[n] == 3 && packet[n + 1] == 3)
                    {
                        s.checks.entry(check_key).or_default().negative_until =
                            Some(Instant::now() + Duration::from_secs(10));
                    }
                }
                return packet::rewrite_icmp(&packet, original)
                    .map_or(Decision::Drop, Decision::Local);
            }
        }
        // Local backends reply to the nonlocal VIP source through the TUN.
        if let Some(t) = packet::tuple(&packet) {
            let original = s
                .networks
                .iter()
                .find_map(|(id, n)| s.reverse.get(&(*id, n.local, t)).copied());
            if let Some(original) = original {
                return response(&mut s, original, packet, true);
            }
        }
        if let Some(t) = packet::tuple(&packet)
            && let Some(sequence) = packet::syn_sequence(&packet)
        {
            let replace = s.flows.get(&t).is_some_and(|f| {
                let failed = s
                    .networks
                    .get(&f.key.network)
                    .and_then(|n| {
                        n.vips
                            .iter()
                            .find(|v| v.config.id == f.key.vip)
                            .and_then(|v| {
                                v.config
                                    .listeners
                                    .iter()
                                    .find(|l| l.protocol == t.protocol && l.port == t.dport)
                            })
                            .map(|l| {
                                eligibility(&s, f.key.network, n.local, l, &f.backend).0 != "ready"
                            })
                    })
                    .unwrap_or(true);
                f.initial_syn != Some(sequence)
                    || !f.established && packet::empty_syn(&packet) && failed
            });
            if replace {
                remove_flow(&mut s, t);
            }
        }
        // Existing bindings also retain old VIP addresses/listeners while draining.
        if let Some(t) = packet::tuple(&packet) {
            let draining = s.flows.get(&t).is_some_and(|f| {
                if f.key.protocol == Protocol::Tcp {
                    return true;
                }
                let current = s.networks.get(&f.key.network).and_then(|n| {
                    n.vips
                        .iter()
                        .find(|v| v.address == Some(t.dst) && v.config.id == f.key.vip)
                        .and_then(|v| {
                            v.config
                                .listeners
                                .iter()
                                .find(|l| l.protocol == t.protocol && l.port == t.dport)
                        })
                        .map(|l| (n.local, l))
                });
                current.is_none_or(|(local, l)| {
                    eligibility(&s, f.key.network, local, l, &f.backend).0 == "ready"
                })
            });
            if draining {
                return forward(&mut s, t, packet);
            }
        }
        let Some((network, vip, local, address)) = s.networks.iter().find_map(|(id, n)| {
            n.vips
                .iter()
                .find(|v| v.address == Some(dst))
                .map(|v| (*id, v.clone(), n.local, n.address))
        }) else {
            return Decision::Pass;
        };
        if address != Some(src) {
            return Decision::Drop;
        }
        let max = s.limits.max_vip_fragments;
        let Some(packet) = s
            .fragments
            .entry(network)
            .or_default()
            .accept(packet, max, None)
        else {
            return Decision::Drop;
        };
        let Some(t) = packet::tuple(&packet) else {
            return Decision::Drop;
        };
        let Some(l) = vip
            .config
            .listeners
            .iter()
            .find(|l| l.protocol == t.protocol && l.port == t.dport)
            .cloned()
        else {
            return packet::reject(&packet).map_or(Decision::Drop, Decision::Local);
        };
        let key = Key {
            network,
            vip: vip.config.id.clone(),
            protocol: t.protocol,
            port: t.dport,
        };
        if vip.error.is_some() {
            count(&mut s, &key, None, |c| c.dropped += 1);
            return packet::reject(&packet).map_or(Decision::Drop, Decision::Local);
        }
        if t.protocol == Protocol::Udp
            && s.flows
                .get(&t)
                .is_some_and(|f| eligibility(&s, network, local, &l, &f.backend).0 != "ready")
        {
            remove_flow(&mut s, t);
            count(&mut s, &key, None, |c| c.failovers += 1);
        }
        if s.flows.contains_key(&t) {
            return forward(&mut s, t, packet);
        }
        if t.protocol == Protocol::Tcp && !packet::tcp_syn(&packet) {
            return Decision::Drop;
        }
        let Some((backend, peer)) = select(&s, network, local, &l) else {
            count(&mut s, &key, None, |c| c.dropped += 1);
            return packet::reject(&packet).map_or(Decision::Drop, Decision::Local);
        };
        if s.flows.len().saturating_add(s.retired.len()) >= s.limits.max_vip_flows {
            count(&mut s, &key, None, |c| c.dropped += 1);
            return packet::reject(&packet).map_or(Decision::Drop, Decision::Local);
        }
        let Some((port, guard)) = reserve(t.protocol) else {
            return Decision::Drop;
        };
        let Some(destination) = s.paths.get(&(network, peer)).and_then(|p| p.address) else {
            return Decision::Drop;
        };
        let is_local = peer == local;
        let wire = Tuple {
            src: if is_local { dst } else { src },
            dst: destination,
            sport: port,
            dport: backend.port,
            protocol: t.protocol,
        };
        let Some(out) = packet::rewrite(&packet, wire) else {
            return Decision::Drop;
        };
        s.reverse.insert((network, peer, wire.reverse()), t);
        s.flows.insert(
            t,
            Flow {
                key: key.clone(),
                backend: backend.clone(),
                peer,
                wire,
                at: Instant::now(),
                idle: Duration::from_secs(u64::from(l.idle_timeout_secs)),
                local: is_local,
                initial_syn: packet::syn_sequence(&packet),
                established: false,
                _guard: guard,
            },
        );
        count(&mut s, &key, Some(&backend), |c| {
            c.flows += 1;
            c.tx_packets += 1;
            c.tx_bytes += out.len() as u64;
        });
        if is_local {
            Decision::Local(out)
        } else {
            Decision::Send(Route { network, peer }, out)
        }
    }
    /// Called only after the overlay authenticated source and destination.
    pub fn incoming(&self, network: NetworkId, peer: EndpointId, packet: Bytes) -> Decision {
        let mut s = self.lock();
        if let Some((kind, sequence)) = parse_probe(&packet) {
            let Some(net) = s.networks.get(&network) else {
                return Decision::Drop;
            };
            let Some(source) = net.address else {
                return Decision::Drop;
            };
            if kind == 1 {
                let Some((_, destination)) = packet::addresses(&packet).map(|(a, b)| (b, a)) else {
                    return Decision::Drop;
                };
                return Decision::Send(
                    Route { network, peer },
                    probe(source, destination, 2, sequence),
                );
            }
            if kind == 2
                && let Some(p) = s.paths.get_mut(&(network, peer))
                && let Some((expected, at)) = p.pending
                && expected == sequence
            {
                let rtt = at.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                p.rtt = Some(
                    p.rtt
                        .map_or(rtt, |old| old.saturating_mul(7).saturating_add(rtt) / 8),
                );
                p.heard = Some(Instant::now());
                p.pending = None;
                p.misses = 0;
            }
            return Decision::Drop;
        }
        if let Some(t) = packet::tuple(&packet)
            && s.retired.contains_key(&(network, peer, t))
        {
            return Decision::Drop;
        }
        // Ordinary non-VIP traffic retains its existing admission behavior.
        if packet::header(&packet).is_none() || !s.flows.values().any(|f| f.key.network == network)
        {
            return Decision::Pass;
        }
        // Authentication happens before fragment assembly, preventing cross-peer mixing.
        let was_fragmented = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0;
        let max = s.limits.max_vip_fragments;
        let Some(packet) =
            s.fragments
                .entry(network)
                .or_default()
                .accept(packet, max, Some(*peer.as_bytes()))
        else {
            return Decision::Drop;
        };
        if let Some(t) = packet::tuple(&packet)
            && let Some(original) = s.reverse.get(&(network, peer, t)).copied()
        {
            return response(&mut s, original, packet, false);
        }
        if let Some(quote) = packet::icmp_quote(&packet)
            && let Some(original) = s.reverse.get(&(network, peer, quote.reverse())).copied()
        {
            if let Some(f) = s.flows.get(&original) {
                let backend = f.backend.clone();
                let key = f.key.clone();
                if packet::header(&packet).is_some_and(|n| packet[n] == 3 && packet[n + 1] == 3) {
                    let check = s
                        .checks
                        .entry((network, peer, quote.dst, quote.protocol, backend.port))
                        .or_default();
                    check.negative_until = Some(Instant::now() + Duration::from_secs(10));
                }
                count(&mut s, &key, Some(&backend), |c| c.dropped += 1);
            }
            return packet::rewrite_icmp(&packet, original).map_or(Decision::Drop, Decision::Local);
        }
        if was_fragmented {
            Decision::Local(packet)
        } else {
            Decision::Pass
        }
    }
}
fn forward(s: &mut State, t: Tuple, packet: Bytes) -> Decision {
    let Some(f) = s.flows.get_mut(&t) else {
        return Decision::Drop;
    };
    f.at = Instant::now();
    if t.protocol == Protocol::Tcp && packet::tcp_reset(&packet) {
        f.idle = Duration::from_secs(1);
    }
    let (wire, peer, local, backend, key) =
        (f.wire, f.peer, f.local, f.backend.clone(), f.key.clone());
    let Some(out) = packet::rewrite(&packet, wire) else {
        return Decision::Drop;
    };
    count(s, &key, Some(&backend), |c| {
        c.tx_packets += 1;
        c.tx_bytes += out.len() as u64;
    });
    if local {
        Decision::Local(out)
    } else {
        Decision::Send(
            Route {
                network: key.network,
                peer,
            },
            out,
        )
    }
}
fn remove_flow(s: &mut State, t: Tuple) {
    if let Some(f) = s.flows.remove(&t) {
        s.reverse.remove(&(f.key.network, f.peer, f.wire.reverse()));
        s.retired.insert(
            (f.key.network, f.peer, f.wire.reverse()),
            (Instant::now() + Duration::from_secs(120), f._guard),
        );
    }
}
fn count(s: &mut State, key: &Key, backend: Option<&Backend>, change: impl Fn(&mut Counters)) {
    change(s.counters.entry((key.clone(), None)).or_default());
    if let Some(b) = backend {
        change(
            s.counters
                .entry((key.clone(), Some(b.clone())))
                .or_default(),
        );
    }
}
fn response(s: &mut State, original: Tuple, packet: Bytes, _local: bool) -> Decision {
    let Some(f) = s.flows.get_mut(&original) else {
        return Decision::Drop;
    };
    f.at = Instant::now();
    if original.protocol == Protocol::Tcp && packet::syn_ack(&packet) {
        f.established = true;
    }
    if original.protocol == Protocol::Tcp && packet::tcp_reset(&packet) {
        f.idle = Duration::from_secs(1);
    }
    let (key, backend) = (f.key.clone(), f.backend.clone());
    let Some(out) = packet::rewrite(&packet, original.reverse()) else {
        return Decision::Drop;
    };
    count(s, &key, Some(&backend), |c| {
        c.rx_packets += 1;
        c.rx_bytes += out.len() as u64;
    });
    Decision::Local(out)
}
fn eligibility(
    s: &State,
    network: NetworkId,
    local: EndpointId,
    l: &Listener,
    b: &Backend,
) -> (String, Option<u64>, Option<u64>) {
    let Ok(peer) = b.peer.parse::<EndpointId>() else {
        return ("invalid identity".into(), None, None);
    };
    let Some(p) = s.paths.get(&(network, peer)) else {
        return ("no data path".into(), None, None);
    };
    let age = p
        .heard
        .map(|t| t.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
    let rtt = p
        .rtt
        .filter(|_| peer == local || age.is_some_and(|n| n < 10000));
    if !p.available || p.misses >= 2 {
        return ("no data path".into(), rtt, age);
    }
    if rtt.is_none() {
        return ("measuring RTT".into(), None, age);
    }
    if let Some(address) = p.address {
        let c = s.checks.get(&(network, peer, address, l.protocol, b.port));
        if c.is_some_and(|c| c.negative_until.is_some_and(|t| Instant::now() < t)) {
            return ("port unreachable".into(), rtt, age);
        }
        if l.protocol == Protocol::Tcp && l.port_check {
            let Some(c) = c else {
                return ("checking port".into(), rtt, age);
            };
            if c.bad >= l.failure_threshold {
                return ("port check failed".into(), rtt, age);
            }
            if !c.ever_ok || c.good < l.recovery_threshold && c.bad == 0 {
                return ("checking port".into(), rtt, age);
            }
            if c.good == 0 && c.bad < l.failure_threshold && c.at.is_none() {
                return ("checking port".into(), rtt, age);
            }
        }
    }
    ("ready".into(), rtt, age)
}
fn select(
    s: &State,
    network: NetworkId,
    local: EndpointId,
    l: &Listener,
) -> Option<(Backend, EndpointId)> {
    l.backends
        .iter()
        .filter_map(|b| {
            let (state, rtt, _) = eligibility(s, network, local, l, b);
            (state == "ready").then_some((rtt?, b.clone(), b.peer.parse::<EndpointId>().ok()?))
        })
        .min_by_key(|(rtt, b, _)| (*rtt, b.clone()))
        .map(|(_, b, p)| (b, p))
}
fn probe(src: Ipv4Addr, dst: Ipv4Addr, kind: u8, sequence: u64) -> Bytes {
    let mut p = vec![0; 45];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&45u16.to_be_bytes());
    p[8] = 64;
    p[9] = 253;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..36].copy_from_slice(PROBE);
    p[36] = kind;
    p[37..45].copy_from_slice(&sequence.to_be_bytes());
    let c = packet::checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    Bytes::from(p)
}
fn parse_probe(p: &[u8]) -> Option<(u8, u64)> {
    (packet::header(p) == Some(20) && p.len() == 45 && p[9] == 253 && &p[20..36] == PROBE).then(
        || {
            (
                p[36],
                u64::from_be_bytes([p[37], p[38], p[39], p[40], p[41], p[42], p[43], p[44]]),
            )
        },
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::vip::VipConfig;
    fn packet(t: Tuple, flags: u8) -> Bytes {
        let len = if t.protocol == Protocol::Tcp { 40 } else { 36 };
        let mut p = vec![0; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[8] = 64;
        p[9] = if t.protocol == Protocol::Tcp { 6 } else { 17 };
        p[12..16].copy_from_slice(&t.src.octets());
        p[16..20].copy_from_slice(&t.dst.octets());
        if t.protocol == Protocol::Tcp {
            p[32] = 0x50;
            p[33] = flags;
        } else {
            p[24..26].copy_from_slice(&((len - 20) as u16).to_be_bytes());
        }
        let c = packet::checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        packet::rewrite(&p, t).unwrap()
    }
    fn fixture(
        protocol: Protocol,
    ) -> (
        VipRouter,
        NetworkId,
        EndpointId,
        EndpointId,
        EndpointId,
        Tuple,
    ) {
        let network = NetworkId::from_bytes([7; 32]);
        let local = iroh::SecretKey::generate().public();
        let a = iroh::SecretKey::generate().public();
        let b = iroh::SecretKey::generate().public();
        let mut cfg = VipConfig::new("service");
        let mut l = Listener::new(protocol, 443);
        l.port_check = false;
        l.backends = vec![
            Backend {
                peer: a.to_string(),
                port: 6443,
            },
            Backend {
                peer: b.to_string(),
                port: 7443,
            },
        ];
        cfg.listeners.push(l);
        let router = VipRouter::default();
        let t = Tuple {
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(10, 0, 0, 240),
            sport: 40000,
            dport: 443,
            protocol,
        };
        router.configure(
            network,
            local,
            Some(t.src),
            vec![VipStatus {
                config: cfg,
                revision: "r".into(),
                address: Some(t.dst),
                error: None,
                listeners: vec![],
            }],
            vec![
                (a, Ipv4Addr::new(10, 0, 0, 2), true),
                (b, Ipv4Addr::new(10, 0, 0, 3), true),
            ],
            &Limits::default(),
        );
        {
            let mut s = router.lock();
            for (peer, rtt) in [(a, 1000), (b, 2000)] {
                let p = s.paths.get_mut(&(network, peer)).unwrap();
                p.rtt = Some(rtt);
                p.heard = Some(Instant::now());
            }
        }
        (router, network, local, a, b, t)
    }
    #[tokio::test]
    async fn tcp_uses_lowest_rtt_remaps_both_ports_and_drains_after_removal() {
        let (r, n, _, a, _, t) = fixture(Protocol::Tcp);
        let Decision::Send(route, out) = r.outgoing(packet(t, 2)) else {
            panic!("route expected")
        };
        assert_eq!(route.peer, a);
        let wire = packet::tuple(&out).unwrap();
        assert_eq!(wire.dport, 6443);
        assert_ne!(wire.sport, t.sport);
        let reply = packet(wire.reverse(), 0x12);
        let Decision::Local(reply) = r.incoming(n, a, reply) else {
            panic!("reverse NAT expected")
        };
        assert_eq!(packet::tuple(&reply), Some(t.reverse()));
        assert_eq!(packet::checksum(&reply[..20]), 0);
        {
            r.lock().networks.get_mut(&n).unwrap().vips.clear();
        }
        assert!(matches!(r.outgoing(packet(t, 0x10)), Decision::Send(_, _)));
    }
    #[tokio::test]
    async fn udp_pins_until_failure_then_moves_without_replaying() {
        let (r, n, _, a, b, t) = fixture(Protocol::Udp);
        let Decision::Send(first, _) = r.outgoing(packet(t, 0)) else {
            panic!("route expected")
        };
        assert_eq!(first.peer, a);
        {
            let mut s = r.lock();
            s.paths.get_mut(&(n, b)).unwrap().rtt = Some(100);
        }
        let Decision::Send(still, _) = r.outgoing(packet(t, 0)) else {
            panic!("route expected")
        };
        assert_eq!(still.peer, a);
        {
            r.lock().paths.get_mut(&(n, a)).unwrap().available = false;
        }
        let Decision::Send(next, out) = r.outgoing(packet(t, 0)) else {
            panic!("failover expected")
        };
        assert_eq!(next.peer, b);
        assert_eq!(packet::tuple(&out).unwrap().dport, 7443);
        assert_eq!(r.statuses(n)[0].listeners[0].counters.failovers, 1);
    }
    #[tokio::test]
    async fn local_backend_uses_nonlocal_source_and_restores_client_tuple() {
        let (r, n, local, _, _, t) = fixture(Protocol::Udp);
        {
            let mut s = r.lock();
            let l = &mut s.networks.get_mut(&n).unwrap().vips[0].config.listeners[0];
            l.backends = vec![Backend {
                peer: local.to_string(),
                port: 5353,
            }];
        }
        let Decision::Local(out) = r.outgoing(packet(t, 0)) else {
            panic!("local delivery expected")
        };
        let wire = packet::tuple(&out).unwrap();
        assert_eq!(wire.src, t.dst);
        assert_eq!(wire.dst, t.src);
        assert_eq!(wire.dport, 5353);
        let Decision::Local(reply) = r.outgoing(packet(wire.reverse(), 0)) else {
            panic!("local reverse NAT expected")
        };
        assert_eq!(packet::tuple(&reply), Some(t.reverse()));
    }
    #[tokio::test]
    async fn tcp_check_connects_only_after_the_overlay_socket_is_bound() {
        use std::io;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (_, network, local, _, _, _) = fixture(Protocol::Tcp);
        let server = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = server.local_addr().unwrap().port();
        let job = || CheckJob {
            key: (network, local, Ipv4Addr::LOCALHOST, Protocol::Tcp, port),
            source: Ipv4Addr::LOCALHOST,
            timeout: Duration::from_secs(1),
        };
        let called = AtomicUsize::new(0);
        let (_, ok) = job()
            .run(|_, source| {
                assert_eq!(source, Ipv4Addr::LOCALHOST);
                called.fetch_add(1, Ordering::Relaxed);
                Err(io::Error::other("VPN replaced"))
            })
            .await;
        assert!(!ok);
        assert_eq!(called.load(Ordering::Relaxed), 1);
        let (_, ok) = job()
            .run(|socket, source| socket.bind((source, 0).into()))
            .await;
        assert!(ok);
        let (_, peer) = server.accept().await.unwrap();
        assert_eq!(peer.ip(), Ipv4Addr::LOCALHOST);
    }

    #[tokio::test]
    async fn active_tcp_port_checks_recover_after_a_real_listener_appears() {
        let (r, n, local, _, _, _) = fixture(Protocol::Tcp);
        let server = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = server.local_addr().unwrap().port();
        {
            let mut s = r.lock();
            let net = s.networks.get_mut(&n).unwrap();
            let l = &mut net.vips[0].config.listeners[0];
            l.port_check = true;
            l.failure_threshold = 1;
            l.backends = vec![Backend {
                peer: local.to_string(),
                port,
            }];
            s.paths.get_mut(&(n, local)).unwrap().address = Some(Ipv4Addr::LOCALHOST);
        }
        let (_, jobs) = r.tick(32);
        for job in jobs {
            let (job, ok) = job.run(|_, _| Ok(())).await;
            assert!(ok);
            r.checked(job, ok);
        }
        assert!(r.statuses(n)[0].listeners[0].selected.is_some());
        drop(server);
        {
            for check in r.lock().checks.values_mut() {
                check.at = None;
            }
        }
        let (_, jobs) = r.tick(32);
        for job in jobs {
            let (job, ok) = job.run(|_, _| Ok(())).await;
            assert!(!ok);
            r.checked(job, ok);
        }
        assert!(r.statuses(n)[0].listeners[0].selected.is_none());
        let _server = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        {
            for check in r.lock().checks.values_mut() {
                check.at = None;
            }
        }
        let (_, jobs) = r.tick(32);
        for job in jobs {
            let (job, ok) = job.run(|_, _| Ok(())).await;
            r.checked(job, ok);
        }
        assert!(r.statuses(n)[0].listeners[0].selected.is_some());
    }
    #[test]
    fn unknown_rtt_is_not_selected_and_reflected_probes_do_not_forge_measurements() {
        let (r, n, _, a, _, _) = fixture(Protocol::Udp);
        {
            let mut s = r.lock();
            for p in s.paths.values_mut() {
                p.rtt = None;
                p.heard = None;
            }
        }
        assert!(r.statuses(n)[0].listeners[0].selected.is_none());
        let (probes, _) = r.tick(32);
        let (_, p) = probes
            .into_iter()
            .find(|(route, _)| route.peer == a)
            .unwrap();
        r.incoming(n, a, p);
        assert!(r.statuses(n)[0].listeners[0].selected.is_none());
    }
    #[tokio::test]
    async fn a_new_syn_reselects_backend_and_an_unanswered_empty_syn_can_fail_over() {
        let (r, n, _, a, b, t) = fixture(Protocol::Tcp);
        let Decision::Send(first, out) = r.outgoing(packet(t, 2)) else {
            panic!("first SYN must be routed");
        };
        assert_eq!(first.peer, a);
        let wire = packet::tuple(&out).unwrap();
        {
            r.lock().paths.get_mut(&(n, a)).unwrap().available = false;
        }
        let Decision::Send(next, _) = r.outgoing(packet(t, 2)) else {
            panic!("pending connect should recover");
        };
        assert_eq!(next.peer, b);
        assert!(matches!(
            r.incoming(n, a, packet(wire.reverse(), 0x12)),
            Decision::Drop
        ));
        {
            let mut s = r.lock();
            let path = s.paths.get_mut(&(n, a)).unwrap();
            path.available = true;
            path.rtt = Some(1);
        }
        let mut fresh = packet(t, 2).to_vec();
        fresh[24..28].copy_from_slice(&1u32.to_be_bytes());
        let Decision::Send(new, _) = r.outgoing(Bytes::from(fresh)) else {
            panic!("new connection should reselect");
        };
        assert_eq!(new.peer, a);
    }
}
