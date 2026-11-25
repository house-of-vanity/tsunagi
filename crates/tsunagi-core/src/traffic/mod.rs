//! Window-scoped, local observations. Each reader owns just its current interval.
//! The first branch on the packet path skips all monitor work when nobody is watching.
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    NetworkId,
    config::{MAX_INTERVAL_FLOWS, MAX_TRAFFIC_READERS},
    iroh_types::EndpointId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// How the local agent handled the observed traffic.
pub enum Role {
    /// Ordinary authenticated overlay traffic.
    Mesh,
    /// Local internet traffic carried by the selected exit peer.
    ViaExit,
    /// Internet traffic forwarded for a remote exit client.
    ServeExit,
    /// Traffic translated or probed by the virtual service router.
    Vip,
    /// One accepted overlay broadcast copy.
    Broadcast,
    /// A sample from an admitted mesh throughput test.
    SpeedTest,
    /// Messages on an authenticated control session.
    Control,
    /// Opaque datagrams forwarded between other mesh members.
    Relay,
}

impl Role {
    /// Whether this role counts transport data rather than locally visible IP packets.
    pub fn transport(self) -> bool {
        matches!(self, Self::Control | Self::Relay)
    }
}

/// Addresses on the side of this agent and on the side of its authenticated peer.
/// For encrypted transit the two endpoint IDs are ordered, with TX from the first.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    /// Public network identity.
    pub network: [u8; 32],
    /// Authenticated peer, or first endpoint of an opaque relay pair.
    pub peer: [u8; 32],
    /// Local forwarding or transport role.
    pub role: Role,
    /// Admitted header metadata used for aggregation.
    pub flow: Flow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// One bidirectional IP conversation, control session, or opaque relay pair.
pub enum Flow {
    /// IPv4 endpoints from the agent-facing and peer-facing sides.
    Ip {
        /// Source when sending, destination when receiving.
        near: [u8; 4],
        /// Destination when sending, source when receiving.
        far: [u8; 4],
        /// IPv4 protocol number.
        protocol: u8,
        /// Transport header fields available in this packet.
        detail: IpDetail,
    },
    /// Aggregated authenticated control envelopes.
    Control,
    /// An end-to-end mesh envelope passing through this device.
    Relay {
        /// The second endpoint, ordered by public key.
        other: [u8; 32],
        /// Opaque plugin protocol tag carried by the relay header.
        wire_protocol: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Transport fields read from an IPv4 header and its bounded prefix.
pub enum IpDetail {
    /// TCP/UDP ports in near/far order.
    Ports(u16, u16),
    /// ICMP echo requests and replies for the address pair.
    Echo,
    /// Another ICMP type and code.
    Icmp(u8, u8),
    /// Noninitial fragment with no transport header.
    Fragment,
    /// Protocol has no recognised, readable transport prefix.
    Other,
}

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Tx,
    Rx,
}

impl Flow {
    pub(crate) fn ip(packet: &[u8], dir: Direction) -> Option<Self> {
        let header = packet.get(..20)?;
        let offset = usize::from(header[0] & 15) * 4;
        let total = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if header[0] >> 4 != 4 || offset < 20 {
            return None;
        }
        let body = packet.get(..total)?.get(offset..)?;
        let protocol = header[9];
        let a: [u8; 4] = header[12..16].try_into().ok()?;
        let b: [u8; 4] = header[16..20].try_into().ok()?;
        let (near, far) = match dir {
            Direction::Tx => (a, b),
            Direction::Rx => (b, a),
        };
        let detail = if (u16::from_be_bytes([header[6], header[7]]) & 0x1fff) != 0 {
            IpDetail::Fragment
        } else {
            match (protocol, body) {
                (6 | 17, [a, b, c, d, ..]) => {
                    let (src, dst) = (u16::from_be_bytes([*a, *b]), u16::from_be_bytes([*c, *d]));
                    match dir {
                        Direction::Tx => IpDetail::Ports(src, dst),
                        Direction::Rx => IpDetail::Ports(dst, src),
                    }
                }
                (1, [0 | 8, 0, ..]) => IpDetail::Echo,
                (1, [kind, code, ..]) => IpDetail::Icmp(*kind, *code),
                _ => IpDetail::Other,
            }
        };
        Some(Self::Ip {
            near,
            far,
            protocol,
            detail,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Counters added during one observation interval.
pub struct FlowDelta {
    /// Stable bidirectional identity of this flow.
    pub key: FlowKey,
    /// Bytes sent in this interval.
    pub tx_bytes: u64,
    /// Bytes received in this interval.
    pub rx_bytes: u64,
    /// Packets or transport messages sent.
    pub tx_packets: u64,
    /// Packets or transport messages received.
    pub rx_packets: u64,
    /// Age of the most recent observation when the interval was drained.
    pub age_ms: u64,
}

#[derive(Default, Debug, Serialize, Deserialize)]
/// An interval delta for one local subscriber.
pub struct TrafficSnapshot {
    /// Flows observed since the previous drain.
    pub flows: Vec<FlowDelta>,
    /// Elapsed monotonic milliseconds since opening or the preceding drain.
    pub interval_ms: u64,
    /// Packets/messages that could not be counted during this interval.
    pub omitted: u64,
}

#[derive(Debug)]
struct Counts {
    tx: u64,
    rx: u64,
    ntx: u64,
    nrx: u64,
    last: Instant,
}

#[derive(Debug)]
struct Bucket {
    // Concurrent writers can spill into a different lane, including the reverse
    // direction of the same flow. The window merges these after the drain.
    lanes: [Mutex<HashMap<FlowKey, Counts>>; 4],
    since: Mutex<Instant>,
    entries: AtomicUsize,
    omitted: AtomicU64,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl Bucket {
    fn add(&self, key: FlowKey, dir: Direction, len: u64, now: Instant) {
        for lane in &self.lanes {
            let Ok(mut flows) = lane.try_lock() else {
                continue;
            };
            let counts = match flows.entry(key) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    if self.entries.fetch_add(1, Ordering::Relaxed) >= MAX_INTERVAL_FLOWS {
                        self.entries.fetch_sub(1, Ordering::Relaxed);
                        continue;
                    }
                    e.insert(Counts {
                        tx: 0,
                        rx: 0,
                        ntx: 0,
                        nrx: 0,
                        last: now,
                    })
                }
            };
            counts.last = counts.last.max(now);
            let (bytes, packets) = match dir {
                Direction::Tx => (&mut counts.tx, &mut counts.ntx),
                Direction::Rx => (&mut counts.rx, &mut counts.nrx),
            };
            *bytes = bytes.saturating_add(len);
            *packets = packets.saturating_add(1);
            return;
        }
        self.omitted.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default, Debug)]
pub(crate) struct TrafficMonitor {
    active: AtomicBool,
    readers: ArcSwap<Vec<Weak<Bucket>>>,
    // Only registration/unregistration use this lock.
    registration: Mutex<()>,
}

impl TrafficMonitor {
    pub(crate) fn subscribe(self: &Arc<Self>) -> Result<TrafficSubscription, String> {
        let _edit = self.registration.lock().unwrap_or_else(|e| e.into_inner());
        let mut readers = (**self.readers.load()).clone();
        if readers.len() >= MAX_TRAFFIC_READERS {
            return Err("Too many traffic monitor windows are open".into());
        }
        let bucket = Arc::new(Bucket {
            lanes: Default::default(),
            since: Mutex::new(Instant::now()),
            entries: AtomicUsize::new(0),
            omitted: AtomicU64::new(0),
        });
        readers.push(Arc::downgrade(&bucket));
        self.readers.store(Arc::new(readers));
        self.active.store(true, Ordering::Release);
        Ok(TrafficSubscription {
            owner: Arc::downgrade(self),
            bucket,
        })
    }

    pub(crate) fn prepare(
        &self,
        make: impl FnOnce() -> Option<(FlowKey, Direction, u64)>,
    ) -> Observation {
        if !self.active.load(Ordering::Acquire) {
            return Observation(None);
        }
        let readers = self.readers.load_full();
        Observation(make().map(|(key, dir, len)| Pending {
            readers,
            key,
            dir,
            len,
        }))
    }

    pub(crate) fn packet(
        &self,
        network: NetworkId,
        peer: EndpointId,
        dir: Direction,
        packet: &[u8],
        role: impl FnOnce() -> Role,
    ) -> Observation {
        self.prepare(|| {
            Some((
                FlowKey {
                    network: *network.as_bytes(),
                    peer: *peer.as_bytes(),
                    role: role(),
                    flow: Flow::ip(packet, dir)?,
                },
                dir,
                packet.len() as u64,
            ))
        })
    }

    pub(crate) fn control(&self, network: NetworkId, peer: EndpointId, dir: Direction, len: u64) {
        self.prepare(|| {
            Some((
                FlowKey {
                    network: *network.as_bytes(),
                    peer: *peer.as_bytes(),
                    role: Role::Control,
                    flow: Flow::Control,
                },
                dir,
                len,
            ))
        })
        .record();
    }

    pub(crate) fn relay(
        &self,
        network: NetworkId,
        source: [u8; 32],
        dest: [u8; 32],
        wire_protocol: u64,
        len: usize,
    ) {
        self.prepare(|| {
            let (peer, other, dir) = if source <= dest {
                (source, dest, Direction::Tx)
            } else {
                (dest, source, Direction::Rx)
            };
            Some((
                FlowKey {
                    network: *network.as_bytes(),
                    peer,
                    role: Role::Relay,
                    flow: Flow::Relay {
                        other,
                        wire_protocol,
                    },
                },
                dir,
                len as u64,
            ))
        })
        .record();
    }
}

struct Pending {
    readers: Arc<Vec<Weak<Bucket>>>,
    key: FlowKey,
    dir: Direction,
    len: u64,
}
pub(crate) struct Observation(Option<Pending>);
impl Pending {
    fn count(&self, len: u64) {
        let now = Instant::now();
        for reader in self.readers.iter().filter_map(Weak::upgrade) {
            reader.add(self.key, self.dir, len, now);
        }
    }
}
impl Observation {
    pub(crate) fn record(self) {
        if let Some(pending) = self.0 {
            pending.count(pending.len);
        }
    }
    pub(crate) fn record_fragment(&self, len: usize) {
        if let Some(pending) = &self.0 {
            pending.count(len as u64);
        }
    }
}

/// Drops the reader and turns off observation when the last window disconnects.
#[derive(Debug)]
pub struct TrafficSubscription {
    owner: Weak<TrafficMonitor>,
    bucket: Arc<Bucket>,
}

impl TrafficSubscription {
    /// Atomically start a fresh interval; serialisation never holds the collector lock.
    pub fn snapshot(&self) -> TrafficSnapshot {
        let (now, previous, lanes, omitted) = {
            let mut since = self.bucket.since.lock().unwrap_or_else(|e| e.into_inner());
            let locks = self
                .bucket
                .lanes
                .each_ref()
                .map(|lane| lane.lock().unwrap_or_else(|e| e.into_inner()));
            let now = Instant::now();
            self.bucket.entries.store(0, Ordering::Relaxed);
            let lanes = locks.map(|mut lock| std::mem::take(&mut *lock));
            (
                now,
                std::mem::replace(&mut *since, now),
                lanes,
                self.bucket.omitted.swap(0, Ordering::Relaxed),
            )
        };
        let [mut flows, second, third, fourth] = lanes;
        for (key, c) in [second, third, fourth].into_iter().flatten() {
            flows
                .entry(key)
                .and_modify(|a| {
                    a.tx = a.tx.saturating_add(c.tx);
                    a.rx = a.rx.saturating_add(c.rx);
                    a.ntx = a.ntx.saturating_add(c.ntx);
                    a.nrx = a.nrx.saturating_add(c.nrx);
                    a.last = a.last.max(c.last)
                })
                .or_insert(c);
        }
        TrafficSnapshot {
            interval_ms: millis(now.saturating_duration_since(previous)),
            omitted,
            flows: flows
                .into_iter()
                .map(|(key, c)| FlowDelta {
                    key,
                    tx_bytes: c.tx,
                    rx_bytes: c.rx,
                    tx_packets: c.ntx,
                    rx_packets: c.nrx,
                    age_ms: millis(now.saturating_duration_since(c.last)),
                })
                .collect(),
        }
    }
}

impl Drop for TrafficSubscription {
    fn drop(&mut self) {
        if let Some(monitor) = self.owner.upgrade() {
            let _edit = monitor
                .registration
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let bucket = Arc::downgrade(&self.bucket);
            let remaining: Vec<_> = monitor
                .readers
                .load()
                .iter()
                .filter(|r| !Weak::ptr_eq(r, &bucket))
                .cloned()
                .collect();
            let active = !remaining.is_empty();
            monitor.readers.store(Arc::new(remaining));
            monitor.active.store(active, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests;
