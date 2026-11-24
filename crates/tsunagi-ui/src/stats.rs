//! Traffic rates derived from successive status snapshots.
//!
//! The agent reports cumulative packet and byte counters, not rates. The GUI
//! samples them each time a fresh snapshot arrives and turns the deltas into
//! per-second rates plus short rolling histories for sparklines. One series per
//! key: a network total, and each peer within it. Both packets and bytes are
//! tracked so the UI can switch between them.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use tsunagi::ipc::{OverlayPeerReport, StatusReport};

/// How many rate samples to keep for a sparkline.
const HISTORY: usize = 60;

/// Which quantity a rate or history is of.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Packets per second.
    Packets,
    /// Bytes per second.
    Bytes,
}

/// One series' rolling packet and byte rates.
#[derive(Default)]
pub struct Series {
    last: Option<(Instant, Counters)>,
    packets_rate: f32,
    bytes_rate: f32,
    packets_history: VecDeque<f32>,
    bytes_history: VecDeque<f32>,
}

impl Series {
    /// Samples a single cumulative counter pair (VIP histories own their lifetime).
    pub fn sample(&mut self, now: Instant, packets: u64, bytes: u64) {
        self.sample_peer(
            now,
            Counters {
                epoch: 0,
                tx_packets: packets,
                tx_bytes: bytes,
                rx_packets: 0,
                rx_bytes: 0,
            },
        );
    }

    fn sample_peer(&mut self, now: Instant, counters: Counters) {
        if let Some((then, previous)) = self.last {
            let dt = now.saturating_duration_since(then).as_secs_f32();
            // Ignore duplicate/out-of-order observations without changing the baseline.
            if dt <= 0.0 {
                return;
            }
            if counters.epoch == previous.epoch
                && counters.tx_packets >= previous.tx_packets
                && counters.rx_packets >= previous.rx_packets
                && counters.tx_bytes >= previous.tx_bytes
                && counters.rx_bytes >= previous.rx_bytes
            {
                self.record(
                    (counters.tx_packets - previous.tx_packets) as f32 / dt
                        + (counters.rx_packets - previous.rx_packets) as f32 / dt,
                    (counters.tx_bytes - previous.tx_bytes) as f32 / dt
                        + (counters.rx_bytes - previous.rx_bytes) as f32 / dt,
                );
            } else {
                // A counter reset is a new baseline, never traffic.
                *self = Self::default();
            }
        }
        self.last = Some((now, counters));
    }

    fn record(&mut self, packets: f32, bytes: f32) {
        self.packets_rate = packets;
        self.bytes_rate = bytes;
        push(&mut self.packets_history, packets);
        push(&mut self.bytes_history, bytes);
    }

    /// The current rate in the chosen unit.
    pub fn rate(&self, unit: Unit) -> f32 {
        match unit {
            Unit::Packets => self.packets_rate,
            Unit::Bytes => self.bytes_rate,
        }
    }

    /// The rolling history in the chosen unit.
    pub fn history(&self, unit: Unit) -> &VecDeque<f32> {
        match unit {
            Unit::Packets => &self.packets_history,
            Unit::Bytes => &self.bytes_history,
        }
    }
}

fn push(history: &mut VecDeque<f32>, value: f32) {
    history.push_back(value);
    while history.len() > HISTORY {
        history.pop_front();
    }
}

#[derive(Clone, Copy)]
/// Cumulative tunnel counters in one peer epoch.
pub struct Counters {
    /// Counter reset generation.
    pub epoch: u64,
    /// Sent packets.
    pub tx_packets: u64,
    /// Received packets.
    pub rx_packets: u64,
    /// Sent bytes.
    pub tx_bytes: u64,
    /// Received bytes.
    pub rx_bytes: u64,
}

impl From<&OverlayPeerReport> for Counters {
    fn from(peer: &OverlayPeerReport) -> Self {
        Self {
            epoch: peer.counter_epoch,
            tx_packets: peer.tx_packets,
            rx_packets: peer.rx_packets,
            tx_bytes: peer.tx_bytes,
            rx_bytes: peer.rx_bytes,
        }
    }
}

/// All traffic series, keyed by a stable string.
#[derive(Default)]
pub struct Traffic {
    series: HashMap<String, Series>,
}

impl Traffic {
    /// Folds a fresh snapshot into the rates. Call once per new generation.
    pub fn observe(&mut self, report: &StatusReport, now: Instant) {
        self.observe_peers(
            report.networks.iter().filter_map(|network| {
                Some((
                    network.network_id.as_str(),
                    network
                        .overlay
                        .as_ref()?
                        .peers
                        .iter()
                        .map(|p| (p.public_key.as_str(), Counters::from(p))),
                ))
            }),
            now,
        );
    }

    /// Sample live per-peer counters from either an in-process agent or IPC.
    pub fn observe_peers<'a, I>(
        &mut self,
        networks: impl IntoIterator<Item = (&'a str, I)>,
        now: Instant,
    ) where
        I: IntoIterator<Item = (&'a str, Counters)>,
    {
        let mut active = HashSet::new();
        for (network, peers) in networks {
            let (mut packets_rate, mut bytes_rate) = (0.0, 0.0);
            for (peer, counters) in peers {
                let key = peer_key(network, peer);
                // Duplicate rows are not additional traffic.
                if !active.insert(key.clone()) {
                    continue;
                }
                let series = self.series.entry(key).or_default();
                series.sample_peer(now, counters);
                packets_rate += series.rate(Unit::Packets);
                bytes_rate += series.rate(Unit::Bytes);
            }
            // Sum rates, not cumulative counters of a changing set of peers.
            let key = net_key(network);
            active.insert(key.clone());
            self.series
                .entry(key)
                .or_default()
                .record(packets_rate, bytes_rate);
        }
        self.series.retain(|key, _| active.contains(key));
    }

    /// The network-total series, if sampled.
    pub fn network(&self, network_id: &str) -> Option<&Series> {
        self.series.get(&net_key(network_id))
    }

    /// One peer's series, if sampled.
    pub fn peer(&self, network_id: &str, public_key: &str) -> Option<&Series> {
        self.series.get(&peer_key(network_id, public_key))
    }
}

fn net_key(network_id: &str) -> String {
    format!("net:{network_id}")
}

fn peer_key(network_id: &str, public_key: &str) -> String {
    format!("peer:{network_id}:{public_key}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tsunagi::ipc::{NetworkReport, OverlayPeerReport, OverlayReport};

    fn peer(key: &str, bytes: u64) -> OverlayPeerReport {
        OverlayPeerReport {
            public_key: key.into(),
            tx_bytes: bytes,
            ..Default::default()
        }
    }

    fn report(peers: Vec<OverlayPeerReport>) -> StatusReport {
        StatusReport {
            networks: vec![NetworkReport {
                network_id: "network".into(),
                overlay: Some(OverlayReport {
                    peers,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn joining_peer_does_not_add_its_past_traffic_to_the_network_rate() {
        let mut traffic = Traffic::default();
        let now = Instant::now();
        traffic.observe(&report(vec![peer("a", 100)]), now);
        traffic.observe(
            &report(vec![peer("a", 120), peer("b", 100_000_000_000)]),
            now + Duration::from_secs(1),
        );
        assert_eq!(
            traffic.network("network").map(|s| s.rate(Unit::Bytes)),
            Some(20.0)
        );
        traffic.observe(
            &report(vec![peer("a", 150), peer("b", 100_000_000_040)]),
            now + Duration::from_secs(2),
        );
        assert_eq!(
            traffic.network("network").map(|s| s.rate(Unit::Bytes)),
            Some(70.0)
        );
    }

    #[test]
    fn departed_peers_and_removed_networks_do_not_keep_stale_rates() {
        let mut traffic = Traffic::default();
        let now = Instant::now();
        traffic.observe(&report(vec![peer("a", 100)]), now);
        traffic.observe(&report(vec![peer("a", 140)]), now + Duration::from_secs(1));
        traffic.observe(&report(vec![]), now + Duration::from_secs(2));
        assert!(traffic.peer("network", "a").is_none());
        assert_eq!(
            traffic.network("network").map(|s| s.rate(Unit::Bytes)),
            Some(0.0)
        );
        traffic.observe(&StatusReport::default(), now + Duration::from_secs(3));
        assert!(traffic.network("network").is_none());
    }

    #[test]
    fn restarted_counters_are_a_new_baseline_even_if_they_already_exceed_the_old_value() {
        let mut traffic = Traffic::default();
        let now = Instant::now();
        let mut old = peer("a", 100);
        old.counter_epoch = 1;
        traffic.observe(&report(vec![old]), now);
        let mut restarted = peer("a", 100_000_000_000);
        restarted.counter_epoch = 2;
        traffic.observe(
            &report(vec![restarted.clone()]),
            now + Duration::from_secs(1),
        );
        assert_eq!(
            traffic.peer("network", "a").map(|s| s.rate(Unit::Bytes)),
            Some(0.0)
        );
        restarted.tx_bytes += 80;
        traffic.observe(&report(vec![restarted]), now + Duration::from_secs(2));
        assert_eq!(
            traffic.network("network").map(|s| s.rate(Unit::Bytes)),
            Some(80.0)
        );
    }

    #[test]
    fn reset_in_one_direction_cannot_be_hidden_by_growth_in_the_other() {
        let mut traffic = Traffic::default();
        let now = Instant::now();
        let mut old = peer("a", 100);
        old.rx_bytes = 1000;
        traffic.observe(&report(vec![old]), now);
        let mut reset = peer("a", 50);
        reset.rx_bytes = 10_000;
        traffic.observe(&report(vec![reset]), now + Duration::from_secs(1));
        assert_eq!(
            traffic.network("network").map(|s| s.rate(Unit::Bytes)),
            Some(0.0)
        );
    }
}
