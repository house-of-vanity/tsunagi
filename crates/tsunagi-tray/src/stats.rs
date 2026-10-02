//! Traffic rates derived from successive status snapshots.
//!
//! The agent reports cumulative packet and byte counters, not rates. The GUI
//! samples them each time a fresh snapshot arrives and turns the deltas into
//! per-second rates plus short rolling histories for sparklines. One series per
//! key: a network total, and each peer within it. Both packets and bytes are
//! tracked so the UI can switch between them.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use tsunagi::ipc::StatusReport;

/// How many rate samples to keep for a sparkline.
const HISTORY: usize = 60;

/// Which quantity a rate or history is of.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unit {
    /// Packets per second.
    Packets,
    /// Bytes per second.
    Bytes,
}

/// One series' rolling packet and byte rates.
#[derive(Default)]
pub(crate) struct Series {
    last: Option<(Instant, u64, u64)>,
    packets_rate: f32,
    bytes_rate: f32,
    packets_history: VecDeque<f32>,
    bytes_history: VecDeque<f32>,
}

impl Series {
    fn sample(&mut self, now: Instant, packets: u64, bytes: u64) {
        if let Some((then, prev_packets, prev_bytes)) = self.last {
            let dt = now.saturating_duration_since(then).as_secs_f32();
            if dt > 0.0 {
                self.packets_rate = packets.saturating_sub(prev_packets) as f32 / dt;
                self.bytes_rate = bytes.saturating_sub(prev_bytes) as f32 / dt;
                push(&mut self.packets_history, self.packets_rate);
                push(&mut self.bytes_history, self.bytes_rate);
            }
        }
        self.last = Some((now, packets, bytes));
    }

    /// The current rate in the chosen unit.
    pub(crate) fn rate(&self, unit: Unit) -> f32 {
        match unit {
            Unit::Packets => self.packets_rate,
            Unit::Bytes => self.bytes_rate,
        }
    }

    /// The rolling history in the chosen unit.
    pub(crate) fn history(&self, unit: Unit) -> &VecDeque<f32> {
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

/// All traffic series, keyed by a stable string.
#[derive(Default)]
pub(crate) struct Traffic {
    series: HashMap<String, Series>,
}

impl Traffic {
    /// Folds a fresh snapshot into the rates. Call once per new generation.
    pub(crate) fn observe(&mut self, report: &StatusReport, now: Instant) {
        for network in &report.networks {
            let Some(overlay) = &network.overlay else {
                continue;
            };
            let (mut net_packets, mut net_bytes) = (0u64, 0u64);
            for peer in &overlay.peers {
                let packets = peer.tx_packets.saturating_add(peer.rx_packets);
                let bytes = peer.tx_bytes.saturating_add(peer.rx_bytes);
                net_packets = net_packets.saturating_add(packets);
                net_bytes = net_bytes.saturating_add(bytes);
                self.series
                    .entry(peer_key(&network.network_id, &peer.public_key))
                    .or_default()
                    .sample(now, packets, bytes);
            }
            self.series
                .entry(net_key(&network.network_id))
                .or_default()
                .sample(now, net_packets, net_bytes);
        }
    }

    /// The network-total series, if sampled.
    pub(crate) fn network(&self, network_id: &str) -> Option<&Series> {
        self.series.get(&net_key(network_id))
    }

    /// One peer's series, if sampled.
    pub(crate) fn peer(&self, network_id: &str, public_key: &str) -> Option<&Series> {
        self.series.get(&peer_key(network_id, public_key))
    }
}

fn net_key(network_id: &str) -> String {
    format!("net:{network_id}")
}

fn peer_key(network_id: &str, public_key: &str) -> String {
    format!("peer:{network_id}:{public_key}")
}
