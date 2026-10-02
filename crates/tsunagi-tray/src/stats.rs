//! Traffic rates derived from successive status snapshots.
//!
//! The agent reports cumulative packet counters, not rates. The GUI samples
//! them each time a fresh snapshot arrives and turns the deltas into a
//! packets-per-second rate plus a short rolling history for a sparkline. One
//! series per key: a network total, and each peer within it.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use tsunagi::ipc::StatusReport;

/// How many rate samples to keep for a sparkline.
const HISTORY: usize = 48;

/// One series' rolling rate.
#[derive(Default)]
pub(crate) struct Series {
    last: Option<(Instant, u64)>,
    /// Most recent packets-per-second (tx + rx).
    pub rate: f32,
    /// Recent rates, oldest first, for a sparkline.
    pub history: VecDeque<f32>,
}

impl Series {
    fn sample(&mut self, now: Instant, total: u64) {
        if let Some((then, previous)) = self.last {
            let dt = now.saturating_duration_since(then).as_secs_f32();
            if dt > 0.0 {
                let delta = total.saturating_sub(previous) as f32;
                self.rate = delta / dt;
                self.history.push_back(self.rate);
                while self.history.len() > HISTORY {
                    self.history.pop_front();
                }
            }
        }
        self.last = Some((now, total));
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
            let mut net_total = 0u64;
            for peer in &overlay.peers {
                let total = peer.tx_packets.saturating_add(peer.rx_packets);
                net_total = net_total.saturating_add(total);
                self.series
                    .entry(peer_key(&network.network_id, &peer.public_key))
                    .or_default()
                    .sample(now, total);
            }
            self.series
                .entry(net_key(&network.network_id))
                .or_default()
                .sample(now, net_total);
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
