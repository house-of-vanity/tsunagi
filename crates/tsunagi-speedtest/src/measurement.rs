use crate::packet::HEADER;
use crate::wire::MAX_BPS;
use crate::{Datagram, Direction, Feedback, Quality, Reading};
use std::time::Duration;
use tokio::time::Instant;

const INITIAL_BPS: u64 = 4_000_000;
const MIN_BPS: u64 = 32_000;

pub(crate) struct Receiver {
    pub(crate) direction: Direction,
    mtu: u16,
    packets: u32,
    seen: Vec<u64>,
    window: Option<Window>,
    pub(crate) count: u32,
    pub(crate) best: u64,
}

struct Window {
    start: Instant,
    stage: u8,
    received: u32,
    starts_on_packet: bool,
    arrival_groups: u8,
    last_group: Instant,
    first_arrival: Instant,
    last_arrival: Instant,
    first: u32,
    highest: u32,
    last_send_us: u32,
}

impl Receiver {
    pub(crate) fn new(direction: Direction, mtu: u16, budget: u32) -> Self {
        let packets = budget / u32::from(mtu);
        Self {
            direction,
            mtu,
            packets,
            seen: vec![0; packets.div_ceil(64) as usize],
            window: None,
            count: 0,
            best: 0,
        }
    }

    pub(crate) fn put(&mut self, probe: Datagram, now: Instant) {
        if probe.direction != self.direction
            || probe.size != self.mtu
            || probe.sequence >= self.packets
        {
            return;
        }
        let word = &mut self.seen[(probe.sequence / 64) as usize];
        let bit = 1u64 << (probe.sequence % 64);
        if *word & bit != 0 {
            return;
        }
        *word |= bit;
        self.count += 1;
        if self.window.as_ref().is_none_or(|w| w.stage < probe.stage) {
            self.window = Some(Window {
                start: now,
                stage: probe.stage,
                received: 0,
                starts_on_packet: true,
                arrival_groups: 0,
                last_group: now,
                first_arrival: now,
                last_arrival: now,
                first: probe.sequence,
                highest: probe.sequence,
                last_send_us: probe.sent_us,
            });
        }
        if let Some(w) = &mut self.window
            && w.stage == probe.stage
        {
            if w.received == 0 {
                w.first_arrival = now;
                w.last_group = now;
                w.arrival_groups = 1;
                w.first = probe.sequence;
                w.highest = probe.sequence;
            } else {
                if w.arrival_groups < 3
                    && now.duration_since(w.last_group) >= Duration::from_millis(20)
                {
                    w.arrival_groups += 1;
                    w.last_group = now;
                }
                w.first = w.first.min(probe.sequence);
                w.highest = w.highest.max(probe.sequence);
            }
            w.received += 1;
            w.last_arrival = now;
            w.last_send_us = w.last_send_us.max(probe.sent_us);
        }
    }

    pub(crate) fn bytes(&self) -> u32 {
        self.count * u32::from(self.mtu - HEADER)
    }

    // A rate needs observations spread over a real interval. A queued burst
    // followed by silence must never turn into a capacity estimate.
    pub(crate) fn sample(&mut self, now: Instant, minimum: Duration) -> Option<Feedback> {
        let bytes = self.bytes();
        let w = self.window.as_mut()?;
        let elapsed = now.duration_since(w.start);
        if elapsed < minimum {
            return None;
        }
        let span = w.highest - w.first + 1;
        let loss = (u64::from(span.saturating_sub(w.received)) * 1000 / u64::from(span)) as u16;
        let spread = w.last_arrival.duration_since(w.first_arrival);
        // The first packet of a stage starts its clock. Its bytes arrived before
        // the measured interval. Later windows start exactly when the last one closed.
        let sampled = w.received.saturating_sub(u32::from(w.starts_on_packet));
        let enough = sampled >= 3 && w.arrival_groups >= 3 && spread >= elapsed * 2 / 3;
        if !enough && elapsed < Duration::from_millis(600) {
            return None;
        }
        let bps = if enough {
            (u64::from(sampled) * u64::from(self.mtu - HEADER) * 8_000_000
                / elapsed.as_micros().max(1) as u64)
                .min(MAX_BPS)
        } else {
            0
        };
        let feedback = Feedback {
            stage: w.stage,
            bps,
            lost_per_mille: loss,
            bytes,
            echo_us: w.last_send_us,
        };
        w.start = now;
        w.received = 0;
        w.starts_on_packet = false;
        if bps > 0 {
            self.best = self.best.max(bps);
        }
        Some(feedback)
    }
}

pub(crate) struct Search {
    pub(crate) stage: u8,
    pub(crate) target: u64,
    best: u64,
    baseline_delay: Option<u32>,
    initial_loss: Option<u16>,
    last_echo: Option<u32>,
    confirm: bool,
    previous: Option<u64>,
    measured: Option<u64>,
}

impl Default for Search {
    fn default() -> Self {
        Self {
            stage: 0,
            target: INITIAL_BPS,
            best: 0,
            baseline_delay: None,
            initial_loss: None,
            last_echo: None,
            confirm: false,
            previous: None,
            measured: None,
        }
    }
}

impl Search {
    pub(crate) fn observe(&mut self, sample: Feedback, elapsed_us: u32) {
        if sample.stage != self.stage
            || self.measured.is_some()
            || sample.echo_us > elapsed_us
            || self.last_echo.is_some_and(|echo| echo >= sample.echo_us)
        {
            return;
        }
        self.last_echo = Some(sample.echo_us);
        let bps = sample.bps;
        self.best = self.best.max(bps);
        let delay = elapsed_us - sample.echo_us;
        let base = *self.baseline_delay.get_or_insert(delay);
        self.baseline_delay = Some(base.min(delay));
        let queuing = delay > base.saturating_add(45_000).max(base.saturating_mul(2));
        // A small, constant random loss is common on Wi-Fi and cellular links.
        // Reduce on growing loss, queue delay or a receiver rate below the offer.
        let baseline_loss = *self
            .initial_loss
            .get_or_insert(sample.lost_per_mille.min(100));
        let congested =
            sample.lost_per_mille > baseline_loss + 30 || bps < self.target * 4 / 5 || queuing;
        if congested {
            self.confirm = true;
            self.previous = None;
            self.offer(if bps == 0 {
                self.target / 2
            } else {
                bps * 97 / 100
            });
        } else if self.confirm {
            if sample.lost_per_mille > 100 {
                self.previous = None;
                return;
            }
            if let Some(prev) = self.previous
                && prev.abs_diff(bps) <= bps / 6
            {
                self.measured = Some((prev + bps) / 2);
            } else {
                self.previous = Some(bps);
            }
        } else if self.target < MAX_BPS {
            self.offer(self.target.saturating_mul(4));
        }
    }

    fn offer(&mut self, bps: u64) {
        self.target = bps.clamp(MIN_BPS, MAX_BPS);
        self.stage = self.stage.saturating_add(1);
    }

    pub(crate) fn done(&self) -> bool {
        self.measured.is_some()
    }

    pub(crate) fn result(&self, bytes: u32) -> Reading {
        if let Some(bps) = self.measured {
            Reading {
                bps: Some(bps),
                bytes,
                quality: Quality::Measured,
            }
        } else if self.best > 0 {
            Reading {
                bps: Some(self.best),
                bytes,
                quality: Quality::AtLeast,
            }
        } else {
            Reading {
                bps: None,
                bytes,
                quality: Quality::Insufficient,
            }
        }
    }
}

pub(crate) struct Pacer {
    last_tick: Instant,
    // Fractional packet credit in payload bit-nanoseconds.
    credit: u64,
    cost: u64,
}

impl Pacer {
    pub(crate) fn new(start: Instant, mtu: u16) -> Self {
        Self {
            last_tick: start,
            credit: 0,
            cost: u64::from(mtu - HEADER) * 8_000_000_000,
        }
    }

    pub(crate) fn packets(&mut self, now: Instant, bps: u64) -> u32 {
        // The event loop may have been descheduled. Never catch up with a long burst.
        let elapsed = now.duration_since(self.last_tick).as_nanos().min(3_000_000) as u64;
        self.last_tick = now;
        self.credit += elapsed * bps;
        let packets = self.credit / self.cost;
        self.credit %= self.cost;
        packets.min(512) as u32
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::net::Ipv4Addr;

    fn packet(sequence: u32, stage: u8, sent_us: u32) -> Datagram {
        Datagram {
            id: 7,
            source: Ipv4Addr::LOCALHOST,
            destination: Ipv4Addr::BROADCAST,
            direction: Direction::Download,
            stage,
            sequence,
            sent_us,
            size: 1280,
        }
    }

    #[test]
    fn bounded_reordered_packets_are_counted_once_and_do_not_reopen_earlier_stages() {
        let t = Instant::now();
        let mut rx = Receiver::new(Direction::Download, 1280, 1280 * 8);
        for (i, s) in [(7, 1), (1, 0), (3, 1), (3, 1), (8, 1), (u32::MAX, 1)] {
            rx.put(packet(i, s, 0), t);
        }
        rx.put(
            Datagram {
                direction: Direction::Upload,
                ..packet(4, 1, 0)
            },
            t,
        );
        rx.put(
            Datagram {
                size: 1500,
                ..packet(5, 1, 0)
            },
            t,
        );
        assert_eq!(rx.count, 3);
        assert_eq!(rx.bytes(), 3 * u32::from(1280 - HEADER));
        assert!(
            rx.window
                .as_ref()
                .is_some_and(|w| w.stage == 1 && w.received == 2)
        );
    }

    #[test]
    fn a_short_burst_or_compressed_catchup_cannot_establish_throughput() {
        let start = Instant::now();
        let mut receiver = Receiver::new(Direction::Download, 1280, NORMAL_BYTES_FOR_TEST);
        for i in 0..500 {
            receiver.put(packet(i, 0, i), start);
        }
        let window = Duration::from_millis(120);
        for i in 500..520 {
            receiver.put(packet(i, 0, i), start + window);
        }
        assert!(receiver.sample(start + window, window).is_none());
        let feedback = receiver
            .sample(start + Duration::from_millis(650), window)
            .unwrap();
        assert_eq!(feedback.bps, 0);
        assert_eq!(receiver.best, 0);
    }

    const NORMAL_BYTES_FOR_TEST: u32 = 1024 * 1024;

    #[test]
    fn retransmitted_feedback_does_not_supply_two_confirmation_windows() {
        let mut search = Search::default();
        let f = |stage, bps, lost_per_mille, bytes, echo_us| Feedback {
            stage,
            bps,
            lost_per_mille,
            bytes,
            echo_us,
        };
        search.observe(f(0, 1_000_000, 700, 15000, 120_000), 121_000);
        let observed = f(1, 970_000, 0, 30000, 241_000);
        search.observe(observed, 242_000);
        search.observe(observed, 243_000);
        assert!(!search.done());
        search.observe(f(1, 970_000, 0, 45000, 360_000), 361_000);
        assert!(search.done());
    }
}
