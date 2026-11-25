use crate::packet::HEADER;
use crate::wire::MAX_BPS;
use crate::{Datagram, Direction, Feedback, Quality, Reading};
use std::time::Duration;
use tokio::time::Instant;

const INITIAL_BPS: u64 = 8_000_000;
// A tail shorter than a regular feedback period may still contain a sustained
// train. Require both clocks to span this interval and multiple arrival groups.
const MIN_TRAIN: Duration = Duration::from_millis(60);
const MIN_BPS: u64 = 32_000;

pub(crate) struct Receiver {
    pub(crate) direction: Direction,
    mtu: u16,
    packets: u32,
    seen: Vec<u64>,
    stage: u8,
    window: Option<Window>,
    pub(crate) count: u32,
    best: u64,
}

struct Window {
    received: u32,
    opening_group: u32,
    arrival_groups: u8,
    last_group: Instant,
    first_arrival: Instant,
    last_arrival: Instant,
    first: u32,
    highest: u32,
    first_send_us: u32,
    last_send_us: u32,
}

impl Window {
    fn new(probe: Datagram, now: Instant) -> Self {
        Self {
            received: 1,
            opening_group: 1,
            arrival_groups: 1,
            last_group: now,
            first_arrival: now,
            last_arrival: now,
            first: probe.sequence,
            highest: probe.sequence,
            first_send_us: probe.sent_us,
            last_send_us: probe.sent_us,
        }
    }

    fn push(&mut self, probe: Datagram, now: Instant) {
        if self.arrival_groups < 3
            && now.duration_since(self.last_group) >= Duration::from_millis(20)
        {
            self.arrival_groups += 1;
            self.last_group = now;
        }
        self.first = self.first.min(probe.sequence);
        self.highest = self.highest.max(probe.sequence);
        self.first_send_us = self.first_send_us.min(probe.sent_us);
        self.last_send_us = self.last_send_us.max(probe.sent_us);
        // Packets already in the first arrival batch did not traverse the measured interval.
        if now.duration_since(self.first_arrival) < Duration::from_millis(1) {
            self.opening_group += 1;
        }
        self.received += 1;
        self.last_arrival = now;
    }

    fn rate(&self, mtu: u16) -> Option<u64> {
        let arrivals = self.last_arrival.duration_since(self.first_arrival);
        let sends = Duration::from_micros(u64::from(self.last_send_us - self.first_send_us));
        let packets = self.received.saturating_sub(self.opening_group);
        if packets < 3 || self.arrival_groups < 3 || arrivals < MIN_TRAIN || sends < MIN_TRAIN {
            return None;
        }
        // Feedback and End may arrive late, or queued packets may arrive together.
        // Use the slower of the sender's and receiver's independent train clocks.
        let elapsed = arrivals.max(sends).as_micros() as u64;
        Some((u64::from(packets) * u64::from(mtu - HEADER) * 8_000_000 / elapsed).min(MAX_BPS))
    }
}

impl Receiver {
    pub(crate) fn new(direction: Direction, mtu: u16, budget: u32) -> Self {
        let packets = budget / u32::from(mtu);
        Self {
            direction,
            mtu,
            packets,
            seen: vec![0; packets.div_ceil(64) as usize],
            stage: 0,
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
        if probe.stage < self.stage {
            return;
        }
        if probe.stage > self.stage {
            self.finish_window();
            self.stage = probe.stage;
        }
        match &mut self.window {
            Some(window) => window.push(probe, now),
            None => self.window = Some(Window::new(probe, now)),
        }
    }

    fn finish_window(&mut self) {
        if let Some(rate) = self.window.take().and_then(|w| w.rate(self.mtu)) {
            self.best = self.best.max(rate);
        }
    }

    pub(crate) fn finish(mut self, estimate: Reading) -> Reading {
        self.finish_window();
        // Final delivery belongs to the receiver. A sender may have stopped on its
        // byte limit before receiving feedback for a faster, fully observed train.
        if self.best == 0 {
            return Reading {
                bps: None,
                bytes: self.bytes(),
                quality: Quality::Insufficient,
            };
        }
        if estimate.quality == Quality::Measured
            && let Some(rate) = estimate.bps
            && self.best.abs_diff(rate) <= rate / 5
        {
            return Reading {
                bps: Some(rate.min(self.best)),
                bytes: self.bytes(),
                quality: Quality::Measured,
            };
        }
        Reading {
            bps: Some(self.best),
            bytes: self.bytes(),
            quality: Quality::AtLeast,
        }
    }

    pub(crate) fn bytes(&self) -> u32 {
        self.count * u32::from(self.mtu - HEADER)
    }

    // A rate needs observations spread over a real interval. A queued burst
    // followed by silence must never turn into a capacity estimate.
    pub(crate) fn sample(&mut self, now: Instant, minimum: Duration) -> Option<Feedback> {
        let bytes = self.bytes();
        let w = self.window.as_ref()?;
        let elapsed = now.duration_since(w.first_arrival);
        if elapsed < minimum {
            return None;
        }
        let span = w.highest - w.first + 1;
        let loss = (u64::from(span.saturating_sub(w.received)) * 1000 / u64::from(span)) as u16;
        let rate = w.rate(self.mtu);
        if rate.is_none() && elapsed < Duration::from_millis(600) {
            return None;
        }
        let bps = rate.unwrap_or(0);
        let feedback = Feedback {
            stage: self.stage,
            bps,
            lost_per_mille: loss,
            bytes,
            echo_us: w.last_send_us,
        };
        self.window = None;
        self.best = self.best.max(bps);
        Some(feedback)
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Ramp,
    // A rate backed off from congestion needs another, higher offer to test it.
    Settle { verified: bool },
    Challenge { previous_rate: u64 },
}

pub(crate) struct Search {
    pub(crate) stage: u8,
    pub(crate) target: u64,
    best: u64,
    baseline_delay: Option<u32>,
    initial_loss: Option<u16>,
    last_echo: Option<u32>,
    phase: Phase,
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
            phase: Phase::Ramp,
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
        // Loss present at the first offer also reduces the payload rate that
        // can arrive at higher offers. Look for additional loss or queuing.
        // A very lossy first sample may already be an overloaded slow path.
        let baseline_loss = *self
            .initial_loss
            .get_or_insert(sample.lost_per_mille.min(400));
        let expected = self.target * u64::from(1000 - baseline_loss) / 1000;
        let congested =
            sample.lost_per_mille > baseline_loss + 30 || bps < expected * 4 / 5 || queuing;
        if congested {
            let verified = match self.phase {
                Phase::Challenge { previous_rate } => {
                    bps.abs_diff(previous_rate) <= previous_rate / 5
                }
                Phase::Settle { verified } => verified && bps >= self.target * 4 / 5,
                Phase::Ramp => false,
            };
            self.phase = Phase::Settle { verified };
            self.previous = None;
            self.offer(if bps == 0 {
                self.target / 2
            } else {
                bps * 97 / 100
            });
        } else if let Phase::Settle { verified } = self.phase {
            if sample.lost_per_mille > 100 {
                self.previous = None;
                return;
            }
            if let Some(prev) = self.previous.replace(bps)
                && prev.abs_diff(bps) <= bps / 6
            {
                let steady = (prev + bps) / 2;
                if verified {
                    self.measured = Some(steady);
                } else if elapsed_us >= 850_000 {
                    // A cold tunnel or one busy scheduler slice can look like a bottleneck.
                    // Two samples at our own reduced rate prove only that we can sustain it.
                    self.phase = Phase::Challenge {
                        previous_rate: steady,
                    };
                    self.offer(steady * 2);
                    self.previous = None;
                }
            }
        } else if self.target < MAX_BPS {
            self.phase = Phase::Ramp;
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
        let elapsed = now
            .duration_since(self.last_tick)
            .as_nanos()
            .min(12_000_000) as u64;
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
        assert_eq!(rx.stage, 1);
        assert!(rx.window.as_ref().is_some_and(|w| w.received == 2));
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
    fn final_rate_uses_delivered_payload_even_when_end_overtakes_feedback() {
        let start = Instant::now();
        let mut rx = Receiver::new(Direction::Download, 1280, NORMAL_BYTES_FOR_TEST);
        // The first train takes twice as long to arrive as to send. The faster
        // second train ends before the next feedback tick.
        for i in 0..=100 {
            rx.put(
                packet(i, 0, i * 1_000),
                start + Duration::from_millis(u64::from(i) * 2),
            );
        }
        let tick = Duration::from_millis(220);
        let initial = rx.sample(start + tick, tick).unwrap();
        let payload_bits = u64::from(1280 - HEADER) * 8;
        assert_eq!(initial.bps, payload_bits * 500);
        for i in 0..=100 {
            rx.put(
                packet(101 + i, 1, 250_000 + i * 1_000),
                start + Duration::from_millis(250 + u64::from(i)),
            );
        }
        let result = rx.finish(Reading {
            bytes: initial.bytes,
            bps: Some(initial.bps),
            quality: Quality::AtLeast,
        });
        assert_eq!(result.bps, Some(payload_bits * 1000));
        assert_eq!(result.quality, Quality::AtLeast);
        assert_eq!(result.bytes, 202 * u32::from(1280 - HEADER));
    }

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
        assert!(!search.done());
        search.observe(f(1, 970_000, 0, 100_000, 900_000), 901_000);
        assert_eq!(search.stage, 2);
        search.observe(f(2, 1_000_000, 450, 120_000, 1_060_000), 1_061_000);
        search.observe(f(3, 970_000, 0, 150_000, 1_220_000), 1_221_000);
        search.observe(f(3, 970_000, 0, 180_000, 1_380_000), 1_381_000);
        assert!(search.done());
    }
}
