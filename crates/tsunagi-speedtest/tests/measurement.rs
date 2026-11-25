//! Independently clocked sessions exchange real control records and shaped IPv4 probes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use tsunagi_speedtest::*;

#[derive(Clone)]
struct Link {
    remote: Handle,
    start: Instant,
    rate: u64,
    control_delay: Duration,
    drop_every: u32,
    state: Arc<Mutex<Delivery>>,
    samples: Arc<Mutex<Vec<Progress>>>,
}

#[derive(Default)]
struct Delivery {
    // Tokens represent one millisecond of useful payload on this shaped path.
    tick: u64,
    credit: u64,
    bytes: u64,
    packets: u32,
}

impl Io for Link {
    async fn control(&self, message: Control) -> bool {
        // The harness creates the responding session with the real Start record.
        if !matches!(message, Control::Start(_)) {
            if !self.control_delay.is_zero() {
                tokio::time::sleep(self.control_delay).await;
            }
            self.remote
                .control(Control::decode(&message.encode().unwrap()).unwrap());
        }
        true
    }

    fn packet(&self, packet: Bytes) -> bool {
        let probe = decode_packet(&packet).unwrap();
        let tick = self.start.elapsed().as_millis() as u64;
        let mut state = self.state.lock().unwrap();
        if state.tick != tick {
            let elapsed = tick - state.tick;
            state.credit =
                (state.credit + self.rate * elapsed / 8000).min(self.rate * 4 / 8000 + 1300);
            state.tick = tick;
        }
        state.bytes += packet.len() as u64;
        if state.credit >= probe.payload_len() as u64 {
            state.credit -= probe.payload_len() as u64;
            state.packets += 1;
            if self.drop_every != 0 && state.packets.is_multiple_of(self.drop_every) {
                return true;
            }
            self.remote.data(probe);
            // Duplicates must never add more bytes or improve the reported rate.
            self.remote.data(probe);
        }
        true
    }

    fn progress(&self, update: Progress) {
        self.samples.lock().unwrap().push(update);
    }
}

fn config(local: u8, remote: u8, bytes: u32) -> Config {
    Config {
        id: 7,
        local: Ipv4Addr::new(10, 11, 12, local),
        remote: Ipv4Addr::new(10, 11, 12, remote),
        mtu: 1280,
        byte_limit: bytes,
        rtt: Duration::from_millis(20),
    }
}

async fn measure(down: u64, up: u64, budget: u32) -> (Progress, Progress, Link, Link) {
    shaped(down, up, budget, Duration::ZERO, 0).await
}

async fn shaped(
    down: u64,
    up: u64,
    budget: u32,
    control_delay: Duration,
    drop_every: u32,
) -> (Progress, Progress, Link, Link) {
    let cfg = |a, b| Config {
        rtt: control_delay.max(Duration::from_millis(20)),
        ..config(a, b, budget)
    };
    let (a, initiator) = initiate(cfg(1, 2));
    let start = Start {
        id: 7,
        byte_limit: budget,
        mtu: 1280,
    };
    let (b, responder) = respond(cfg(2, 1), start);
    let now = Instant::now();
    let link = |remote, rate| Link {
        remote,
        start: now,
        rate,
        control_delay,
        drop_every,
        state: Default::default(),
        samples: Default::default(),
    };
    let ab = link(b, up);
    let ba = link(a, down);
    let (a, b) = tokio::join!(initiator.run(ab.clone()), responder.run(ba.clone()));
    assert!(now.elapsed() <= Duration::from_secs(5));
    assert!(ab.state.lock().unwrap().bytes <= u64::from(budget));
    assert!(ba.state.lock().unwrap().bytes <= u64::from(budget));
    (a, b, ab, ba)
}

#[tokio::test(start_paused = true)]
async fn both_directions_measure_delivery_and_show_it_before_completion() {
    let (a, b, ab, _) = measure(10_000_000, 40_000_000, NORMAL_BYTES).await;
    assert_eq!(a, b);
    assert_eq!(a.state, State::Complete);
    for (sample, expected) in [(a.down, 10_000_000), (a.up, 40_000_000)] {
        let bps = sample.bps.unwrap();
        assert!(
            (expected * 8 / 10..=expected * 12 / 10).contains(&bps),
            "{sample:?}"
        );
        assert_eq!(sample.quality, Quality::Measured, "{sample:?}");
    }
    let updates = ab.samples.lock().unwrap();
    assert!(
        updates
            .iter()
            .any(|p| p.state == State::Download && p.down.bps.is_some())
    );
    assert!(
        updates
            .iter()
            .any(|p| p.state == State::Upload && p.up.bps.is_some())
    );
}

#[tokio::test(start_paused = true)]
async fn a_fast_path_extends_the_probe_but_never_turns_a_short_burst_into_a_peak() {
    let (a, _, _, _) = measure(1_000_000_000, 1_000_000_000, NORMAL_BYTES).await;
    assert_eq!(a.state, State::Complete);
    assert!(a.down.bytes > 16 * 1024 * 1024);
    assert!(
        a.down
            .bps
            .is_some_and(|v| (700_000_000..=1_150_000_000).contains(&v)),
        "{a:?}"
    );
    let (short, _, _, _) = measure(1_000_000_000, 1_000_000_000, 4096).await;
    assert_eq!(short.down.quality, Quality::Insufficient);
    assert_eq!(short.down.bps, None);
}

#[tokio::test(start_paused = true)]
async fn persistent_random_loss_does_not_masquerade_as_a_slow_link() {
    let (a, _, _, _) = shaped(
        20_000_000,
        45_000_000,
        NORMAL_BYTES,
        Duration::from_millis(45),
        20,
    )
    .await;
    assert_eq!(a.state, State::Complete);
    for (reading, rate) in [(a.down, 20_000_000), (a.up, 45_000_000)] {
        assert!(
            reading
                .bps
                .is_some_and(|v| (rate * 7 / 10..=rate * 11 / 10).contains(&v)),
            "{a:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn fast_metered_path_returns_a_sustained_lower_bound_within_its_budget() {
    let (a, _, _, _) = measure(4_000_000_000, 4_000_000_000, METERED_BYTES).await;
    assert_eq!(a.state, State::Complete);
    for reading in [a.down, a.up] {
        assert_eq!(reading.quality, Quality::AtLeast);
        assert!(
            reading
                .bps
                .is_some_and(|v| (50_000_000..1_000_000_000).contains(&v))
        );
    }
}

#[tokio::test(start_paused = true)]
async fn unreachable_data_path_cannot_synthesize_a_rate_or_keep_the_exchange_open() {
    let (a, _, _, _) = measure(0, 0, NORMAL_BYTES).await;
    assert_eq!(a.state, State::Complete);
    for reading in [a.down, a.up] {
        assert_eq!(reading.quality, Quality::Insufficient);
        assert_eq!(reading.bps, None);
    }
}

struct Silent;
impl Io for Silent {
    fn control(&self, _: Control) -> impl Future<Output = bool> + Send {
        std::future::pending()
    }
    fn packet(&self, _: Bytes) -> bool {
        false
    }
    fn progress(&self, _: Progress) {}
}

#[tokio::test(start_paused = true)]
async fn a_blocked_control_stream_cannot_hold_up_cancellation_or_the_deadline() {
    let (handle, runner) = initiate(config(1, 2, NORMAL_BYTES));
    let task = tokio::spawn(runner.run(Silent));
    tokio::task::yield_now().await;
    handle.cancel();
    let before = Instant::now();
    assert_eq!(task.await.unwrap().state, State::Cancelled);
    assert!(before.elapsed() <= Duration::from_millis(25));

    let (_keep_ingress, runner) = initiate(config(1, 2, NORMAL_BYTES));
    let before = Instant::now();
    assert_eq!(runner.run(Silent).await.state, State::TimedOut);
    assert!(before.elapsed() <= Duration::from_secs(5));
}

#[test]
fn control_records_have_finite_limits_and_exact_framing() {
    let message = Control::Start(Start {
        id: 42,
        byte_limit: NORMAL_BYTES,
        mtu: 1280,
    });
    let mut wire = message.encode().unwrap();
    assert_eq!(Control::decode(&wire), Some(message));
    for n in 0..wire.len() {
        assert_eq!(Control::decode(&wire[..n]), None);
    }
    wire.push(0);
    assert_eq!(Control::decode(&wire), None);
    assert_eq!(Control::decode(&[255; 65]), None);
    for (byte_limit, mtu) in [
        (0, 1280),
        (NORMAL_BYTES + 1, 1280),
        (1000, 4),
        (1000, u16::MAX),
    ] {
        let wire = Control::Start(Start {
            id: 1,
            byte_limit,
            mtu,
        })
        .encode()
        .unwrap();
        assert_eq!(Control::decode(&wire), None);
    }
}

struct OpenControl;
impl Io for OpenControl {
    fn control(&self, _: Control) -> impl Future<Output = bool> + Send {
        std::future::ready(true)
    }
    fn packet(&self, _: Bytes) -> bool {
        false
    }
    fn progress(&self, _: Progress) {}
}

#[tokio::test(start_paused = true)]
async fn an_unrelated_busy_reply_does_not_cancel_the_active_request() {
    let (handle, session) = initiate(config(1, 2, NORMAL_BYTES));
    handle.control(Control::Busy { id: 8 });
    let task = tokio::spawn(session.run(OpenControl));
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    handle.control(Control::Busy { id: 7 });
    assert_eq!(task.await.unwrap().state, State::Busy);
}

#[tokio::test(start_paused = true)]
async fn slower_control_feedback_leaves_time_for_both_directions() {
    let (a, b, _, _) = shaped(
        12_000_000,
        25_000_000,
        NORMAL_BYTES,
        Duration::from_millis(130),
        0,
    )
    .await;
    assert_eq!(a, b);
    assert_eq!(a.state, State::Complete);
    assert!(
        a.down
            .bps
            .is_some_and(|v| (9_000_000..=14_000_000).contains(&v))
    );
    assert!(
        a.up.bps
            .is_some_and(|v| (17_000_000..=28_000_000).contains(&v))
    );
}

#[tokio::test(start_paused = true)]
async fn slow_links_accumulate_enough_arrivals_for_a_rate() {
    let (a, _, _, _) = measure(100_000, 256_000, NORMAL_BYTES).await;
    assert_eq!(a.state, State::Complete);
    for (r, rate) in [(a.down, 100_000), (a.up, 256_000)] {
        assert!(
            r.bps
                .is_some_and(|v| (rate * 65 / 100..=rate * 125 / 100).contains(&v)),
            "{r:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn persistent_heavy_loss_reports_only_sustained_lower_bounds() {
    let (a, _, _, _) = shaped(50_000_000, 50_000_000, NORMAL_BYTES, Duration::ZERO, 3).await;
    for r in [a.down, a.up] {
        assert_eq!(r.quality, Quality::AtLeast, "{r:?}");
        assert!(r.bps.is_some_and(|v| (100_000..=33_500_000).contains(&v)));
    }
}

#[test]
fn a_finished_rate_requires_evidence_of_delivered_payload() {
    for quality in [Quality::AtLeast, Quality::Measured] {
        let message = Control::Report {
            id: 1,
            direction: Direction::Download,
            reading: Reading {
                bps: Some(8_000_000_000),
                bytes: 0,
                quality,
            },
        };
        assert!(Control::decode(&message.encode().unwrap()).is_none());
    }
}
