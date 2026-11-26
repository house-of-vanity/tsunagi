use crate::measurement::{Pacer, Receiver, Search};
use crate::packet::{MAX_MTU, MIN_MTU, PacketBuilder};
use crate::{
    Control, Datagram, Direction, Feedback, NORMAL_BYTES, Progress, Quality, Reading, Start, State,
};
use bytes::Bytes;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep_until, timeout_at};

const TOTAL_TIME: Duration = Duration::from_secs(5);
const DIRECTION_TIME: Duration = Duration::from_millis(1900);
const FEEDBACK_TICK: Duration = Duration::from_millis(25);
const PACE_TICK: Duration = Duration::from_millis(1);

/// Parameters for one locally admitted, authenticated peer.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Fresh random identifier for the exchange. A responder uses the identifier from the request.
    pub id: u64,
    /// Local overlay IPv4 address on this network.
    pub local: Ipv4Addr,
    /// Authenticated peer's overlay address on this network.
    pub remote: Ipv4Addr,
    /// Maximum complete diagnostic datagram size supported by this route.
    pub mtu: u16,
    /// Local policy's maximum diagnostic IPv4 bytes in each direction.
    pub byte_limit: u32,
    /// Recent peer RTT, used to select the feedback interval and bound the final drain.
    pub rtt: Duration,
}

/// Delivery for exactly one network and peer. The host uses its usual network
/// authentication for control and its ordinary encrypted packet path for probes.
pub trait Io: Send + Sync {
    /// Enqueue or send one reliable authenticated control record.
    fn control(&self, message: Control) -> impl Future<Output = bool> + Send;
    /// Attempt to send one packet without blocking the tunnel or buffering unbounded data.
    fn packet(&self, packet: Bytes) -> bool;
    /// Publish a live observation or terminal state.
    fn progress(&self, update: Progress);
}

#[derive(Default)]
struct Ingress(Mutex<Option<Receiver>>);

impl Ingress {
    fn with<T>(&self, f: impl FnOnce(&mut Option<Receiver>) -> T) -> T {
        let mut guard = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        f(&mut guard)
    }
}

/// Cloneable, nonblocking ingress for a single test. Data is counted in place;
/// it is never put on the reliable message queue.
#[derive(Clone)]
pub struct Handle {
    id: u64,
    local: Ipv4Addr,
    remote: Ipv4Addr,
    events: mpsc::Sender<Control>,
    cancel: watch::Sender<bool>,
    ingress: Arc<Ingress>,
}

impl Handle {
    /// Deliver an authenticated control record for an existing test.
    pub fn control(&self, message: Control) {
        if message.id() == self.id && message.valid() {
            if matches!(message, Control::Cancel { .. }) {
                self.cancel();
            } else {
                let _ = self.events.try_send(message);
            }
        }
    }

    /// Count a validated probe from the bound peer in the current receiving direction.
    pub fn data(&self, packet: Datagram) {
        if packet.id == self.id && packet.source == self.remote && packet.destination == self.local
        {
            self.ingress.with(|rx| {
                if let Some(rx) = rx {
                    rx.put(packet, Instant::now());
                }
            });
        }
    }

    /// Interrupt local work, including outstanding control sends.
    pub fn cancel(&self) {
        self.cancel.send_replace(true);
    }
}

/// A single, bounded two-direction exchange. Nothing runs until the host calls `run`.
pub struct Session {
    cfg: Config,
    request: Option<Start>,
    events: mpsc::Receiver<Control>,
    cancel: watch::Receiver<bool>,
    ingress: Arc<Ingress>,
    progress: Progress,
}

/// Prepare an outgoing session. The test begins when its runner sends its Start record.
pub fn initiate(config: Config) -> (Handle, Session) {
    new_session(config, None)
}

/// Prepare the response to a verified Start. Local and requested traffic limits are intersected.
pub fn respond(mut config: Config, request: Start) -> (Handle, Session) {
    config.id = request.id;
    new_session(config, Some(request))
}

fn new_session(config: Config, request: Option<Start>) -> (Handle, Session) {
    let (tx, events) = mpsc::channel(32);
    let (cancel_tx, cancel) = watch::channel(false);
    let ingress = Arc::new(Ingress::default());
    let handle = Handle {
        id: config.id,
        local: config.local,
        remote: config.remote,
        events: tx,
        cancel: cancel_tx,
        ingress: ingress.clone(),
    };
    let session = Session {
        cfg: config,
        request,
        events,
        cancel,
        ingress,
        progress: Progress::default(),
    };
    (handle, session)
}

fn open_control(control: Option<Control>) -> Result<Control, State> {
    match control {
        Some(Control::Busy { .. }) => Err(State::Busy),
        Some(Control::Cancel { .. }) => Err(State::Cancelled),
        Some(control) => Ok(control),
        None => Err(State::Cancelled),
    }
}

async fn send(io: &impl Io, message: Control) -> Result<(), State> {
    if io.control(message).await {
        Ok(())
    } else {
        Err(State::Failed)
    }
}

impl Session {
    /// Run both directions under one five-second deadline and return the same final
    /// snapshot that is published to the host. Dropping the future stops packet generation.
    pub async fn run(mut self, io: impl Io) -> Progress {
        let deadline = Instant::now() + TOTAL_TIME;
        let mut cancellation = self.cancel.clone();
        io.progress(self.progress);
        let state = tokio::select! {
            biased;
            _ = cancellation.wait_for(|v| *v) => State::Cancelled,
            result = timeout_at(deadline, self.exchange(&io, deadline)) => {
                match result { Ok(Ok(())) => State::Complete, Ok(Err(state)) => state, Err(_) => State::TimedOut }
            }
        };
        self.ingress.with(|rx| *rx = None);
        self.progress.state = state;
        io.progress(self.progress);
        if matches!(state, State::Cancelled | State::Failed | State::TimedOut) {
            // A blocked control stream must never delay local release or shutdown.
            let _ = timeout_at(
                deadline.min(Instant::now() + Duration::from_millis(20)),
                io.control(Control::Cancel { id: self.cfg.id }),
            )
            .await;
        }
        self.progress
    }

    async fn exchange(&mut self, io: &impl Io, deadline: Instant) -> Result<(), State> {
        let id = self.cfg.id;
        self.cfg.byte_limit = self.cfg.byte_limit.min(NORMAL_BYTES);
        self.cfg.mtu = self.cfg.mtu.min(MAX_MTU);
        if self.cfg.mtu < MIN_MTU || self.cfg.byte_limit == 0 || self.cfg.local == self.cfg.remote {
            return Err(State::Failed);
        }
        let negotiation_started = Instant::now();
        if let Some(start) = self.request {
            if !Control::Start(start).valid() {
                return Err(State::Failed);
            }
            self.cfg.mtu = self.cfg.mtu.min(start.mtu);
            self.cfg.byte_limit = self.cfg.byte_limit.min(start.byte_limit);
            send(
                io,
                Control::Accepted {
                    id,
                    mtu: self.cfg.mtu,
                    byte_limit: self.cfg.byte_limit,
                },
            )
            .await?;
        } else {
            send(
                io,
                Control::Start(Start {
                    id,
                    mtu: self.cfg.mtu,
                    byte_limit: self.cfg.byte_limit,
                }),
            )
            .await?;
            loop {
                if let Control::Accepted {
                    mtu, byte_limit, ..
                } = open_control(self.events.recv().await)?
                {
                    if mtu > self.cfg.mtu || byte_limit > self.cfg.byte_limit {
                        return Err(State::Failed);
                    }
                    self.cfg.mtu = mtu;
                    self.cfg.byte_limit = byte_limit;
                    break;
                }
            }
        }

        let negotiation_time = negotiation_started.elapsed();
        for direction in [Direction::Download, Direction::Upload] {
            self.progress.state = match direction {
                Direction::Download => State::Download,
                Direction::Upload => State::Upload,
            };
            io.progress(self.progress);
            let sender = (direction == Direction::Download) == self.request.is_some();
            let result = if sender {
                self.send_probes(io, direction, deadline, negotiation_time)
                    .await?
            } else {
                self.receive_probes(io, direction).await?
            };
            *self.progress.at(direction) = result;
            io.progress(self.progress);
        }
        Ok(())
    }

    async fn send_probes(
        &mut self,
        io: &impl Io,
        direction: Direction,
        deadline: Instant,
        negotiation_time: Duration,
    ) -> Result<Reading, State> {
        let waiting = Instant::now();
        loop {
            if matches!(open_control(self.events.recv().await)?, Control::Ready { direction: d, .. } if d == direction)
            {
                break;
            }
        }
        let start = Instant::now();
        // End and Report travel on reliable control. Leave room for their
        // exchange and a queued feedback message even on a slow control path.
        // Only the receiver's data packets contribute to the measured rate.
        let report_time = negotiation_time
            .max(waiting.elapsed())
            .saturating_mul(3)
            .saturating_add(Duration::from_millis(200))
            .min(Duration::from_millis(1600));
        let remaining = deadline
            .saturating_duration_since(start)
            .saturating_sub(report_time);
        let phase = if direction == Direction::Download {
            remaining / 2
        } else {
            remaining
        };
        let end = start + phase.min(DIRECTION_TIME);
        let mut tick = interval_at(start + PACE_TICK, PACE_TICK);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut search = Search::default();
        let mut pacer = Pacer::new(start, self.cfg.mtu);
        let builder = PacketBuilder::new(
            self.cfg.local,
            self.cfg.remote,
            self.cfg.id,
            direction,
            self.cfg.mtu,
        );
        let limit = self.cfg.byte_limit / u32::from(self.cfg.mtu);
        let mut packets = 0;
        let mut last_bytes = 0;
        let mut last_feedback = start;
        let max_silence = (self
            .cfg
            .rtt
            .saturating_mul(3)
            .saturating_add(Duration::from_millis(200)))
        .clamp(Duration::from_millis(700), Duration::from_millis(950));
        while packets < limit && !search.done() && Instant::now() < end {
            tokio::select! {
                control = self.events.recv() => {
                    if let Control::Feedback { direction: d, sample, .. } = open_control(control)?
                        && d == direction && sample.bytes >= last_bytes && sample.bytes <= self.cfg.byte_limit
                    {
                        if sample.bytes > last_bytes {
                            last_feedback = Instant::now();
                            last_bytes = sample.bytes;
                        }
                        if sample.bps > 0 {
                            *self.progress.at(direction) = Reading { bps: Some(sample.bps), bytes: last_bytes, quality: Quality::Measuring };
                            io.progress(self.progress);
                        }
                        search.observe(sample, start.elapsed().as_micros() as u32);
                    }
                }
                _ = tick.tick() => {
                    let now = Instant::now();
                    let silence = if last_bytes == 0 { max_silence.max(Duration::from_millis(1100)) } else { max_silence };
                    if now.duration_since(last_feedback) > silence {
                        break;
                    }
                    let emit = pacer.packets(now, search.target).min(limit - packets);
                    for index in 0..emit {
                        if index > 0 && index.is_multiple_of(64) {
                            tokio::task::yield_now().await;
                        }
                        let elapsed_us = start.elapsed().as_micros() as u32;
                        let packet = builder.packet(search.stage, packets, elapsed_us);
                        // A tunnel waiting for a handshake can retain a submitted
                        // packet. Charge that attempt, then release the unissued
                        // part of this batch for a later tick if the tunnel is full.
                        packets += 1;
                        if !io.packet(packet) {
                            break;
                        }
                    }
                }
            }
        }
        send(
            io,
            Control::End {
                id: self.cfg.id,
                direction,
                packets,
                reading: search.result(last_bytes),
            },
        )
        .await?;
        loop {
            if let Control::Report {
                direction: d,
                reading,
                ..
            } = open_control(self.events.recv().await)?
                && d == direction
            {
                if reading.bytes > packets * u32::from(self.cfg.mtu - crate::packet::HEADER) {
                    return Err(State::Failed);
                }
                return Ok(reading);
            }
        }
    }

    async fn receive_probes(
        &mut self,
        io: &impl Io,
        direction: Direction,
    ) -> Result<Reading, State> {
        let id = self.cfg.id;
        self.ingress
            .with(|rx| *rx = Some(Receiver::new(direction, self.cfg.mtu, self.cfg.byte_limit)));
        send(io, Control::Ready { id, direction }).await?;
        let mut tick = interval_at(Instant::now() + FEEDBACK_TICK, FEEDBACK_TICK);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let window = self
            .cfg
            .rtt
            .clamp(Duration::from_millis(100), Duration::from_millis(220));
        let (packets, estimate) = loop {
            tokio::select! {
                control = self.events.recv() => {
                    if let Control::End { direction: d, packets, reading, .. } = open_control(control)?
                        && d == direction
                    {
                        if packets > self.cfg.byte_limit / u32::from(self.cfg.mtu) { return Err(State::Failed); }
                        break (packets, reading);
                    }
                }
                _ = tick.tick() => {
                    let sample = self.ingress.with(|rx| rx.as_mut().and_then(|r| r.sample(Instant::now(), window)));
                    if let Some(sample) = sample {
                        self.update_receiver(io, direction, sample);
                        send(io, Control::Feedback { id, direction, sample }).await?;
                    }
                }
            }
        };
        let received = self.ingress.with(|rx| rx.as_ref().map_or(0, |r| r.count));
        if received < packets {
            // Reliable End and encrypted probes may take different paths.
            let drain = self
                .cfg
                .rtt
                .clamp(Duration::from_millis(25), Duration::from_millis(120));
            sleep_until(Instant::now() + drain).await;
        }
        let rx = self.ingress.with(Option::take).ok_or(State::Failed)?;
        if rx.count > packets {
            return Err(State::Failed);
        }
        let reading = rx.finish(estimate);
        send(
            io,
            Control::Report {
                id,
                direction,
                reading,
            },
        )
        .await?;
        Ok(reading)
    }

    fn update_receiver(&mut self, io: &impl Io, direction: Direction, sample: Feedback) {
        let reading = self.progress.at(direction);
        reading.bytes = sample.bytes;
        if sample.bps > 0 {
            reading.bps = Some(sample.bps);
        }
        io.progress(self.progress);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn data_ingress_is_bound_to_the_session_id_and_both_assigned_addresses() {
        let local = Ipv4Addr::new(10, 1, 2, 3);
        let remote = Ipv4Addr::new(10, 1, 2, 4);
        let conf = Config {
            id: 42,
            local,
            remote,
            mtu: 1280,
            byte_limit: 32_000,
            rtt: Duration::ZERO,
        };
        let (handle, _) = initiate(conf);
        handle.ingress.with(|rx| {
            *rx = Some(Receiver::new(
                Direction::Download,
                conf.mtu,
                conf.byte_limit,
            ))
        });
        let make = |src, dst, id, seq| {
            let raw = PacketBuilder::new(src, dst, id, Direction::Download, 1280).packet(0, seq, 7);
            crate::decode_packet(&raw).unwrap()
        };
        for (ipfrom, ipto, id, seq) in [
            (remote, local, 41, 0),
            (local, remote, 42, 1),
            (Ipv4Addr::LOCALHOST, local, 42, 2),
            (remote, Ipv4Addr::LOCALHOST, 42, 3),
            (remote, local, 42, 4),
        ] {
            handle.data(make(ipfrom, ipto, id, seq));
        }
        assert_eq!(
            handle.ingress.with(|rx| rx.as_ref().map(|r| r.count)),
            Some(1)
        );
    }
}
