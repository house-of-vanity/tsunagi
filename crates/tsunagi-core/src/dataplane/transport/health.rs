//! Authenticated probes of the actual data link, independent of control RTT.
//! Keys are negotiated privately for each physical link. No fixed wire magic.
use super::{PacketLink, SharedLink, TransportError};
use crate::{BoxFuture, NetworkId};
use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

#[derive(Clone, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
pub(crate) struct Settings {
    marker: [u8; 16],
    key: [u8; 32],
}
impl Settings {
    pub(crate) fn fresh() -> Self {
        Self {
            marker: rand::random(),
            key: rand::random(),
        }
    }
}
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HealthSettings([REDACTED])")
    }
}
struct Samples {
    pending: VecDeque<(u64, Instant)>,
    recent: VecDeque<bool>,
}
impl Samples {
    fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            recent: VecDeque::new(),
        }
    }
    fn sent(&mut self, seq: u64, now: Instant) {
        self.pending.push_back((seq, now));
    }
    fn acknowledge(&mut self, seq: u64) {
        if let Some(i) = self.pending.iter().position(|(n, _)| *n == seq) {
            self.pending.remove(i);
            self.recent.push_back(true);
        }
    }
    fn expire(&mut self, now: Instant) {
        while self
            .pending
            .front()
            .is_some_and(|(_, at)| now.duration_since(*at) >= Duration::from_secs(3))
        {
            self.pending.pop_front();
            self.recent.push_back(false);
        }
        while self.recent.len() > 20 {
            self.recent.pop_front();
        }
    }
    fn degraded(&self) -> bool {
        self.recent.len() >= 15
            && self.recent.iter().filter(|ok| !**ok).count() * 100 >= self.recent.len() * 60
    }
}
/// A monitored physical link. It forwards application bytes unchanged.
pub(crate) struct HealthLink {
    raw: SharedLink,
    settings: Mutex<Option<Settings>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    stop: watch::Sender<bool>,
    reason: Mutex<Option<String>>,
}
impl std::fmt::Debug for HealthLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthLink")
            .field("raw", &self.raw)
            .finish_non_exhaustive()
    }
}
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}
impl HealthLink {
    pub(crate) fn new(raw: SharedLink, local: EndpointId, settings: Option<Settings>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(64);
        let (stop, _) = watch::channel(false);
        let link = Arc::new(Self {
            raw: raw.clone(),
            settings: Mutex::new(settings),
            rx: tokio::sync::Mutex::new(rx),
            stop,
            reason: Mutex::new(None),
        });
        let weak = Arc::downgrade(&link);
        let mut stopped = link.stop.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut samples = Samples::new();
            let mut sequence = rand::random::<u64>();
            let mut since: Option<Instant> = None;
            let mut marker = None;
            loop {
                tokio::select! {
                    biased;
                    _=stopped.changed()=>break,
                    _=interval.tick()=>{
                        let Some(link)=weak.upgrade()else{break;};let Some(settings)=lock(&link.settings).clone()else{continue;};
                        if marker != Some(settings.marker) { marker = Some(settings.marker); samples = Samples::new(); since = None; }
                        let start=*since.get_or_insert_with(Instant::now);let now=Instant::now();samples.expire(now);
                        if now.duration_since(start)>=Duration::from_secs(20) && samples.degraded() {
                            *lock(&link.reason)=Some("data delivery checks: at least 60% loss over the last 20 probes".into());break;
                        }
                        sequence=sequence.wrapping_add(1);
                        let size=raw.max_datagram_size();
                        let packet=probe(&settings,local,1,sequence,size.min(1000));
                        samples.sent(sequence,now);
                        let _=raw.send(packet);
                    }
                    packet=raw.recv()=>{
                        let Some(packet)=packet else{break;};let Some(link)=weak.upgrade()else{break;};
                        let settings=lock(&link.settings).clone();
                        if let Some(settings)=settings && packet.starts_with(&settings.marker) {
                            if let Some((kind,seq))=verify(&settings,raw.peer(),&packet) {
                                if kind==1 {let _=raw.send(probe(&settings,local,2,seq,packet.len()));}
                                else if kind==2 {samples.acknowledge(seq);}
                            }
                        } else {let _=tx.try_send(packet);}
                    }

                }
            }
            raw.close();
            if let Some(link) = weak.upgrade() {
                link.stop.send_replace(true);
            }
        });
        link
    }
    pub(crate) fn configure(&self, settings: Settings) {
        *lock(&self.settings) = Some(settings);
    }
}
fn probe(settings: &Settings, sender: EndpointId, kind: u8, seq: u64, size: usize) -> Bytes {
    let mut bytes = vec![0; size.max(57)];
    bytes[..16].copy_from_slice(&settings.marker);
    bytes[16] = kind;
    bytes[17..25].copy_from_slice(&seq.to_be_bytes());
    rand::fill(&mut bytes[25..size.max(57) - 32]);
    let tail = bytes.len() - 32;
    if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(&settings.key) {
        mac.update(sender.as_bytes());
        mac.update(&bytes[..tail]);
        bytes[tail..].copy_from_slice(&mac.finalize().into_bytes());
    }
    Bytes::from(bytes)
}
fn verify(settings: &Settings, sender: EndpointId, bytes: &[u8]) -> Option<(u8, u64)> {
    if bytes.len() < 57 || !bytes.starts_with(&settings.marker) {
        return None;
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&settings.key).ok()?;
    let tail = bytes.len() - 32;
    mac.update(sender.as_bytes());
    mac.update(&bytes[..tail]);
    mac.verify_slice(&bytes[tail..]).ok()?;
    Some((
        bytes[16],
        u64::from_be_bytes(bytes.get(17..25)?.try_into().ok()?),
    ))
}
impl PacketLink for HealthLink {
    fn network(&self) -> NetworkId {
        self.raw.network()
    }
    fn peer(&self) -> EndpointId {
        self.raw.peer()
    }
    fn max_datagram_size(&self) -> usize {
        self.raw.max_datagram_size()
    }
    fn send(&self, payload: Bytes) -> Result<(), TransportError> {
        if self.is_closed() {
            Err(TransportError::Closed)
        } else {
            self.raw.send(payload)
        }
    }
    fn send_flow(
        &self,
        payload: Bytes,
        flow: super::super::routing::FlowId,
    ) -> Result<(), TransportError> {
        if self.is_closed() {
            Err(TransportError::Closed)
        } else {
            self.raw.send_flow(payload, flow)
        }
    }
    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            let mut stop = self.stop.subscribe();
            if *stop.borrow() {
                return None;
            }
            let mut rx = self.rx.lock().await;
            tokio::select! {biased;_=stop.changed()=>None,packet=rx.recv()=>packet}
        })
    }
    fn closed(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut stop = self.stop.subscribe();
            if !*stop.borrow() {
                let _ = stop.changed().await;
            }
        })
    }
    fn is_closed(&self) -> bool {
        *self.stop.borrow() || self.raw.is_closed()
    }
    fn close(&self) {
        self.stop.send_replace(true);
        self.raw.close();
    }
    fn failure_reason(&self) -> Option<String> {
        lock(&self.reason)
            .clone()
            .or_else(|| self.raw.failure_reason())
    }
    fn path_description(&self) -> String {
        self.raw.path_description()
    }
}
impl Drop for HealthLink {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.raw.close();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn no_false_failure_before_window_but_persistent_loss_is_detected() {
        let mut samples = Samples::new();
        let now = Instant::now();
        for seq in 0..20 {
            samples.sent(seq, now);
            if seq % 5 == 0 {
                samples.acknowledge(seq);
            }
        }
        assert!(!samples.degraded());
        samples.expire(now + Duration::from_secs(4));
        assert!(samples.degraded());
        for seq in 20..40 {
            samples.sent(seq, now);
            samples.acknowledge(seq);
        }
        samples.expire(now + Duration::from_secs(4));
        assert!(!samples.degraded());
    }
    #[test]
    fn a_forged_or_reflected_probe_cannot_claim_delivery() {
        let a = crate::identity::DeviceIdentity::generate().endpoint_id();
        let b = crate::identity::DeviceIdentity::generate().endpoint_id();
        let settings = Settings::fresh();
        let packet = probe(&settings, a, 1, 42, 1100);
        assert_eq!(verify(&settings, a, &packet), Some((1, 42)));
        assert!(verify(&settings, b, &packet).is_none());
        let mut forged = packet.to_vec();
        forged[16] = 2;
        assert!(verify(&settings, a, &forged).is_none());
    }
}
