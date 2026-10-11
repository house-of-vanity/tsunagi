//! One cancellable actor and UDP socket per pair. All payload and health frames
//! are inside the Amnezia-masked authenticated WireGuard tunnel.
use crate::profile::PairProfile;
use boringtun::noise::{Tunn, TunnResult};
use bytes::Bytes;
use iroh::EndpointId;
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tsunagi::dataplane::transport::{PacketLink, TransportError};
use tsunagi::{BoxFuture, NetworkId};

pub(crate) const MAX_PAYLOAD: usize = tsunagi::config::MAX_DATA_DATAGRAM;
const CHUNK: usize = 700;
const QUEUE: usize = 64;
const WINDOW: Duration = Duration::from_secs(20);

pub(crate) struct PairLink {
    network: NetworkId,
    peer: EndpointId,
    pub(crate) attempt: [u8; 16],
    tx: mpsc::Sender<Bytes>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    stop: watch::Sender<bool>,
    closed: AtomicBool,
    remote: Mutex<Option<SocketAddr>>,
    reason: Mutex<Option<String>>,
}
impl std::fmt::Debug for PairLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwgPair")
            .field("network", &self.network)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}
impl PairLink {
    pub(crate) fn has_authenticated_path(&self) -> bool {
        match self.remote.lock() {
            Ok(remote) => remote.is_some(),
            Err(_) => false,
        }
    }
}
impl PacketLink for PairLink {
    fn network(&self) -> NetworkId {
        self.network
    }
    fn peer(&self) -> EndpointId {
        self.peer
    }
    fn max_datagram_size(&self) -> usize {
        MAX_PAYLOAD
    }
    fn send(&self, payload: Bytes) -> Result<(), TransportError> {
        if self.is_closed() {
            return Err(TransportError::Closed);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(TransportError::TooLarge {
                size: payload.len(),
                limit: MAX_PAYLOAD,
            });
        }
        self.tx
            .try_send(payload)
            .map_err(|_| TransportError::Other("AWG send queue full or closed".into()))
    }
    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            let mut stop = self.stop.subscribe();
            if *stop.borrow() {
                return None;
            }
            let mut rx = self.rx.lock().await;
            tokio::select! {biased; _=stop.changed()=>None,packet=rx.recv()=>packet}
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
        self.closed.load(Ordering::Acquire) || *self.stop.borrow()
    }
    fn close(&self) {
        self.stop.send_replace(true);
    }
    fn failure_reason(&self) -> Option<String> {
        match self.reason.lock() {
            Ok(reason) => reason.clone(),
            Err(_) => None,
        }
    }
    fn path_description(&self) -> String {
        match self.remote.lock() {
            Ok(addr) => match *addr {
                Some(addr) => format!("awg UDP via {addr}"),
                None => "awg UDP, establishing".into(),
            },
            Err(_) => "awg UDP".into(),
        }
    }
}
impl Drop for PairLink {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

pub(crate) fn start(
    network: NetworkId,
    peer: EndpointId,
    socket: UdpSocket,
    tunn: Tunn,
    profile: PairProfile,
    candidates: Vec<SocketAddr>,
    parent: watch::Receiver<bool>,
) -> Arc<PairLink> {
    let (tx, rx) = mpsc::channel(QUEUE);
    let (in_tx, in_rx) = mpsc::channel(QUEUE);
    let (stop, _) = watch::channel(false);
    let link = Arc::new(PairLink {
        network,
        peer,
        attempt: profile.id(),
        tx,
        rx: tokio::sync::Mutex::new(in_rx),
        stop: stop.clone(),
        closed: AtomicBool::new(false),
        remote: Mutex::new(None),
        reason: Mutex::new(None),
    });
    let weak = Arc::downgrade(&link);
    tokio::spawn(async move {
        let mut engine = Engine {
            stop: stop.subscribe(),
            socket,
            tunn,
            profile,
            candidates,
            remote: None,
            inbox: in_tx,
            rx,
            counter: rand::random(),
            sequence: 0,
            pending: VecDeque::new(),
            samples: VecDeque::new(),
            assemblies: HashMap::new(),
            started: Instant::now(),
            last_authenticated: Instant::now(),
        };
        engine.run(parent, &weak).await;
        if let Some(link) = weak.upgrade() {
            link.closed.store(true, Ordering::Release);
            link.stop.send_replace(true);
        }
    });
    link
}

struct Assembly {
    created: Instant,
    count: u16,
    chunks: Vec<Option<Bytes>>,
}
struct Engine {
    stop: watch::Receiver<bool>,
    socket: UdpSocket,
    tunn: Tunn,
    profile: PairProfile,
    candidates: Vec<SocketAddr>,
    remote: Option<SocketAddr>,
    inbox: mpsc::Sender<Bytes>,
    rx: mpsc::Receiver<Bytes>,
    counter: u64,
    sequence: u64,
    pending: VecDeque<(u64, Instant)>,
    samples: VecDeque<bool>,
    assemblies: HashMap<u64, Assembly>,
    started: Instant,
    last_authenticated: Instant,
}
enum ResultOwned {
    Wire(Vec<u8>),
    Plain(Vec<u8>),
    Done,
}
fn own(result: TunnResult<'_>) -> ResultOwned {
    match result {
        TunnResult::WriteToNetwork(p) => ResultOwned::Wire(p.to_vec()),
        TunnResult::WriteToTunnelV4(p, _) => ResultOwned::Plain(p.to_vec()),
        _ => ResultOwned::Done,
    }
}
fn ip(payload: &[u8]) -> Bytes {
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = 253;
    packet[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
    packet[16..20].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 2).octets());
    packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    let sum = packet
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum::<u32>();
    let sum = (sum & 0xffff) + (sum >> 16);
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet.extend_from_slice(payload);
    Bytes::from(packet)
}
impl Engine {
    async fn run(&mut self, mut stop: watch::Receiver<bool>, link: &std::sync::Weak<PairLink>) {
        if *self.stop.borrow() || *stop.borrow() {
            return;
        }
        let mut buffer = [0; 1201];
        let mut scratch = [0; 4096];
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_probe = Instant::now() - Duration::from_secs(2);
        loop {
            tokio::select! {
                biased;
                _=stop.changed()=>break,
                _=self.stop.changed()=>break,
                _=timer.tick()=>{
                    let result=own(self.tunn.update_timers(&mut scratch));self.process(result,None).await;
                    if last_probe.elapsed()>=Duration::from_secs(1) {
                        last_probe=Instant::now();self.sequence=self.sequence.wrapping_add(1);
                        self.pending.push_back((self.sequence,Instant::now()));
                        let mut probe=vec![1];probe.extend_from_slice(&self.sequence.to_be_bytes());
                        probe.resize(713,0);rand::fill(&mut probe[9..]);self.encrypt(&probe).await;
                    }
                    while self.pending.front().is_some_and(|(_,at)|at.elapsed()>=Duration::from_secs(3)) {
                        self.pending.pop_front();self.samples.push_back(false);
                    }
                    while self.samples.len()>20 {self.samples.pop_front();}
                    self.assemblies.retain(|_,a|a.created.elapsed()<Duration::from_secs(5));
                    if self.started.elapsed()>WINDOW && (self.last_authenticated.elapsed()>Duration::from_secs(10)
                        || (self.samples.len()>=15&&self.samples.iter().filter(|ok|!**ok).count()*100>=self.samples.len()*60)) {
                        if let Some(link)=link.upgrade() && let Ok(mut reason)=link.reason.lock() {*reason=Some("AWG data delivery checks: persistent loss or timeout".into());}
                        break;
                    }
                }
                packet=self.socket.recv_from(&mut buffer)=>{
                    if let Ok((len,source))=packet && let Some(message)=self.profile.decode(&buffer[..len]) {
                            let result=own(self.tunn.decapsulate(None,&message,&mut scratch));
                            if matches!(result,ResultOwned::Plain(_)) {
                                self.remote=Some(source);self.last_authenticated=Instant::now();
                                if let Some(link)=link.upgrade() && let Ok(mut remote)=link.remote.lock(){*remote=Some(source);}
                            }
                            self.process(result,Some(source)).await;
                            for _ in 0..16 {
                                let result=own(self.tunn.decapsulate(None,&[],&mut scratch));
                                if matches!(result,ResultOwned::Done){break;}
                                self.process(result,Some(source)).await;
                            }
                    }
                }
                packet=self.rx.recv()=>{
                    let Some(packet)=packet else{break;};
                    let count=packet.len().max(1).div_ceil(CHUNK) as u16;
                    self.counter=self.counter.wrapping_add(1);
                    for (index,chunk) in packet.chunks(CHUNK).enumerate() {
                        let mut payload=vec![3];payload.extend_from_slice(&self.counter.to_be_bytes());
                        payload.extend_from_slice(&(index as u16).to_be_bytes());payload.extend_from_slice(&count.to_be_bytes());
                        payload.extend_from_slice(chunk);self.encrypt(&payload).await;
                        // Large logical datagrams must let local readers and other
                        // pairs drain their bounded socket/command queues.
                        if (index + 1).is_multiple_of(16) {tokio::task::yield_now().await;}
                    }
                }

            }
        }
    }
    async fn encrypt(&mut self, payload: &[u8]) {
        let packet = self.profile.pad(ip(payload));
        let mut scratch = [0; 4096];
        let result = own(self.tunn.encapsulate(&packet, &mut scratch));
        self.process(result, None).await;
    }
    async fn wire(&self, raw: &[u8], target: Option<SocketAddr>) {
        let Some(wire) = self.profile.encode(raw) else {
            return;
        };
        let targets: Vec<_> = target
            .or(self.remote)
            .map(|a| vec![a])
            .unwrap_or_else(|| self.candidates.clone());
        for addr in targets {
            if raw.first() == Some(&1) {
                for signature in self.profile.signature_packets() {
                    let _ = self.send_wire(&signature, addr).await;
                }
                for junk in self.profile.junk_packets() {
                    let _ = self.send_wire(&junk, addr).await;
                }
            }
            let _ = self.send_wire(&wire, addr).await;
        }
    }
    async fn send_wire(&self, bytes: &[u8], address: SocketAddr) {
        let mut stop = self.stop.clone();
        if *stop.borrow() {
            return;
        }
        tokio::select! {biased; _=stop.changed()=>{}, _=tokio::time::timeout(Duration::from_millis(100),self.socket.send_to(bytes,address))=>{}}
    }
    async fn process(&mut self, result: ResultOwned, target: Option<SocketAddr>) {
        match result {
            ResultOwned::Wire(raw) => self.wire(&raw, target).await,
            ResultOwned::Plain(packet) => {
                let Some(payload) = packet.get(20..) else {
                    return;
                };
                let Some(seq) = payload
                    .get(1..9)
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_be_bytes)
                else {
                    return;
                };
                match payload.first() {
                    Some(1) => {
                        let mut pong = vec![2];
                        pong.extend_from_slice(&seq.to_be_bytes());
                        pong.resize(713, 0);
                        let packet = self.profile.pad(ip(&pong));
                        let mut scratch = [0; 4096];
                        if let ResultOwned::Wire(raw) =
                            own(self.tunn.encapsulate(&packet, &mut scratch))
                        {
                            self.wire(&raw, target).await;
                        }
                    }
                    Some(2) => {
                        if let Some(index) =
                            self.pending.iter().position(|(pending, _)| *pending == seq)
                        {
                            self.pending.remove(index);
                            self.samples.push_back(true);
                        }
                    }
                    Some(3) => self.fragment(seq, payload),
                    _ => {}
                }
            }
            ResultOwned::Done => {}
        }
    }
    fn fragment(&mut self, id: u64, payload: &[u8]) {
        let Some(header) = payload.get(9..13) else {
            return;
        };
        let index = u16::from_be_bytes([header[0], header[1]]);
        let count = u16::from_be_bytes([header[2], header[3]]);
        let chunk = &payload[13..];
        if count == 0
            || usize::from(count) > MAX_PAYLOAD.div_ceil(CHUNK)
            || index >= count
            || chunk.len() > CHUNK
        {
            return;
        }
        if !self.assemblies.contains_key(&id) && self.assemblies.len() >= 8 {
            return;
        }
        let assembly = self.assemblies.entry(id).or_insert_with(|| Assembly {
            created: Instant::now(),
            count,
            chunks: vec![None; count.into()],
        });
        if assembly.count != count {
            return;
        }
        assembly.chunks[usize::from(index)] = Some(Bytes::copy_from_slice(chunk));
        if assembly.chunks.iter().all(Option::is_some)
            && let Some(assembly) = self.assemblies.remove(&id)
        {
            let mut packet = Vec::new();
            for chunk in assembly.chunks.into_iter().flatten() {
                packet.extend_from_slice(&chunk);
            }
            if packet.len() <= MAX_PAYLOAD {
                let _ = self.inbox.try_send(Bytes::from(packet));
            }
        }
    }
}
