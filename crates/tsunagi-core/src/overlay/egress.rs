//! A Windows exit offer terminates its forwarded connections on physical
//! sockets. This keeps them out of the destination-only routes used by local
//! applications. The stack and its sockets live for the offer, independently
//! of this device's upstream selection.
use super::router::Route;
use crate::identity::NetworkId;
use crate::vip::{
    Protocol,
    packet::{self, Tuple},
};
use bytes::Bytes;
use smoltcp::wire::{IpAddress, TcpPacket, UdpPacket};
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpSocket, UdpSocket},
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
};

mod tcp;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

use crate::config::{EXIT_FORWARD_FLOWS, EXIT_FORWARD_FRAGMENTS, EXIT_FORWARD_QUEUE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Physical {
    pub index: u32,
    pub address: Ipv4Addr,
}

impl Physical {
    async fn tcp(self, remote: SocketAddr) -> io::Result<tokio::net::TcpStream> {
        let socket = TcpSocket::new_v4()?;
        #[cfg(windows)]
        windows::pin(&socket, self.index)?;
        socket.bind((self.address, 0).into())?;
        socket.connect(remote).await
    }

    fn datagram(self, protocol: socket2::Protocol) -> io::Result<UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};
        let ty = if protocol == Protocol::UDP {
            Type::DGRAM
        } else {
            Type::RAW
        };
        let socket = Socket::new(Domain::IPV4, ty, Some(protocol))?;
        #[cfg(windows)]
        windows::pin(&socket, self.index)?;
        socket.bind(&SocketAddr::V4(SocketAddrV4::new(self.address, 0)).into())?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    }
}

type Reply = Arc<dyn Fn(Route, Bytes) + Send + Sync>;
type Offers = Vec<(NetworkId, Physical)>;

pub(super) struct Gateway {
    input: mpsc::Sender<(Route, Bytes)>,
    offers: watch::Sender<Offers>,
    worker: JoinHandle<()>,
}

impl Gateway {
    pub fn new(mtu: u32, reply: impl Fn(Route, Bytes) + Send + Sync + 'static) -> Self {
        let (input, packets) = mpsc::channel(EXIT_FORWARD_QUEUE);
        let (offers, serving) = watch::channel(Vec::new());
        let worker = tokio::spawn(run(mtu, Arc::new(reply), packets, serving));
        Self {
            input,
            offers,
            worker,
        }
    }

    pub fn configure(&self, mut offers: Offers) {
        offers.sort_by_key(|(network, _)| *network);
        self.offers.send_if_modified(|old| {
            if *old == offers {
                return false;
            }
            *old = offers;
            true
        });
    }

    pub fn forward(&self, origin: Route, packet: Bytes) -> bool {
        self.offers
            .borrow()
            .iter()
            .any(|(network, _)| *network == origin.network)
            && self.input.try_send((origin, packet)).is_ok()
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

type FlowKey = (NetworkId, iroh::EndpointId, Tuple);
struct Flow {
    tx: mpsc::Sender<Bytes>,
    task: tokio::task::AbortHandle,
}

async fn run(
    mtu: u32,
    reply: Reply,
    mut incoming: mpsc::Receiver<(Route, Bytes)>,
    mut serving: watch::Receiver<Offers>,
) {
    let mut flows: HashMap<FlowKey, Flow> = HashMap::new();
    let mut jobs = JoinSet::new();
    let mut fragments = packet::Reassembly::default();
    loop {
        let (origin, part) = tokio::select! {
            biased;
            changed = serving.changed() => {
                if changed.is_err() { return; }
                let offers = serving.borrow_and_update();
                flows.retain(|(network, _, _), flow| {
                    let keep = offers.iter().any(|(net, _)| net == network);
                    if !keep { flow.task.abort(); }
                    keep
                });
                // Incomplete datagrams from a withdrawn offer must not survive a rejoin.
                fragments = packet::Reassembly::default();
                continue;
            }
            Some(result) = jobs.join_next_with_id(), if !jobs.is_empty() => {
                if let Ok((id, Some(key))) = result
                    && flows.get(&key).is_some_and(|flow| flow.task.id() == id) {
                    flows.remove(&key);
                }
                continue;
            }
            input = incoming.recv() => match input { Some(input) => input, None => return },
        };
        let Some(physical) = serving
            .borrow()
            .iter()
            .find(|(net, _)| *net == origin.network)
            .map(|(_, p)| *p)
        else {
            continue;
        };
        let Some(packet) =
            fragments.accept(part, EXIT_FORWARD_FRAGMENTS, Some(*origin.peer.as_bytes()))
        else {
            continue;
        };
        let Some(n) = packet::header(&packet) else {
            continue;
        };
        if packet[8] <= 1 {
            continue;
        }
        if packet[9] == 1 {
            if jobs.len() < EXIT_FORWARD_FLOWS
                && packet.get(n) == Some(&8)
                && packet.len() >= n + 8
                && packet[n + 1] == 0
                && packet::checksum(&packet[n..]) == 0
            {
                let reply = reply.clone();
                let mut offers = serving.clone();
                jobs.spawn(async move {
                            tokio::select! {
                                _ = offers.wait_for(|nets| !nets.iter().any(|(net, _)| *net == origin.network)) => {},
                                _ = echo(physical, origin, packet, n, &reply, mtu) => {}
                            }
                            None
                        });
            }
            continue;
        }
        let Some(tuple) = packet::tuple(&packet) else {
            continue;
        };
        let src = IpAddress::Ipv4(tuple.src);
        let dst = IpAddress::Ipv4(tuple.dst);
        let valid =
            match tuple.protocol {
                Protocol::Tcp => TcpPacket::new_checked(&packet[n..])
                    .is_ok_and(|p| p.verify_checksum(&src, &dst)),
                Protocol::Udp => UdpPacket::new_checked(&packet[n..])
                    .is_ok_and(|p| p.verify_checksum(&src, &dst)),
            };
        if !valid {
            continue;
        }
        let key = (origin.network, origin.peer, tuple);
        if let Some(flow) = flows.get(&key) {
            let _ = flow.tx.try_send(packet);
            continue;
        }
        if jobs.len() >= EXIT_FORWARD_FLOWS
            || (tuple.protocol == Protocol::Tcp && !packet::tcp_syn(&packet))
        {
            continue;
        }
        let (tx, rx) = mpsc::channel(EXIT_FORWARD_QUEUE.min(16));
        let reply = reply.clone();
        let task = jobs.spawn(async move {
            match tuple.protocol {
                Protocol::Tcp => tcp::serve(physical, origin, tuple, packet, rx, reply, mtu).await,
                Protocol::Udp => {
                    let _ = udp(physical, origin, tuple, packet, rx, reply, mtu).await;
                }
            }
            Some(key)
        });
        flows.insert(key, Flow { tx, task });
    }
}

fn remote(t: Tuple) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(t.dst, t.dport))
}

fn respond(reply: &Reply, origin: Route, packet: Bytes, mtu: u32) {
    for part in packet::fragments(packet, mtu) {
        reply(origin, part);
    }
}

async fn udp(
    physical: Physical,
    origin: Route,
    tuple: Tuple,
    first: Bytes,
    mut incoming: mpsc::Receiver<Bytes>,
    reply: Reply,
    mtu: u32,
) -> io::Result<()> {
    let socket = physical.datagram(socket2::Protocol::UDP)?;
    socket.connect(remote(tuple)).await?;
    let socket = &socket;
    let send = |p: Bytes| async move {
        if let Some(n) = packet::header(&p) {
            socket.send(&p[n + 8..]).await?;
        }
        Ok::<_, io::Error>(())
    };
    send(first).await?;
    let mut buf = vec![0; 65_507];
    loop {
        tokio::select! {
            packet = incoming.recv() => match packet { Some(p) => send(p).await?, None => return Ok(()) },
            result = socket.recv(&mut buf) => {
                let len = result?;
                if let Some(p) = udp_packet(tuple.reverse(), &buf[..len]) { respond(&reply, origin, p, mtu); }
            },
            _ = tokio::time::sleep(Duration::from_secs(120)) => return Ok(()),
        }
    }
}

fn ip_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    proto: u8,
    payload_len: usize,
) -> Option<Vec<u8>> {
    let len = u16::try_from(20usize.checked_add(payload_len)?).ok()?;
    let mut bytes = vec![0; usize::from(len)];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&len.to_be_bytes());
    bytes[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
    bytes[8] = 64;
    bytes[9] = proto;
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    let checksum = packet::checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    Some(bytes)
}

fn udp_packet(tuple: Tuple, body: &[u8]) -> Option<Bytes> {
    let mut bytes = ip_packet(tuple.src, tuple.dst, 17, body.len().checked_add(8)?)?;
    let mut p = UdpPacket::new_unchecked(&mut bytes[20..]);
    p.set_src_port(tuple.sport);
    p.set_dst_port(tuple.dport);
    p.set_len((body.len() + 8) as u16);
    p.payload_mut().copy_from_slice(body);
    p.fill_checksum(&tuple.src.into(), &tuple.dst.into());
    Some(bytes.into())
}

async fn echo(
    physical: Physical,
    origin: Route,
    packet: Bytes,
    n: usize,
    reply: &Reply,
    mtu: u32,
) -> io::Result<()> {
    let Some((source, destination)) = packet::addresses(&packet) else {
        return Ok(());
    };
    let socket = physical.datagram(socket2::Protocol::ICMPV4)?;
    socket.set_ttl(u32::from(packet[8] - 1))?;
    socket.connect((destination, 0)).await?;
    // Raw ICMP sockets can observe other echo replies. An independent nonce and
    // the original data correlate a reply with this one authenticated request.
    let nonce = rand::random::<u32>().to_be_bytes();
    let mut request = packet[n..].to_vec();
    request[4..8].copy_from_slice(&nonce);
    request[2..4].fill(0);
    let checksum = packet::checksum(&request);
    request[2..4].copy_from_slice(&checksum.to_be_bytes());
    socket.send(&request).await?;
    // Winsock delivers unrelated replies to other raw ICMP sockets too. A longer
    // reply must not trigger WSAEMSGSIZE and abort this request.
    let mut buf = vec![0; usize::from(u16::MAX)];
    let until = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let len = tokio::time::timeout_at(until, socket.recv(&mut buf)).await??;
        let Some(h) = packet::header(&buf[..len]) else {
            continue;
        };
        let body = &buf[h..len];
        if buf[9] != 1
            || body.len() != request.len()
            || body[0..2] != [0, 0]
            || body[4..] != request[4..]
            || packet::checksum(body) != 0
        {
            continue;
        }
        if let Some(mut out) = ip_packet(destination, source, 1, body.len()) {
            out[20..].copy_from_slice(body);
            out[24..28].copy_from_slice(&packet[n + 4..n + 8]);
            out[22..24].fill(0);
            let checksum = packet::checksum(&out[20..]);
            out[22..24].copy_from_slice(&checksum.to_be_bytes());
            respond(reply, origin, out.into(), mtu);
        }
        return Ok(());
    }
}
