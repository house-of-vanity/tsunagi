//! A DNS-only endpoint on the application side of one Android TUN descriptor.
//! The kernel reserves port 53. smoltcp terminates UDP and TCP without root.
use super::Resolver;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{self, Device, DeviceCapabilities, Medium},
    socket::{tcp, udp},
    time::Instant as NetTime,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::VecDeque,
    fs::File,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};
use tsunagi::dns::server::{MAX_MESSAGE_LEN, truncate_for_udp};

const PORT: u16 = 53;
const QUEUE: usize = 32;
const TCP_CLIENTS: usize = 8;

#[cfg(test)]
mod tests;

pub(crate) struct DnsPort {
    address: Ipv4Addr,
    input: mpsc::Sender<Vec<u8>>,
    worker: JoinHandle<()>,
}

impl DnsPort {
    pub(crate) fn start(
        address: Ipv4Addr,
        mtu: usize,
        resolver: Resolver,
        fd: Arc<AsyncFd<File>>,
    ) -> Self {
        let (input, packets) = mpsc::channel(QUEUE);
        let worker = tokio::spawn(run(address, mtu, resolver, packets, fd));
        Self {
            address,
            input,
            worker,
        }
    }

    /// Consume only packets sent to our private endpoint by a local VPN address.
    pub(crate) fn intercept(&self, bytes: &[u8], local: &[IpAddr]) -> bool {
        let Ok(packet) = smoltcp::wire::Ipv4Packet::new_checked(bytes) else {
            return false;
        };
        if packet.version() != 4 || packet.dst_addr() != self.address {
            return false;
        }
        if local.contains(&IpAddr::V4(packet.src_addr())) {
            let _ = self.input.try_send(bytes.to_vec());
        }
        true
    }
}

impl Drop for DnsPort {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

struct Wire {
    mtu: usize,
    input: Option<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}
struct Rx(Vec<u8>);
impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}
impl Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: NetTime) -> Option<(Rx, Tx<'_>)> {
        self.input
            .take()
            .map(|packet| (Rx(packet), Tx(&mut self.output)))
    }
    fn transmit(&mut self, _: NetTime) -> Option<Tx<'_>> {
        (self.output.len() < QUEUE).then_some(Tx(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct TcpSlot {
    handle: SocketHandle,
    pending: Option<u64>,
}
enum Client {
    Udp(IpEndpoint),
    Tcp { slot: usize, request: u64 },
}
type Jobs = JoinSet<(Client, Option<Vec<u8>>)>;

struct Stack {
    iface: Interface,
    wire: Wire,
    sockets: SocketSet<'static>,
    udp: SocketHandle,
    tcp: Vec<TcpSlot>,
    next_request: u64,
}

impl Stack {
    fn new(address: Ipv4Addr, mtu: usize) -> Self {
        let mut wire = Wire {
            mtu,
            input: None,
            output: VecDeque::new(),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut wire, NetTime::from_millis(0));
        // This is a point-to-point IP device. Its only neighbour is Android, whatever
        // the OS chose as the source address among the attached networks.
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(address), 0));
        });
        let mut sockets = SocketSet::new(Vec::new());
        let datagrams = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; QUEUE],
                vec![0; QUEUE * mtu],
            )
        };
        let mut socket = udp::Socket::new(datagrams(), datagrams());
        let _ = socket.bind(PORT);
        let udp = sockets.add(socket);
        let tcp = (0..TCP_CLIENTS)
            .map(|_| {
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; MAX_MESSAGE_LEN + 2]),
                    tcp::SocketBuffer::new(vec![0; usize::from(u16::MAX) + 2]),
                );
                socket.set_timeout(Some(smoltcp::time::Duration::from_secs(10)));
                let _ = socket.listen(PORT);
                TcpSlot {
                    handle: sockets.add(socket),
                    pending: None,
                }
            })
            .collect();
        Self {
            iface,
            wire,
            sockets,
            udp,
            tcp,
            next_request: 0,
        }
    }

    fn poll(&mut self, now: NetTime) {
        self.iface.poll(now, &mut self.wire, &mut self.sockets);
    }

    fn dispatch(&mut self, resolver: &Resolver, jobs: &mut Jobs) {
        let udp = self.sockets.get_mut::<udp::Socket>(self.udp);
        while let Ok((wire, metadata)) = udp.recv() {
            if jobs.len() >= QUEUE || wire.len() > MAX_MESSAGE_LEN {
                continue;
            }
            let resolver = resolver.clone();
            let query = wire.to_vec();
            let limit = self.wire.mtu.saturating_sub(28);
            jobs.spawn(async move {
                let reply = resolver
                    .answer(&query)
                    .await
                    .map(|reply| truncate_for_udp(&query, reply, limit));
                (Client::Udp(metadata.endpoint), reply)
            });
        }
        for (index, slot) in self.tcp.iter_mut().enumerate() {
            let tcp = self.sockets.get_mut::<tcp::Socket>(slot.handle);
            if !tcp.is_open() {
                slot.pending = None;
                let _ = tcp.listen(PORT);
            }
            if slot.pending.is_some() || tcp.send_queue() != 0 {
                continue;
            }
            if tcp.state() == tcp::State::CloseWait && tcp.recv_queue() < 2 {
                tcp.close();
                continue;
            }
            let mut header = [0; 2];
            if tcp.peek_slice(&mut header) != Ok(2) {
                continue;
            }
            let len = usize::from(u16::from_be_bytes(header));
            if !(12..=MAX_MESSAGE_LEN).contains(&len) {
                tcp.abort();
                continue;
            }
            if tcp.recv_queue() < len + 2 || jobs.len() >= QUEUE {
                continue;
            }
            let mut query = vec![0; len];
            if tcp.recv_slice(&mut header) != Ok(2) || tcp.recv_slice(&mut query) != Ok(len) {
                tcp.abort();
                continue;
            }
            self.next_request = self.next_request.wrapping_add(1);
            let request = self.next_request;
            slot.pending = Some(request);
            let resolver = resolver.clone();
            jobs.spawn(async move {
                (
                    Client::Tcp {
                        slot: index,
                        request,
                    },
                    resolver.answer(&query).await,
                )
            });
        }
    }

    fn deliver(&mut self, client: Client, reply: Option<Vec<u8>>) {
        match client {
            Client::Udp(peer) => {
                if let Some(reply) = reply {
                    let _ = self
                        .sockets
                        .get_mut::<udp::Socket>(self.udp)
                        .send_slice(&reply, peer);
                }
            }
            Client::Tcp { slot, request } => {
                let slot = &mut self.tcp[slot];
                if slot.pending != Some(request) {
                    return;
                }
                slot.pending = None;
                let tcp = self.sockets.get_mut::<tcp::Socket>(slot.handle);
                if let Some(reply) = reply
                    && let Ok(len) = u16::try_from(reply.len())
                    && tcp.send_slice(&len.to_be_bytes()) == Ok(2)
                    && tcp.send_slice(&reply) == Ok(reply.len())
                {
                    return;
                }
                tcp.abort();
            }
        }
    }
}

async fn run(
    address: Ipv4Addr,
    mtu: usize,
    resolver: Resolver,
    mut input: mpsc::Receiver<Vec<u8>>,
    fd: Arc<AsyncFd<File>>,
) {
    let mut stack = Stack::new(address, mtu);
    let mut jobs = Jobs::new();
    let start = Instant::now();
    loop {
        let now = NetTime::from_millis(start.elapsed().as_millis() as i64);
        stack.poll(now);
        stack.dispatch(&resolver, &mut jobs);
        stack.poll(now);
        while let Some(packet) = stack.wire.output.pop_front() {
            if !matches!(fd.async_io(Interest::WRITABLE, |mut file| file.write(&packet)).await, Ok(n) if n == packet.len())
            {
                return;
            }
        }
        let delay = stack
            .iface
            .poll_delay(now, &stack.sockets)
            .map(Duration::from);
        tokio::select! {
            packet = input.recv() => match packet { Some(packet) => stack.wire.input = Some(packet), None => return },
            Some(Ok((client, reply))) = jobs.join_next(), if !jobs.is_empty() => stack.deliver(client, reply),
            _ = async { if let Some(delay) = delay { tokio::time::sleep(delay).await } else { std::future::pending().await } } => {}
        }
    }
}
