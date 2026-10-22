//! A real userspace TCP stack attached to each memory TUN, without host routes.
use bytes::Bytes;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as TcpInstant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tsunagi::overlay::MemoryTun;

struct TunDevice {
    input: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tun: Arc<MemoryTun>,
}
struct Rx(Vec<u8>);
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
struct Tx(Arc<MemoryTun>);
impl TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_from_os(Bytes::from(packet));
        result
    }
}
impl Device for TunDevice {
    type RxToken<'a>
        = Rx
    where
        Self: 'a;
    type TxToken<'a>
        = Tx
    where
        Self: 'a;
    fn receive(&mut self, _: TcpInstant) -> Option<(Rx, Tx)> {
        self.input
            .lock()
            .unwrap()
            .pop_front()
            .map(|packet| (Rx(packet), Tx(self.tun.clone())))
    }
    fn transmit(&mut self, _: TcpInstant) -> Option<Tx> {
        Some(Tx(self.tun.clone()))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        caps
    }
}
struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    socket: SocketHandle,
    device: TunDevice,
    reader: tokio::task::JoinHandle<()>,
}
impl Stack {
    fn new(tun: Arc<MemoryTun>, address: Ipv4Addr) -> Self {
        let input = Arc::new(Mutex::new(VecDeque::new()));
        let queue = input.clone();
        let received = tun.clone();
        let reader = tokio::spawn(async move {
            while let Some(packet) = received.pop_to_os().await {
                let mut queue = queue.lock().unwrap();
                assert!(queue.len() < 256);
                queue.push_back(packet.to_vec());
            }
        });
        let mut device = TunDevice { input, tun };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, TcpInstant::from_millis(0));
        let [a, b, c, d] = address.octets();
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::v4(a, b, c, d), 24))
                .unwrap()
        });
        let mut sockets = SocketSet::new(Vec::new());
        let socket = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 65536]),
            tcp::SocketBuffer::new(vec![0; 65536]),
        ));
        Self {
            iface,
            sockets,
            socket,
            device,
            reader,
        }
    }
    fn tcp(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(self.socket)
    }
    fn poll(&mut self, now: TcpInstant) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }
}
impl Drop for Stack {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

pub(super) struct TcpPair {
    client: Stack,
    server: Stack,
    started: Instant,
}
impl TcpPair {
    pub(super) async fn connect(
        a: Arc<MemoryTun>,
        a_ip: Ipv4Addr,
        b: Arc<MemoryTun>,
        b_ip: Ipv4Addr,
    ) -> Self {
        let mut pair = Self {
            client: Stack::new(a, a_ip),
            server: Stack::new(b, b_ip),
            started: Instant::now(),
        };
        pair.server.tcp().listen(22).unwrap();
        let [a, b, c, d] = b_ip.octets();
        pair.client
            .sockets
            .get_mut::<tcp::Socket>(pair.client.socket)
            .connect(
                pair.client.iface.context(),
                (IpAddress::v4(a, b, c, d), 22),
                40000,
            )
            .unwrap();
        pair.until(|p| {
            p.client.tcp().state() == tcp::State::Established
                && p.server.tcp().state() == tcp::State::Established
        })
        .await;
        pair
    }
    fn poll(&mut self) {
        let now = TcpInstant::from_millis(self.started.elapsed().as_millis() as i64);
        self.client.poll(now);
        self.server.poll(now);
    }
    async fn until(&mut self, mut ready: impl FnMut(&mut Self) -> bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut ticks = tokio::time::interval(Duration::from_millis(2));
            loop {
                ticks.tick().await;
                self.poll();
                if ready(self) {
                    break;
                }
            }
        })
        .await
        .expect("same TCP connection must progress across carrier/route changes");
    }
    pub(super) fn queue_while_unreachable(&mut self, payload: &[u8]) {
        assert_eq!(
            self.client.tcp().send_slice(payload).unwrap(),
            payload.len()
        );
        self.poll();
    }
    pub(super) async fn receive_queued(&mut self, payload: &[u8]) {
        let mut received = Vec::new();
        self.until(|p| {
            if p.server.tcp().can_recv() {
                p.server
                    .tcp()
                    .recv(|bytes| {
                        received.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            received.len() >= payload.len()
        })
        .await;
        assert_eq!(received, payload);
        assert_eq!(self.client.tcp().state(), tcp::State::Established);
        assert_eq!(self.server.tcp().state(), tcp::State::Established);
    }
    pub(super) async fn exchange(&mut self, payload: &[u8]) {
        self.queue_while_unreachable(payload);
        self.receive_queued(payload).await;
        assert_eq!(
            self.server.tcp().send_slice(payload).unwrap(),
            payload.len()
        );
        let mut received = Vec::new();
        self.until(|p| {
            if p.client.tcp().can_recv() {
                p.client
                    .tcp()
                    .recv(|bytes| {
                        received.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            received.len() >= payload.len()
        })
        .await;
        assert_eq!(received, payload);
    }
}
