//! smoltcp owns the member-facing half of one stream. The OS owns the
//! physical TCP connection. Both directions apply backpressure independently.
use super::*;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{self, Device, DeviceCapabilities, Medium},
    socket::tcp::{Socket, SocketBuffer, State},
    time::Instant as NetTime,
    wire::{HardwareAddress, IpCidr},
};
use std::collections::VecDeque;
use tokio::io::AsyncWriteExt;

struct Wire {
    mtu: usize,
    input: Option<Bytes>,
    output: VecDeque<Bytes>,
}

struct Rx(Bytes);
impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct Tx<'a>(&'a mut VecDeque<Bytes>);
impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        self.0.push_back(bytes.into());
        result
    }
}

impl Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: NetTime) -> Option<(Rx, Tx<'_>)> {
        self.input.take().map(|p| (Rx(p), Tx(&mut self.output)))
    }
    fn transmit(&mut self, _: NetTime) -> Option<Tx<'_>> {
        (self.output.len() < EXIT_FORWARD_QUEUE).then_some(Tx(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub(super) async fn serve(
    physical: Physical,
    origin: Route,
    flow: Tuple,
    syn: Bytes,
    mut incoming: mpsc::Receiver<Bytes>,
    reply: Reply,
    mtu: u32,
) {
    let Ok(Ok(mut upstream)) =
        tokio::time::timeout(Duration::from_secs(8), physical.tcp(remote(flow))).await
    else {
        if let Some(reset) = packet::reject(&syn) {
            reply(origin, reset);
        }
        return;
    };
    let mut wire = Wire {
        mtu: mtu as usize,
        input: Some(syn),
        output: VecDeque::new(),
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut iface = Interface::new(config, &mut wire, NetTime::ZERO);
    iface.update_ip_addrs(|ips| {
        let _ = ips.push(IpCidr::new(flow.dst.into(), 0));
    });
    let mut sockets = SocketSet::new(Vec::new());
    let buffer = || SocketBuffer::new(vec![0; 64 * 1024]);
    let mut tcp = Socket::new(buffer(), buffer());
    tcp.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
    if tcp.listen((flow.dst, flow.dport)).is_err() {
        return;
    }
    let handle = sockets.add(tcp);
    let start = std::time::Instant::now();
    let mut remote_fin = false;
    let mut local_fin = false;
    loop {
        let now = NetTime::from_millis(start.elapsed().as_millis() as i64);
        iface.poll(now, &mut wire, &mut sockets);
        let tcp = sockets.get_mut::<Socket>(handle);
        if tcp.can_recv() {
            let write = tcp.recv(|buf| match upstream.try_write(buf) {
                Ok(n) => (n, Ok(n > 0)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, Ok(false)),
                Err(e) => (0, Err(e)),
            });
            if matches!(write, Ok(Err(_))) {
                tcp.abort();
            }
        }
        if !local_fin
            && !tcp.may_recv()
            && matches!(
                tcp.state(),
                State::CloseWait | State::Closing | State::LastAck | State::TimeWait
            )
        {
            let _ = upstream.shutdown().await;
            local_fin = true;
        }
        if tcp.can_send() && !remote_fin {
            match tcp.send(|buf| match upstream.try_read(buf) {
                Ok(n) => (n, Ok(Some(n))),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, Ok(None)),
                Err(e) => (0, Err(e)),
            }) {
                Ok(Ok(Some(0))) => {
                    remote_fin = true;
                    tcp.close();
                }
                Ok(Err(_)) => tcp.abort(),
                _ => {}
            }
        }
        iface.poll(now, &mut wire, &mut sockets);
        for p in wire.output.drain(..) {
            reply(origin, p);
        }
        let tcp = sockets.get::<Socket>(handle);
        // A reset during the handshake returns smoltcp to Listen. This
        // worker owns exactly one physical connection and must never accept
        // a second SYN on that connection or retain an idle flow slot.
        if matches!(tcp.state(), State::Listen | State::Closed) {
            return;
        }
        let delay = iface
            .poll_delay(now, &sockets)
            .map(Duration::from)
            .unwrap_or(Duration::from_secs(3600));
        tokio::select! {
            packet = incoming.recv() => match packet { Some(p) => wire.input = Some(p), None => return },
            ready = upstream.readable(), if !remote_fin && tcp.can_send() => { if ready.is_err() { return; } }
            ready = upstream.writable(), if tcp.can_recv() => { if ready.is_err() { return; } }
            _ = tokio::time::sleep(delay) => {}
        }
    }
}
