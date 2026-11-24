#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use simple_dns::{CLASS, Name, Packet, PacketFlag, Question, TYPE};
use std::os::{fd::OwnedFd, unix::net::UnixDatagram};
use tsunagi::dns::{Zone, ZoneName, Zones};

#[tokio::test]
async fn android_tun_dns_truncates_udp_and_returns_the_complete_answer_over_tcp() {
    let address = Ipv4Addr::new(192, 0, 2, 53);
    let phone = Ipv4Addr::new(10, 10, 0, 1);
    let (fd, os) = UnixDatagram::pair().unwrap();
    fd.set_nonblocking(true).unwrap();
    os.set_nonblocking(true).unwrap();
    let fd = AsyncFd::new(File::from(OwnedFd::from(fd))).unwrap();
    let os = tokio::net::UnixDatagram::from_std(os).unwrap();
    let resolver = Resolver::new(|_| panic!("a mesh name went upstream"));
    resolver.replace(Some(Zones::new([Zone::new(
        ZoneName::new("tsng").unwrap(),
        (1..=90).map(|host| ("api".into(), Ipv4Addr::new(10, 1, 2, host))),
    )])));
    let port = DnsPort::start(address, 1280, resolver, Arc::new(fd));
    let mut wire = Wire {
        mtu: 1280,
        input: None,
        output: VecDeque::new(),
    };
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut wire,
        NetTime::from_millis(0),
    );
    iface.update_ip_addrs(|a| a.push(IpCidr::new(IpAddress::Ipv4(phone), 0)).unwrap());
    let mut sockets = SocketSet::new(Vec::new());
    let buf = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
    let mut datagram = udp::Socket::new(buf(), buf());
    datagram.bind(41000).unwrap();
    let mut packet = Packet::new_query(42);
    packet.questions.push(Question::new(
        Name::new("api.tsng").unwrap(),
        TYPE::A.into(),
        CLASS::IN.into(),
        false,
    ));
    let query = packet.build_bytes_vec().unwrap();
    datagram.send_slice(&query, (address, PORT)).unwrap();
    let udp = sockets.add(datagram);
    let tcp = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 8192]),
        tcp::SocketBuffer::new(vec![0; 512]),
    ));
    let mut sent = false;
    let mut received = Vec::new();
    let mut buf = [0; 1500];
    let start = Instant::now();
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let now = NetTime::from_millis(start.elapsed().as_millis() as i64);
            iface.poll(now, &mut wire, &mut sockets);
            if let Ok((reply, from)) = sockets.get_mut::<udp::Socket>(udp).recv() {
                assert_eq!(from.endpoint, (address, PORT).into());
                let reply = Packet::parse(reply).unwrap();
                assert_eq!(reply.id(), 42);
                assert!(reply.has_flags(PacketFlag::TRUNCATION | PacketFlag::AUTHORITATIVE_ANSWER));
                sockets
                    .get_mut::<tcp::Socket>(tcp)
                    .connect(iface.context(), (address, PORT), 41001)
                    .unwrap();
            }
            let stream = sockets.get_mut::<tcp::Socket>(tcp);
            if stream.can_send() && !sent {
                let mut frame = (query.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&query);
                assert_eq!(stream.send_slice(&frame).unwrap(), frame.len());
                sent = true;
            }
            while stream.can_recv() {
                let n = stream.recv_slice(&mut buf).unwrap();
                received.extend_from_slice(&buf[..n]);
            }
            if let Some(prefix) = received.first_chunk::<2>()
                && received.len() == 2 + usize::from(u16::from_be_bytes(*prefix))
            {
                break;
            }
            iface.poll(now, &mut wire, &mut sockets);
            for outgoing in wire.output.drain(..) {
                assert!(port.intercept(&outgoing, &[phone.into()]));
            }
            let delay = iface
                .poll_delay(now, &sockets)
                .map(Duration::from)
                .unwrap_or(Duration::from_secs(4));
            tokio::select! {
                n = os.recv(&mut buf) => wire.input = Some(buf[..n.unwrap()].to_vec()),
                _ = tokio::time::sleep(delay) => {}
            }
        }
    })
    .await
    .expect("DNS over the Android packet device must complete");
    let reply = Packet::parse(&received[2..]).unwrap();
    assert_eq!(reply.id(), 42);
    assert!(!reply.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(reply.answers.len(), 90);
}
