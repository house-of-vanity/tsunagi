//! These run on loopback on every host. The gateway uses the same code as
//! Windows, with a loopback source in place of the pinned physical adapter.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use tokio::net::{TcpListener, UdpSocket};

fn route() -> Route {
    Route {
        network: NetworkId::from_bytes([4; 32]),
        peer: iroh::SecretKey::from_bytes(&[3; 32]).public(),
    }
}

fn addr() -> Ipv4Addr {
    Ipv4Addr::new(10, 13, 37, 9)
}

#[tokio::test]
async fn a_udp_flow_keeps_its_external_port_while_the_upstream_changes_and_stops_with_its_offer() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let route = route();
    let (replies, mut rx) = mpsc::channel(8);
    let gateway = Gateway::new(1280, move |r, p| {
        assert_eq!(r, route);
        let _ = replies.try_send(p);
    });
    let physical = Physical {
        index: 0,
        address: Ipv4Addr::LOCALHOST,
    };
    gateway.configure(vec![(route.network, physical)]);
    let flow = Tuple {
        src: addr(),
        dst: Ipv4Addr::LOCALHOST,
        sport: 10403,
        dport: server.local_addr().unwrap().port(),
        protocol: Protocol::Udp,
    };
    let mut port = None;
    for body in [b"first".as_slice(), b"after upstream change"] {
        gateway.configure(vec![(route.network, physical)]);
        assert!(gateway.forward(route, udp_packet(flow, body).unwrap()));
        let mut buf = [0; 128];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], body);
        assert_eq!(port.get_or_insert(from.port()), &from.port());
        server.send_to(body, from).await.unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(crate::vip::packet::tuple(&answer), Some(flow.reverse()));
        assert_eq!(&answer[28..], body);
    }
    gateway.configure(Vec::new());
    assert!(!gateway.forward(route, udp_packet(flow, b"withdrawn").unwrap()));
}

#[tokio::test]
async fn refused_tcp_returns_a_reset_to_the_originating_client() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let (tx, mut rx) = mpsc::channel(2);
    let route = route();
    let gateway = Gateway::new(1280, move |r, p| {
        assert_eq!(r, route);
        let _ = tx.try_send(p);
    });
    gateway.configure(vec![(
        route.network,
        Physical {
            index: 0,
            address: Ipv4Addr::LOCALHOST,
        },
    )]);
    let flow = Tuple {
        src: addr(),
        dst: Ipv4Addr::LOCALHOST,
        sport: 42000,
        dport: port,
        protocol: Protocol::Tcp,
    };
    let mut syn = vec![0; 40];
    syn[0] = 0x45;
    syn[2..4].copy_from_slice(&40u16.to_be_bytes());
    syn[8] = 64;
    syn[9] = 6;
    syn[32] = 0x50;
    syn[33] = 2;
    let checksum = crate::vip::packet::checksum(&syn[..20]);
    syn[10..12].copy_from_slice(&checksum.to_be_bytes());
    assert!(gateway.forward(route, crate::vip::packet::rewrite(&syn, flow).unwrap()));
    let answer = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(crate::vip::packet::tcp_reset(&answer));
    assert_eq!(crate::vip::packet::tuple(&answer), Some(flow.reverse()));
}

fn tcp_packet(tuple: Tuple, flags: u8, seq: u32, ack: u32, body: &[u8]) -> Bytes {
    let mut bytes = ip_packet(tuple.src, tuple.dst, 6, 20 + body.len()).unwrap();
    bytes[24..28].copy_from_slice(&seq.to_be_bytes());
    bytes[28..32].copy_from_slice(&ack.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = flags;
    bytes[34..36].copy_from_slice(&65535u16.to_be_bytes());
    bytes[40..].copy_from_slice(body);
    packet::rewrite(&bytes, tuple).unwrap()
}

#[tokio::test]
async fn a_tcp_stream_to_the_same_destination_survives_offer_reconciliation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        for expected in [b"one", b"two"] {
            let mut body = [0; 3];
            socket.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, expected);
            socket.write_all(&body).await.unwrap();
        }
    });
    tokio::time::timeout(Duration::from_secs(4), async {
        let route = route();
        let (tx, mut rx) = mpsc::channel(16);
        let gateway = Gateway::new(1280, move |r, p| {
            assert_eq!(r, route);
            let _ = tx.try_send(p);
        });
        let physical = Physical {
            index: 0,
            address: Ipv4Addr::LOCALHOST,
        };
        gateway.configure(vec![(route.network, physical)]);
        let flow = Tuple {
            src: addr(),
            dst: Ipv4Addr::LOCALHOST,
            sport: 43210,
            dport: port,
            protocol: Protocol::Tcp,
        };
        let mut seq: u32 = 123;
        assert!(gateway.forward(route, tcp_packet(flow, 2, seq, 0, &[])));
        let synack = rx.recv().await.unwrap();
        assert!(packet::syn_ack(&synack));
        let mut ack = u32::from_be_bytes(synack[24..28].try_into().unwrap()).wrapping_add(1);
        seq += 1;
        for body in [b"one", b"two"] {
            assert!(gateway.forward(route, tcp_packet(flow, 0x18, seq, ack, body)));
            seq += body.len() as u32;
            loop {
                let p = rx.recv().await.unwrap();
                let tcp = TcpPacket::new_checked(&p[20..]).unwrap();
                if !tcp.payload().is_empty() {
                    assert_eq!(tcp.payload(), body);
                    ack = ack.wrapping_add(body.len() as u32);
                    assert!(gateway.forward(route, tcp_packet(flow, 0x10, seq, ack, &[])));
                    break;
                }
            }
            // A configuration change for a different membership cannot create a new B socket.
            gateway.configure(vec![
                (route.network, physical),
                (NetworkId::from_bytes([7; 32]), physical),
            ]);
        }
        server.await.unwrap();
    })
    .await
    .unwrap();
}

/// Two disposable Wintun adapters provide an offline "WAN" and an upstream.
/// A longer prefix on the latter captures local applications for the same IP.
#[cfg(all(windows, feature = "tun-device"))]
#[tokio::test]
#[ignore = "requires an elevated disposable Windows runner and wintun.dll"]
async fn physical_member_sockets_survive_a_more_specific_wintun_route() {
    use crate::overlay::{
        Cidr,
        provision::{InterfacePlan, InterfaceProvisioner, WintunProvisioner},
        tun::TunDevice,
    };
    let wan = Ipv4Addr::new(198, 18, 222, 1);
    let upstream = Ipv4Addr::new(198, 18, 222, 5);
    let site = Ipv4Addr::new(198, 18, 222, 6);
    for dev in netdev::get_interfaces() {
        assert!(
            dev.ipv4
                .iter()
                .all(|net| !net.contains(&wan) && !net.contains(&site)),
            "test subnet is in use on {}",
            dev.name
        );
    }
    async fn read(device: &dyn TunDevice, endpoint: SocketAddrV4, body: &[u8]) -> Tuple {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let p = device.recv().await.unwrap();
                if let Some(t) = packet::tuple(&p)
                    && t.dst == *endpoint.ip()
                    && t.dport == endpoint.port()
                    && p.get(28..) == Some(body)
                {
                    return t;
                }
            }
        })
        .await
        .unwrap()
    }
    async fn wait_source(site: SocketAddrV4, wanted: Ipv4Addr) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
                if s.connect(site).await.is_ok() && s.local_addr().unwrap().ip() == wanted {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }
    let id = rand::random::<u32>();
    let provision = WintunProvisioner::new().unwrap();
    let uplink = provision
        .reconcile(&InterfacePlan::new(
            format!("tsfw-a-{id:x}"),
            1280,
            vec![Cidr::new(wan.into(), 24).unwrap()],
        ))
        .await
        .unwrap()
        .device
        .unwrap();
    let site = SocketAddrV4::new(site, 38201);
    wait_source(site, wan).await;
    let index = netdev::get_interfaces()
        .into_iter()
        .find(|i| i.ipv4.iter().any(|a| a.addr() == wan))
        .unwrap()
        .index;
    let physical = Physical {
        index,
        address: wan,
    };
    let origin = route();
    let (tx, mut rx) = mpsc::channel(8);
    let gateway = Gateway::new(1280, move |_, packet| {
        let _ = tx.try_send(packet);
    });
    gateway.configure(vec![(origin.network, physical)]);
    let flow = Tuple {
        src: addr(),
        dst: *site.ip(),
        sport: 21002,
        dport: site.port(),
        protocol: Protocol::Udp,
    };
    let mut send = async |tuple, payload: &[u8]| {
        assert!(gateway.forward(origin, udp_packet(tuple, payload).unwrap()));
        let observed = read(&*uplink, site, payload).await;
        assert_eq!(observed.src, wan);
        uplink
            .send(udp_packet(observed.reverse(), payload).unwrap())
            .await
            .unwrap();
        let back = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet::tuple(&back), Some(tuple.reverse()));
        observed.sport
    };
    let initial = send(flow, b"before").await;
    let capture = provision
        .reconcile(&InterfacePlan::new(
            format!("tsfw-c-{id:x}"),
            1280,
            vec![Cidr::new(upstream.into(), 30).unwrap()],
        ))
        .await
        .unwrap()
        .device
        .unwrap();
    wait_source(site, upstream).await;
    let local = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    local.send_to(b"local B", site).await.unwrap();
    assert_eq!(read(&*capture, site, b"local B").await.src, upstream);
    assert_eq!(send(flow, b"same A socket").await, initial);
    send(
        Tuple {
            sport: 21003,
            ..flow
        },
        b"new A socket",
    )
    .await;

    // Raw ICMP uses the identical physical interface selection and restores A's
    // identifier and sequence after reading the actual reply from the uplink.
    let mut ping = ip_packet(addr(), *site.ip(), 1, 12).unwrap();
    ping[20] = 8;
    ping[24..32].copy_from_slice(b"pingdata");
    let checksum = packet::checksum(&ping[20..]);
    ping[22..24].copy_from_slice(&checksum.to_be_bytes());
    assert!(gateway.forward(origin, ping.into()));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let wire = uplink.recv().await.unwrap();
            let Some(n) = packet::header(&wire) else {
                continue;
            };
            if wire[9] != 1 || wire.get(n + 8..) != Some(b"data") {
                continue;
            }
            assert_eq!(packet::addresses(&wire), Some((wan, *site.ip())));
            let mut pong = ip_packet(*site.ip(), wan, 1, wire.len() - n).unwrap();
            pong[20..].copy_from_slice(&wire[n..]);
            pong[20..24].fill(0);
            let checksum = packet::checksum(&pong[20..]);
            pong[22..24].copy_from_slice(&checksum.to_be_bytes());
            uplink.send(pong.into()).await.unwrap();
            break;
        }
        let reply = rx.recv().await.unwrap();
        assert_eq!(packet::addresses(&reply), Some((*site.ip(), addr())));
        assert_eq!(&reply[24..], b"pingdata");
        assert_eq!(packet::checksum(&reply[20..]), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn resetting_a_half_open_mesh_handshake_closes_the_physical_socket() {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let route = route();
    let (tx, mut rx) = mpsc::channel(4);
    let gateway = Gateway::new(1280, move |_, packet| {
        let _ = tx.try_send(packet);
    });
    gateway.configure(vec![(
        route.network,
        Physical {
            index: 0,
            address: Ipv4Addr::LOCALHOST,
        },
    )]);
    let flow = Tuple {
        src: addr(),
        dst: Ipv4Addr::LOCALHOST,
        sport: 43211,
        dport: listener.local_addr().unwrap().port(),
        protocol: Protocol::Tcp,
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        assert!(gateway.forward(route, tcp_packet(flow, 2, 500, 0, &[])));
        let (mut physical, _) = listener.accept().await.unwrap();
        let synack = rx.recv().await.unwrap();
        assert!(packet::syn_ack(&synack));
        let ack = u32::from_be_bytes(synack[24..28].try_into().unwrap()).wrapping_add(1);
        assert!(gateway.forward(route, tcp_packet(flow, 0x14, 501, ack, &[])));
        assert_eq!(physical.read(&mut [0; 1]).await.unwrap(), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_server_half_close_still_receives_the_members_final_bytes_and_fin() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (out, mut rx) = mpsc::channel(8);
    let origin = route();
    let gateway = Gateway::new(1280, move |_, packet| {
        let _ = out.try_send(packet);
    });
    gateway.configure(vec![(
        origin.network,
        Physical {
            index: 0,
            address: Ipv4Addr::LOCALHOST,
        },
    )]);
    let flow = Tuple {
        src: addr(),
        dst: Ipv4Addr::LOCALHOST,
        sport: 42041,
        dport: listener.local_addr().unwrap().port(),
        protocol: Protocol::Tcp,
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        assert!(gateway.forward(origin, tcp_packet(flow, 2, 200, 0, &[])));
        let (mut server, _) = listener.accept().await.unwrap();
        server.shutdown().await.unwrap();
        let synack = rx.recv().await.unwrap();
        assert!(packet::syn_ack(&synack));
        let ack = u32::from_be_bytes(synack[24..28].try_into().unwrap()).wrapping_add(1);
        assert!(gateway.forward(origin, tcp_packet(flow, 0x10, 201, ack, &[])));
        loop {
            let p = rx.recv().await.unwrap();
            if TcpPacket::new_checked(&p[20..]).unwrap().fin() {
                break;
            }
        }
        assert!(gateway.forward(
            origin,
            tcp_packet(flow, 0x19, 201, ack.wrapping_add(1), b"last bytes")
        ));
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"last bytes");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn at_capacity_existing_udp_flows_continue_and_a_new_tuple_is_dropped() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin = route();
    let gateway = Gateway::new(1280, |_, _| {});
    gateway.configure(vec![(
        origin.network,
        Physical {
            index: 0,
            address: Ipv4Addr::LOCALHOST,
        },
    )]);
    let flow = Tuple {
        src: addr(),
        dst: Ipv4Addr::LOCALHOST,
        sport: 1024,
        dport: server.local_addr().unwrap().port(),
        protocol: Protocol::Udp,
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut buf = [0; 2];
        for i in 0..EXIT_FORWARD_FLOWS {
            let p = udp_packet(
                Tuple {
                    sport: flow.sport + i as u16,
                    ..flow
                },
                b"a",
            )
            .unwrap();
            assert!(gateway.forward(origin, p));
            assert_eq!(server.recv(&mut buf).await.unwrap(), 1);
        }
        let extra = Tuple {
            sport: u16::MAX,
            ..flow
        };
        assert!(gateway.forward(origin, udp_packet(extra, b"no").unwrap()));
        assert!(gateway.forward(origin, udp_packet(flow, b"ok").unwrap()));
        assert_eq!(server.recv(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf, b"ok");
    })
    .await
    .unwrap();
}
