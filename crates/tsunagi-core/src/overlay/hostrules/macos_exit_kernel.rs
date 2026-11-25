//! Privileged macOS regression. Both ends are throwaway utuns; only a /30
//! inside the simulated uplink is captured when switching the exit on.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv4Repr, TcpPacket, TcpSeqNumber, UdpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use super::*;
use crate::overlay::Cidr;
use crate::overlay::provision::{InterfacePlan, InterfaceProvisioner, UtunProvisioner};
use crate::overlay::tun::TunDevice;

const UPLINK: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 6);
const CAPTURE: &str = "192.0.2.4/30";
const FIRST: Ipv4Addr = Ipv4Addr::new(198, 18, 222, 1);
const SECOND: Ipv4Addr = Ipv4Addr::new(198, 19, 222, 1);
const WAIT: Duration = Duration::from_secs(5);

async fn utun(addresses: &[Ipv4Addr]) -> Arc<dyn TunDevice> {
    let cidrs = addresses
        .iter()
        .map(|ip| Cidr::new((*ip).into(), 28).unwrap())
        .collect();
    UtunProvisioner::new()
        .unwrap()
        .reconcile(&InterfacePlan::new("test", 1280, cidrs))
        .await
        .unwrap()
        .device
        .unwrap()
}

struct Capture<'a> {
    overlay: &'a str,
    uplink: DefaultRoute,
    anchor: String,
    token: Mutex<Option<String>>,
    added_route: bool,
    added_scoped: bool,
}

impl Drop for Capture<'_> {
    fn drop(&mut self) {
        if self.added_route {
            let _ = run_tool(Tool::Route, &route_del_args(CAPTURE, self.overlay), None);
        }
        if self.added_scoped {
            let _ = run_tool(
                Tool::Route,
                &scoped_args("delete", CAPTURE, &self.uplink),
                None,
            );
        }
        // Loading an empty ruleset removes just this temporary anchor's rules.
        let _ = run_tool(Tool::Pfctl, &load_args(&self.anchor), Some(""));
        release_pf(&run_tool, &self.token);
    }
}

impl Capture<'_> {
    fn offer(&self, use_upstream: bool) {
        let ranges = [FIRST, SECOND]
            .map(|ip| Ipv4Range::new(Ipv4Addr::from(u32::from(ip) & !0xf), 28).unwrap());
        let rules = pf_rules(
            self.overlay,
            &self.uplink,
            &ranges[..1],
            use_upstream.then_some(&ClientRules {
                uid: 0,
                overlay: &ranges,
            }),
        );
        acquire_pf(&run_tool, &self.token).unwrap();
        run_ok(
            &run_tool,
            Tool::Pfctl,
            &load_args(&self.anchor),
            Some(&rules),
        )
        .unwrap();
        enable_forwarding(&run_tool).unwrap();
    }
    fn enable(&mut self) {
        self.offer(true);
        run_ok(
            &run_tool,
            Tool::Route,
            &scoped::marked_args("add", CAPTURE, &self.uplink, 114275),
            None,
        )
        .unwrap();
        self.added_scoped = true;
        run_ok(
            &run_tool,
            Tool::Route,
            &route_set_args("add", CAPTURE, self.overlay, Some(SECOND)),
            None,
        )
        .unwrap();
        self.added_route = true;
    }
}

/// Ignore interface housekeeping and pure TCP ACKs while waiting for our packet.
async fn packet(
    device: &dyn TunDevice,
    destination: Ipv4Addr,
    protocol: IpProtocol,
    port: u16,
    payload: &[u8],
) -> Bytes {
    timeout(WAIT, async {
        loop {
            let raw = device.recv().await.expect("utun closed");
            let Ok(ip) = Ipv4Packet::new_checked(&raw[..]) else {
                continue;
            };
            if ip.version() != 4 || ip.dst_addr() != destination || ip.next_header() != protocol {
                continue;
            }
            let matches = match protocol {
                IpProtocol::Udp => UdpPacket::new_checked(ip.payload())
                    .is_ok_and(|udp| udp.dst_port() == port && udp.payload() == payload),
                IpProtocol::Tcp => TcpPacket::new_checked(ip.payload()).is_ok_and(|tcp| {
                    tcp.dst_port() == port
                        && tcp.payload() == payload
                        && (tcp.syn() || !payload.is_empty())
                }),
                _ => false,
            };
            if matches {
                return raw;
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "no {protocol} packet for {destination}:{port} on {}",
            device.name()
        )
    })
}

fn reply(request: &[u8]) -> Bytes {
    let ip = Ipv4Packet::new_checked(request).unwrap();
    let tcp_request = (ip.next_header() == IpProtocol::Tcp)
        .then(|| TcpPacket::new_checked(ip.payload()).unwrap());
    // Acknowledge TCP SYNs and echo data so the test observes return traffic
    // on the very socket that originated each flow.
    let reply_ip = Ipv4Repr {
        src_addr: ip.dst_addr(),
        dst_addr: ip.src_addr(),
        next_header: ip.next_header(),
        payload_len: tcp_request
            .as_ref()
            .map_or(ip.payload().len(), |tcp| 20 + tcp.payload().len()),
        hop_limit: 64,
    };
    let mut bytes = vec![0; reply_ip.buffer_len() + reply_ip.payload_len];
    let mut out = Ipv4Packet::new_unchecked(&mut bytes[..]);
    reply_ip.emit(&mut out, &Default::default());
    let src = reply_ip.src_addr.into();
    let dst = reply_ip.dst_addr.into();
    if let Some(incoming) = tcp_request {
        let mut tcp = TcpPacket::new_unchecked(out.payload_mut());
        tcp.set_header_len(20);
        tcp.set_src_port(incoming.dst_port());
        tcp.set_dst_port(incoming.src_port());
        tcp.set_syn(incoming.syn());
        tcp.set_ack(true);
        tcp.set_seq_number(if incoming.syn() {
            TcpSeqNumber(100)
        } else {
            incoming.ack_number()
        });
        tcp.set_ack_number(incoming.seq_number() + incoming.segment_len());
        tcp.set_window_len(8192);
        tcp.payload_mut().copy_from_slice(incoming.payload());
        tcp.fill_checksum(&src, &dst);
    } else {
        out.payload_mut().copy_from_slice(ip.payload());
        let mut udp = UdpPacket::new_unchecked(out.payload_mut());
        let (src_port, dst_port) = (udp.dst_port(), udp.src_port());
        udp.set_src_port(src_port);
        udp.set_dst_port(dst_port);
        udp.fill_checksum(&src, &dst);
    }
    bytes.into()
}

async fn open_tcp(uplink: &dyn TunDevice, port: u16) -> TcpStream {
    let connect = TcpStream::connect((REMOTE, port));
    let peer = async {
        let syn = packet(uplink, REMOTE, IpProtocol::Tcp, port, &[]).await;
        assert_eq!(
            Ipv4Packet::new_checked(&syn[..]).unwrap().src_addr(),
            UPLINK
        );
        uplink.send(reply(&syn)).await.unwrap();
    };
    let (stream, ()) = tokio::join!(timeout(WAIT, connect), peer);
    stream.expect("SYN-ACK did not reach socket").unwrap()
}

fn check_capture_routes(overlay: &str, uplink: &str) {
    for (scope, expected) in [(vec![], overlay), (owned(&["-ifscope", uplink]), uplink)] {
        let mut args = owned(&["-n", "get"]);
        args.extend(scope);
        args.extend(owned(&["-net", CAPTURE]));
        let output = run_ok(&run_tool, Tool::Route, &args, None).unwrap();
        eprintln!("route {}:\n{output}", args.join(" "));
        let actual = output
            .lines()
            .find_map(|line| line.trim().strip_prefix("interface: "));
        assert_eq!(actual, Some(expected));
        assert_eq!(output.contains("PROTO2"), expected == uplink);
        assert_eq!(output.contains("IFSCOPE"), expected == uplink);
        assert_eq!(
            output.split_whitespace().any(|s| s == "114275"),
            expected == uplink
        );
    }
}

async fn udp_round_trip(uplink: &dyn TunDevice, socket: &UdpSocket, stage: &str) {
    let port = socket.peer_addr().unwrap().port();
    eprintln!("{stage}: UDP {}", socket.local_addr().unwrap());
    socket
        .send(b"QUIC path")
        .await
        .unwrap_or_else(|e| panic!("{stage}: sending UDP: {e}"));
    let raw = packet(uplink, REMOTE, IpProtocol::Udp, port, b"QUIC path").await;
    let ip = Ipv4Packet::new_checked(&raw[..]).unwrap();
    assert_eq!(ip.src_addr(), UPLINK);
    assert_eq!(
        UdpPacket::new_checked(ip.payload()).unwrap().src_port(),
        socket.local_addr().unwrap().port()
    );
    uplink.send(reply(&raw)).await.unwrap();
    let mut buf = [0; 64];
    let len = timeout(WAIT, socket.recv(&mut buf))
        .await
        .expect("UDP reply did not reach socket")
        .unwrap();
    assert_eq!(&buf[..len], b"QUIC path");
}

async fn member_round_trip(
    overlay: &dyn TunDevice,
    uplink: &dyn TunDevice,
    port: u16,
    data: &[u8],
) -> u16 {
    let member = Ipv4Addr::from(u32::from(FIRST) + 2);
    let ip = Ipv4Repr {
        src_addr: member,
        dst_addr: REMOTE,
        next_header: IpProtocol::Udp,
        payload_len: 8 + data.len(),
        hop_limit: 64,
    };
    let mut raw = vec![0; ip.buffer_len() + ip.payload_len];
    let mut out = Ipv4Packet::new_unchecked(&mut raw[..]);
    ip.emit(&mut out, &Default::default());
    let mut udp = UdpPacket::new_unchecked(out.payload_mut());
    udp.set_len(ip.payload_len as u16);
    udp.set_src_port(port);
    udp.set_dst_port(8020);
    udp.payload_mut().copy_from_slice(data);
    udp.fill_checksum(&member.into(), &REMOTE.into());
    overlay.send(raw.into()).await.unwrap();
    let outbound = packet(uplink, REMOTE, IpProtocol::Udp, 8020, data).await;
    let physical = Ipv4Packet::new_checked(&outbound[..]).unwrap();
    assert_eq!(physical.src_addr(), UPLINK);
    let translated = UdpPacket::new_checked(physical.payload())
        .unwrap()
        .src_port();
    uplink.send(reply(&outbound)).await.unwrap();
    let inbound = packet(overlay, member, IpProtocol::Udp, port, data).await;
    assert_eq!(
        Ipv4Packet::new_checked(&inbound[..]).unwrap().src_addr(),
        REMOTE
    );
    translated
}

#[tokio::test]
#[ignore = "requires root, the stock Apple PF anchor, and a disposable macOS runner"]
async fn exit_preserves_underlay_and_both_meshes() {
    assert_eq!(agent_uid(&run_tool).unwrap(), 0);
    let uplink = utun(&[UPLINK]).await;
    let overlay = utun(&[FIRST, SECOND]).await;

    let mut relay = open_tcp(&*uplink, 8001).await;
    let existing_quic = UdpSocket::bind((UPLINK, 0)).await.unwrap();
    existing_quic.connect((REMOTE, 8006)).await.unwrap();
    udp_round_trip(&*uplink, &existing_quic, "before exit").await;
    let mut capture = Capture {
        overlay: overlay.name(),
        uplink: DefaultRoute {
            interface: uplink.name().to_owned(),
            gateway: Some(Ipv4Addr::new(192, 0, 2, 2)),
        },
        anchor: anchor_name(overlay.name()).unwrap(),
        token: Mutex::new(None),
        added_route: false,
        added_scoped: false,
    };
    // The local offer enables kernel forwarding. A keeps the same translated
    // address and port when B installs an upstream route to this IP.
    capture.offer(false);
    let port = member_round_trip(&*overlay, &*uplink, 43001, b"member before").await;
    capture.enable();
    assert_eq!(
        member_round_trip(&*overlay, &*uplink, 43001, b"member during").await,
        port
    );
    member_round_trip(&*overlay, &*uplink, 43002, b"new member flow").await;
    check_capture_routes(overlay.name(), uplink.name());
    udp_round_trip(&*uplink, &existing_quic, "existing socket after exit").await;

    // An already established relay must preserve its address and port.
    relay.write_all(b"established relay").await.unwrap();
    let established = packet(
        &*uplink,
        REMOTE,
        IpProtocol::Tcp,
        8001,
        b"established relay",
    )
    .await;
    let ip = Ipv4Packet::new_checked(&established[..]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(ip.src_addr(), UPLINK);
    assert_eq!(tcp.src_port(), relay.local_addr().unwrap().port());
    uplink.send(reply(&established)).await.unwrap();
    let mut echo = [0; b"established relay".len()];
    timeout(WAIT, relay.read_exact(&mut echo))
        .await
        .expect("established TCP reply did not reach socket")
        .unwrap();
    assert_eq!(&echo, b"established relay");

    // The kernel selects the overlay source on new wildcard sockets. Real
    // replies to the translated address must reach those same sockets.
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    socket.connect((REMOTE, 8002)).await.unwrap();
    assert_eq!(socket.local_addr().unwrap().ip(), SECOND);
    udp_round_trip(&*uplink, &socket, "new socket after exit").await;
    let new_relay = open_tcp(&*uplink, 8003).await;
    assert_eq!(new_relay.local_addr().unwrap().ip(), SECOND);

    // Same destination, ordinary UID: external traffic must enter the exit.
    let program = "import socket, sys\nsocket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'ordinary', (sys.argv[1], 8004))";
    let mut child = tokio::process::Command::new("/usr/bin/python3");
    child
        .uid(65534)
        .gid(65534)
        .args(["-I", "-c", program, &REMOTE.to_string()])
        .kill_on_drop(true);
    assert!(
        timeout(WAIT, child.status())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    let ordinary = packet(&*overlay, REMOTE, IpProtocol::Udp, 8004, b"ordinary").await;
    assert_eq!(
        Ipv4Packet::new_checked(&ordinary[..]).unwrap().src_addr(),
        SECOND
    );

    // Root traffic to either mesh also stays on the overlay with its own alias.
    let mesh = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    for local in [FIRST, SECOND] {
        let peer = Ipv4Addr::from(u32::from(local) + 1);
        mesh.send_to(b"mesh", (peer, 8005)).await.unwrap();
        let raw = packet(&*overlay, peer, IpProtocol::Udp, 8005, b"mesh").await;
        assert_eq!(Ipv4Packet::new_checked(&raw[..]).unwrap().src_addr(), local);
    }
}
