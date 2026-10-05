#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};
use std::sync::atomic::AtomicBool;

fn network() -> NetworkId {
    NetworkKeys::derive(
        &NetworkName::new("routing-tests").unwrap(),
        &NetworkSecret::from_bytes([3; 32]).unwrap(),
    )
    .network_id()
}
fn peer(seed: u8) -> EndpointId {
    iroh::SecretKey::from_bytes(&[seed; 32]).public()
}
fn id(seed: u8) -> PeerId {
    *peer(seed).as_bytes()
}
fn tag() -> u64 {
    envelope::protocol_tag("ip")
}

#[derive(Debug)]
struct Wire {
    peer: EndpointId,
    sent: Mutex<Vec<Bytes>>,
    feed: mpsc::Sender<Bytes>,
    inbound: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    dead: AtomicBool,
    count: AtomicU64,
    record: bool,
}
impl Wire {
    fn new(seed: u8, record: bool) -> Arc<Self> {
        let (feed, inbound) = mpsc::channel(32);
        Arc::new(Self {
            peer: peer(seed),
            sent: Mutex::default(),
            feed,
            inbound: tokio::sync::Mutex::new(inbound),
            dead: AtomicBool::new(false),
            count: AtomicU64::new(0),
            record,
        })
    }
    fn take(&self) -> Vec<Bytes> {
        std::mem::take(&mut self.sent.lock().unwrap())
    }
}
impl PacketLink for Wire {
    fn network(&self) -> NetworkId {
        network()
    }
    fn peer(&self) -> EndpointId {
        self.peer
    }
    fn max_datagram_size(&self) -> usize {
        MAX_DATA_DATAGRAM
    }
    fn send(&self, frame: Bytes) -> Result<(), TransportError> {
        if self.is_closed() {
            return Err(TransportError::Closed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        if self.record {
            self.sent.lock().unwrap().push(frame);
        }
        Ok(())
    }
    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move { self.inbound.lock().await.recv().await })
    }
    fn closed(&self) -> BoxFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
    fn is_closed(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }
    fn path_description(&self) -> String {
        "test-direct".into()
    }
}

fn topology(hub: &RelayHub, edges: &[(u8, &[u8])], members: &[u8]) {
    hub.set_topology(
        edges
            .iter()
            .map(|(a, bs)| (id(*a), bs.iter().map(|b| id(*b)).collect()))
            .collect(),
        members.iter().map(|p| id(*p)).collect(),
    );
}

#[tokio::test]
async fn ecmp_is_per_flow_direct_wins_and_existing_tunnel_survives_changes() {
    let hub = RelayHub::new(network(), peer(1));
    let b = Wire::new(2, true);
    let c = Wire::new(3, true);
    hub.set_direct(peer(2), "ip", b.clone());
    hub.set_direct(peer(3), "ip", c.clone());
    topology(&hub, &[(2, &[4]), (3, &[4])], &[1, 2, 3, 4]);
    let link = hub.link(peer(4), "ip");
    let mut chosen = HashMap::new();
    for _ in 0..8 {
        for flow in 0..100 {
            link.send_flow(Bytes::from_static(b"ciphertext"), flow)
                .unwrap();
        }
        for (hop, wire) in [(2, &b), (3, &c)] {
            for frame in wire.take() {
                let header = envelope::decode(&frame).unwrap();
                assert_eq!(header.source, id(1));
                assert_eq!(header.destination, id(4));
                if let Some(old) = chosen.insert(header.flow, hop) {
                    assert_eq!(old, hop);
                }
            }
        }
    }
    assert_eq!(
        chosen.values().copied().collect::<HashSet<_>>(),
        HashSet::from([2, 3])
    );
    let direct = Wire::new(4, true);
    hub.set_direct(peer(4), "ip", direct.clone());
    link.send_flow(Bytes::from_static(b"direct"), 8).unwrap();
    assert_eq!(direct.take().len(), 1);
    assert!(b.take().is_empty() && c.take().is_empty());
    hub.clear_direct(peer(4), "ip");
    b.dead.store(true, Ordering::Relaxed);
    for flow in 0..100 {
        link.send_flow(Bytes::from_static(b"fallback"), flow)
            .unwrap();
    }
    assert_eq!(c.take().len(), 100);
    hub.clear_direct(peer(2), "ip");
    topology(&hub, &[(3, &[])], &[1, 2, 3, 4]);
    assert!(link.send(Bytes::new()).is_err());
    assert!(!link.is_closed());
    assert!(Arc::ptr_eq(&link, &hub.link(peer(4), "ip")));
    hub.remove_peer(peer(4));
    assert!(link.is_closed());
    tokio::time::timeout(std::time::Duration::from_secs(1), link.closed())
        .await
        .unwrap();
    assert!(link.recv().await.is_none());
    hub.close();
}

#[tokio::test]
async fn transport_reader_forwards_without_any_plugin_reader_and_isolates_protocols() {
    let hub = RelayHub::new(network(), peer(2));
    let a = Wire::new(1, true);
    let c = Wire::new(3, true);
    hub.set_direct(peer(1), "ip", a.clone());
    hub.set_direct(peer(3), "ip", c.clone());
    topology(&hub, &[(3, &[4])], &[1, 2, 3, 4]);
    let frame = envelope::encode(id(1), id(4), 91, tag(), b"end-to-end encrypted");
    let pointer = frame.as_ptr();
    a.feed.send(frame).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while hub.counters().forwarded == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let sent = c.take();
    assert_eq!(sent[0].as_ptr(), pointer);
    assert_eq!(
        envelope::decode(&sent[0]).unwrap().remaining,
        ROUTING_HOP_LIMIT - 1
    );
    assert_eq!(&sent[0][RELAY_OVERHEAD..], b"end-to-end encrypted");
    assert_eq!(hub.counters().forwarded, 1);
    hub.close();
}

#[tokio::test]
async fn a_frame_is_delivered_only_to_the_protocol_it_names() {
    let hub = RelayHub::new(network(), peer(2));
    hub.set_direct(peer(1), "ip", Wire::new(1, true));
    let ip = hub.link(peer(1), "ip");
    let other = hub.link(peer(1), "other-ip");
    let plane = ip.plane.clone();
    plane.receive(id(1), envelope::encode(id(1), id(2), 0, tag(), b"for ip"));
    plane.receive(
        id(1),
        envelope::encode(
            id(1),
            id(2),
            0,
            envelope::protocol_tag("other-ip"),
            b"for other",
        ),
    );
    plane.receive(
        id(1),
        envelope::encode(
            id(1),
            id(2),
            0,
            envelope::protocol_tag("nobody-runs-this"),
            b"for nobody",
        ),
    );
    assert_eq!(ip.recv().await.unwrap(), Bytes::from_static(b"for ip"));
    assert_eq!(
        other.recv().await.unwrap(),
        Bytes::from_static(b"for other")
    );
    assert_eq!(hub.counters().dropped_unknown, 1);
    hub.close();
}

/// A middle member joins two neighbours over different transports, and the
/// two ends share a protocol the middle has never heard of.
#[tokio::test]
async fn a_tunnel_crosses_a_middle_member_whose_links_are_of_different_kinds() {
    let a = RelayHub::new(network(), peer(1));
    let c = RelayHub::new(network(), peer(3));
    let b = RelayHub::new(network(), peer(2));
    let a_to_c = Wire::new(3, true);
    let c_to_a = Wire::new(1, true);
    let c_to_b = Wire::new(2, true);
    let b_to_c = Wire::new(3, true);
    a.set_direct(peer(3), "wg", a_to_c.clone());
    c.set_direct(peer(1), "wg", c_to_a);
    c.set_direct(peer(2), "wg-quic", c_to_b.clone());
    b.set_direct(peer(3), "wg-quic", b_to_c.clone());
    topology(&a, &[(3, &[1, 2])], &[1, 2, 3]);
    topology(&b, &[(3, &[1, 2])], &[1, 2, 3]);
    topology(&c, &[(1, &[3]), (2, &[3])], &[1, 2, 3]);

    let outgoing = a.link(peer(2), "tunnel");
    let incoming = b.link(peer(1), "tunnel");
    outgoing
        .send_flow(Bytes::from_static(b"sealed"), 5)
        .unwrap();
    let frame = a_to_c.take().remove(0);

    // The middle forwards it onto its other kind of link without looking
    // inside.
    c.state().plane.receive(id(1), frame);
    let frame = c_to_b.take().remove(0);
    assert_eq!(c.counters().forwarded, 1);

    b.state().plane.receive(id(3), frame);
    assert_eq!(
        incoming.recv().await.unwrap(),
        Bytes::from_static(b"sealed")
    );
    assert_eq!(b.counters().received_via, 1);
    assert_eq!(
        b.route(peer(1)),
        Some(RouteSummary {
            hops: 2,
            via: peer(3)
        })
    );
    a.close();
    b.close();
    c.close();
}

#[tokio::test]
async fn a_neighbour_is_reached_over_the_preferred_kind_and_falls_back_when_it_is_lost() {
    let hub = RelayHub::new(network(), peer(1));
    hub.set_priority(vec!["wg".into(), "tcp-tls".into(), "wg-quic".into()]);
    let slow = Wire::new(2, true);
    let fast = Wire::new(2, true);
    hub.set_direct(peer(2), "wg-quic", slow.clone());
    let link = hub.link(peer(2), "tunnel");
    link.send(Bytes::from_static(b"one")).unwrap();
    assert_eq!(slow.take().len(), 1);
    assert_eq!(hub.direct_kinds(peer(2)), ["wg-quic"]);

    // A better kind appears: traffic moves to it with nothing to redo.
    hub.set_direct(peer(2), "wg", fast.clone());
    assert_eq!(hub.direct_kinds(peer(2)), ["wg", "wg-quic"]);
    link.send(Bytes::from_static(b"two")).unwrap();
    assert_eq!(fast.take().len(), 1);
    assert!(slow.take().is_empty());

    // It dies: the worse one carries on, and the logical link is untouched.
    fast.dead.store(true, Ordering::Relaxed);
    link.send(Bytes::from_static(b"three")).unwrap();
    assert_eq!(slow.take().len(), 1);
    assert!(!link.is_closed());
    assert_eq!(
        hub.route(peer(2)),
        Some(RouteSummary {
            hops: 1,
            via: peer(2)
        })
    );

    hub.clear_direct(peer(2), "wg-quic");
    hub.clear_direct(peer(2), "wg");
    assert!(!hub.reachable(peer(2)));
    assert!(Arc::ptr_eq(&link, &hub.link(peer(2), "tunnel")));
    hub.close();
}

#[tokio::test]
async fn local_delivery_is_bounded_and_malformed_or_unknown_sources_are_dropped() {
    let hub = RelayHub::new(network(), peer(2));
    let a = Wire::new(1, true);
    hub.set_direct(peer(1), "ip", a);
    let link = hub.link(peer(1), "ip");
    let plane = link.plane.clone();
    for _ in 0..INBOX + 1 {
        plane.receive(id(1), envelope::encode(id(1), id(2), 0, tag(), b"ip"));
    }
    assert_eq!(hub.counters().dropped_congested, 1);
    for _ in 0..INBOX {
        assert_eq!(link.recv().await.unwrap(), Bytes::from_static(b"ip"));
    }
    plane.receive(id(1), Bytes::from_static(b"broken"));
    plane.receive(
        id(1),
        envelope::encode(id(9), id(2), 0, tag(), b"unknown member"),
    );
    assert_eq!(hub.counters().dropped_unknown, 2);
    plane.receive(
        id(1),
        envelope::encode(id(1), id(9), 0, tag(), b"unknown destination"),
    );
    assert_eq!(hub.counters().dropped_no_link, 1);
    hub.close();
}

#[tokio::test]
async fn inconsistent_tables_cannot_loop_beyond_the_hop_limit() {
    let a = RelayHub::new(network(), peer(1));
    let b = RelayHub::new(network(), peer(2));
    let ab = Wire::new(2, true);
    let ba = Wire::new(1, true);
    a.set_direct(peer(2), "ip", ab.clone());
    b.set_direct(peer(1), "ip", ba.clone());
    // Deliberately inconsistent snapshots while updates are in flight.
    topology(&a, &[(2, &[4])], &[1, 2, 3, 4]);
    topology(&b, &[(1, &[4])], &[1, 2, 3, 4]);
    let ap = a.link(peer(4), "ip").plane.clone();
    let bp = b.link(peer(4), "ip").plane.clone();
    let mut frame = envelope::encode(id(3), id(4), 7, tag(), b"transit");
    for turn in 0..ROUTING_HOP_LIMIT {
        let (plane, incoming, wire) = if turn % 2 == 0 {
            (&ap, id(2), &ab)
        } else {
            (&bp, id(1), &ba)
        };
        plane.receive(incoming, frame);
        let sent = wire.take();
        if turn == ROUTING_HOP_LIMIT - 1 {
            assert!(sent.is_empty());
            break;
        }
        assert_eq!(sent.len(), 1);
        frame = sent.into_iter().next().unwrap();
    }
    assert_eq!(
        a.counters().forwarded + b.counters().forwarded,
        u64::from(ROUTING_HOP_LIMIT - 1)
    );
    assert_eq!(
        a.counters().dropped_hop_limit + b.counters().dropped_hop_limit,
        1
    );
    a.close();
    b.close();
}

/// Measures the actual synchronous transit routine, including header checks,
/// snapshot lookup, ECMP, in-place TTL update and mock transport submission.
/// Packet construction, encryption and socket I/O are outside this measurement.
#[tokio::test]
#[ignore = "manual release-mode forwarding microbenchmark"]
async fn forwarding_benchmark() {
    let hub = RelayHub::new(network(), peer(2));
    let wire = Wire::new(3, false);
    hub.set_direct(peer(3), "ip", wire.clone());
    let alternate = Wire::new(5, false);
    hub.set_direct(peer(5), "ip", alternate.clone());
    topology(&hub, &[(3, &[4]), (5, &[4])], &[1, 2, 3, 4, 5]);
    let plane = hub.link(peer(4), "ip").plane.clone();
    let source = id(1);
    let destination = id(4);
    let incoming = id(1);
    for size in [64, 1280] {
        let mut elapsed = std::time::Duration::ZERO;
        const COUNT: usize = 10000;
        const BATCHES: usize = 100;
        for _ in 0..BATCHES {
            let frames: Vec<_> = (0..COUNT)
                .map(|flow| {
                    envelope::encode(source, destination, flow as u64, tag(), &vec![42; size])
                })
                .collect();
            let start = std::time::Instant::now();
            for frame in frames {
                plane.receive(incoming, std::hint::black_box(frame));
            }
            elapsed += start.elapsed();
        }
        let count = (COUNT * BATCHES) as f64;
        println!(
            "transit {size} B: {:.1} ns/packet, {:.2} Mpps (1M packets, two equal paths)",
            elapsed.as_nanos() as f64 / count,
            count / elapsed.as_secs_f64() / 1e6
        );
    }
    assert_eq!(
        wire.count.load(Ordering::Relaxed) + alternate.count.load(Ordering::Relaxed),
        2000000
    );
    hub.close();
}
