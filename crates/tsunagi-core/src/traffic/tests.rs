#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;

fn ip(proto: u8, reply: bool) -> Vec<u8> {
    let mut p = vec![0; 32];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&32u16.to_be_bytes());
    p[9] = proto;
    let (a, b, x, y) = if reply {
        (2, 1, 443u16, 49152u16)
    } else {
        (1, 2, 49152, 443)
    };
    p[12..16].copy_from_slice(&[10, 0, 0, a]);
    p[16..20].copy_from_slice(&[10, 0, 0, b]);
    p[20..22].copy_from_slice(&x.to_be_bytes());
    p[22..24].copy_from_slice(&y.to_be_bytes());
    if proto == 1 {
        p[20] = if reply { 0 } else { 8 };
        p[21] = 0;
    }
    p
}

#[test]
fn dormant_monitor_and_independent_window_lifetimes() {
    let monitor = Arc::new(TrafficMonitor::default());
    let submit = || {
        monitor
            .prepare(|| Some((control(), Direction::Tx, 100)))
            .record()
    };
    fn control() -> FlowKey {
        FlowKey {
            network: [1; 32],
            peer: [2; 32],
            role: Role::Control,
            flow: Flow::Control,
        }
    }
    assert!(
        monitor
            .prepare(|| panic!("observer ran while closed"))
            .0
            .is_none()
    );
    let a = monitor.subscribe().unwrap();
    assert!(a.snapshot().flows.is_empty());
    submit();
    let pending = monitor.prepare(|| Some((control(), Direction::Rx, 50)));
    let b = monitor.subscribe().unwrap();
    pending.record();
    submit();
    let a_sample = a.snapshot();
    assert_eq!(a_sample.flows[0].tx_bytes, 200);
    assert_eq!(a_sample.flows[0].rx_bytes, 50);
    assert_eq!(b.snapshot().flows[0].tx_bytes, 100);
    assert!(a.snapshot().flows.is_empty());
    drop((a, b));
    assert!(
        monitor
            .prepare(|| panic!("observer left active"))
            .0
            .is_none()
    );
    assert!(monitor.subscribe().unwrap().snapshot().flows.is_empty());
}

#[test]
fn tuple_and_echo_replies_have_the_same_key_and_fragments_never_invent_ports() {
    for protocol in [6, 17, 1] {
        let key = Flow::ip(&ip(protocol, false), Direction::Tx).unwrap();
        assert_eq!(Some(key), Flow::ip(&ip(protocol, true), Direction::Rx));
    }
    let mut packet = ip(17, false);
    packet[7] = 1;
    assert!(matches!(
        Flow::ip(&packet, Direction::Tx),
        Some(Flow::Ip {
            detail: IpDetail::Fragment,
            ..
        })
    ));
    packet[0] = 0x4f;
    assert!(Flow::ip(&packet, Direction::Tx).is_none());
    assert!(Flow::ip(&[], Direction::Rx).is_none());
}

#[test]
fn bounded_interval_reports_overflow_and_preserves_known_counters() {
    let monitor = Arc::new(TrafficMonitor::default());
    let sub = monitor.subscribe().unwrap();
    for i in 0..=MAX_INTERVAL_FLOWS {
        let mut peer = [0; 32];
        peer[..8].copy_from_slice(&(i as u64).to_be_bytes());
        monitor
            .prepare(|| {
                Some((
                    FlowKey {
                        network: [0; 32],
                        peer,
                        role: Role::Control,
                        flow: Flow::Control,
                    },
                    Direction::Tx,
                    20,
                ))
            })
            .record();
    }
    let sample = sub.snapshot();
    assert_eq!(sample.flows.len(), MAX_INTERVAL_FLOWS);
    assert_eq!(sample.omitted, 1);
    assert!(postcard::to_stdvec(&sample).unwrap().len() < (1 << 20));
    assert_eq!(sub.snapshot().omitted, 0);
}

#[test]
fn busy_writers_share_the_flow_without_waiting_and_closed_windows_release_inflight_buffers() {
    let monitor = Arc::new(TrafficMonitor::default());
    let sub = monitor.subscribe().unwrap();
    let key = FlowKey {
        network: [1; 32],
        peer: [2; 32],
        role: Role::Control,
        flow: Flow::Control,
    };
    monitor.prepare(|| Some((key, Direction::Tx, 20))).record();
    let held = sub.bucket.lanes[0].lock().unwrap();
    monitor.prepare(|| Some((key, Direction::Rx, 30))).record();
    drop(held);
    let result = sub.snapshot();
    assert_eq!(result.flows.len(), 1);
    assert_eq!(
        (
            result.flows[0].tx_bytes,
            result.flows[0].rx_bytes,
            result.omitted
        ),
        (20, 30, 0)
    );
    let pending = monitor.prepare(|| Some((key, Direction::Rx, 10)));
    let bucket = Arc::downgrade(&sub.bucket);
    drop(sub);
    assert!(bucket.upgrade().is_none());
    pending.record();
}
