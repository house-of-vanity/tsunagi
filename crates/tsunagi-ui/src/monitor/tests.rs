#![allow(clippy::unwrap_used)]
use super::history::*;
use tsunagi::traffic::*;

fn sample(port: u16, tx: bool) -> FlowDelta {
    FlowDelta {
        key: FlowKey {
            network: [1; 32],
            peer: [2; 32],
            role: Role::Mesh,
            flow: Flow::Ip {
                near: [10, 0, 0, 1],
                far: [10, 0, 0, 2],
                protocol: 6,
                detail: IpDetail::Ports(port, 443),
            },
        },
        tx_bytes: if tx { 90 } else { 0 },
        rx_bytes: if tx { 0 } else { 100 },
        tx_packets: u64::from(tx),
        rx_packets: u64::from(!tx),
        age_ms: 0,
    }
}
#[test]
fn window_history_expires_and_long_capture_is_paged_and_bidirectional() {
    let mut db = History::open(None).unwrap();
    let filter = Filter::default();
    db.apply(&[sample(1, true)], 1_000, 1_000, false).unwrap();
    db.apply(&[sample(1, false)], 2_000, 1_000, false).unwrap();
    let p = db.page(&filter).unwrap();
    assert_eq!(
        (p.rows[0].data.tx_bytes, p.rows[0].data.rx_bytes),
        (90, 100)
    );
    db.apply(&[], 62_000, 1_000, false).unwrap();
    assert!(db.page(&filter).unwrap().rows.is_empty());
    let flows: Vec<_> = (0..151).map(|port| sample(port, true)).collect();
    db.apply(&flows, 63_000, 1_000, true).unwrap();
    db.apply(&[], 3 * 86_400_000, 1_000, true).unwrap();
    let p = db.page(&filter).unwrap();
    assert_eq!(p.rows.len(), PAGE_SIZE);
    assert!(p.more);
    let next = Filter {
        before: Some(p.rows.last().unwrap().id),
        ..filter.clone()
    };
    assert!(
        db.page(&next)
            .unwrap()
            .rows
            .iter()
            .all(|r| r.id < p.rows.last().unwrap().id)
    );
    assert!(
        db.page(&Filter {
            network: Some([9; 32]),
            ..filter.clone()
        })
        .unwrap()
        .rows
        .is_empty()
    );
    assert!(
        db.page(&Filter {
            transport: true,
            ..filter.clone()
        })
        .unwrap()
        .rows
        .is_empty()
    );
    drop(db);
    assert!(
        History::open(None)
            .unwrap()
            .page(&filter)
            .unwrap()
            .rows
            .is_empty()
    );
}

#[test]
fn peer_filter_matches_both_relay_endpoints_only_in_the_selected_network() {
    let mut db = History::open(None).unwrap();
    let mut relay = sample(80, true);
    relay.key.flow = Flow::Relay {
        other: [3; 32],
        wire_protocol: 1,
    };
    relay.key.role = Role::Relay;
    let mut other_net = relay.clone();
    other_net.key.network = [9; 32];
    db.apply(&[relay, other_net, sample(80, true)], 1000, 1000, true)
        .unwrap();
    for id in [[2; 32], [3; 32]] {
        let f = Filter {
            network: Some([1; 32]),
            peer: Some(id),
            transport: true,
            role: Some(Role::Relay),
            ..Filter::default()
        };
        let page = db.page(&f).unwrap();
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].data.key.network, [1; 32]);
    }
    let filtered = Filter {
        network: Some([1; 32]),
        protocol: Some(17),
        ..Filter::default()
    };
    assert!(db.page(&filtered).unwrap().rows.is_empty());
}

#[cfg(unix)]
#[test]
fn private_cache_file_is_unlinked_and_remains_writable_across_transactions() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = History::open(Some(dir.path())).unwrap();
    let batch: Vec<_> = (0..4096).map(|n| sample(n, true)).collect();
    for t in [1000, 3 * 86_400_000] {
        db.apply(&batch, t, 1000, true).unwrap();
    }
    assert_eq!(dir.path().read_dir().unwrap().count(), 0);
    let p = db.page(&Filter::default()).unwrap();
    assert!(p.more);
    assert_eq!(p.rows[0].data.tx_bytes, 180);
    db.apply(&[], 3 * 86_400_000 + 60_000, 1_000, false)
        .unwrap();
    assert!(db.page(&Filter::default()).unwrap().rows.is_empty());
}

#[test]
fn live_monitor_has_readable_rows_inside_phone_and_desktop_widths() {
    use super::Window;
    use std::time::{Duration, Instant};
    let mut win = Window::new(None);
    let feed = win.feed();
    assert!(win.worker.view().0.rows.is_empty());
    feed.sample(TrafficSnapshot {
        flows: vec![sample(55201, true)],
        interval_ms: 1_000,
        omitted: 0,
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    while win.worker.view().0.rows.is_empty() {
        assert!(Instant::now() < deadline, "worker did not publish the flow");
        std::thread::yield_now();
    }
    for width in [320., 390., 720., 900.] {
        let ctx = egui::Context::default();
        ctx.set_fonts(crate::app_fonts());
        let frame = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 600.),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    win.show(ui, None, 0);
                    assert!(
                        ui.min_rect().right() <= width,
                        "monitor grew beyond {width}: {:?}",
                        ui.min_rect()
                    );
                });
            },
        );
        for value in ["10.0.0.1:55201", "10.0.0.2:443", "TCP", "Mesh"] {
            assert!(frame.shapes.iter().any(|s|matches!(&s.shape,egui::Shape::Text(t) if t.galley.text().contains(value) && t.visual_bounding_rect().right()<=width)), "{value} outside {width}");
        }
    }
    drop(win);
    assert!(!feed.sample(TrafficSnapshot::default()));
}
