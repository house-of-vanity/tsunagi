#![allow(clippy::unwrap_used, clippy::panic)]
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
        before: Some(p.rows.last().unwrap().cursor()),
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
fn sorting_uses_the_entire_filtered_capture_and_pages_through_ties() {
    use super::{Column, Sort};
    let mut db = History::open(None).unwrap();
    let mut data: Vec<_> = (0..150)
        .map(|port| {
            let mut flow = sample(port, true);
            flow.tx_bytes = u64::from((port * 7) % 13) * 1024;
            flow
        })
        .collect();
    let mut foreign = sample(443, true);
    foreign.key.network = [7; 32];
    foreign.tx_bytes = 99_000_000;
    data.push(foreign);
    db.apply(&data, 1000, 1000, true).unwrap();
    for descending in [false, true] {
        let mut filter = Filter {
            network: Some([1; 32]),
            sort: Sort {
                column: Column::Sent,
                descending,
            },
            ..Default::default()
        };
        let mut seen = Vec::new();
        loop {
            let page = db.page(&filter).unwrap();
            seen.extend(page.rows.iter().map(|r| (r.data.tx_bytes, r.id)));
            if !page.more {
                break;
            }
            filter.before = Some(page.rows.last().unwrap().cursor());
        }
        assert_eq!(seen.len(), 150);
        assert!(seen.windows(2).all(|pair| if descending {
            pair[0] > pair[1]
        } else {
            pair[0] < pair[1]
        }));
    }
}

#[test]
fn a_stale_member_name_does_not_reindex_the_capture_every_refresh() {
    use tsunagi::ipc::{MemberReport, NetworkReport, PeerReport, StatusReport};
    let peer = tsunagi::identity::DeviceIdentity::from_secret_bytes(&[9; 32]).endpoint_id();
    let network = tsunagi::NetworkId::from_bytes([3; 32]);
    let mut report = StatusReport {
        networks: vec![NetworkReport {
            network_id: network.to_string(),
            name: "lab".into(),
            members: vec![MemberReport {
                endpoint_id: peer.to_string(),
                hostname: Some("old".into()),
                ..Default::default()
            }],
            peers: vec![PeerReport {
                endpoint_id: peer.to_string(),
                hostname: Some("current".into()),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut names = super::Names::default();
    assert!(names.refresh(Some(&report), 1));
    assert_eq!(names.peer(network.as_bytes(), peer.as_bytes()), "current");
    assert!(!names.refresh(Some(&report), 2));
    report.networks[0].peers[0].hostname = None;
    assert!(names.refresh(Some(&report), 3));
    assert_eq!(names.peer(network.as_bytes(), peer.as_bytes()), "old");
}

#[test]
fn endpoint_names_use_the_rows_network_and_current_peer_and_vip_records() {
    use super::{Column, Names};
    use tsunagi::ipc::{MemberReport, NetworkReport, OverlayReport, StatusReport};
    use tsunagi::vip::{VipConfig, VipStatus};

    let network = |id, name: &str, host: &str| NetworkReport {
        network_id: tsunagi::NetworkId::from_bytes([id; 32]).to_string(),
        name: name.into(),
        members: vec![MemberReport {
            hostname: Some(host.into()),
            overlay_address_v4: Some("10.0.0.2".into()),
            ..Default::default()
        }],
        overlay: Some(OverlayReport {
            address: Some("10.0.0.1".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut report = StatusReport {
        hostname: "laptop".into(),
        networks: vec![network(1, "tsng", "music"), network(2, "vpn", "home")],
        ..Default::default()
    };
    report.networks[0].vips.push(VipStatus {
        config: VipConfig::new("radio"),
        revision: String::new(),
        address: Some("10.0.0.3".parse().unwrap()),
        error: None,
        listeners: vec![],
    });
    let mut names = Names::default();
    names.refresh(Some(&report), 1);
    let mut key = sample(55201, true).key;
    assert_eq!(
        names.resolved_endpoint(&key, Column::Near).as_deref(),
        Some("laptop.tsng:55201")
    );
    assert_eq!(
        names.resolved_endpoint(&key, Column::Far).as_deref(),
        Some("music.tsng:443")
    );
    key.network = [2; 32];
    assert_eq!(
        names.resolved_endpoint(&key, Column::Far).as_deref(),
        Some("home.vpn:443")
    );
    key.network = [1; 32];
    key.flow = Flow::Ip {
        near: [10, 0, 0, 3],
        far: [1, 1, 1, 1],
        protocol: 1,
        detail: IpDetail::Echo,
    };
    assert_eq!(
        names.resolved_endpoint(&key, Column::Near).as_deref(),
        Some("radio.tsng")
    );
    assert_eq!(names.resolved_endpoint(&key, Column::Far), None);
    report.networks[0].vips[0].error = Some("address conflict".into());
    report.networks[0].members.clear();
    names.refresh(Some(&report), 2);
    assert_eq!(names.resolved_endpoint(&key, Column::Near), None);
    assert_eq!(
        names.resolved_endpoint(&sample(1, true).key, Column::Far),
        None
    );
}

#[test]
fn sorting_uses_display_names_numeric_endpoints_and_live_rates() {
    use super::{Column, Names, Network, Sort};
    use std::{collections::BTreeMap, sync::Arc};
    let mut db = History::open(None).unwrap();
    let first = sample(200, true);
    let mut second = sample(9, true);
    second.key.peer = [3; 32];
    if let Flow::Ip { ref mut far, .. } = second.key.flow {
        *far = [10, 0, 0, 10];
    }
    second.tx_bytes = 250;
    let mut names = Names::default();
    names.networks.insert(
        [1; 32],
        Network {
            name: "lab".into(),
            peers: BTreeMap::from([([2; 32], "zeta".into()), ([3; 32], "Alpha".into())]),
        },
    );
    db.use_names(Arc::new(names.clone()));
    db.apply(&[first.clone(), second.clone()], 1000, 1000, true)
        .unwrap();
    let filter = |column| Filter {
        sort: Sort {
            column,
            descending: false,
        },
        ..Default::default()
    };
    assert_eq!(
        db.page(&filter(Column::Peer)).unwrap().rows[0]
            .data
            .key
            .peer,
        [3; 32]
    );
    names
        .networks
        .get_mut(&[1; 32])
        .unwrap()
        .peers
        .insert([2; 32], "aardvark".into());
    db.use_names(Arc::new(names));
    for (column, id) in [(Column::Peer, 2), (Column::Near, 3), (Column::Far, 2)] {
        assert_eq!(
            db.page(&filter(column)).unwrap().rows[0].data.key.peer,
            [id; 32]
        );
    }
    db.apply(&[first], 3000, 1000, true).unwrap();
    let speeds = db.page(&filter(Column::SendRate)).unwrap();
    assert_eq!(
        (speeds.rows[0].data.key.peer, speeds.rows[0].tx_rate),
        ([3; 32], 0.)
    );
    assert!(speeds.rows[1].tx_rate > 0.);
}

#[test]
fn monitor_rows_stay_on_one_line_and_headers_sort_in_both_themes() {
    use super::{Column, Network, Window};
    use egui::{Color32, Context, Event, Pos2, Rect, Shape, Theme};
    use std::time::{Duration, Instant};

    for (theme, width) in [
        (Theme::Dark, 920.),
        (Theme::Light, 920.),
        (Theme::Dark, 320.),
    ] {
        let ctx = Context::default();
        ctx.set_theme(theme);
        ctx.set_fonts(crate::app_fonts());
        ctx.style_mut(|s| {
            s.interaction.tooltip_delay = 0.;
            s.interaction.show_tooltips_only_when_still = false;
        });
        let mut win = Window::new(None);
        win.names
            .addresses
            .insert(([1; 32], [10, 0, 0, 2].into()), "music.lab".into());
        win.names.networks.insert(
            [1; 32],
            Network {
                name: "lab".into(),
                peers: [([2; 32], "alder".into()), ([3; 32], "birch".into())].into(),
            },
        );
        let left = sample(55201, true);
        let mut right = sample(7, false);
        right.key.peer = [3; 32];
        let feed = win.feed();
        assert!(win.worker.view().0.rows.is_empty());
        feed.sample(TrafficSnapshot {
            flows: vec![left, right],
            interval_ms: 1000,
            omitted: 0,
        });
        let wait = |win: &Window| {
            let deadline = Instant::now() + Duration::from_secs(3);
            while win.worker.view().0.rows.len() != 2 {
                assert!(Instant::now() < deadline);
                std::thread::yield_now();
            }
        };
        wait(&win);
        let draw = |win: &mut Window, events: Vec<Event>| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(width, 480.))),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        win.show(ui, None, 0);
                        assert!(ui.min_rect().right() <= width);
                    });
                },
            )
        };
        let label = |frame: &egui::FullOutput, value: &str| {
            frame
                .shapes
                .iter()
                .find_map(|s| match &s.shape {
                    Shape::Text(t) if t.galley.text() == value => {
                        let section = &t.galley.job.sections[0].format;
                        assert!(
                            section.font_id.size >= 14.,
                            "{value} at {}",
                            section.font_id.size
                        );
                        assert!(
                            s.clip_rect.contains_rect(t.visual_bounding_rect()),
                            "{value} clipped at {width}: {:?} outside {:?}",
                            t.visual_bounding_rect(),
                            s.clip_rect
                        );
                        Some((
                            t.visual_bounding_rect(),
                            t.override_text_color.unwrap_or(section.color),
                        ))
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("missing {value} at {width}"))
        };
        let click = |win: &mut Window, pos| {
            for pressed in [true, false] {
                draw(
                    win,
                    vec![
                        Event::PointerMoved(pos),
                        Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: Default::default(),
                        },
                    ],
                );
            }
            wait(win);
        };
        let mut frame = draw(&mut win, vec![]);
        let checkbox = label(&frame, "Resolve names").0.center();
        if width > 900. {
            let name = label(&frame, "music.lab:443").0.center();
            draw(&mut win, vec![Event::PointerMoved(name)]);
            frame = draw(&mut win, vec![]);
            assert!(
                frame.shapes.iter().any(
                    |s| matches!(&s.shape, Shape::Text(t) if t.galley.text() == "10.0.0.2:443")
                ),
                "hovering a resolved name reveals the numeric endpoint"
            );
            click(&mut win, checkbox);
            frame = draw(&mut win, vec![]);
            label(&frame, "10.0.0.2:443");
            assert!(
                !frame.shapes.iter().any(
                    |s| matches!(&s.shape, Shape::Text(t) if t.galley.text() == "music.lab:443")
                )
            );
            click(&mut win, checkbox);
            frame = draw(&mut win, vec![]);
            label(&frame, "music.lab:443");
        }
        let chooser = frame
            .shapes
            .iter()
            .find_map(|s| match &s.shape {
                Shape::Text(t) if t.galley.text().contains("Columns 1/") => {
                    Some(t.visual_bounding_rect())
                }
                _ => None,
            })
            .unwrap();
        assert!(
            chooser.right() < width,
            "column chooser is outside the viewport at {width}"
        );
        let (peer, _) = label(&frame, "alder");
        let (sent, ink) = label(&frame, "90 B");
        let (header, _) = label(&frame, "Sent");
        assert!((peer.center().y - sent.center().y).abs() < 2.);
        assert!((label(&frame, "birch").0.center().y - peer.center().y).abs() < 34.);
        assert!((sent.right() - header.right()).abs() < 2.);
        assert!(sent.left() > width * 0.33 || width < 400.);
        let bg = if theme == Theme::Dark {
            Color32::from_gray(35)
        } else {
            Color32::from_gray(239)
        };
        let luminance = |c: Color32| {
            let v = egui::Rgba::from(c);
            0.2126 * v.r() + 0.7152 * v.g() + 0.0722 * v.b()
        };
        let (a, b) = (luminance(ink), luminance(bg));
        assert!(
            (a.max(b) + 0.05) / (a.min(b) + 0.05) >= 4.5,
            "contrast of {ink:?} at {width}"
        );
        click(&mut win, peer.center());
        frame = draw(&mut win, vec![]);
        assert!(!frame.shapes.iter().any(
            |s| matches!(&s.shape,Shape::Text(t) if t.galley.text().contains("packets sent"))
        ));
        assert!(
            (label(&frame, "birch").0.center().y - label(&frame, "alder").0.center().y).abs() < 34.
        );
        for descending in [true, false] {
            click(&mut win, header.center());
            assert_eq!(
                (win.filter.sort.column, win.filter.sort.descending),
                (Column::Sent, descending)
            );
            frame = draw(&mut win, vec![]);
            assert_eq!(
                label(&frame, "alder").0.top() < label(&frame, "birch").0.top(),
                descending
            );
        }
        drop(win);
        assert!(!feed.sample(TrafficSnapshot::default()));
    }
}
