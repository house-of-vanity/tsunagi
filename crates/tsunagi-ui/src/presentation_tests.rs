#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::{
    client::{Client, Command},
    devices, home,
    stats::{Traffic, Unit},
};
use egui::{Context, Event, FullOutput, Pos2, Rect, Vec2};
use egui_phosphor::regular as icon;
use tsunagi::ipc::{
    DataPathReport, MemberReport, NetworkReport, OverlayPeerReport, OverlayReport, PeerReport,
};

#[test]
fn keyboard_focus_explains_an_icon_and_the_shared_font_contains_the_status_glyphs() {
    let ctx = Context::default();
    ctx.set_fonts(crate::app_fonts());
    let draw = |time| {
        frame(&ctx, egui::vec2(360., 500.), time, vec![], |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let r = crate::widgets::icon_button(ui, icon::EYE, "Show secret");
                r.request_focus();
                let font = egui::TextStyle::Body.resolve(ui.style());
                for glyph in [
                    icon::EYE,
                    icon::EYE_SLASH,
                    icon::NETWORK,
                    icon::CHECK_CIRCLE,
                    icon::WARNING,
                    icon::MINUS_CIRCLE,
                    icon::PAUSE_CIRCLE,
                    icon::MOON,
                    icon::SIGN_OUT,
                    icon::FINGERPRINT,
                    icon::HASH,
                    icon::TREE_STRUCTURE,
                    icon::DEVICE_MOBILE,
                    icon::DEVICES,
                    icon::BROADCAST,
                    icon::FLOW_ARROW,
                    icon::GITHUB_LOGO,
                    icon::SCALES,
                ] {
                    assert!(
                        ui.fonts(|f| f.has_glyphs(&font, glyph)),
                        "missing glyph {glyph}"
                    );
                }
            });
        })
    };
    draw(0.);
    draw(0.1);
    assert!(label(&draw(0.2), "Show secret").is_some());
}

struct ReadOnly;
impl Client for ReadOnly {
    fn busy(&self) -> bool {
        false
    }
    fn send(&self, _: Command) {
        panic!("reading the UI issued a command");
    }
}
fn frame(
    ctx: &Context,
    size: Vec2,
    time: f64,
    events: Vec<Event>,
    draw: impl FnMut(&Context),
) -> FullOutput {
    ctx.run(
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
            time: Some(time),
            events,
            ..Default::default()
        },
        draw,
    )
}
fn label(frame: &FullOutput, value: &str) -> Option<Rect> {
    frame.shapes.iter().find_map(|s| match &s.shape {
        egui::Shape::Text(t) if t.galley.text() == value => Some(t.visual_bounding_rect()),
        _ => None,
    })
}
fn press(pos: Pos2, pressed: bool) -> Event {
    Event::PointerButton {
        pos,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: Default::default(),
    }
}
#[test]
fn secret_eye_masks_by_default_and_long_touch_explains_without_revealing() {
    let ctx = Context::default();
    ctx.set_fonts(crate::app_fonts());
    ctx.set_os(egui::os::OperatingSystem::Android);
    let mut form = home::JoinForm::default();
    form.secret.push_str("test-only-value");
    let mut draw = |time, events| {
        frame(&ctx, egui::vec2(360., 720.), time, events, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| home::draw_join(ui, &ReadOnly, &mut form));
        })
    };
    draw(0., vec![]);
    let masked = draw(0.1, vec![]);
    assert!(label(&masked, "test-only-value").is_none());
    let eye = label(&masked, icon::EYE)
        .expect("show secret button")
        .center();
    let touch = |phase| Event::Touch {
        device_id: egui::TouchDeviceId(0),
        id: egui::TouchId(1),
        phase,
        pos: eye,
        force: None,
    };
    draw(
        0.2,
        vec![
            touch(egui::TouchPhase::Start),
            Event::PointerMoved(eye),
            press(eye, true),
        ],
    );
    draw(1.2, vec![]);
    let held = draw(1.3, vec![]);
    assert!(label(&held, "Show secret").is_some());
    draw(
        1.4,
        vec![
            touch(egui::TouchPhase::End),
            press(eye, false),
            Event::PointerGone,
        ],
    );
    assert!(label(&draw(1.5, vec![]), "test-only-value").is_none());
    for (time, visible) in [(2., true), (3., false)] {
        draw(time, vec![Event::PointerMoved(eye), press(eye, true)]);
        draw(time + 0.1, vec![press(eye, false)]);
        let out = draw(time + 0.2, vec![]);
        assert_eq!(label(&out, "test-only-value").is_some(), visible);
        assert!(label(&out, if visible { icon::EYE_SLASH } else { icon::EYE }).is_some());
    }
}

#[test]
fn rotating_the_devices_view_keeps_the_peer_and_fits_traffic_and_states_on_screen() {
    let ctx = Context::default();
    ctx.set_os(egui::os::OperatingSystem::Android);
    ctx.set_fonts(crate::app_fonts());
    let mut net = NetworkReport {
        name: "lab".into(),
        network_id: "network".into(),
        ..Default::default()
    };
    for (id, state) in [
        ("alpha", "ready"),
        ("bravo", "waiting"),
        ("charlie", "error"),
        ("delta", "offline"),
        ("echo", "control only"),
        ("foxtrot", "idle"),
    ] {
        net.members.push(MemberReport {
            endpoint_id: id.into(),
            hostname: Some(id.into()),
            online: state != "offline",
            overlay_address_v4: Some("192.168.254.251".into()),
            ..Default::default()
        });
        if state != "offline" {
            net.peers.push(PeerReport {
                endpoint_id: id.into(),
                path: DataPathReport::Relayed {
                    hops: 2,
                    via: "another".into(),
                },
                data_error: match state {
                    "waiting" => Some(tsunagi::agent::DATA_CONNECTING.into()),
                    "error" => Some("Carrier unavailable".into()),
                    "control only" => Some(tsunagi::agent::DATA_DISABLED.into()),
                    _ => None,
                },
                agent_version: Some("1.0.4".into()),
                ..Default::default()
            });
        }
    }
    let mut overlay_peers = vec![OverlayPeerReport {
        endpoint_id: "alpha".into(),
        handshake_secs_ago: Some(2),
        tx_bytes: 2048,
        rx_bytes: 512,
        ..Default::default()
    }];
    // Only the reachable peer with a healthy path may show Idle. A problem
    // or an offline observation takes precedence over quiet IP counters.
    overlay_peers.extend(["bravo", "charlie", "delta", "echo", "foxtrot"].map(|id| {
        OverlayPeerReport {
            endpoint_id: id.into(),
            idle: true,
            ..Default::default()
        }
    }));
    net.overlay = Some(OverlayReport {
        peers: overlay_peers,
        ..Default::default()
    });
    let draw = |size, time, events| {
        frame(&ctx, size, time, events, |ctx| {
            devices::show(
                ctx,
                &ReadOnly,
                &mut Unit::Bytes,
                (&mut None, &mut None),
                &net,
                "self",
                &Traffic::default(),
            )
        })
    };
    let portrait = egui::vec2(360., 740.);
    draw(portrait, 0., vec![]);
    let pos = label(&draw(portrait, 0.1, vec![]), "alpha")
        .unwrap()
        .center();
    draw(
        portrait,
        0.2,
        vec![Event::PointerMoved(pos), press(pos, true)],
    );
    draw(portrait, 0.3, vec![press(pos, false)]);
    for (index, width) in [580., 740., 960.].into_iter().enumerate() {
        let size = egui::vec2(width, 360.);
        let time = 1. + index as f64;
        draw(size, time, vec![]);
        let out = draw(size, time + 0.1, vec![]);
        for text in [
            "bytes (TX / RX)",
            "2.0 kB / 512 B",
            "Ready",
            "Idle",
            "Waiting",
            "Error",
            "Offline",
            "Control only",
            "Endpoint ID",
        ] {
            let rect = label(&out, text).unwrap_or_else(|| panic!("missing {text} at {width}"));
            assert!(
                rect.left() >= 0. && rect.right() <= width,
                "{text} exceeds {width}: {rect:?}"
            );
        }
    }
    assert!(label(&draw(portrait, 4., vec![]), "Endpoint ID").is_some());
}

#[test]
fn compact_roster_reserves_the_full_tx_rx_pair_as_counters_grow() {
    use egui::os::OperatingSystem::{Android, Mac};

    for (os, width, font_size, density) in [
        (Android, 480., 13., 1.),
        (Mac, 600., 13., 2.),
        (Mac, 740., 13., 1.),
        (Android, 800., 19., 2.625),
    ] {
        let ctx = Context::default();
        ctx.set_os(os);
        ctx.set_fonts(crate::app_fonts());
        ctx.style_mut(|style| {
            style
                .text_styles
                .insert(egui::TextStyle::Body, egui::FontId::proportional(font_size));
        });
        let mut net = NetworkReport {
            name: "lab".into(),
            peers: vec![PeerReport {
                endpoint_id: "alpha".into(),
                hostname: Some("alpha".into()),
                agent_version: Some("1.0.6".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(width, 320.))),
            ..Default::default()
        };
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .unwrap()
            .native_pixels_per_point = Some(density);
        let mut first_cell = None;
        for (mut unit, tx, rx, expected) in [
            (Unit::Bytes, 0, 0, "0 B / 0 B"),
            (Unit::Bytes, 293_069, 294_400, "286.2 kB / 287.5 kB"),
            (
                Unit::Bytes,
                (1 << 30) - 1,
                (1 << 20) - 1,
                "1024.0 MB / 1024.0 kB",
            ),
            (Unit::Bytes, u64::MAX, 1 << 50, "16.0 EB / 1.0 PB"),
            (Unit::Packets, 1_234_567, 7_654_321, "1234567 / 7654321"),
            (
                Unit::Packets,
                u64::MAX,
                u64::MAX - 1,
                "18446744073709551615 / 18446744073709551614",
            ),
        ] {
            net.overlay = Some(OverlayReport {
                peers: vec![OverlayPeerReport {
                    endpoint_id: "alpha".into(),
                    tx_bytes: tx,
                    rx_bytes: rx,
                    tx_packets: tx,
                    rx_packets: rx,
                    ..Default::default()
                }],
                ..Default::default()
            });
            let output = ctx.run(input.clone(), |ctx| {
                devices::show(
                    ctx,
                    &ReadOnly,
                    &mut unit,
                    (&mut None, &mut None),
                    &net,
                    "self",
                    &Traffic::default(),
                );
            });
            let (text, cell) = output
                .shapes
                .iter()
                .find_map(|s| match &s.shape {
                    egui::Shape::Text(t) if t.galley.text() == expected => Some((t, s.clip_rect)),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("missing {expected} at {width}"));
            assert!(!text.galley.elided, "{expected} truncated at {width}");
            assert!(
                cell.contains_rect(text.visual_bounding_rect()),
                "{expected} clipped"
            );
            assert!(cell.left() >= 0. && cell.right() <= width);
            if unit == Unit::Bytes {
                let bounds = (cell.left(), cell.right());
                assert_eq!(*first_cell.get_or_insert(bounds), bounds);
            }
            assert!(label(&output, "alpha").unwrap().right() <= cell.left());
            let disclosure = label(&output, icon::CARET_RIGHT).unwrap();
            assert!(cell.right() <= disclosure.left() && disclosure.right() <= width);
            if let Some(version) = label(&output, "v1.0.6") {
                assert!(cell.right() <= version.left() && version.right() <= disclosure.left());
            }
        }
    }
}

#[test]
fn desktop_full_table_survives_long_names_and_compact_exit_icon_starts_and_stops() {
    use std::cell::RefCell;
    #[derive(Default)]
    struct Actions(RefCell<Vec<Command>>);
    impl Client for Actions {
        fn busy(&self) -> bool {
            false
        }
        fn send(&self, command: Command) {
            self.0.borrow_mut().push(command);
        }
    }
    let client = Actions::default();
    let mut net = NetworkReport {
        active: true,
        name: "lab".into(),
        network_id: "lab-id".into(),
        peers: vec![PeerReport {
            endpoint_id: "gw-device".into(),
            hostname: Some("a-long-gateway-name-repeated".repeat(3)),
            exit_node: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    for (width, full, stopping) in [
        (1230., true, false),
        (990., true, false),
        (640., false, false),
        (640., false, true),
    ] {
        let ctx = Context::default();
        ctx.set_os(egui::os::OperatingSystem::Mac);
        ctx.set_fonts(crate::app_fonts());
        net.exit.via = stopping.then(|| "gw-device".into());
        let mut pending = None;
        let mut draw = |time, events| {
            frame(&ctx, egui::vec2(width, 680.), time, events, |ctx| {
                devices::show(
                    ctx,
                    &client,
                    &mut Unit::Bytes,
                    (&mut pending, &mut None),
                    &net,
                    "local",
                    &Traffic::default(),
                )
            })
        };
        draw(0., vec![]);
        let out = draw(0.1, vec![]);
        assert_eq!(
            label(&out, "RTT data / control").is_some(),
            full,
            "width {width}"
        );
        let at = label(&out, icon::SIGN_OUT).unwrap().center();
        draw(0.2, vec![Event::PointerMoved(at), press(at, true)]);
        draw(0.3, vec![press(at, false)]);
        draw(0.4, vec![]);
        let out = draw(0.5, vec![]);
        let accept = label(&out, if stopping { "Stop" } else { "Use" })
            .expect("confirmation")
            .center();
        assert!(label(&out, "Endpoint ID").is_none());
        draw(0.6, vec![Event::PointerMoved(accept), press(accept, true)]);
        draw(0.7, vec![press(accept, false)]);
        assert!(
            matches!(client.0.borrow_mut().pop(),Some(Command::SetExitNode { network_id,peer }) if network_id=="lab-id" && peer.as_deref()==(!stopping).then_some("gw-device"))
        );
    }
}

#[test]
fn exit_users_scroll_a_row_inside_the_existing_card_and_disappear_on_deselection() {
    for (width, os) in [
        (360., egui::os::OperatingSystem::Android),
        (860., egui::os::OperatingSystem::Mac),
    ] {
        let ctx = Context::default();
        ctx.set_fonts(crate::app_fonts());
        ctx.set_os(os);
        let mut state = home::UiState::default();
        let mut network = NetworkReport {
            name: "office".into(),
            network_id: "lab".into(),
            active: true,
            range: Some("10.2.3.0/24".into()),
            overlay: Some(OverlayReport {
                address: Some("10.2.3.4".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        for i in 0..12 {
            network.peers.push(PeerReport {
                endpoint_id: format!("public-{i:02}"),
                hostname: Some(format!("peer-{i:02}")),
                ..Default::default()
            });
        }
        network.exit.offering = true;
        network.exit.forwarding = Some(true);
        network.exit.offer_rules = Some(tsunagi::ipc::RuleSetReport {
            ok: true,
            detail: "ok".into(),
        });
        let report = tsunagi::ipc::StatusReport::default();
        let mut draw = |net: &NetworkReport, time, events| {
            let mut height = 0.;
            let out = frame(&ctx, egui::vec2(width, 720.), time, events, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    home::draw_network(
                        ui,
                        &ReadOnly,
                        &mut state,
                        &Traffic::default(),
                        net,
                        &report,
                        true,
                    );
                    height = ui.min_rect().height();
                    assert!(ui.min_rect().right() <= width);
                });
            });
            (out, height)
        };
        draw(&network, 0., vec![]);
        let (folded, _) = draw(&network, 0.1, vec![]);
        let title = label(&folded, "office").unwrap().center();
        draw(
            &network,
            0.2,
            vec![Event::PointerMoved(title), press(title, true)],
        );
        draw(&network, 0.3, vec![press(title, false)]);
        let (empty, baseline) = draw(&network, 0.4, vec![]);
        assert!(label(&empty, "peer-00").is_none());
        network.peers[0].uses_our_exit = true;
        let (one, h) = draw(&network, 0.5, vec![]);
        assert!(label(&one, "1 exit user").is_some() && label(&one, "peer-00").is_some());
        assert!((h - baseline).abs() < 1.);
        for p in &mut network.peers {
            p.uses_our_exit = true;
        }
        let (many, h) = draw(&network, 0.6, vec![]);
        assert!(label(&many, "12 exit users").is_some());
        assert!((h - baseline).abs() < 1.);
        let first = label(&many, "peer-00").unwrap();
        let heading = label(&many, "12 exit users").unwrap();
        if os == egui::os::OperatingSystem::Android {
            assert!(
                heading.left() <= 168.,
                "mobile roster belongs close to the metadata"
            );
        }
        assert!(
            (first.left() - heading.left()).abs() < 3.,
            "roster names align with the heading"
        );
        let row = label(&many, "peer-01").unwrap().top() - first.top();
        let down = many
            .shapes
            .iter()
            .filter_map(|s| match &s.shape {
                egui::Shape::Text(t) if t.galley.text() == icon::CARET_DOWN => {
                    Some(t.visual_bounding_rect())
                }
                _ => None,
            })
            .max_by(|a, b| a.left().total_cmp(&b.left()))
            .unwrap()
            .center();
        assert!((down.y - heading.center().y).abs() < 3. && down.x - first.left() < 160.);
        draw(
            &network,
            0.7,
            vec![Event::PointerMoved(down), press(down, true)],
        );
        draw(&network, 0.8, vec![press(down, false)]);
        let (scrolled, h) = draw(&network, 0.9, vec![]);
        assert!((label(&scrolled, "peer-01").unwrap().top() - first.top()).abs() < 1. && row > 10.);
        assert!((h - baseline).abs() < 1.);
        for p in &mut network.peers {
            p.uses_our_exit = false;
        }
        let (empty, h) = draw(&network, 1., vec![]);
        assert!(label(&empty, "peer-01").is_none());
        assert!((h - baseline).abs() < 1.);
    }
}
