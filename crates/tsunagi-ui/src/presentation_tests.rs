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
    net.overlay = Some(OverlayReport {
        peers: vec![OverlayPeerReport {
            endpoint_id: "alpha".into(),
            handshake_secs_ago: Some(2),
            tx_bytes: 2048,
            rx_bytes: 512,
            ..Default::default()
        }],
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
