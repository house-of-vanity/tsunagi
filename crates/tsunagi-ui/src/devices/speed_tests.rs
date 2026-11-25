#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use std::cell::RefCell;
use tsunagi::ipc::{PeerReport, SpeedBatchReport, SpeedPeerReport, SpeedPhase, SpeedRate};

#[derive(Default)]
struct ClientLog(RefCell<Vec<Command>>);

impl Client for ClientLog {
    fn send(&self, cmd: Command) {
        self.0.borrow_mut().push(cmd);
    }
    fn busy(&self) -> bool {
        false
    }
}

fn network() -> NetworkReport {
    let mut n = NetworkReport {
        active: true,
        name: "mesh".into(),
        network_id: "network".into(),
        ..Default::default()
    };
    for (id, offers_exit) in [("alice", true), ("ben", false), ("older", true)] {
        n.peers.push(PeerReport {
            endpoint_id: id.into(),
            hostname: Some(id.into()),
            exit_node: offers_exit,
            ..Default::default()
        });
    }
    n.speed.capable = vec!["alice".into(), "ben".into()];
    n
}

fn reading(phase: SpeedPhase) -> SpeedPeerReport {
    SpeedPeerReport {
        phase,
        down: Some(SpeedRate {
            bps: 125_000_000,
            lower_bound: false,
        }),
        up: Some(SpeedRate {
            bps: 35_995_000,
            lower_bound: true,
        }),
        bytes: 1_900_000,
        elapsed_ms: 600,
        path: Some("wg direct".into()),
        measured_at_unix_secs: 0,
    }
}

struct Screen {
    ctx: egui::Context,
    width: f32,
    log: ClientLog,
}

impl Screen {
    fn new(width: f32, mobile: bool) -> Self {
        let ctx = egui::Context::default();
        ctx.set_fonts(crate::app_fonts());
        if mobile {
            ctx.set_os(egui::os::OperatingSystem::Android);
        }
        Self {
            ctx,
            width,
            log: ClientLog::default(),
        }
    }

    fn frame(&self, n: &NetworkReport, events: Vec<egui::Event>) -> egui::FullOutput {
        self.frame_at(n, None, events)
    }

    fn frame_at(
        &self,
        n: &NetworkReport,
        time: Option<f64>,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        self.ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(self.width, 650.),
                )),
                events,
                time,
                ..Default::default()
            },
            |ctx| {
                show(
                    ctx,
                    &self.log,
                    &mut Unit::Bytes,
                    (&mut None, &mut None),
                    n,
                    "self",
                    &Traffic::default(),
                )
            },
        )
    }

    fn click(&self, n: &NetworkReport, pos: egui::Pos2) {
        for pressed in [true, false] {
            self.frame(
                n,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
    }
}

fn positions(out: &egui::FullOutput, find: impl Fn(&str) -> bool) -> Vec<egui::Pos2> {
    out.shapes
        .iter()
        .filter_map(|s| match &s.shape {
            egui::Shape::Text(t) if find(t.galley.text()) => {
                Some(t.pos + t.galley.rect.center().to_vec2())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn live_and_completed_readings_keep_the_same_row_and_tapping_retests_a_non_exit_peer() {
    for (width, mobile) in [(320., true), (860., true), (1440., false)] {
        let mut n = network();
        let s = Screen::new(width, mobile);
        s.frame(&n, vec![]);
        let idle = s.frame(&n, vec![]);
        let gauges = positions(&idle, |s| s == icon::GAUGE);
        assert_eq!(gauges.len(), 2, "capable peers only");
        let button = gauges[1];
        let peer_pos = positions(&idle, |s| s == "ben")[0];
        let after = positions(&idle, |s| s == "older")[0];
        s.click(&n, button);
        for phase in [
            SpeedPhase::Preparing,
            SpeedPhase::Download,
            SpeedPhase::Upload,
            SpeedPhase::Done,
        ] {
            let live_down = phase == SpeedPhase::Download;
            let mut report = reading(phase);
            if live_down {
                report.down = Some(SpeedRate {
                    bps: 19_900_000,
                    lower_bound: false,
                });
                report.up = None;
            }
            n.speed.peers.insert("ben".into(), report);
            let out = s.frame(&n, vec![]);
            if live_down {
                assert!(!positions(&out, |s| s == format!("{} 20", icon::ARROW_DOWN)).is_empty());
                assert!(!positions(&out, |s| s == format!("{} —", icon::ARROW_UP)).is_empty());
            }
            assert_eq!(positions(&out, |s| s == "ben"), [peer_pos]);
            assert_eq!(positions(&out, |s| s == "older"), [after]);
            assert!(
                positions(&out, |s| s == "Endpoint ID").is_empty(),
                "speed tap expanded a row"
            );
        }
        let done = s.frame(&n, vec![]);
        let down_text = format!("{} 125", icon::ARROW_DOWN);
        let up_text = format!("{} 36", icon::ARROW_UP);
        for value in [&down_text, &up_text] {
            let lines = positions(&done, |s| s == value);
            assert_eq!(lines.len(), 1);
            assert!((lines[0].x - button.x).abs() < 31.);
            assert!((lines[0].y - button.y).abs() < 12.);
            assert!(lines[0].x < width);
        }
        let down = positions(&done, |s| s == down_text)[0];
        let up = positions(&done, |s| s == up_text)[0];
        if width > 650. {
            assert!(
                (down.y - up.y).abs() < 1. && down.x < up.x,
                "wide screens show both rates on one line"
            );
        } else {
            assert!(
                (down.x - up.x).abs() < 1. && down.y < up.y,
                "portrait shows a rate on each line"
            );
        }
        s.click(&n, button);
        let log = s.log.0.borrow();
        assert_eq!(log.len(), 2);
        assert!(log.iter().all(|cmd| matches!(cmd, Command::StartSpeedTest { network_id, peer: Some(peer) } if network_id == "network" && peer == "ben")));
    }
}

#[test]
fn long_press_explains_a_partial_result_without_requesting_another_test() {
    let s = Screen::new(360., true);
    let mut n = network();
    n.speed.peers.insert(
        "ben".into(),
        reading(SpeedPhase::Failed("Peer timed out".into())),
    );
    let draw = |time, events| s.frame_at(&n, Some(time), events);
    draw(0., vec![]);
    let pos = positions(&draw(0.1, vec![]), |s| s.contains("Retry"))[0];
    let touch = |phase| egui::Event::Touch {
        device_id: egui::TouchDeviceId(0),
        id: egui::TouchId(1),
        phase,
        pos,
        force: None,
    };
    let pointer = |pressed| egui::Event::PointerButton {
        pos,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: Default::default(),
    };
    draw(
        0.2,
        vec![
            touch(egui::TouchPhase::Start),
            egui::Event::PointerMoved(pos),
            pointer(true),
        ],
    );
    draw(1.2, vec![]);
    let held = draw(1.3, vec![]);
    let tips = positions(&held, |text| {
        text.contains("Peer timed out")
            && text.contains("at least 35.99 Mbit/s")
            && text.contains("Path at start  wg direct")
    });
    assert_eq!(tips.len(), 1);
    draw(
        1.4,
        vec![
            touch(egui::TouchPhase::End),
            pointer(false),
            egui::Event::PointerGone,
        ],
    );
    assert!(s.log.0.borrow().is_empty());
}

#[test]
fn exit_batch_requires_an_online_capable_exit_and_stops_in_its_own_network() {
    let mut n = network();
    let s = Screen::new(360., true);
    s.frame(&n, vec![]);
    let start = positions(&s.frame(&n, vec![]), |s| s.contains("Test exits"))[0];
    n.peers[0].exit_node = false;
    s.frame(&n, vec![]);
    s.click(&n, start);
    assert!(s.log.0.borrow().is_empty());
    n.peers[0].exit_node = true;
    s.frame(&n, vec![]);
    s.click(&n, start);
    n.speed.batch = Some(SpeedBatchReport { done: 0, total: 1 });
    let batch = s.frame(&n, vec![]);
    assert!(!positions(&batch, |s| s.contains("0/1")).is_empty());
    s.click(&n, positions(&batch, |s| s.contains("Stop"))[0]);
    assert!(matches!(s.log.0.borrow().as_slice(), [
        Command::StartSpeedTest { network_id, peer: None },
        Command::StopSpeedTest { network_id: stopped },
    ] if network_id == "network" && stopped == network_id));
}
