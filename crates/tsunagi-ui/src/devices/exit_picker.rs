//! The remote-exit chooser. Each radio row is one touch target, including its telemetry.
use super::{ExitConfirm, devices, rtt_text};
use crate::exit;
use egui::{Align2, FontId, Pos2, Rect, Sense, Ui};
use tsunagi::ipc::{DataPathReport, NetworkReport};

/// Draw the selectable exits for one network and return a choice for confirmation.
pub fn choose_exit(ui: &mut Ui, network: &NetworkReport, own: &str) -> Option<ExitConfirm> {
    ui.heading(&network.name);
    if let Some(rules) = &network.exit.client_rules
        && !rules.ok
    {
        ui.colored_label(exit::LOUD, &rules.detail);
    }
    let width = ui.available_width();
    let (header, _) = ui.allocate_exact_size(egui::vec2(width, 22.), Sense::hover());
    let columns = Columns::new(header);
    let muted = ui.visuals().weak_text_color();
    for (x, label) in [
        (columns.name, "Exit node"),
        (columns.rtt, "Data RTT"),
        (columns.path, "Path"),
    ] {
        ui.painter().text(
            egui::pos2(x, header.center().y),
            Align2::LEFT_CENTER,
            label,
            egui::TextStyle::Small.resolve(ui.style()),
            muted,
        );
    }
    let current = network.exit.via.as_deref();
    let mut choice = None;
    let local = Row {
        peer: None,
        name: "No exit node",
        address: None,
        rtt: None,
        path: "Local",
        transport: None,
        selected: current.is_none(),
    };
    if local.draw(ui, &network.network_id)
        && let Some(id) = current
    {
        choice = Some(ExitConfirm::stop_from_tile(network, id));
    }
    let mut candidates = devices(network, own);
    candidates.retain(|d| d.exit_node || d.in_use);
    candidates.sort_by_key(|d| !d.in_use);
    if let Some(id) = current
        && !candidates.iter().any(|d| d.id == id)
    {
        Row {
            peer: Some(id),
            name: &exit::name_of(network, id),
            address: None,
            rtt: None,
            path: "Offline",
            transport: None,
            selected: true,
        }
        .draw(ui, &network.network_id);
    }
    for candidate in &candidates {
        let name = candidate.name();
        let relayed;
        let (path, transport) = if !candidate.online {
            ("Offline", None)
        } else if candidate.in_use && !network.exit.via_online || candidate.data_error.is_some() {
            ("Unavailable", None)
        } else {
            match candidate.path {
                Some(DataPathReport::Direct { transport }) => ("Direct", Some(transport.as_str())),
                Some(DataPathReport::Relayed { hops, .. }) => {
                    relayed = format!("{hops} hops");
                    ("Relayed", Some(relayed.as_str()))
                }
                _ => ("Connecting", None),
            }
        };
        let row = Row {
            peer: Some(candidate.id),
            name: &name,
            address: candidate.address.as_deref(),
            rtt: candidate.data_rtt_ms,
            path,
            transport,
            selected: candidate.in_use,
        };
        if row.draw(ui, &network.network_id) && !candidate.in_use {
            choice = Some(ExitConfirm {
                network_id: network.network_id.clone(),
                peer_id: candidate.id.into(),
                name,
                stop: false,
                main: true,
            });
        }
    }
    if !candidates.iter().any(|d| d.exit_node) {
        ui.weak("No connected peers offer an exit node.");
    }
    choice
}

struct Columns {
    name: f32,
    rtt: f32,
    path: f32,
}
impl Columns {
    fn new(rect: Rect) -> Self {
        let path = rect.right() - (rect.width() * 0.24).clamp(66., 110.);
        Self {
            name: rect.left() + 31.,
            rtt: path - 61.,
            path,
        }
    }
}

struct Row<'a> {
    peer: Option<&'a str>,
    name: &'a str,
    address: Option<&'a str>,
    rtt: Option<u64>,
    path: &'a str,
    transport: Option<&'a str>,
    selected: bool,
}
impl Row<'_> {
    fn draw(&self, ui: &mut Ui, network: &str) -> bool {
        let font = egui::TextStyle::Body.resolve(ui.style());
        let small = egui::TextStyle::Small.resolve(ui.style());
        let height = (font.size + small.size + 18.).max(52.);
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::hover());
        let id = ui.make_persistent_id(("exit choice", network, self.peer));
        let response = ui.interact(rect, id, Sense::click());
        response.widget_info(|| {
            egui::WidgetInfo::selected(
                egui::WidgetType::RadioButton,
                true,
                self.selected,
                self.name,
            )
        });
        let visuals = ui.style().interact_selectable(&response, self.selected);
        let painter = ui.painter();
        if self.selected || response.hovered() || response.has_focus() {
            painter.rect_filled(rect, 3., visuals.weak_bg_fill);
        }
        painter.hline(
            rect.x_range(),
            rect.bottom(),
            ui.visuals().widgets.noninteractive.bg_stroke,
        );
        let dot = rect.left_center() + egui::vec2(15., 0.);
        painter.circle_stroke(dot, 6., visuals.fg_stroke);
        if self.selected {
            painter.circle_filled(dot, 3., visuals.text_color());
        }
        let c = Columns::new(rect);
        let center = rect.center().y;
        let muted = ui.visuals().weak_text_color();
        let line = |x: f32, end: f32, y: f32, value: &str, font: &FontId, color| {
            let mut job =
                egui::text::LayoutJob::simple_singleline(value.into(), font.clone(), color);
            job.wrap.max_rows = 1;
            job.wrap.break_anywhere = true;
            job.wrap.max_width = (end - x - 5.).max(0.);
            let text = painter.layout_job(job);
            painter.galley(Pos2::new(x, y - text.size().y * 0.5), text, color);
        };
        let pair = |x, end, label, detail: Option<&str>| {
            let y = if detail.is_some() {
                center - small.size * 0.55
            } else {
                center
            };
            line(x, end, y, label, &font, visuals.text_color());
            if let Some(detail) = detail {
                line(x, end, center + font.size * 0.65, detail, &small, muted);
            }
        };
        pair(c.name, c.rtt, self.name, self.address);
        line(
            c.rtt,
            c.path,
            center,
            &rtt_text(self.rtt),
            &font,
            visuals.text_color(),
        );
        pair(c.path, rect.right(), self.path, self.transport);
        response.clicked()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::choose_exit;
    use egui::{CentralPanel, Context, Event, PointerButton, Pos2, RawInput, Rect, Shape};
    use tsunagi::ipc::{DataPathReport, ExitReport, MemberReport, NetworkReport, PeerReport};

    #[test]
    fn exit_table_fits_phone_widths_and_the_whole_row_selects_the_exact_peer() {
        let mut network = NetworkReport {
            name: "lab".into(),
            network_id: "network-id".into(),
            exit: ExitReport {
                via: Some("old-id".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        for (id, name, offer) in [
            ("new-id", "west", true),
            ("self", "my-phone", true),
            ("ordinary", "worker", false),
        ] {
            network.peers.push(PeerReport {
                endpoint_id: id.into(),
                hostname: Some(name.into()),
                data_rtt_ms: Some(37),
                rtt_ms: Some(142),
                path: DataPathReport::Direct {
                    transport: "wg".into(),
                },
                exit_node: offer,
                ..Default::default()
            });
        }
        network.members.push(MemberReport {
            endpoint_id: "old-id".into(),
            hostname: Some("east".into()),
            ..Default::default()
        });
        network.members.push(MemberReport {
            endpoint_id: "new-id".into(),
            hostname: Some("west".into()),
            overlay_address_v4: Some("10.9.0.4".into()),
            ..Default::default()
        });
        for width in [320., 430.] {
            let ctx = Context::default();
            let frame = |events| {
                let mut chosen = None;
                let out = ctx.run(
                    RawInput {
                        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(width, 640.))),
                        events,
                        ..Default::default()
                    },
                    |ctx| {
                        CentralPanel::default().show(ctx, |ui| {
                            chosen = choose_exit(ui, &network, "self");
                        });
                    },
                );
                (out, chosen)
            };
            let (out, initial) = frame(Vec::new());
            assert!(initial.is_none());
            let labels: Vec<_> = out
                .shapes
                .iter()
                .filter_map(|s| match &s.shape {
                    Shape::Text(t) => Some((t.galley.text(), t.visual_bounding_rect())),
                    _ => None,
                })
                .collect();
            for text in [
                "No exit node",
                "east",
                "west",
                "10.9.0.4",
                "37 ms",
                "Direct",
                "wg",
                "Offline",
            ] {
                assert!(
                    labels.iter().any(|(label, _)| *label == text),
                    "missing {text}"
                );
            }
            assert!(
                !labels
                    .iter()
                    .any(|(label, _)| matches!(*label, "my-phone" | "worker"))
            );
            assert!(
                labels
                    .iter()
                    .all(|(_, r)| r.left() >= 0. && r.right() <= width + 1.)
            );
            let y = |name| {
                labels
                    .iter()
                    .find(|(label, _)| *label == name)
                    .unwrap()
                    .1
                    .center()
                    .y
            };
            assert!(y("west") - y("east") >= 44.);
            let tap = |name| {
                let pos = egui::pos2(width - 14., y(name) + 8.0);
                frame(vec![
                    Event::PointerMoved(pos),
                    Event::PointerButton {
                        pos,
                        button: PointerButton::Primary,
                        pressed: true,
                        modifiers: Default::default(),
                    },
                ]);
                frame(vec![Event::PointerButton {
                    pos,
                    button: PointerButton::Primary,
                    pressed: false,
                    modifiers: Default::default(),
                }])
                .1
            };
            assert!(tap("east").is_none());
            let select = tap("west").unwrap();
            assert!(!select.stop);
            assert_eq!(
                (select.network_id.as_str(), select.peer_id.as_str()),
                ("network-id", "new-id")
            );
            let stop = tap("No exit node").unwrap();
            assert!(stop.stop);
            assert_eq!(stop.peer_id, "old-id");
        }
    }
}
