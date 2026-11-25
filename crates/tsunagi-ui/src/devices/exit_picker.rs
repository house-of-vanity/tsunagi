//! One touch target per exit, grouped by the network that will carry the traffic.
use super::{ExitConfirm, devices};
use crate::{exit, format, widgets};
use egui::{Align, Align2, Color32, FontFamily, FontId, Rect, Sense, Ui, pos2, vec2};
use egui_phosphor::regular as icon;
use tsunagi::ipc::{DataPathReport, NetworkReport};

/// The per-network view uses the same chooser as the complete Android list.
pub fn choose_exit(ui: &mut Ui, network: &NetworkReport, own: &str) -> Option<ExitConfirm> {
    choose_exit_from_networks(ui, std::slice::from_ref(network), own)
}

/// Local internet is one device-wide choice. Each peer selection keeps its network ID.
pub fn choose_exit_from_networks(
    ui: &mut Ui,
    networks: &[NetworkReport],
    own: &str,
) -> Option<ExitConfirm> {
    let current = networks
        .iter()
        .find_map(|n| n.exit.via.as_deref().map(|via| (n, via)));
    let local = Row {
        name: "No exit node",
        caption: "Use this phone’s connection",
        latency: None,
        path: None,
        selected: current.is_none(),
        glyph: icon::GLOBE,
    };
    let mut choice = None;
    if local.draw(ui, "local internet")
        && let Some((network, id)) = current
    {
        choice = Some(ExitConfirm::stop_from_tile(network, id));
    }
    let mut groups: Vec<_> = networks
        .iter()
        .filter(|n| {
            n.exit.via.is_some()
                || n.active && n.peers.iter().any(|p| p.exit_node && p.endpoint_id != own)
        })
        .collect();
    groups.sort_by_key(|n| (n.exit.via.is_none(), n.name.to_lowercase(), &n.network_id));
    if groups.is_empty() {
        ui.add_space(12.);
        ui.label(
            egui::RichText::new(if networks.is_empty() {
                "Join a network to choose an exit node."
            } else if networks.iter().all(|n| !n.active) {
                "Start a network to choose an exit node."
            } else {
                "No connected peers offer an exit node."
            })
            .size(16.),
        );
    }
    for network in groups {
        let ambiguous = networks
            .iter()
            .any(|n| n.name == network.name && n.network_id != network.network_id && n.active);
        let title = if ambiguous {
            format!("{} · {}", network.name, format::short(&network.network_id))
        } else {
            network.name.clone()
        };
        ui.add_space(10.);
        let (header, hint) =
            ui.allocate_exact_size(vec2(ui.available_width(), 30.), Sense::hover());
        widgets::single_line(
            ui.painter(),
            header,
            Align::Min,
            &title,
            bold(19.),
            ui.visuals().strong_text_color(),
        );
        widgets::hint(hint, &network.network_id);
        if let Some(rules) = &network.exit.client_rules
            && !rules.ok
        {
            ui.colored_label(exit::LOUD, &rules.detail);
        }
        let mut candidates = devices(network, own);
        candidates.retain(|d| d.exit_node || d.in_use);
        candidates.sort_by_key(|d| !d.in_use);
        if let Some(id) = network.exit.via.as_deref()
            && !candidates.iter().any(|d| d.id == id)
        {
            Row {
                name: &exit::name_of(network, id),
                caption: "",
                latency: None,
                path: Some("Offline"),
                selected: true,
                glyph: icon::SIGN_OUT,
            }
            .draw(ui, (&network.network_id, id));
        }
        for d in candidates {
            let name = d.name();
            let path = if !d.online {
                "Offline".into()
            } else if d.in_use && !network.exit.via_online || d.data_error.is_some() {
                "Unavailable".into()
            } else {
                match d.path {
                    Some(DataPathReport::Direct { transport }) => format!("Direct · {transport}"),
                    Some(DataPathReport::Relayed { hops, .. }) => {
                        format!("Relay · {hops} {}", if *hops == 1 { "hop" } else { "hops" })
                    }
                    _ => "Connecting".into(),
                }
            };
            let latency = d.data_rtt_ms.map(|ms| format!("{ms} ms"));
            let row = Row {
                name: &name,
                caption: d.address.as_deref().unwrap_or(""),
                latency: latency.as_deref(),
                path: Some(&path),
                selected: d.in_use,
                glyph: icon::SIGN_OUT,
            };
            if row.draw(ui, (&network.network_id, d.id)) && !d.in_use {
                choice = Some(ExitConfirm {
                    network_id: network.network_id.clone(),
                    peer_id: d.id.into(),
                    name: format!("{name} · {title}"),
                    stop: false,
                    main: true,
                });
            }
        }
    }
    choice
}

fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("Bold".into()))
}

/// Foreground and background for primary actions in the phone's light and dark themes.
pub fn exit_action_colors(dark: bool) -> (Color32, Color32) {
    if dark {
        (
            Color32::from_rgb(141, 216, 244),
            Color32::from_rgb(9, 37, 50),
        )
    } else {
        (Color32::from_rgb(15, 88, 117), Color32::WHITE)
    }
}

struct Row<'a> {
    name: &'a str,
    caption: &'a str,
    latency: Option<&'a str>,
    path: Option<&'a str>,
    selected: bool,
    glyph: &'static str,
}
impl Row<'_> {
    fn draw(&self, ui: &mut Ui, id: impl std::hash::Hash) -> bool {
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 58.), Sense::hover());
        let response = ui.interact(
            rect,
            ui.make_persistent_id(("exit choice", id)),
            Sense::click(),
        );
        response.widget_info(|| {
            egui::WidgetInfo::selected(
                egui::WidgetType::RadioButton,
                true,
                self.selected,
                self.name,
            )
        });
        let dark = ui.visuals().dark_mode;
        let (text, detail, surface, selected_fill, accent) = if dark {
            (
                Color32::from_rgb(244, 248, 250),
                Color32::from_rgb(188, 202, 212),
                Color32::from_rgb(39, 45, 50),
                Color32::from_rgb(28, 58, 71),
                Color32::from_rgb(141, 216, 244),
            )
        } else {
            (
                Color32::from_rgb(25, 38, 47),
                Color32::from_rgb(65, 86, 100),
                Color32::from_rgb(238, 242, 245),
                Color32::from_rgb(219, 240, 248),
                Color32::from_rgb(15, 88, 117),
            )
        };
        let painter = ui.painter();
        painter.rect_filled(
            rect,
            8.,
            if self.selected {
                selected_fill
            } else {
                surface
            },
        );
        if self.selected || response.hovered() || response.has_focus() {
            painter.rect_stroke(rect, 8., (1_f32, accent), egui::StrokeKind::Inside);
        }
        let glyph = if self.selected {
            icon::CHECK_CIRCLE
        } else {
            self.glyph
        };
        painter.text(
            pos2(rect.left() + 22., rect.center().y),
            Align2::CENTER_CENTER,
            glyph,
            FontId::proportional(23.),
            if self.selected { accent } else { detail },
        );
        let left = rect.left() + 44.;
        let right = rect.right() - 12.;
        let split = if self.path.is_some() {
            right - (rect.width() * 0.36).clamp(93., 142.)
        } else {
            right
        };
        let cell = |x, end, y, h| Rect::from_min_size(pos2(x, y), vec2(end - x, h));
        let line = |bounds, align, value, font, color| {
            widgets::single_line(painter, bounds, align, value, font, color)
        };
        let one = |x, end| cell(x, end, rect.top(), rect.height());
        let top = |x, end| cell(x, end, rect.top() + 5., 26.);
        let bottom = |x, end| cell(x, end, rect.top() + 32., 20.);
        line(
            if self.caption.is_empty() {
                one(left, split)
            } else {
                top(left, split)
            },
            Align::Min,
            self.name,
            bold(19.),
            text,
        );
        if !self.caption.is_empty() {
            line(
                bottom(left, split),
                Align::Min,
                self.caption,
                FontId::proportional(15.),
                detail,
            );
        }
        if let Some(path) = self.path {
            if let Some(rtt) = self.latency {
                line(
                    top(split + 4., right),
                    Align::Max,
                    rtt,
                    FontId::proportional(17.),
                    text,
                );
            }
            line(
                if self.latency.is_some() {
                    bottom(split + 4., right)
                } else {
                    one(split + 4., right)
                },
                Align::Max,
                path,
                FontId::proportional(15.),
                detail,
            );
        }
        response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::choose_exit_from_networks;
    use egui::{CentralPanel, Context, Event, PointerButton, Pos2, RawInput, Rect, Shape};
    use tsunagi::ipc::{DataPathReport, ExitReport, MemberReport, NetworkReport, PeerReport};

    #[test]
    fn exit_table_fits_phone_widths_and_the_whole_row_selects_the_exact_peer() {
        let mut network = NetworkReport {
            active: true,
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
        let mut other = network.clone();
        other.name = "work".into();
        other.network_id = "other-network".into();
        other.exit = ExitReport::default();
        other.peers[0].hostname = Some("office".into());
        other
            .members
            .iter_mut()
            .find(|m| m.endpoint_id == "new-id")
            .unwrap()
            .hostname = Some("office".into());
        let networks = [network, other];
        for width in [320., 430.] {
            let ctx = Context::default();
            ctx.set_fonts(crate::app_fonts());
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
                            chosen = choose_exit_from_networks(ui, &networks, "self");
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
                "Direct · wg",
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
            let office = tap("office").unwrap();
            assert_eq!(
                (office.network_id.as_str(), office.peer_id.as_str()),
                ("other-network", "new-id")
            );
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
