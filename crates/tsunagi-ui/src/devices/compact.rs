//! A width-constrained device table for touch. Optional columns move into the
//! expanded row before any essential columns run out of space.
use super::{
    AMBER, Device, ExitConfirm, ForgetConfirm, NetworkReport, Traffic, Unit, data_path_text, exit,
    forget_button, format, icon, rtt_text, speed, traffic_pair, tunnel_cell,
};
use crate::widgets;
use egui::{Align2, Color32, FontId, Rect, Sense, Ui, Vec2, pos2, vec2};

#[derive(Clone, Copy)]
enum Column {
    Device,
    Speed,
    State,
    Address,
    Rtt,
    Traffic,
    Version,
    Path,
    Plot,
}

impl Column {
    fn title(self, unit: Unit) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Speed => speed::HEADER,
            Self::State => "State",
            Self::Address => "IPv4",
            Self::Rtt => "Data RTT",
            Self::Traffic if unit == Unit::Bytes => "bytes (TX / RX)",
            Self::Traffic => "pkts (TX / RX)",
            Self::Version => "Version",
            Self::Path => "Data path",
            Self::Plot => "Traffic / s",
        }
    }
}

fn columns(ui: &Ui, width: f32, landscape: bool, unit: Unit) -> Vec<(Column, f32)> {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let measure = |s: &str| {
        ui.painter()
            .layout_no_wrap(s.into(), font.clone(), Color32::WHITE)
            .size()
            .x
            + 10.
    };
    let mut cols = vec![
        (Column::Device, 0.),
        (
            Column::Speed,
            if landscape {
                speed::WIDTH.min(width * 0.28)
            } else {
                speed::PORTRAIT_WIDTH.min(width * 0.18)
            },
        ),
    ];
    if landscape && width >= 510. {
        cols.push((Column::State, measure("Control only").min(width * 0.16)));
    }
    cols.push((
        Column::Address,
        measure("255.255.255.255").min(width * if landscape { 0.27 } else { 0.35 }),
    ));
    cols.push((
        Column::Rtt,
        measure("9999 ms").min(width * if landscape { 0.15 } else { 0.22 }),
    ));
    if landscape && width >= 420. {
        cols.push((
            Column::Traffic,
            measure(Column::Traffic.title(unit))
                .max(measure("999 MB / 999 MB"))
                .min(width * 0.29),
        ));
        let mut spare = width - cols.iter().map(|c| c.1).sum::<f32>() - 122.;
        for (column, desire) in [
            (Column::Version, measure("v1.0.4-rc.1")),
            (Column::Path, measure("tcp-tls direct")),
            (Column::Plot, 110.),
        ] {
            if spare < desire {
                break;
            }
            cols.push((column, desire));
            spare -= desire;
        }
    }
    let other: f32 = cols.iter().map(|c| c.1).sum();
    // Reserve the disclosure arrow at the end, including on small split screens.
    cols[0].1 = (width - other - 16.).max(0.);
    cols
}

fn text_cell(ui: &Ui, rect: Rect, text: &str, font: &FontId, color: Color32) {
    let mut job = egui::text::LayoutJob::simple_singleline(text.into(), font.clone(), color);
    job.wrap.max_rows = 1;
    job.wrap.max_width = (rect.width() - 3.).max(0.);
    job.wrap.break_anywhere = true;
    let galley = ui.painter().layout_job(job);
    let pos = pos2(rect.left(), rect.center().y - galley.size().y / 2.);
    ui.painter_at(rect).galley(pos, galley, color);
}

pub(super) fn roster(
    ui: &mut Ui,
    network: &NetworkReport,
    members: &[Device<'_>],
    traffic: &Traffic,
    unit: Unit,
    (exit, forget): (&mut Option<ExitConfirm>, &mut Option<ForgetConfirm>),
    speed: &speed::Controls<'_>,
) {
    // An Android rotation changes the surrounding scroll area but not the selected peer.
    let id = egui::Id::new(("expanded device", &network.network_id));
    let mut selected = ui.data(|d| d.get_temp::<String>(id));
    let width = ui.available_width();
    let columns = columns(ui, width, widgets::landscape(ui.ctx()), unit);
    let font = egui::TextStyle::Body.resolve(ui.style());
    let size = vec2(width, ui.text_style_height(&egui::TextStyle::Body) + 9.);
    ui.spacing_mut().item_spacing.y = 1.;
    let (header, _) = ui.allocate_exact_size(size, Sense::hover());
    let mut x = header.left();
    for &(column, w) in &columns {
        let mut rect = Rect::from_min_size(pos2(x, header.top()), vec2(w, size.y));
        if matches!(column, Column::Device) {
            rect.min.x += 20.;
        }
        if matches!(column, Column::Speed) {
            ui.painter_at(rect).text(
                rect.center(),
                Align2::CENTER_CENTER,
                column.title(unit),
                font.clone(),
                ui.visuals().text_color(),
            );
            let r = ui.interact(rect, id.with("speed units"), Sense::click());
            widgets::hint(r, speed::HEADER_HINT);
        } else {
            text_cell(
                ui,
                rect,
                column.title(unit),
                &font,
                ui.visuals().text_color(),
            );
        }
        x += w;
    }
    for (index, member) in members.iter().enumerate() {
        let (row, _) = ui.allocate_exact_size(size, Sense::hover());
        let response = ui.interact(row, id.with(member.id), Sense::click());
        let clicked = response.clicked();
        let exit_hint = if member.in_use {
            " · Selected internet exit"
        } else if member.exit_node {
            " · Offers an exit node"
        } else {
            ""
        };
        let description = format!("{} · {}{exit_hint}", member.name(), member.channel_hint());
        response.widget_info(|| {
            egui::WidgetInfo::labeled(
                egui::WidgetType::SelectableLabel,
                response.enabled(),
                &description,
            )
        });
        widgets::hint(response, &description);
        if clicked {
            selected = (selected.as_deref() != Some(member.id)).then(|| member.id.to_owned());
        }
        let open = selected.as_deref() == Some(member.id);
        if open || index % 2 == 0 {
            ui.painter().rect_filled(
                row,
                2.,
                if open {
                    ui.visuals().widgets.hovered.weak_bg_fill
                } else {
                    ui.visuals().faint_bg_color
                },
            );
        }
        let channel = member.channel();
        let normal = if member.online {
            ui.visuals().text_color()
        } else {
            channel.color(ui)
        };
        let mut x = row.left();
        for &(column, w) in &columns {
            let mut rect = Rect::from_min_size(pos2(x, row.top()), vec2(w, row.height()));
            x += w;
            let text = match column {
                Column::Speed => {
                    speed.cell(ui, rect, member);
                    continue;
                }
                Column::Device => {
                    channel.paint(
                        ui,
                        Rect::from_center_size(rect.left_center() + vec2(9., 0.), Vec2::splat(16.)),
                    );
                    rect.min.x += 20.;
                    if member.in_use || member.exit_node {
                        ui.painter_at(rect).text(
                            rect.right_center(),
                            Align2::RIGHT_CENTER,
                            icon::SIGN_OUT,
                            font.clone(),
                            if member.in_use { exit::GOOD } else { normal },
                        );
                        rect.max.x -= font.size + 3.;
                    }
                    member.name()
                }
                Column::State => channel.label().into(),
                Column::Address => member.address.as_deref().unwrap_or("—").into(),
                Column::Rtt => rtt_text(member.data_rtt_ms),
                Column::Version => member.version_label(),
                Column::Path => {
                    data_path_text(member.path, member.via_name.as_deref(), member.online)
                }
                Column::Traffic => member.overlay.filter(|_| member.online).map_or_else(
                    || "—".into(),
                    |peer| {
                        let (tx, rx) = unit.counters(peer);
                        traffic_pair(tx, rx, unit)
                    },
                ),
                Column::Plot => {
                    if let Some(peer) = member.overlay.filter(|_| member.online) {
                        let mut plot = ui.new_child(
                            egui::UiBuilder::new()
                                .max_rect(rect.shrink2(vec2(2., 2.)))
                                .layout(egui::Layout::top_down(egui::Align::Min)),
                        );
                        format::sparkline(
                            &mut plot,
                            traffic.peer(&network.network_id, &peer.public_key),
                            unit,
                            rect.height() - 4.,
                        );
                    }
                    continue;
                }
            };
            text_cell(
                ui,
                rect,
                &text,
                &font,
                if matches!(column, Column::State) {
                    channel.color(ui)
                } else {
                    normal
                },
            );
        }
        ui.painter().text(
            row.right_center(),
            Align2::RIGHT_CENTER,
            if open {
                icon::CARET_DOWN
            } else {
                icon::CARET_RIGHT
            },
            font.clone(),
            ui.visuals().text_color(),
        );
        if open {
            ui.push_id(member.id, |ui| {
                details(ui, network, member, traffic, unit, exit, forget)
            });
        }
    }
    ui.data_mut(|d| match selected {
        Some(member) => d.insert_temp(id, member),
        None => d.remove::<String>(id),
    });
}

fn details(
    ui: &mut egui::Ui,
    network: &NetworkReport,
    member: &Device<'_>,
    traffic: &Traffic,
    unit: Unit,
    exit: &mut Option<ExitConfirm>,
    forget: &mut Option<ForgetConfirm>,
) {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 4.0;
            ui.columns(2, |cols| {
                cols[0].small("Data path");
                let path = data_path_text(member.path, member.via_name.as_deref(), member.online);
                cols[0].horizontal_wrapped(|ui| {
                    ui.label(path);
                    if member.online {
                        tunnel_cell(ui, member);
                    }
                });
                cols[1].small("Tsunagi version");
                cols[1].label(member.agent_version.unwrap_or("Unknown"));
            });
            if let Some(path) = member.data_transport_detail {
                ui.add(egui::Label::new(path).wrap());
            }
            if member.online {
                ui.columns(2, |cols| {
                    cols[0].small("Data RTT");
                    cols[0].label(rtt_text(member.data_rtt_ms));
                    cols[1].small("Control RTT");
                    cols[1].label(rtt_text(member.control_rtt_ms));
                });
            }
            if let Some(peer) = member.overlay.filter(|_| member.online) {
                ui.separator();
                let (tx, rx) = unit.counters(peer);
                let sent_color = ui.visuals().hyperlink_color;
                ui.columns(2, |cols| {
                    for (col, arrow, caption, count, color) in [
                        (0, icon::ARROW_UP, "Sent", tx, sent_color),
                        (1, icon::ARROW_DOWN, "Received", rx, exit::GOOD),
                    ] {
                        cols[col].horizontal(|ui| {
                            ui.colored_label(color, arrow);
                            ui.label(caption);
                        });
                        let value = format::amount(count, unit);
                        let value = match unit {
                            Unit::Packets => format!("{value} pkts"),
                            Unit::Bytes => value,
                        };
                        let size = cols[col].text_style_height(&egui::TextStyle::Body) + 2.0;
                        cols[col].label(egui::RichText::new(value).size(size).strong());
                    }
                });
                format::sparkline(
                    ui,
                    traffic.peer(&network.network_id, &peer.public_key),
                    unit,
                    28.0,
                );
            }
            ui.separator();
            ui.columns(2, |cols| {
                cols[0].small("Endpoint ID");
                format::copy_field(&mut cols[0], &format::short(member.id), member.id);
                cols[1].small("IPv4");
                if let Some(address) = &member.address {
                    format::copy_field(&mut cols[1], address, address);
                } else {
                    cols[1].weak("—");
                }
            });
            if let Some(name) = &member.copy {
                format::copy_field(ui, name, name);
            }
            if let Some(error) = member.data_error {
                ui.colored_label(member.channel().color(ui), error);
            }
            if let Some((taken, holder)) = &member.name_taken {
                ui.colored_label(AMBER, format!("Name {taken} belongs to {holder}."));
            }
            if (member.exit_node || member.in_use)
                && ui
                    .button(if member.in_use {
                        "Stop using exit node"
                    } else {
                        "Use exit node"
                    })
                    .clicked()
            {
                *exit = Some(ExitConfirm {
                    network_id: network.network_id.clone(),
                    peer_id: member.id.into(),
                    name: member.name(),
                    stop: member.in_use,
                    main: false,
                });
            }
            forget_button(ui, member, network, forget);
        });
}
