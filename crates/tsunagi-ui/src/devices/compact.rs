//! One line per member and one expanded detail block, with no horizontal scroller.
use super::{
    AMBER, Device, ExitConfirm, ForgetConfirm, NetworkReport, Traffic, Unit, data_path_text,
    devices, exit, forget_button, format, icon, rtt_text, tunnel_cell,
};

pub(super) fn roster(
    ui: &mut egui::Ui,
    network: &NetworkReport,
    own_id: &str,
    traffic: &Traffic,
    unit: Unit,
    (exit, forget): (&mut Option<ExitConfirm>, &mut Option<ForgetConfirm>),
) {
    let members = devices(network, own_id);
    let online = members.iter().filter(|m| m.online).count();
    ui.strong(format!(
        "devices ({} online / {} known)",
        online,
        members.len()
    ));
    let id = ui.make_persistent_id(("expanded device", &network.network_id));
    let mut selected = ui.data(|d| d.get_temp::<String>(id));
    let width = ui.available_width();
    let font = egui::TextStyle::Body.resolve(ui.style());
    let measure = |s: &str| {
        ui.painter()
            .layout_no_wrap(s.to_owned(), font.clone(), ui.visuals().text_color())
            .size()
            .x
    };
    let rtt_x = width - (measure("9999 ms") + 18.0).min(width * 0.25);
    let ip_x = rtt_x - (measure("255.255.255.255") + 14.0).min(width * 0.40);
    let offsets = [16.0, ip_x, rtt_x];
    let size = egui::vec2(width, ui.text_style_height(&egui::TextStyle::Body) + 8.0);
    ui.spacing_mut().item_spacing.y = 1.0;
    let (header, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    for (x, title) in offsets.into_iter().zip(["device", "IPv4", "RTT"]) {
        ui.painter().text(
            header.left_center() + egui::vec2(x, 0.),
            egui::Align2::LEFT_CENTER,
            title,
            font.clone(),
            ui.visuals().weak_text_color(),
        );
    }
    for (index, member) in members.iter().enumerate() {
        let (row, _) = ui.allocate_exact_size(size, egui::Sense::hover());
        let response = ui.interact(row, id.with(member.id), egui::Sense::click());
        if response.clicked() {
            selected = (selected.as_deref() != Some(member.id)).then(|| member.id.to_owned());
        }
        let open = selected.as_deref() == Some(member.id);
        if open || index % 2 == 0 {
            ui.painter().rect_filled(
                row,
                2.0,
                if open {
                    ui.visuals().widgets.hovered.weak_bg_fill
                } else {
                    ui.visuals().faint_bg_color
                },
            );
        }
        let dot = row.left_center() + egui::vec2(6., 0.);
        if member.online {
            ui.painter().circle_filled(dot, 3., exit::GOOD);
        } else {
            ui.painter().circle_stroke(
                dot,
                3.,
                egui::Stroke::new(1.0_f32, ui.visuals().weak_text_color()),
            );
        }
        let name = member.name();
        let rtt = rtt_text(member.control_rtt_ms);
        let labels = [
            name.as_str(),
            member.address.as_deref().unwrap_or("—"),
            rtt.as_str(),
        ];
        let color = if member.online {
            ui.visuals().text_color()
        } else {
            ui.visuals().weak_text_color()
        };
        for ((x, end), label) in offsets
            .into_iter()
            .zip([ip_x, rtt_x, width - 13.0])
            .zip(labels)
        {
            let mut job =
                egui::text::LayoutJob::simple_singleline(label.into(), font.clone(), color);
            job.wrap.max_rows = 1;
            job.wrap.max_width = (end - x - 4.0).max(0.0);
            job.wrap.break_anywhere = true;
            let galley = ui.painter().layout_job(job);
            let origin = row.left_center() + egui::vec2(x, -galley.size().y * 0.5);
            ui.painter().galley(origin, galley, color);
        }
        ui.painter().text(
            row.right_center(),
            egui::Align2::RIGHT_CENTER,
            if open {
                icon::CARET_DOWN
            } else {
                icon::CARET_RIGHT
            },
            font.clone(),
            ui.visuals().weak_text_color(),
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
    ui.horizontal_wrapped(|ui| {
        ui.weak(if member.online { "online" } else { "offline" });
        if let Some(name) = &member.copy {
            format::copy_field(ui, &member.name(), name);
        }
        if let Some(address) = &member.address {
            format::copy_field(ui, address, address);
        }
    });
    ui.horizontal_wrapped(|ui| {
        ui.weak("Endpoint ID");
        format::copy_field(ui, &format::short(member.id), member.id);
    });
    let (path, _) = data_path_text(member.path, member.via_name.as_deref(), member.online);
    ui.horizontal_wrapped(|ui| {
        ui.label(path);
        tunnel_cell(ui, member);
    });
    if let Some(error) = member.data_error {
        ui.colored_label(AMBER, error);
    }
    if let Some((taken, holder)) = &member.name_taken {
        ui.colored_label(AMBER, format!("Name {taken} belongs to {holder}."));
    }
    if let Some(peer) = member.overlay {
        let series = traffic.peer(&network.network_id, &peer.public_key);
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "TX {} · {} pkts",
                format::bytes(peer.tx_bytes as f64),
                peer.tx_packets
            ));
            ui.label(format!(
                "RX {} · {} pkts",
                format::bytes(peer.rx_bytes as f64),
                peer.rx_packets
            ));
            ui.weak(format::series_rate(series, unit));
        });
        format::sparkline(ui, series, unit, 22.);
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
    ui.separator();
}
