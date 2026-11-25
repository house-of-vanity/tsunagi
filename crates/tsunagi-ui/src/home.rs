//! Shared compact network tiles, device header and join form.
use crate::{
    client::{Client, Command},
    devices, exit, format,
    stats::{Traffic, Unit},
};
use egui_phosphor::regular as icon;
use std::collections::BTreeSet;
use tsunagi::ipc::{NetworkReport, StatusReport};
use zeroize::{Zeroize, Zeroizing};

const BAD: egui::Color32 = egui::Color32::from_rgb(0xd0, 0x4a, 0x3c);
/// A neutral, not-garish red for the Leave button.
const LEAVE_RED: egui::Color32 = egui::Color32::from_rgb(0xa8, 0x3a, 0x3a);

/// Join form fields.
#[derive(Default)]
pub struct JoinForm {
    /// Visible network name.
    pub name: String,
    /// User-entered network secret.
    pub secret: Zeroizing<String>,
}

/// Local UI state kept across frames.
pub struct UiState {
    /// Join form draft.
    pub join: JoinForm,
    /// Whether rates and sparklines are shown in packets or bytes.
    pub unit: Unit,
    /// Network details opened during this run, keyed by identity even for namesakes.
    expanded_networks: BTreeSet<String>,
    /// An in-progress hostname edit (`None` when not editing).
    pub host_edit: Option<String>,
    /// Network ids whose devices window is open.
    pub open_devices: BTreeSet<String>,
    /// Per-network VIP drafts.
    pub vip_windows: std::collections::BTreeMap<String, crate::vip::Window>,
    /// Whether the About window is open.
    pub about_open: bool,
    /// An exit-node choice waiting for the user to confirm it.
    pub exit_confirm: Option<devices::ExitConfirm>,
    /// A selected offline claim waiting for cleanup confirmation.
    pub forget_confirm: Option<devices::ForgetConfirm>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            join: JoinForm::default(),
            unit: Unit::Bytes,
            expanded_networks: BTreeSet::new(),
            host_edit: None,
            open_devices: BTreeSet::new(),
            vip_windows: Default::default(),
            about_open: false,
            exit_confirm: None,
            forget_confirm: None,
        }
    }
}

/// The device header: id (with a copy button) and an editable hostname.
pub fn draw_header(
    ui: &mut egui::Ui,
    agent: &dyn Client,
    state: &mut UiState,
    report: &StatusReport,
) {
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.weak("device");
        // Clicking the shortened id copies the full one.
        format::copy_field(ui, &format::short(&report.endpoint_id), &report.endpoint_id);
    });

    ui.horizontal(|ui| {
        ui.weak("host");
        match &mut state.host_edit {
            None => {
                ui.label(&report.hostname);
                if ui
                    .small_button(icon::PENCIL_SIMPLE)
                    .on_hover_text("rename")
                    .clicked()
                {
                    state.host_edit = Some(report.hostname.clone());
                }
            }
            Some(buffer) => {
                let response = ui.add(egui::TextEdit::singleline(buffer).desired_width(150.0));
                let submit = (response.lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    || ui.small_button(icon::CHECK).on_hover_text("save").clicked();
                if submit {
                    agent.send(Command::SetHostname(buffer.trim().to_string()));
                    state.host_edit = None;
                } else if ui.small_button(icon::X).on_hover_text("cancel").clicked() {
                    state.host_edit = None;
                }
            }
        }
    });

    if !report.cache_healthy {
        ui.colored_label(
            egui::Color32::from_rgb(0xd9, 0x9a, 0x00),
            "cache unavailable",
        );
    }
    if let Some(error) = &report.overlay_config_error {
        ui.colored_label(BAD, format!("Shared overlay interface {error}"));
    }
}

/// One compact network tile.
pub fn draw_network(
    ui: &mut egui::Ui,
    agent: &dyn Client,
    state: &mut UiState,
    traffic: &Traffic,
    network: &NetworkReport,
    report: &StatusReport,
    offer_exit: bool,
) -> bool {
    let mut pick_exit = false;
    ui.add_space(5.0);
    ui.push_id(&network.network_id, |ui| {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            let mut open = state.expanded_networks.contains(&network.network_id);
            let status = if network.active {
                format!(
                    "{} online",
                    devices::online_count(network, &report.endpoint_id)
                )
            } else {
                "Stopped".to_owned()
            };
            if network_header(ui, &network.name, &status, open).clicked() {
                open = !open;
                if open {
                    state.expanded_networks.insert(network.network_id.clone());
                } else {
                    state.expanded_networks.remove(&network.network_id);
                }
            }
            if let Some(via) = &network.exit.via {
                draw_selected_exit(ui, network, via, state);
            }
            for warning in exit::warnings(network) {
                draw_exit_warning(ui, &warning);
            }
            if !network.range_conflicts.is_empty() {
                ui.colored_label(BAD, "Stopped: overlapping network ranges");
            }
            if !open {
                return;
            }

            ui.separator();
            draw_metadata(ui, network, &report.endpoint_id);
            draw_protocols(ui, agent, network, &report.available_protocols);
            format::sparkline(ui, traffic.network(&network.network_id), state.unit, 34.0);

            pick_exit = network_settings(ui, agent, network, offer_exit);
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                if ui
                    .button(format!("{} Copy secret", icon::COPY))
                    .on_hover_text("Copy this network's secret to the clipboard")
                    .clicked()
                {
                    agent.send(Command::CopySecret {
                        network_id: network.network_id.clone(),
                    });
                }
                if ui.button("Show devices").clicked() {
                    state.open_devices.insert(network.network_id.clone());
                }
                if ui.button("VIP").clicked() {
                    state
                        .vip_windows
                        .entry(network.network_id.clone())
                        .or_default();
                }
            });
        });
    });
    pick_exit
}

fn draw_metadata(ui: &mut egui::Ui, network: &NetworkReport, own_id: &str) {
    egui::Grid::new(ui.id().with("metadata"))
        .num_columns(2)
        .spacing([10.0, 3.0])
        .show(ui, |ui| {
            ui.weak("name");
            format::copy_field(ui, &network.name, &network.name);
            ui.end_row();
            ui.weak("id");
            format::copy_field(ui, &format::short(&network.network_id), &network.network_id);
            ui.end_row();
            if let Some(range) = &network.range {
                ui.weak("range");
                format::copy_field(ui, range, range);
                ui.end_row();
            }
            if let Some(address) = network.overlay.as_ref().and_then(|o| o.address.as_ref()) {
                ui.weak("addr");
                format::copy_field(ui, address, address);
                ui.end_row();
            }
            ui.weak("peers");
            ui.label(format!("{} known", devices::known_count(network, own_id)));
            ui.end_row();
        });
}

fn network_settings(
    ui: &mut egui::Ui,
    agent: &dyn Client,
    network: &NetworkReport,
    offer_exit: bool,
) -> bool {
    let mut pick_exit = false;
    if !network.range_conflicts.is_empty() {
        for conflict in &network.range_conflicts {
            ui.label(format!(
                "{} ({}) uses {}",
                conflict.name, conflict.network_id, conflict.range
            ));
        }
        ui.label("Switching suspends these networks until this network stops, then resumes them automatically.");
        if network.auto_start {
            ui.weak("This network will resume automatically when its range is free.");
        }
    }
    ui.horizontal_wrapped(|ui| {
        if !network.active && !network.range_conflicts.is_empty() {
            if ui.button("Switch to this network").clicked() {
                agent.send(Command::SetActive {
                    network_id: network.network_id.clone(),
                    active: true,
                });
            }
            if network.auto_start && ui.button("Keep stopped").clicked() {
                agent.send(Command::SetActive {
                    network_id: network.network_id.clone(),
                    active: false,
                });
            }
        } else {
            let mut active = network.active;
            if ui.checkbox(&mut active, "active").changed() {
                agent.send(Command::SetActive {
                    network_id: network.network_id.clone(),
                    active,
                });
            }
        }
        let mut broadcast = network.broadcast;
        if ui.checkbox(&mut broadcast, "broadcast").changed() {
            agent.send(Command::SetBroadcast {
                network_id: network.network_id.clone(),
                enabled: broadcast,
            });
        }
        if offer_exit {
            let mut offering = network.exit.offering;
            if ui
                .checkbox(&mut offering, "exit node")
                .on_hover_text("Let members send all their internet traffic through this device, which can see it.")
                .changed()
            {
                agent.send(Command::SetExitOffer {
                    network_id: network.network_id.clone(),
                    enabled: offering,
                });
            }
        } else {
            pick_exit = ui.button("Exit node…").clicked();
        }
        let leave = egui::Button::new(egui::RichText::new("Leave").color(egui::Color32::WHITE))
            .fill(LEAVE_RED);
        if ui.add(leave).clicked() {
            agent.send(Command::Leave {
                network_id: network.network_id.clone(),
            });
        }
    });
    pick_exit
}

fn network_header(ui: &mut egui::Ui, name: &str, status: &str, open: bool) -> egui::Response {
    let height = ui.text_style_height(&egui::TextStyle::Heading).max(30.0);
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::CollapsingHeader, ui.is_enabled(), name)
    });
    let visuals = ui.style().interact(&response);
    if response.hovered() || response.has_focus() {
        ui.painter().rect_filled(rect, 3.0, visuals.weak_bg_fill);
    }
    let font = egui::TextStyle::Body.resolve(ui.style());
    ui.painter().text(
        rect.left_center(),
        egui::Align2::LEFT_CENTER,
        if open {
            icon::CARET_DOWN
        } else {
            icon::CARET_RIGHT
        },
        font.clone(),
        visuals.text_color(),
    );
    let end = ui.painter().text(
        rect.right_center(),
        egui::Align2::RIGHT_CENTER,
        status,
        font.clone(),
        ui.visuals().text_color(),
    );
    let left = rect.left() + font.size + 6.0;
    let mut job = egui::text::LayoutJob::simple_singleline(
        name.into(),
        egui::FontId::new(font.size + 4.0, egui::FontFamily::Name("Bold".into())),
        ui.visuals().strong_text_color(),
    );
    job.wrap.max_width = (end.left() - left - 8.0).max(0.0);
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    let title = ui.painter().layout_job(job);
    ui.painter().galley(
        egui::pos2(left, rect.center().y - title.size().y / 2.0),
        title,
        visuals.text_color(),
    );
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(name)
}

fn draw_selected_exit(ui: &mut egui::Ui, network: &NetworkReport, via: &str, state: &mut UiState) {
    ui.horizontal_wrapped(|ui| {
        let color = if network.exit.via_online {
            exit::GOOD
        } else {
            exit::LOUD
        };
        let name = exit::name_of(network, via);
        let clicked = ui
            .add(egui::Button::new(egui::RichText::new(icon::SIGN_OUT).color(color)).frame(false))
            .on_hover_text("Stop using this exit node")
            .clicked();
        if ui
            .link(format!("Exit via {name}"))
            .on_hover_text("Stop using this exit node")
            .clicked()
            || clicked
        {
            state.exit_confirm = Some(devices::ExitConfirm::stop_from_tile(network, via));
        }
        if let Some(t) = network.exit.traffic {
            ui.label(format!(
                "{} {}",
                icon::ARROW_UP,
                format::bytes(t.tx_bytes as f64)
            ))
            .on_hover_text("Sent through this exit");
            ui.label(format!(
                "{} {}",
                icon::ARROW_DOWN,
                format::bytes(t.rx_bytes as f64)
            ))
            .on_hover_text("Received through this exit");
        }
    });
}

fn draw_protocols(
    ui: &mut egui::Ui,
    agent: &dyn Client,
    network: &NetworkReport,
    available: &[tsunagi::ipc::ProtocolReport],
) {
    let summary = if network.protocols.is_empty() {
        "none".into()
    } else {
        network.protocols.join(", ")
    };
    egui::CollapsingHeader::new(format!("data transports  {summary}"))
        .id_salt(("protocols", &network.network_id))
        .show(ui, |ui| {
            ui.weak("Order sets the first choice. Peers that support link comparison can switch to a faster enabled transport.");
            let mut selected = network.protocols.clone();
            let mut changed = false;
            ui.add_enabled_ui(!agent.busy(), |ui| {
                // Enabled items follow the user's preference; unchecked items
                // follow the agent's catalog. The worker refreshes after edits.
                let ordered: Vec<_> = network
                    .protocols
                    .iter()
                    .filter_map(|name| available.iter().find(|p| &p.name == name))
                    .chain(
                        available
                            .iter()
                            .filter(|p| !network.protocols.contains(&p.name)),
                    )
                    .collect();
                for protocol in ordered {
                    ui.horizontal(|ui| {
                        let mut on = selected.contains(&protocol.name);
                        if ui.checkbox(&mut on, &protocol.name).changed() {
                            if on {
                                selected.push(protocol.name.clone());
                            } else {
                                selected.retain(|p| p != &protocol.name);
                            }
                            changed = true;
                        }
                        if let Some(index) = selected.iter().position(|p| p == &protocol.name) {
                            if ui
                                .add_enabled(index > 0, egui::Button::new(icon::ARROW_UP))
                                .on_hover_text("prefer earlier")
                                .clicked()
                            {
                                selected.swap(index, index - 1);
                                changed = true;
                            }
                            if ui
                                .add_enabled(
                                    index + 1 < selected.len(),
                                    egui::Button::new(icon::ARROW_DOWN),
                                )
                                .on_hover_text("prefer later")
                                .clicked()
                            {
                                selected.swap(index, index + 1);
                                changed = true;
                            }
                        }
                    });
                    ui.indent(("description", &network.network_id, &protocol.name), |ui| {
                        ui.weak(&protocol.summary);
                    });
                }
            });
            if selected.is_empty() {
                ui.weak("Control only; no IP traffic in this network.");
            }
            if changed {
                agent.send(Command::SetProtocols {
                    network_id: network.network_id.clone(),
                    protocols: selected,
                });
            }
        });
}

/// A prominent line about an exit node. One that carries a command copies it
/// when clicked.
fn draw_exit_warning(ui: &mut egui::Ui, warning: &exit::Warning) {
    let text = egui::RichText::new(format!("{} {}", icon::WARNING, warning.text))
        .color(exit::LOUD)
        .strong();
    let label = egui::Label::new(text).wrap();
    match warning.copy {
        Some(command) => {
            let response = ui
                .add(label.sense(egui::Sense::click()))
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text("click to copy the command");
            if response.clicked() {
                ui.ctx().copy_text(command.to_owned());
            }
        }
        None => {
            ui.add(label);
        }
    }
}

/// The join form: aligned name and secret, a generate button, and Join.
pub fn draw_join(ui: &mut egui::Ui, agent: &dyn Client, join: &mut JoinForm) {
    const INPUT_WIDTH: f32 = 208.0;
    ui.label("Join or create a network");
    egui::Grid::new("join")
        .num_columns(2)
        .spacing([8.0, 6.0])
        .show(ui, |ui| {
            ui.label("name");
            ui.add(egui::TextEdit::singleline(&mut join.name).desired_width(INPUT_WIDTH));
            ui.end_row();

            ui.label("secret");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut *join.secret)
                        .id("join-secret".into())
                        .desired_width(INPUT_WIDTH - 26.0)
                        .password(true),
                );
                if ui
                    .button(icon::SHUFFLE)
                    .on_hover_text("Generate a new random secret")
                    .clicked()
                {
                    join.secret = tsunagi::identity::NetworkSecret::generate().encode();
                }
            });
            ui.end_row();
        });

    let ready = !join.name.trim().is_empty() && !join.secret.trim().is_empty();
    if ui
        .add_enabled(ready, egui::Button::new("Join / create"))
        .clicked()
    {
        agent.send(Command::Join {
            name: join.name.trim().to_string(),
            secret: Zeroizing::new(join.secret.trim().to_owned()),
        });
        join.secret.zeroize();
    }
}
