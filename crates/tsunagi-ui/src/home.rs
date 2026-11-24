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
            unit: Unit::Packets,
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
    ui.add_space(6.0);
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            format::copy_field(ui, network.name.as_str(), &network.name);
            if ui.button("VIP").clicked(){state.vip_windows.entry(network.network_id.clone()).or_default();}
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let leave =
                    egui::Button::new(egui::RichText::new("Leave").color(egui::Color32::WHITE))
                        .fill(LEAVE_RED);
                if ui.add(leave).clicked() {
                    agent.send(Command::Leave {
                        network_id: network.network_id.clone(),
                    });
                }
            });
        });

        let address = network.overlay.as_ref().and_then(|o| o.address.as_ref());
        let series = traffic.network(&network.network_id);

        egui::Grid::new(("net", &network.network_id))
            .num_columns(2)
            .spacing([10.0, 3.0])
            .show(ui, |ui| {
                ui.weak("id");
                format::copy_field(ui, &format::short(&network.network_id), &network.network_id);
                ui.end_row();

                if let Some(range) = &network.range {
                    ui.weak("range");
                    format::copy_field(ui, range, range);
                    ui.end_row();
                }
                if let Some(address) = address {
                    ui.weak("addr");
                    format::copy_field(ui, address, address);
                    ui.end_row();
                }
                ui.weak("peers");
                ui.label(format!(
                    "{} online · {} known",
                    devices::online_count(network, &report.endpoint_id),
                    devices::known_count(network, &report.endpoint_id)
                ));
                ui.end_row();
            });

        draw_protocols(ui, agent, network, &report.available_protocols);

        format::sparkline(ui, series, state.unit, 34.0);

        if !network.range_conflicts.is_empty() {
            ui.colored_label(BAD, "Stopped: overlapping network ranges");
            for conflict in &network.range_conflicts {
                ui.label(format!("{} ({}) uses {}", conflict.name, conflict.network_id, conflict.range));
            }
            ui.label("Switching suspends these networks until this network stops, then resumes them automatically.");
            if network.auto_start { ui.weak("This network will resume automatically when its range is free."); }
        }
        ui.horizontal_wrapped(|ui| {
            if !network.active && !network.range_conflicts.is_empty() {
                if ui.button("Switch to this network").clicked() {
                    agent.send(Command::SetActive { network_id: network.network_id.clone(), active: true });
                }
                if network.auto_start && ui.button("Keep stopped").clicked() {
                    agent.send(Command::SetActive { network_id: network.network_id.clone(), active: false });
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
            if !offer_exit && ui.button("Exit node…").clicked() { pick_exit = true; }
            let mut offering = network.exit.offering;
            if offer_exit && ui
                .checkbox(&mut offering, "exit node")
                .on_hover_text(
                    "let other members send all their internet traffic through this \
                     device, which can see it",
                )
                .changed()
            {
                agent.send(Command::SetExitOffer {
                    network_id: network.network_id.clone(),
                    enabled: offering,
                });
            }
        });
        ui.horizontal(|ui| {
            // In the bottom left corner while this device sends its traffic through
            // somebody: green while that works, red while it does not.
            if let Some(via) = &network.exit.via {
                let color = if network.exit.via_online {
                    exit::GOOD
                } else {
                    exit::LOUD
                };
                let response = ui
                    .add(
                        egui::Label::new(
                            egui::RichText::new(icon::SIGN_OUT).size(18.0).color(color),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text(format!(
                        "exit node: {} — click to stop",
                        exit::name_of(network, via)
                    ));
                if response.clicked() {
                    state.exit_confirm = Some(devices::ExitConfirm::stop_from_tile(network, via));
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Show devices").clicked() {
                    state.open_devices.insert(network.network_id.clone());
                }
                if ui
                    .button(format!("{} Copy secret", icon::COPY))
                    .on_hover_text("copy this network's secret to the clipboard")
                    .clicked()
                {
                    agent.send(Command::CopySecret {
                        network_id: network.network_id.clone(),
                    });
                }
            });
        });
        for warning in exit::warnings(network) {
            draw_exit_warning(ui, &warning);
        }
    });
    pick_exit
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
