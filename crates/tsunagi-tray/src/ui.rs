//! The main window: a compact overview. Per-network detail (the full peer
//! table with inline plots) lives in a separate devices window (see
//! [`crate::devices`]), opened from each tile.
//!
//! Pure rendering: state comes from the snapshot and the traffic sampler, a
//! change to a switch or button sends a [`Command`] to the worker, and local UI
//! state (the join form, the unit toggle, which devices windows are open, an
//! in-progress hostname edit) lives in [`UiState`].

use std::collections::BTreeSet;

use eframe::egui;
use egui_phosphor::regular as icon;

use tsunagi::ipc::{NetworkReport, StatusReport};

use crate::agent::{AgentClient, Command, Snapshot};
use crate::format;
use crate::stats::{Traffic, Unit};

const OK: egui::Color32 = egui::Color32::from_rgb(0x3c, 0xb0, 0x4a);
const BAD: egui::Color32 = egui::Color32::from_rgb(0xd0, 0x4a, 0x3c);
/// A neutral, not-garish red for the Leave button.
const LEAVE_RED: egui::Color32 = egui::Color32::from_rgb(0xa8, 0x3a, 0x3a);

/// Join form fields.
#[derive(Default)]
pub(crate) struct JoinForm {
    pub(crate) name: String,
    pub(crate) secret: String,
}

/// Local UI state kept across frames.
pub(crate) struct UiState {
    pub(crate) join: JoinForm,
    /// Whether rates and sparklines are shown in packets or bytes.
    pub(crate) unit: Unit,
    /// An in-progress hostname edit (`None` when not editing).
    pub(crate) host_edit: Option<String>,
    /// Network ids whose devices window is open.
    pub(crate) open_devices: BTreeSet<String>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            join: JoinForm::default(),
            unit: Unit::Packets,
            host_edit: None,
            open_devices: BTreeSet::new(),
        }
    }
}

/// Draws the main window.
pub(crate) fn draw(
    ctx: &egui::Context,
    agent: &AgentClient,
    state: &mut UiState,
    snapshot: &Snapshot,
    traffic: &Traffic,
) {
    egui::TopBottomPanel::top("top").show(ctx, |ui| {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("tsunagi");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(icon::ARROWS_CLOCKWISE)
                    .on_hover_text("Refresh")
                    .clicked()
                {
                    agent.send(Command::Refresh);
                }
                if snapshot.busy {
                    ui.add(egui::Spinner::new());
                }
                ui.separator();
                ui.selectable_value(&mut state.unit, Unit::Bytes, "bytes");
                ui.selectable_value(&mut state.unit, Unit::Packets, "pkts");
                ui.label("show:");
            });
        });
        ui.add_space(4.0);
    });

    egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
        if let Some(action) = &snapshot.last_action {
            ui.add_space(4.0);
            match action {
                Ok(message) => ui.colored_label(OK, message),
                Err(error) => ui.colored_label(BAD, error),
            };
        }
        ui.add_space(4.0);
        draw_join(ui, agent, &mut state.join);
        ui.add_space(4.0);
    });

    egui::CentralPanel::default().show(ctx, |ui| match &snapshot.status {
        None => {
            ui.add_space(8.0);
            ui.label("Connecting to the agent…");
        }
        Some(Err(error)) => draw_unreachable(ui, agent, error),
        Some(Ok(report)) => {
            draw_header(ui, agent, state, report);
            ui.separator();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if report.networks.is_empty() {
                        ui.add_space(6.0);
                        ui.weak("No networks yet — join one below.");
                    }
                    for network in &report.networks {
                        draw_network(ui, agent, state, traffic, network);
                    }
                });
        }
    });
}

/// The "agent cannot be reached" state.
fn draw_unreachable(ui: &mut egui::Ui, agent: &AgentClient, error: &str) {
    ui.add_space(8.0);
    ui.colored_label(BAD, "The agent is not reachable.");
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.weak("socket");
        ui.monospace(agent.socket().display().to_string());
    });
    ui.add_space(4.0);
    ui.weak(error);
    ui.add_space(6.0);
    ui.weak(
        "Start the agent, or check that this user may open its control socket \
         (its group, mode 0660).",
    );
}

/// The device header: id (with a copy button) and an editable hostname.
fn draw_header(ui: &mut egui::Ui, agent: &AgentClient, state: &mut UiState, report: &StatusReport) {
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
}

/// One compact network tile.
fn draw_network(
    ui: &mut egui::Ui,
    agent: &AgentClient,
    state: &mut UiState,
    traffic: &Traffic,
    network: &NetworkReport,
) {
    ui.add_space(6.0);
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            format::copy_field(ui, network.name.as_str(), &network.name);
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
                    "{} connected · {} known",
                    network.peers.len(),
                    network.members.len()
                ));
                ui.end_row();
            });

        format::sparkline(ui, series, state.unit, 34.0);

        ui.horizontal(|ui| {
            let mut active = network.active;
            if ui.checkbox(&mut active, "active").changed() {
                agent.send(Command::SetActive {
                    network_id: network.network_id.clone(),
                    active,
                });
            }
            let mut broadcast = network.broadcast;
            if ui.checkbox(&mut broadcast, "broadcast").changed() {
                agent.send(Command::SetBroadcast {
                    network_id: network.network_id.clone(),
                    enabled: broadcast,
                });
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
    });
}

/// The join form: aligned name and secret, a generate button, and Join.
fn draw_join(ui: &mut egui::Ui, agent: &AgentClient, join: &mut JoinForm) {
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
                    egui::TextEdit::singleline(&mut join.secret)
                        .desired_width(INPUT_WIDTH - 26.0)
                        .password(true),
                );
                if ui
                    .button(icon::SHUFFLE)
                    .on_hover_text("Generate a new random secret")
                    .clicked()
                {
                    join.secret = tsunagi::identity::NetworkSecret::generate()
                        .encode()
                        .as_str()
                        .to_owned();
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
            secret: join.secret.trim().to_string(),
        });
        join.secret.clear();
    }
}
