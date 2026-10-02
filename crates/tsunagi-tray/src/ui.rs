//! The window contents, drawn from the latest agent snapshot.
//!
//! Pure rendering: the current state comes from the snapshot, and a change to a
//! switch or a button sends a [`Command`] to the worker. egui is immediate
//! mode, so the switches reflect the agent's state and only a user change
//! dispatches a command.

use eframe::egui;

use tsunagi::ipc::{NetworkReport, StatusReport};

use crate::agent::{AgentClient, Command, Snapshot};

/// Join form state, kept across frames.
#[derive(Default)]
pub(crate) struct JoinForm {
    pub(crate) name: String,
    pub(crate) secret: String,
}

/// Draws the whole window.
pub(crate) fn draw(
    ctx: &egui::Context,
    agent: &AgentClient,
    join: &mut JoinForm,
    snapshot: &Snapshot,
) {
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.heading("tsunagi");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("⟳").on_hover_text("Refresh").clicked() {
                    agent.send(Command::Refresh);
                }
                if snapshot.busy {
                    ui.add(egui::Spinner::new());
                }
            });
        });

        match &snapshot.status {
            None => {
                ui.add_space(8.0);
                ui.label("Connecting to the agent…");
            }
            Some(Err(error)) => draw_unreachable(ui, agent, error),
            Some(Ok(report)) => {
                draw_header(ui, report);
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    if report.networks.is_empty() {
                        ui.label("No networks yet. Join one below.");
                    }
                    for network in &report.networks {
                        draw_network(ui, agent, network);
                    }
                });
                ui.separator();
                draw_join(ui, agent, join);
            }
        }

        if let Some(action) = &snapshot.last_action {
            ui.add_space(6.0);
            match action {
                Ok(message) => ui.colored_label(egui::Color32::from_rgb(0x3c, 0xb0, 0x4a), message),
                Err(error) => ui.colored_label(egui::Color32::from_rgb(0xd0, 0x4a, 0x3c), error),
            };
        }
    });
}

/// The "agent cannot be reached" state, with the socket it tried.
fn draw_unreachable(ui: &mut egui::Ui, agent: &AgentClient, error: &str) {
    ui.add_space(8.0);
    ui.colored_label(
        egui::Color32::from_rgb(0xd0, 0x4a, 0x3c),
        "The agent is not reachable.",
    );
    ui.add_space(4.0);
    ui.label(format!("socket: {}", agent.socket().display()));
    ui.label(error);
    ui.add_space(6.0);
    ui.label(
        "Start the agent, or check that this user may open its control socket \
         (its group, mode 0660).",
    );
}

/// The device line: id, hostname, cache health.
fn draw_header(ui: &mut egui::Ui, report: &StatusReport) {
    ui.add_space(4.0);
    ui.label(format!("device  {}", short(&report.endpoint_id)));
    ui.label(format!("host    {}", report.hostname));
    if !report.cache_healthy {
        ui.colored_label(
            egui::Color32::from_rgb(0xd9, 0x9a, 0x00),
            "cache unavailable",
        );
    }
}

/// One network: name, range, this device's address, switches, peers, leave.
fn draw_network(ui: &mut egui::Ui, agent: &AgentClient, network: &NetworkReport) {
    ui.add_space(6.0);
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.strong(network.name.as_str());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Leave").clicked() {
                    agent.send(Command::Leave {
                        network_id: network.network_id.clone(),
                    });
                }
            });
        });
        ui.label(format!("id     {}", short(&network.network_id)));
        if let Some(range) = &network.range {
            ui.label(format!("range  {range}"));
        }
        if let Some(address) = network.overlay.as_ref().and_then(|o| o.address.as_ref()) {
            ui.label(format!("addr   {address}"));
        }

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
        });

        let connected = network.peers.len();
        let known = network.members.len();
        ui.label(format!("peers  {connected} connected · {known} known"));
    });
}

/// The join form: name + secret + button.
fn draw_join(ui: &mut egui::Ui, agent: &AgentClient, join: &mut JoinForm) {
    ui.add_space(4.0);
    ui.label("Join a network");
    ui.horizontal(|ui| {
        ui.label("name");
        ui.text_edit_singleline(&mut join.name);
    });
    ui.horizontal(|ui| {
        ui.label("secret");
        ui.add(egui::TextEdit::singleline(&mut join.secret).password(true));
    });
    let ready = !join.name.trim().is_empty() && !join.secret.trim().is_empty();
    if ui.add_enabled(ready, egui::Button::new("Join")).clicked() {
        agent.send(Command::Join {
            name: join.name.trim().to_string(),
            secret: join.secret.trim().to_string(),
        });
        join.secret.clear();
    }
}

/// A short, readable prefix of a long identifier (char-safe, no panic).
fn short(id: &str) -> String {
    const KEEP: usize = 12;
    if id.chars().count() <= KEEP {
        id.to_string()
    } else {
        format!("{}…", id.chars().take(KEEP).collect::<String>())
    }
}
