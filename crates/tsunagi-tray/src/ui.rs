//! The main window: a compact overview. Per-network detail (the full peer
//! table with inline plots) lives in a separate devices window (see
//! [`crate::devices`]), opened from each tile.
//!
//! Pure rendering: state comes from the snapshot and the traffic sampler, a
//! change to a switch or button sends a [`tsunagi_ui::client::Command`] to the worker, and local UI
//! state (the join form, the unit toggle, which devices windows are open, an
//! in-progress hostname edit) lives in [`UiState`].

pub(crate) use tsunagi_ui::home::UiState;
use tsunagi_ui::home::{draw_header, draw_join, draw_network};

use eframe::egui;
use egui_phosphor::regular as icon;

use crate::agent::{AgentClient, Snapshot};
use crate::devices;
use crate::stats::{Traffic, Unit};

const OK: egui::Color32 = egui::Color32::from_rgb(0x3c, 0xb0, 0x4a);
const BAD: egui::Color32 = egui::Color32::from_rgb(0xd0, 0x4a, 0x3c);

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
            ui.label(
                egui::RichText::new(env!("CARGO_PKG_VERSION"))
                    .small()
                    .weak(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if tsunagi_ui::widgets::icon_button(ui, icon::INFO, "About Tsunagi").clicked() {
                    state.about_open = true;
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
                        draw_network(ui, agent, state, traffic, network, report, true);
                    }
                });
        }
    });

    devices::confirm_exit(ctx, agent, &mut state.exit_confirm, None);
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
