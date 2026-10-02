//! The About window: what this software is, and what it is talking to.
//!
//! Compact on purpose — one table for the client, one for the agent. The agent
//! half is whatever the agent says about itself, so a client and an agent that
//! are not the same build show up as such.

use eframe::egui;

use tsunagi::ipc::{PrivilegeReport, StatusReport};

use crate::agent::Snapshot;
use crate::format;

const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
const AUTHOR: &str = "AB <tsunagi@hexor.cy>";
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Draws the window body into its viewport.
pub(crate) fn show(ctx: &egui::Context, socket: &std::path::Path, snapshot: &Snapshot) {
    egui::CentralPanel::default().show(ctx, |ui| {
        // Long paths and a taller agent table must scroll rather than be cut.
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| body(ui, socket, snapshot));
    });
}

fn body(ui: &mut egui::Ui, socket: &std::path::Path, snapshot: &Snapshot) {
    {
        ui.horizontal(|ui| {
            ui.heading("tsunagi");
            ui.label(egui::RichText::new(VERSION).small().weak());
        });
        ui.label("Peer-to-peer mesh network with no server.");
        ui.add_space(6.0);

        section(ui, "client");
        grid(ui, "about client", |ui| {
            row(ui, "repository", |ui| {
                ui.hyperlink(REPOSITORY);
            });
            row(ui, "author", |ui| {
                format::copy_field(ui, AUTHOR, AUTHOR);
            });
            row(ui, "license", |ui| {
                ui.label(env!("CARGO_PKG_LICENSE"));
            });
            row(ui, "build", |ui| {
                ui.label(format!(
                    "{} {} · {}",
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                    if cfg!(debug_assertions) {
                        "debug"
                    } else {
                        "release"
                    }
                ));
            });
        });

        ui.add_space(8.0);
        section(ui, "agent");
        let socket = socket.display().to_string();
        match &snapshot.status {
            None => {
                grid(ui, "about agent", |ui| {
                    row(ui, "socket", |ui| format::copy_field(ui, &socket, &socket));
                    row(ui, "state", |ui| {
                        ui.label("connecting…");
                    });
                });
            }
            Some(Err(error)) => {
                grid(ui, "about agent", |ui| {
                    row(ui, "socket", |ui| format::copy_field(ui, &socket, &socket));
                    row(ui, "state", |ui| {
                        ui.colored_label(egui::Color32::from_rgb(0xd8, 0x4a, 0x3a), "unreachable");
                    });
                    row(ui, "reason", |ui| {
                        ui.add(egui::Label::new(error).wrap());
                    });
                });
            }
            Some(Ok(report)) => agent_table(ui, &socket, report),
        }
    }
}

fn agent_table(ui: &mut egui::Ui, socket: &str, report: &StatusReport) {
    grid(ui, "about agent", |ui| {
        row(ui, "socket", |ui| format::copy_field(ui, socket, socket));
        row(ui, "state", |ui| {
            ui.colored_label(egui::Color32::from_rgb(0x3c, 0xb0, 0x4a), "connected");
        });
        row(ui, "version", |ui| {
            if report.version.is_empty() {
                ui.weak("unknown");
            } else if report.version == VERSION {
                ui.label(&report.version);
            } else {
                ui.colored_label(
                    egui::Color32::from_rgb(0xd8, 0x9a, 0x2a),
                    format!("{} (client is {VERSION})", report.version),
                );
            }
        });
        if !report.protocols.is_empty() {
            row(ui, "protocols", |ui| {
                ui.label(report.protocols.join(" · "));
            });
        }
        row(ui, "endpoint id", |ui| {
            format::copy_field(ui, &format::short(&report.endpoint_id), &report.endpoint_id);
        });
        row(ui, "hostname", |ui| {
            ui.label(&report.hostname);
        });
        if !report.program.is_empty() {
            row(ui, "binary", |ui| {
                format::copy_field(ui, &report.program, &report.program);
            });
        }
        if !report.state_dir.is_empty() {
            row(ui, "state dir", |ui| {
                format::copy_field(ui, &report.state_dir, &report.state_dir);
            });
            row(ui, "cache dir", |ui| {
                format::copy_field(ui, &report.cache_dir, &report.cache_dir);
            });
        }
        row(ui, "interface", |ui| match &report.privilege {
            PrivilegeReport::Unknown => {
                ui.weak("unknown");
            }
            PrivilegeReport::Available => {
                ui.label("can be managed (CAP_NET_ADMIN)");
            }
            PrivilegeReport::Missing(_) => {
                ui.colored_label(egui::Color32::from_rgb(0xd8, 0x9a, 0x2a), "no privileges");
            }
            PrivilegeReport::Unsupported => {
                ui.label("not supported on this platform");
            }
        });
        row(ui, "cache", |ui| {
            ui.label(if report.cache_healthy {
                "usable"
            } else {
                "unavailable"
            });
        });
        row(ui, "listening", |ui| {
            ui.label(report.bound_sockets.join(", "));
        });
    });
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.label(egui::RichText::new(title).strong());
}

fn grid(ui: &mut egui::Ui, id: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([12.0, 3.0])
        .show(ui, add);
}

/// One label/value line of a table.
fn row(ui: &mut egui::Ui, label: &str, value: impl FnOnce(&mut egui::Ui)) {
    ui.weak(label);
    value(ui);
    ui.end_row();
}
