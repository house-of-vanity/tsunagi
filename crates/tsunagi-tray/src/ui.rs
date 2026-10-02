//! The window contents, drawn from the latest agent snapshot.
//!
//! Pure rendering: state comes from the snapshot and the traffic sampler, and a
//! change to a switch or a button sends a [`Command`] to the worker. The layout
//! targets one fixed, small window, so everything is laid out on a grid and the
//! peer list hides behind a collapsing header.

use std::collections::VecDeque;

use eframe::egui;

use tsunagi::identity::NetworkSecret;
use tsunagi::ipc::{NetworkReport, OverlayPeerReport, StatusReport};

use crate::agent::{AgentClient, Command, Snapshot};
use crate::stats::Traffic;

/// Width of the value column's input fields, so name and secret line up.
const INPUT_WIDTH: f32 = 208.0;
/// Accent used for the traffic sparkline.
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x2f, 0x80, 0xd8);
const OK: egui::Color32 = egui::Color32::from_rgb(0x3c, 0xb0, 0x4a);
const WARN: egui::Color32 = egui::Color32::from_rgb(0xd9, 0x9a, 0x00);
const BAD: egui::Color32 = egui::Color32::from_rgb(0xd0, 0x4a, 0x3c);

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
    traffic: &Traffic,
) {
    egui::TopBottomPanel::top("top").show(ctx, |ui| {
        ui.add_space(4.0);
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
        draw_join(ui, agent, join);
        ui.add_space(4.0);
    });

    egui::CentralPanel::default().show(ctx, |ui| match &snapshot.status {
        None => {
            ui.add_space(8.0);
            ui.label("Connecting to the agent…");
        }
        Some(Err(error)) => draw_unreachable(ui, agent, error),
        Some(Ok(report)) => {
            draw_header(ui, report);
            ui.separator();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if report.networks.is_empty() {
                        ui.add_space(6.0);
                        ui.weak("No networks yet — join one below.");
                    }
                    for network in &report.networks {
                        draw_network(ui, agent, traffic, network);
                    }
                });
        }
    });
}

/// The "agent cannot be reached" state, naming the socket it tried.
fn draw_unreachable(ui: &mut egui::Ui, agent: &AgentClient, error: &str) {
    ui.add_space(8.0);
    ui.colored_label(BAD, "The agent is not reachable.");
    ui.add_space(6.0);
    kv(ui, "socket", &agent.socket().display().to_string());
    ui.add_space(4.0);
    ui.weak(error);
    ui.add_space(6.0);
    ui.weak(
        "Start the agent, or check that this user may open its control socket \
         (its group, mode 0660).",
    );
}

/// The device line.
fn draw_header(ui: &mut egui::Ui, report: &StatusReport) {
    ui.add_space(4.0);
    egui::Grid::new("device")
        .num_columns(2)
        .spacing([10.0, 3.0])
        .show(ui, |ui| {
            kv_row(ui, "device", &short(&report.endpoint_id));
            kv_row(ui, "host", &report.hostname);
        });
    if !report.cache_healthy {
        ui.colored_label(WARN, "cache unavailable");
    }
}

/// One network tile.
fn draw_network(
    ui: &mut egui::Ui,
    agent: &AgentClient,
    traffic: &Traffic,
    network: &NetworkReport,
) {
    ui.add_space(6.0);
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.strong(network.name.as_str());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Leave").clicked() {
                    agent.send(Command::Leave {
                        network_id: network.network_id.clone(),
                    });
                }
            });
        });

        let overlay = network.overlay.as_ref();
        let address = overlay.and_then(|o| o.address.as_ref());
        let series = traffic.network(&network.network_id);

        egui::Grid::new(("net", &network.network_id))
            .num_columns(2)
            .spacing([10.0, 3.0])
            .show(ui, |ui| {
                kv_row(ui, "id", &short(&network.network_id));
                if let Some(range) = &network.range {
                    kv_row(ui, "range", range);
                }
                if let Some(address) = address {
                    kv_row(ui, "addr", address);
                }
                kv_row(
                    ui,
                    "peers",
                    &format!(
                        "{} connected · {} known",
                        network.peers.len(),
                        network.members.len()
                    ),
                );
                if let Some(series) = series {
                    kv_row(ui, "traffic", &rate(series.rate));
                }
            });

        if let Some(series) = series
            && series.history.len() >= 2
        {
            sparkline(ui, &series.history);
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

        if let Some(overlay) = overlay
            && !overlay.peers.is_empty()
        {
            egui::CollapsingHeader::new(format!("peers ({})", overlay.peers.len()))
                .id_salt(("peers", &network.network_id))
                .show(ui, |ui| {
                    draw_peers(ui, traffic, &network.network_id, &overlay.peers);
                });
        }
    });
}

/// The per-peer table inside a network's collapsing header.
fn draw_peers(ui: &mut egui::Ui, traffic: &Traffic, network_id: &str, peers: &[OverlayPeerReport]) {
    egui::Grid::new(("peertable", network_id))
        .num_columns(5)
        .striped(true)
        .spacing([10.0, 3.0])
        .show(ui, |ui| {
            for header in ["peer", "address", "age", "tx/rx", "rate"] {
                ui.weak(header);
            }
            ui.end_row();

            for peer in peers {
                ui.monospace(short(&peer.public_key));
                ui.label(peer.address.clone().unwrap_or_else(|| "—".into()));
                ui.label(match peer.handshake_secs_ago {
                    Some(secs) => format!("{secs}s"),
                    None => "—".into(),
                });
                ui.label(format!("{}/{}", peer.tx_packets, peer.rx_packets));
                let pps = traffic
                    .peer(network_id, &peer.public_key)
                    .map_or(0.0, |series| series.rate);
                ui.label(rate(pps));
                ui.end_row();
            }
        });
}

/// The join form: aligned name and secret, a generate button, and Join.
fn draw_join(ui: &mut egui::Ui, agent: &AgentClient, join: &mut JoinForm) {
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
                    .button("⟳")
                    .on_hover_text("Generate a new random secret")
                    .clicked()
                {
                    join.secret = NetworkSecret::generate().encode().as_str().to_owned();
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

/// A small filled-ish line chart of recent rates, drawn with the painter.
fn sparkline(ui: &mut egui::Ui, history: &VecDeque<f32>) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 26.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let peak = history.iter().copied().fold(1.0_f32, f32::max);
    let count = history.len();
    if count < 2 {
        return;
    }
    let points: Vec<egui::Pos2> = history
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let x = rect.left() + rect.width() * (i as f32 / (count - 1) as f32);
            let y = rect.bottom() - (rect.height() - 2.0) * (value / peak);
            egui::pos2(x, y)
        })
        .collect();
    painter.add(egui::Shape::line(
        points,
        egui::Stroke::new(1.5_f32, ACCENT),
    ));
}

/// A key/value label pair outside a grid.
fn kv(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.weak(key);
        ui.monospace(value);
    });
}

/// A key/value row inside a two-column grid.
fn kv_row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.weak(key);
    ui.label(value);
    ui.end_row();
}

/// Formats a packets-per-second rate.
fn rate(pps: f32) -> String {
    if pps >= 1000.0 {
        format!("{:.1}k pkt/s", pps / 1000.0)
    } else {
        format!("{pps:.0} pkt/s")
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
