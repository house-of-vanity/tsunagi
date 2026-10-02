//! The per-network devices window: full detail about one network — its
//! settings and counters, every connected peer in a table with an inline
//! traffic plot, and the members that are currently offline below.
//!
//! Rendered in a separate OS window (an egui viewport) opened from a tile in
//! the main window.

use std::collections::HashMap;

use eframe::egui;

use tsunagi::ipc::NetworkReport;

use crate::agent::AgentClient;
use crate::format;
use crate::stats::{Traffic, Unit};

/// A readable title for a network's window.
pub(crate) fn title(network: &NetworkReport) -> String {
    format!("tsunagi · {}", network.name)
}

/// Draws the window body into its viewport.
pub(crate) fn show(
    ctx: &egui::Context,
    _agent: &AgentClient,
    unit: Unit,
    network: &NetworkReport,
    traffic: &Traffic,
) {
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.heading(&network.name);
        summary(ui, network);
        ui.add_space(6.0);

        ui.label(egui::RichText::new("traffic").strong());
        format::sparkline(ui, traffic.network(&network.network_id), unit, 48.0);
        ui.add_space(8.0);

        let hostnames: HashMap<&str, &str> = network
            .peers
            .iter()
            .filter_map(|p| p.hostname.as_deref().map(|h| (p.endpoint_id.as_str(), h)))
            .collect();

        let overlay = network.overlay.as_ref();
        let online = overlay.map(|o| o.peers.as_slice()).unwrap_or(&[]);

        ui.label(egui::RichText::new(format!("connected peers ({})", online.len())).strong());
        egui::ScrollArea::vertical()
            .max_height(260.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                connected_table(ui, unit, &network.network_id, online, &hostnames, traffic);
            });

        // Members with no live tunnel right now.
        let online_ids: std::collections::HashSet<&str> =
            online.iter().map(|p| p.endpoint_id.as_str()).collect();
        let offline: Vec<_> = network
            .members
            .iter()
            .filter(|m| !online_ids.contains(m.endpoint_id.as_str()))
            .collect();
        if !offline.is_empty() {
            ui.add_space(8.0);
            ui.label(egui::RichText::new(format!("offline members ({})", offline.len())).strong());
            offline_table(ui, &offline, &hostnames);
        }
    });
}

/// The network's own settings and counters.
fn summary(ui: &mut egui::Ui, network: &NetworkReport) {
    egui::Grid::new("summary")
        .num_columns(2)
        .spacing([12.0, 3.0])
        .show(ui, |ui| {
            ui.weak("id");
            ui.horizontal(|ui| {
                ui.monospace(&network.network_id);
                format::copy_button(ui, &network.network_id);
            });
            ui.end_row();

            ui.weak("active");
            ui.label(yes_no(network.active));
            ui.end_row();
            ui.weak("broadcast");
            ui.label(yes_no(network.broadcast));
            ui.end_row();

            if let Some(range) = &network.range {
                ui.weak("range");
                format::copy_label(ui, range, range);
                ui.end_row();
            }
            if let Some(address) = network.overlay.as_ref().and_then(|o| o.address.as_ref()) {
                ui.weak("this device");
                format::copy_label(ui, address, address);
                ui.end_row();
            }
            ui.weak("candidates");
            ui.label(network.candidates.to_string());
            ui.end_row();
            ui.weak("relay fwd/via/recv");
            ui.label(format!(
                "{} / {} / {}",
                network.relay_forwarded, network.relay_sent_via, network.relay_received_via
            ));
            ui.end_row();
            ui.weak("dial/handshake fails");
            ui.label(format!(
                "{} / {}",
                network.dial_failures, network.handshake_failures
            ));
            ui.end_row();
        });
}

/// The table of peers with a live tunnel.
fn connected_table(
    ui: &mut egui::Ui,
    unit: Unit,
    network_id: &str,
    peers: &[tsunagi::ipc::OverlayPeerReport],
    hostnames: &HashMap<&str, &str>,
    traffic: &Traffic,
) {
    if peers.is_empty() {
        ui.weak("none");
        return;
    }
    egui::Grid::new("connected")
        .num_columns(7)
        .striped(true)
        .spacing([10.0, 4.0])
        .show(ui, |ui| {
            for header in [
                "peer",
                "proto",
                "address",
                "handshake",
                "pkts",
                "bytes",
                "rate / plot",
            ] {
                ui.weak(header);
            }
            ui.end_row();

            for peer in peers {
                let name = hostnames
                    .get(peer.endpoint_id.as_str())
                    .map_or_else(|| format::short(&peer.public_key), |h| (*h).to_string());
                format::copy_label(ui, &name, &name);
                ui.label(&peer.protocol);
                match &peer.address {
                    Some(address) => format::copy_label(ui, address, address),
                    None => {
                        ui.weak("—");
                    }
                }
                ui.label(
                    peer.handshake_secs_ago
                        .map_or_else(|| "never".to_string(), format::age),
                );
                ui.label(format!("{}/{}", peer.tx_packets, peer.rx_packets));
                ui.label(format!(
                    "{} / {}",
                    format::bytes(peer.tx_bytes as f64),
                    format::bytes(peer.rx_bytes as f64)
                ));
                let series = traffic.peer(network_id, &peer.public_key);
                ui.horizontal(|ui| {
                    ui.label(format::series_rate(series, unit));
                    ui.allocate_ui(egui::vec2(90.0, 20.0), |ui| {
                        format::sparkline(ui, series, unit, 18.0);
                    });
                });
                ui.end_row();
            }
        });
}

/// The table of members with no current tunnel.
fn offline_table(
    ui: &mut egui::Ui,
    members: &[&tsunagi::ipc::MemberReport],
    hostnames: &HashMap<&str, &str>,
) {
    egui::Grid::new("offline")
        .num_columns(3)
        .striped(true)
        .spacing([10.0, 4.0])
        .show(ui, |ui| {
            for header in ["member", "address", "failed dials"] {
                ui.weak(header);
            }
            ui.end_row();

            for member in members {
                let name = hostnames
                    .get(member.endpoint_id.as_str())
                    .map_or_else(|| format::short(&member.endpoint_id), |h| (*h).to_string());
                format::copy_label(ui, &name, &member.endpoint_id);
                ui.label(
                    member
                        .overlay_address_v4
                        .clone()
                        .unwrap_or_else(|| "—".into()),
                );
                ui.label(member.failed_dials.to_string());
                ui.end_row();
            }
        });
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
