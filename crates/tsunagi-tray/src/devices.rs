//! The per-network devices window: full detail about one network — its
//! settings and counters, and one table of every device, online first, with
//! inline traffic plots for the connected ones.
//!
//! Rendered in a separate OS window (an egui viewport) opened from a tile in
//! the main window.

use std::collections::HashMap;

use eframe::egui;

use tsunagi::ipc::{NetworkReport, OverlayPeerReport};

use crate::agent::AgentClient;
use crate::format;
use crate::stats::{Traffic, Unit};

/// A readable title for a network's window.
pub(crate) fn title(network: &NetworkReport) -> String {
    format!("tsunagi · {}", network.name)
}

/// One row of the device table, built from a tunnel and/or a signed member.
struct Device<'a> {
    online: bool,
    /// The last hostname seen for it, kept while it is offline.
    hostname: Option<&'a str>,
    /// What clicking the hostname copies: `hostname.network`, so it resolves.
    copy: Option<String>,
    /// The full endpoint id, which clicking the short form copies.
    id: &'a str,
    proto: &'a str,
    address: Option<String>,
    handshake_secs: Option<u64>,
    overlay: Option<&'a OverlayPeerReport>,
}

impl Device<'_> {
    fn sort_key(&self) -> String {
        self.hostname.unwrap_or(self.id).to_lowercase()
    }
}

/// The first characters of an endpoint id, enough to tell devices apart.
fn short_id(id: &str) -> String {
    id.chars().take(5).collect()
}

/// The device cell: the hostname and, in brackets, the start of the id.
/// Clicking either copies its own full value.
fn name_cell(ui: &mut egui::Ui, device: &Device<'_>) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        match (device.hostname, &device.copy) {
            (Some(hostname), Some(copy)) => {
                format::copy_field(ui, hostname, copy);
                format::copy_field(ui, &format!("({})", short_id(device.id)), device.id);
            }
            _ => format::copy_field(ui, &short_id(device.id), device.id),
        }
    });
}

/// Draws the window body into its viewport.
pub(crate) fn show(
    ctx: &egui::Context,
    _agent: &AgentClient,
    unit: &mut Unit,
    network: &NetworkReport,
    own_id: &str,
    traffic: &Traffic,
) {
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.heading(&network.name);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.selectable_value(unit, Unit::Bytes, "bytes");
                ui.selectable_value(unit, Unit::Packets, "pkts");
                ui.label("show:");
            });
        });
        // A copy of the chosen unit for the read-only rendering below.
        let unit = *unit;

        summary(ui, network);
        ui.add_space(6.0);

        ui.label(egui::RichText::new("traffic").strong());
        format::sparkline(ui, traffic.network(&network.network_id), unit, 48.0);
        ui.add_space(8.0);

        let devices = devices(network, own_id);
        let online = devices.iter().filter(|d| d.online).count();
        ui.label(
            egui::RichText::new(format!(
                "devices ({} online / {} known)",
                online,
                devices.len()
            ))
            .strong(),
        );
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                device_table(ui, unit, &network.network_id, &devices, traffic);
            });
    });
}

/// The network's own settings and counters.
fn summary(ui: &mut egui::Ui, network: &NetworkReport) {
    egui::Grid::new("summary")
        .num_columns(2)
        .spacing([12.0, 3.0])
        .show(ui, |ui| {
            ui.weak("id");
            format::copy_field(ui, &network.network_id, &network.network_id);
            ui.end_row();

            ui.weak("active");
            ui.label(yes_no(network.active));
            ui.end_row();
            ui.weak("broadcast");
            ui.label(yes_no(network.broadcast));
            ui.end_row();

            if let Some(range) = &network.range {
                ui.weak("range");
                format::copy_field(ui, range, range);
                ui.end_row();
            }
            if let Some(address) = network.overlay.as_ref().and_then(|o| o.address.as_ref()) {
                ui.weak("this device");
                format::copy_field(ui, address, address);
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

/// Every other device this network knows of, from a live tunnel or the signed
/// membership. This device is in the roster too but is not one of the others.
fn known_ids<'a>(network: &'a NetworkReport, own_id: &str) -> Vec<&'a str> {
    let overlay_peers = network
        .overlay
        .as_ref()
        .map(|o| o.peers.as_slice())
        .unwrap_or(&[]);
    let mut ids: Vec<&str> = Vec::new();
    let candidates = overlay_peers
        .iter()
        .map(|p| p.endpoint_id.as_str())
        .chain(network.peers.iter().map(|p| p.endpoint_id.as_str()))
        .chain(network.members.iter().map(|m| m.endpoint_id.as_str()));
    for id in candidates {
        if id != own_id && !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// How many other devices this network knows of, connected or not.
pub(crate) fn known_count(network: &NetworkReport, own_id: &str) -> usize {
    known_ids(network, own_id).len()
}

/// Builds the device list: every endpoint known from a live tunnel or the
/// signed membership, online ones first.
fn devices<'a>(network: &'a NetworkReport, own_id: &str) -> Vec<Device<'a>> {
    // The signed members carry the last name seen, so a device that is away
    // is still called by it; a live announcement is fresher and wins.
    let mut hostnames: HashMap<&str, &str> = network
        .members
        .iter()
        .filter_map(|m| m.hostname.as_deref().map(|h| (m.endpoint_id.as_str(), h)))
        .collect();
    hostnames.extend(
        network
            .peers
            .iter()
            .filter_map(|p| p.hostname.as_deref().map(|h| (p.endpoint_id.as_str(), h))),
    );
    let overlay_peers = network
        .overlay
        .as_ref()
        .map(|o| o.peers.as_slice())
        .unwrap_or(&[]);

    let ids = known_ids(network, own_id);

    let mut devices: Vec<Device> = ids
        .into_iter()
        .map(|id| {
            let overlay = overlay_peers.iter().find(|p| p.endpoint_id == id);
            let member = network.members.iter().find(|m| m.endpoint_id == id);
            let online = overlay.is_some_and(|p| p.handshake_secs_ago.is_some());
            let hostname = hostnames.get(id).copied();
            Device {
                online,
                hostname,
                copy: hostname.map(|h| format!("{h}.{}", network.name)),
                id,
                proto: overlay.map_or("—", |p| p.protocol.as_str()),
                address: overlay
                    .and_then(|p| p.address.clone())
                    .or_else(|| member.and_then(|m| m.overlay_address_v4.clone())),
                handshake_secs: overlay.and_then(|p| p.handshake_secs_ago),
                overlay,
            }
        })
        .collect();

    devices.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| a.sort_key().cmp(&b.sort_key()))
    });
    devices
}

/// One table of all devices: online rows carry live counters and a plot,
/// offline rows show what is known (name and address) and dashes.
fn device_table(
    ui: &mut egui::Ui,
    unit: Unit,
    network_id: &str,
    devices: &[Device<'_>],
    traffic: &Traffic,
) {
    if devices.is_empty() {
        ui.weak("none");
        return;
    }
    egui::Grid::new("devices")
        .num_columns(8)
        .striped(true)
        .spacing([10.0, 4.0])
        .show(ui, |ui| {
            for header in [
                "device",
                "proto",
                "address",
                "handshake",
                "pkts",
                "bytes",
                "rate",
                "plot",
            ] {
                ui.weak(header);
            }
            ui.end_row();

            for device in devices {
                name_cell(ui, device);
                ui.label(device.proto);
                match &device.address {
                    Some(address) => format::copy_field(ui, address, address),
                    None => {
                        ui.weak("—");
                    }
                }
                ui.label(
                    device
                        .handshake_secs
                        .map_or_else(|| "offline".to_string(), format::age),
                );

                match device.overlay.filter(|_| device.online) {
                    Some(peer) => {
                        ui.label(format!("{}/{}", peer.tx_packets, peer.rx_packets));
                        ui.label(format!(
                            "{} / {}",
                            format::bytes(peer.tx_bytes as f64),
                            format::bytes(peer.rx_bytes as f64)
                        ));
                        let series = traffic.peer(network_id, &peer.public_key);
                        ui.add(egui::Label::new(format::series_rate(series, unit)).truncate());
                        ui.allocate_ui(egui::vec2(100.0, 20.0), |ui| {
                            format::sparkline(ui, series, unit, 18.0);
                        });
                    }
                    None => {
                        for _ in 0..4 {
                            ui.weak("—");
                        }
                    }
                }
                ui.end_row();
            }
        });
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
