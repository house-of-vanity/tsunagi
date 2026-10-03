//! The per-network devices window: full detail about one network — its
//! settings and counters, and one table of every device, online first, with
//! inline traffic plots for the connected ones.
//!
//! Rendered in a separate OS window (an egui viewport) opened from a tile in
//! the main window.

use std::collections::HashMap;

use eframe::egui;

use tsunagi::ipc::{NetworkReport, OverlayPeerReport};

use crate::agent::{AgentClient, Command};
use crate::exit;
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
    /// It is connected and offers to be an exit node.
    exit_node: bool,
    /// It is the exit node this device sends its internet traffic through.
    in_use: bool,
}

/// An exit-node choice the user has to confirm: all their traffic goes through
/// somebody else's device, or stops doing so.
pub(crate) struct ExitConfirm {
    network_id: String,
    peer_id: String,
    name: String,
    /// Stop using it, rather than start.
    stop: bool,
}

impl Device<'_> {
    fn name(&self) -> String {
        self.hostname
            .map_or_else(|| format::short(self.id), str::to_string)
    }

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
    agent: &AgentClient,
    unit: &mut Unit,
    confirm: &mut Option<ExitConfirm>,
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
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                device_table(ui, unit, network, &devices, traffic, confirm);
            });
    });
    confirm_exit(ctx, agent, confirm, &network.network_id);
}

/// The confirmation for an exit-node choice, drawn in the window it was
/// made in. Everything behind it is blocked until it is answered.
fn confirm_exit(
    ctx: &egui::Context,
    agent: &AgentClient,
    confirm: &mut Option<ExitConfirm>,
    network_id: &str,
) {
    let Some(pending) = confirm.as_ref().filter(|c| c.network_id == network_id) else {
        return;
    };
    egui::Area::new(egui::Id::new("exit confirm backdrop"))
        .order(egui::Order::Middle)
        .fixed_pos(egui::Pos2::ZERO)
        .show(ctx, |ui| {
            let screen = ctx.screen_rect();
            ui.allocate_response(screen.size(), egui::Sense::click_and_drag());
            ui.painter()
                .rect_filled(screen, 0.0, egui::Color32::from_black_alpha(140));
        });

    let (mut accepted, mut cancelled) = (false, false);
    egui::Window::new(if pending.stop {
        "Stop using exit node"
    } else {
        "Use as exit node"
    })
    .order(egui::Order::Foreground)
    .collapsible(false)
    .resizable(false)
    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
    .show(ctx, |ui| {
        ui.set_max_width(380.0);
        if pending.stop {
            ui.label(format!("Stop using {} as exit node?", pending.name));
            ui.label("Your internet traffic will leave this device the ordinary way again.");
        } else {
            ui.label(
                egui::RichText::new(format!(
                    "Send ALL your internet traffic through {}?",
                    pending.name
                ))
                .strong(),
            );
            ui.label(
                "Everything not on this network will leave through that device, which can \
                 see it.",
            );
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let label = if pending.stop {
                "Stop"
            } else {
                "Use as exit node"
            };
            if ui.button(label).clicked() {
                accepted = true;
            }
            if ui.button("Cancel").clicked() {
                cancelled = true;
            }
        });
    });
    if accepted {
        agent.send(Command::SetExitNode {
            network_id: pending.network_id.clone(),
            peer: (!pending.stop).then(|| pending.peer_id.clone()),
        });
    }
    if accepted || cancelled || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        *confirm = None;
    }
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
        .chain(network.members.iter().map(|m| m.endpoint_id.as_str()))
        .chain(network.exit.via.as_deref());
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
                exit_node: online
                    && network
                        .peers
                        .iter()
                        .any(|p| p.endpoint_id == id && p.exit_node),
                in_use: network.exit.via.as_deref() == Some(id),
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

/// The widest value each column is expected to hold, so the table starts out
/// wide enough and does not reflow as numbers grow.
const COLUMN_SAMPLES: [&str; 9] = [
    "",
    "exit",
    "tcp-tls",
    "255.255.255.255",
    "23h 59m",
    "99999/99999",
    "1023.9 MB / 1023.9 MB",
    "1023.9 kB/s",
    "",
];

/// Column widths that only ever grow, kept across frames.
///
/// A grid sizes each column to its widest cell *this frame*, so a value that
/// gets shorter — `14.4 MB/s` giving way to `382 pkt/s` — would pull the
/// column in and push every cell after it. Remembering the widest seen keeps
/// the table where it is.
fn column_widths(ui: &egui::Ui, id: egui::Id) -> [f32; 9] {
    let stored: Option<[f32; 9]> = ui.memory(|m| m.data.get_temp(id));
    stored.unwrap_or_else(|| {
        let font = egui::TextStyle::Body.resolve(ui.style());
        let mut widths = [0.0; 9];
        for (width, sample) in widths.iter_mut().zip(COLUMN_SAMPLES) {
            if !sample.is_empty() {
                *width = ui.fonts(|fonts| {
                    fonts
                        .layout_no_wrap(sample.to_owned(), font.clone(), egui::Color32::WHITE)
                        .size()
                        .x
                });
            }
        }
        widths
    })
}

/// One cell, at least as wide as its column has ever been.
fn cell(ui: &mut egui::Ui, column: usize, widths: &mut [f32; 9], add: impl FnOnce(&mut egui::Ui)) {
    let floor = widths[column];
    let response = ui.scope(|ui| {
        ui.set_min_width(floor);
        add(ui);
    });
    widths[column] = widths[column].max(response.response.rect.width());
}

/// The exit-node mark of a device: shown when it offers to be one, bright
/// for the one in use, and clickable (to confirm) only while that can be done.
///
/// The one in use stays clickable even when it has gone away, since stopping
/// is the only way out of the traffic being blocked.
fn exit_cell(
    ui: &mut egui::Ui,
    device: &Device<'_>,
    network_id: &str,
    confirm: &mut Option<ExitConfirm>,
) {
    if !device.exit_node && !device.in_use {
        ui.label("");
        return;
    }
    let (color, hint) = if device.in_use {
        let color = if device.online {
            exit::GOOD
        } else {
            exit::LOUD
        };
        (color, "in use as your exit node — click to stop")
    } else {
        (
            ui.visuals().text_color(),
            "offers to be an exit node — click to send all your internet traffic through it",
        )
    };
    let response = ui
        .add(
            egui::Label::new(
                egui::RichText::new(egui_phosphor::regular::SIGN_OUT)
                    .size(16.0)
                    .color(color),
            )
            .sense(egui::Sense::click()),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(hint);
    if response.clicked() {
        *confirm = Some(ExitConfirm {
            network_id: network_id.to_string(),
            peer_id: device.id.to_string(),
            name: device.name(),
            stop: device.in_use,
        });
    }
}

/// One table of all devices: online rows carry live counters and a plot,
/// offline rows show what is known (name and address) and dashes.
fn device_table(
    ui: &mut egui::Ui,
    unit: Unit,
    network: &NetworkReport,
    devices: &[Device<'_>],
    traffic: &Traffic,
    confirm: &mut Option<ExitConfirm>,
) {
    let network_id = network.network_id.as_str();
    if devices.is_empty() {
        ui.weak("none");
        return;
    }
    let widths_id = egui::Id::new(("devices column widths", network_id));
    let mut widths = column_widths(ui, widths_id);
    egui::Grid::new("devices")
        .num_columns(9)
        .striped(true)
        .spacing([10.0, 4.0])
        .show(ui, |ui| {
            for (column, header) in [
                "device",
                "exit",
                "proto",
                "address",
                "handshake",
                "pkts",
                "bytes",
                "rate",
                "plot",
            ]
            .into_iter()
            .enumerate()
            {
                cell(ui, column, &mut widths, |ui| {
                    ui.weak(header);
                });
            }
            ui.end_row();

            for device in devices {
                cell(ui, 0, &mut widths, |ui| name_cell(ui, device));
                cell(ui, 1, &mut widths, |ui| {
                    exit_cell(ui, device, network_id, confirm);
                });
                cell(ui, 2, &mut widths, |ui| {
                    ui.label(device.proto);
                });
                cell(ui, 3, &mut widths, |ui| match &device.address {
                    Some(address) => format::copy_field(ui, address, address),
                    None => {
                        ui.weak("—");
                    }
                });
                cell(ui, 4, &mut widths, |ui| {
                    ui.label(
                        device
                            .handshake_secs
                            .map_or_else(|| "offline".to_string(), format::age),
                    );
                });

                match device.overlay.filter(|_| device.online) {
                    Some(peer) => {
                        let series = traffic.peer(network_id, &peer.public_key);
                        cell(ui, 5, &mut widths, |ui| {
                            ui.label(format!("{}/{}", peer.tx_packets, peer.rx_packets));
                        });
                        cell(ui, 6, &mut widths, |ui| {
                            ui.label(format!(
                                "{} / {}",
                                format::bytes(peer.tx_bytes as f64),
                                format::bytes(peer.rx_bytes as f64)
                            ));
                        });
                        cell(ui, 7, &mut widths, |ui| {
                            ui.add(
                                egui::Label::new(format::series_rate(series, unit))
                                    .wrap_mode(egui::TextWrapMode::Extend),
                            );
                        });
                        ui.allocate_ui(egui::vec2(100.0, 20.0), |ui| {
                            format::sparkline(ui, series, unit, 18.0);
                        });
                    }
                    None => {
                        for column in 5..8 {
                            cell(ui, column, &mut widths, |ui| {
                                ui.weak("—");
                            });
                        }
                        ui.weak("—");
                    }
                }
                ui.end_row();
            }

            // Everything this agent has moved through the overlay, including
            // devices that have since gone away.
            let (mut tx_packets, mut rx_packets, mut tx_bytes, mut rx_bytes) = (0u64, 0, 0, 0);
            for peer in devices.iter().filter_map(|d| d.overlay) {
                tx_packets += peer.tx_packets;
                rx_packets += peer.rx_packets;
                tx_bytes += peer.tx_bytes;
                rx_bytes += peer.rx_bytes;
            }
            cell(ui, 0, &mut widths, |ui| {
                ui.strong("total");
            });
            for column in 1..5 {
                cell(ui, column, &mut widths, |ui| {
                    ui.label("");
                });
            }
            cell(ui, 5, &mut widths, |ui| {
                ui.strong(format!("{tx_packets}/{rx_packets}"));
            });
            cell(ui, 6, &mut widths, |ui| {
                ui.strong(format!(
                    "{} / {}",
                    format::bytes(tx_bytes as f64),
                    format::bytes(rx_bytes as f64)
                ));
            });
            cell(ui, 7, &mut widths, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format::series_rate(traffic.network(network_id), unit))
                            .strong(),
                    )
                    .wrap_mode(egui::TextWrapMode::Extend),
                );
            });
            ui.end_row();
        });
    ui.memory_mut(|m| m.data.insert_temp(widths_id, widths));
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
