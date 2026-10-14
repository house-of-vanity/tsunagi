//! The per-network devices window: full detail about one network — its
//! settings and counters, and one table of every device, online first, with
//! inline traffic plots for the connected ones.
//!
//! Rendered in a separate OS window (an egui viewport) opened from a tile in
//! the main window.

use std::collections::HashMap;

use eframe::egui;

use tsunagi::ipc::{DataPathReport, NetworkReport, OverlayPeerReport};

use crate::agent::{AgentClient, Command};
use crate::exit;
use crate::format;
use crate::stats::{Traffic, Unit};

/// A device that works but not as well as it could: reached through others,
/// or with a name somebody else holds.
const AMBER: egui::Color32 = egui::Color32::from_rgb(0xd9, 0xa4, 0x2c);

/// A readable title for a network's window.
pub(crate) fn title(network: &NetworkReport) -> String {
    format!("tsunagi · {}", network.name)
}

/// One row of the device table, built from a tunnel and/or a signed member.
struct Device<'a> {
    /// Observed claim version, if this row came from signed membership.
    record_version: Option<u64>,
    /// The agent's own answer to whether it can be reached by any path.
    online: bool,
    /// How packets reach it.
    path: Option<&'a DataPathReport>,
    /// What to call the member its traffic goes through, when it does.
    via_name: Option<String>,
    /// The name it claimed that another member holds, and what to call that
    /// member.
    name_taken: Option<(&'a str, String)>,
    /// The last hostname seen for it, kept while it is offline.
    hostname: Option<&'a str>,
    /// What clicking the hostname copies: `hostname.network`, so it resolves.
    copy: Option<String>,
    /// The full endpoint id, which clicking the short form copies.
    id: &'a str,
    /// End-to-end tunnel protocol, independent of the path carrying it.
    tunnel_protocol: &'a str,
    address: Option<String>,
    handshake_secs: Option<u64>,
    control_rtt_ms: Option<u64>,
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
    /// Asked in the main window, not in the devices window of the network.
    main: bool,
}

/// An exact offline claim selected for durable cleanup.
pub(crate) struct ForgetConfirm {
    network_id: String,
    peer: String,
    version: u64,
    name: String,
    address: Option<String>,
}

impl ExitConfirm {
    /// A question about stopping the exit node a network's tile shows.
    pub(crate) fn stop_from_tile(network: &NetworkReport, peer_id: &str) -> Self {
        Self {
            network_id: network.network_id.clone(),
            peer_id: peer_id.to_string(),
            name: exit::name_of(network, peer_id),
            stop: true,
            main: true,
        }
    }
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
        if let Some((name, holder)) = &device.name_taken {
            ui.label(egui::RichText::new(egui_phosphor::regular::WARNING).color(AMBER))
                .on_hover_text(format!(
                    "Name `{name}` belongs to {holder}. Use this device's address."
                ));
        }
    });
}

/// Draws the window body into its viewport.
pub(crate) fn show(
    ctx: &egui::Context,
    agent: &AgentClient,
    unit: &mut Unit,
    confirmations: (&mut Option<ExitConfirm>, &mut Option<ForgetConfirm>),
    network: &NetworkReport,
    own_id: &str,
    traffic: &Traffic,
) {
    let (confirm, forget_confirm) = confirmations;
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
                device_table(
                    ui,
                    unit,
                    network,
                    &devices,
                    traffic,
                    confirm,
                    forget_confirm,
                );
            });
    });
    confirm_exit(ctx, agent, confirm, Some(&network.network_id));
    confirm_forget(ctx, agent, forget_confirm, &network.network_id);
}

fn confirm_forget(
    ctx: &egui::Context,
    agent: &AgentClient,
    confirm: &mut Option<ForgetConfirm>,
    network: &str,
) {
    let Some(pending) = confirm.as_ref().filter(|c| c.network_id == network) else {
        return;
    };
    egui::Area::new(egui::Id::new("forget node backdrop"))
        .order(egui::Order::Middle)
        .fixed_pos(egui::Pos2::ZERO)
        .show(ctx, |ui| {
            let screen = ctx.screen_rect();
            ui.allocate_response(screen.size(), egui::Sense::click_and_drag());
            ui.painter()
                .rect_filled(screen, 0.0, egui::Color32::from_black_alpha(140));
        });
    let (mut accepted, mut cancelled) = (false, false);
    egui::Window::new("Forget offline node")
        .order(egui::Order::Foreground)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.set_max_width(440.0);
            ui.label(format!("Forget {}?", pending.name));
            ui.monospace(&pending.peer);
            if let Some(address) = &pending.address {
                ui.label(format!("IP: {address}"));
            }
            ui.label("The network will forget this claim and free its name and IP. A returning device can publish a new claim; this does not ban it.");
            ui.horizontal(|ui| {
                accepted = ui.add_enabled(!agent.snapshot().busy, egui::Button::new("Forget")).clicked();
                cancelled = ui.button("Cancel").clicked();
            });
        });
    if accepted {
        agent.send(Command::ForgetNode {
            network_id: pending.network_id.clone(),
            peer: pending.peer.clone(),
            expected_version: pending.version,
        });
    }
    if accepted || cancelled || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        *confirm = None;
    }
}

/// The confirmation for an exit-node choice, drawn in the window it was
/// made in. Everything behind it is blocked until it is answered.
///
/// `network_id` is the devices window the question is drawn in, or `None` for
/// the main window; a question appears in the window it was asked in only.
pub(crate) fn confirm_exit(
    ctx: &egui::Context,
    agent: &AgentClient,
    confirm: &mut Option<ExitConfirm>,
    network_id: Option<&str>,
) {
    let Some(pending) = confirm.as_ref().filter(|c| match network_id {
        Some(id) => !c.main && c.network_id == id,
        None => c.main,
    }) else {
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
    egui::Window::new("Exit node")
        .order(egui::Order::Foreground)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.set_max_width(380.0);
            ui.label(if pending.stop {
                format!("Stop using {}?", pending.name)
            } else {
                format!("Use {} as exit node?", pending.name)
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .button(if pending.stop { "Stop" } else { "Use" })
                    .clicked()
                {
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

/// How many other devices can be reached now, by any path.
pub(crate) fn online_count(network: &NetworkReport, own_id: &str) -> usize {
    devices(network, own_id).iter().filter(|d| d.online).count()
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
            let online = member.is_some_and(|m| m.online)
                || network.peers.iter().any(|p| p.endpoint_id == id);
            let path = network
                .peers
                .iter()
                .find(|p| p.endpoint_id == id)
                .map(|p| &p.path)
                .or_else(|| member.map(|m| &m.path));
            let via_name = match path {
                Some(DataPathReport::Relayed { via, .. }) => Some(exit::name_of(network, via)),
                _ => None,
            };
            let name_taken = member.and_then(|m| {
                m.hostname_conflict
                    .as_ref()
                    .map(|c| (c.name.as_str(), exit::name_of(network, &c.holder)))
            });
            let hostname = hostnames.get(id).copied();
            Device {
                record_version: member.map(|m| m.record_version),
                online,
                path,
                via_name,
                name_taken,
                hostname,
                copy: hostname.map(|h| format!("{h}.{}", network.name)),
                id,
                tunnel_protocol: overlay.map_or("—", |p| p.protocol.as_str()),
                address: overlay
                    .and_then(|p| p.address.clone())
                    .or_else(|| member.and_then(|m| m.overlay_address_v4.clone())),
                handshake_secs: overlay.and_then(|p| p.handshake_secs_ago),
                control_rtt_ms: network
                    .peers
                    .iter()
                    .find(|p| p.endpoint_id == id)
                    .and_then(|p| p.rtt_ms),
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
const COLUMN_SAMPLES: [&str; 10] = [
    "device",
    "exit",
    "end-to-end",
    "999d / 9999 ms",
    "255.255.255.255",
    "direct over tcp-tls",
    "99999/99999",
    "1023.9 MB / 1023.9 MB",
    "1023.9 kB/s",
    "plot",
];

/// Column widths that only ever grow, kept across frames.
///
/// A grid sizes each column to its widest cell *this frame*, so a value that
/// gets shorter — `14.4 MB/s` giving way to `382 pkt/s` — would pull the
/// column in and push every cell after it. Remembering the widest seen keeps
/// the table where it is.
fn column_widths(ui: &egui::Ui, id: egui::Id) -> [f32; 10] {
    let stored: Option<[f32; 10]> = ui.memory(|m| m.data.get_temp(id));
    stored.unwrap_or_else(|| {
        let font = egui::TextStyle::Body.resolve(ui.style());
        let mut widths = [0.0; 10];
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
fn cell(ui: &mut egui::Ui, column: usize, widths: &[f32; 10], add: impl FnOnce(&mut egui::Ui)) {
    let floor = widths[column];
    ui.allocate_ui_with_layout(
        egui::vec2(floor, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_min_width(floor);
            ui.set_max_width(floor);
            add(ui);
        },
    );
}

fn stretch_columns(mut widths: [f32; 10], available: f32) -> [f32; 10] {
    let gaps = 10.0 * (widths.len() - 1) as f32;
    widths[9] = widths[9].max(100.0);
    widths[9] += (available - gaps - widths.iter().sum::<f32>()).max(0.0);
    widths
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
        (ui.visuals().text_color(), "Use this exit node")
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
            main: false,
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
    forget_confirm: &mut Option<ForgetConfirm>,
) {
    let network_id = network.network_id.as_str();
    if devices.is_empty() {
        ui.weak("none");
        return;
    }
    let widths_id = egui::Id::new(("devices column widths", network_id));
    let mut widths = column_widths(ui, widths_id);
    let font = egui::TextStyle::Body.resolve(ui.style());
    for device in devices {
        let name = format!(
            "{} ({}){}",
            device.name(),
            short_id(device.id),
            if !device.online { " Forget" } else { "" }
        );
        let natural = ui.fonts(|fonts| {
            fonts
                .layout_no_wrap(name, font.clone(), egui::Color32::WHITE)
                .size()
                .x
        });
        widths[0] = widths[0].max(natural + 24.0);
    }
    ui.memory_mut(|m| m.data.insert_temp(widths_id, widths));
    let widths = stretch_columns(widths, ui.available_width());
    egui::Grid::new("devices")
        .num_columns(10)
        .min_col_width(0.0)
        .striped(true)
        .spacing([10.0, 4.0])
        .show(ui, |ui| {
            for (column, header) in [
                "device",
                "exit",
                "end-to-end",
                "handshake / RTT",
                "address",
                "data path",
                "pkts",
                "bytes",
                "rate",
                "plot",
            ]
            .into_iter()
            .enumerate()
            {
                cell(ui, column, &widths, |ui| {
                    let response = ui.weak(header);
                    match column {
                        2 => {
                            response.on_hover_text("End-to-end encryption.");
                        }
                        3 => {
                            response.on_hover_text("Handshake age / control-connection RTT.");
                        }
                        5 => {
                            response.on_hover_text("Transport carrying the encrypted tunnel.");
                        }
                        _ => {}
                    }
                });
            }
            ui.end_row();

            for device in devices {
                cell(ui, 0, &widths, |ui| {
                    ui.horizontal(|ui| {
                        name_cell(ui, device);
                        if !device.online
                            && !device.in_use
                            && let Some(version) = device.record_version
                            && ui
                                .add_enabled(network.active, egui::Button::new("Forget"))
                                .on_hover_text("Free this offline device's name and IPv4")
                                .clicked()
                        {
                            *forget_confirm = Some(ForgetConfirm {
                                network_id: network.network_id.clone(),
                                peer: device.id.into(),
                                version,
                                name: device.name(),
                                address: device.address.clone(),
                            });
                        }
                    });
                });
                cell(ui, 1, &widths, |ui| {
                    exit_cell(ui, device, network_id, confirm);
                });
                cell(ui, 2, &widths, |ui| {
                    ui.push_id((device.id, "end-to-end"), |ui| {
                        tunnel_cell(ui, device);
                    });
                });
                cell(ui, 3, &widths, |ui| {
                    ui.label(handshake_rtt_text(
                        device.handshake_secs,
                        device.control_rtt_ms,
                        displayed_protocol(device.tunnel_protocol) != "—",
                    ))
                    .on_hover_text(if device.tunnel_protocol == "tcp-tls" {
                        "Session age / control RTT."
                    } else {
                        "Last handshake age / control RTT."
                    });
                });
                cell(ui, 4, &widths, |ui| match &device.address {
                    Some(address) => format::copy_field(ui, address, address),
                    None => {
                        ui.weak("—");
                    }
                });
                cell(ui, 5, &widths, |ui| {
                    ui.push_id((device.id, "data-path"), |ui| data_path_cell(ui, device));
                });

                match device.overlay.filter(|_| device.online) {
                    Some(peer) => {
                        let series = traffic.peer(network_id, &peer.public_key);
                        cell(ui, 6, &widths, |ui| {
                            ui.label(format!("{}/{}", peer.tx_packets, peer.rx_packets));
                        });
                        cell(ui, 7, &widths, |ui| {
                            ui.label(format!(
                                "{} / {}",
                                format::bytes(peer.tx_bytes as f64),
                                format::bytes(peer.rx_bytes as f64)
                            ));
                        });
                        cell(ui, 8, &widths, |ui| {
                            ui.add(
                                egui::Label::new(format::series_rate(series, unit))
                                    .wrap_mode(egui::TextWrapMode::Extend),
                            );
                        });
                        ui.allocate_ui(egui::vec2(widths[9], 20.0), |ui| {
                            format::sparkline(ui, series, unit, 18.0);
                        });
                    }
                    None => {
                        for column in 6..9 {
                            cell(ui, column, &widths, |ui| {
                                ui.weak("—");
                            });
                        }
                        cell(ui, 9, &widths, |ui| {
                            ui.weak("—");
                        });
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
            cell(ui, 0, &widths, |ui| {
                ui.strong("total");
            });
            for column in 1..6 {
                cell(ui, column, &widths, |ui| {
                    ui.label("");
                });
            }
            cell(ui, 6, &widths, |ui| {
                ui.strong(format!("{tx_packets}/{rx_packets}"));
            });
            cell(ui, 7, &widths, |ui| {
                ui.strong(format!(
                    "{} / {}",
                    format::bytes(tx_bytes as f64),
                    format::bytes(rx_bytes as f64)
                ));
            });
            cell(ui, 8, &widths, |ui| {
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
}

/// A protocol name as it should appear in the table.
fn displayed_protocol(protocol: &str) -> &str {
    if protocol.is_empty() { "—" } else { protocol }
}

/// The end-to-end tunnel and its own health, without transport details.
fn handshake_rtt_text(handshake: Option<u64>, rtt: Option<u64>, has_tunnel: bool) -> String {
    let age = handshake.map_or_else(
        || {
            if has_tunnel {
                "waiting".into()
            } else {
                "—".into()
            }
        },
        format::age,
    );
    let rtt = rtt.map_or_else(|| "—".into(), |value| format!("{value} ms"));
    format!("{age} / {rtt}")
}

fn tunnel_hint(protocol: &str) -> String {
    let name = displayed_protocol(protocol);
    if name == "tcp-tls" {
        format!("{name}: Noise end-to-end encryption")
    } else {
        format!("{name}: WireGuard end-to-end encryption")
    }
}

fn tunnel_cell(ui: &mut egui::Ui, device: &Device<'_>) {
    let protocol = displayed_protocol(device.tunnel_protocol);
    if protocol == "—" {
        ui.weak(protocol);
        return;
    }
    ui.label(protocol).on_hover_text(tunnel_hint(protocol));
}

/// Current route text and whether that route is the preferred direct form.
fn data_path_text(
    path: Option<&DataPathReport>,
    via_name: Option<&str>,
    online: bool,
) -> (String, bool) {
    if !online {
        return ("offline".into(), false);
    }
    match path {
        Some(DataPathReport::Direct { transport }) => (format!("direct over {transport}"), true),
        Some(DataPathReport::Relayed { hops, .. }) => (
            format!("via {} · {hops} hops", via_name.unwrap_or("another device")),
            false,
        ),
        Some(DataPathReport::None) | None => ("no data path yet".into(), false),
    }
}

/// How a device is reached right now.
///
/// A device reached through others is online, over a longer path, and says
/// so: the colour is the only difference in how it is treated.
fn data_path_cell(ui: &mut egui::Ui, device: &Device<'_>) {
    let (text, good) = data_path_text(device.path, device.via_name.as_deref(), device.online);
    let response = if good {
        ui.label(text)
    } else {
        ui.label(egui::RichText::new(text).color(AMBER))
    };
    response.on_hover_text(match device.path {
        Some(DataPathReport::Direct { .. }) => "Direct transport; no mesh relay.",
        Some(DataPathReport::Relayed { .. }) => "Traffic forwarded through another device.",
        _ if device.online => "Control connected; data transport unavailable.",
        _ => "Unreachable.",
    });
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tsunagi::ipc::{HostnameConflictReport, MemberReport};

    fn member(id: &str, online: bool, path: DataPathReport) -> MemberReport {
        MemberReport {
            record_version: 1,
            endpoint_id: id.into(),
            online,
            path,
            ..Default::default()
        }
    }

    #[test]
    fn a_device_reached_through_another_is_online_whatever_its_tunnel_says() {
        // The tray used to call a device online only while its tunnel had
        // handshaken, which disagreed with the command line about the same
        // device. Both now read the agent's answer.
        let network = NetworkReport {
            members: vec![
                member("own", true, DataPathReport::None),
                member(
                    "far",
                    true,
                    DataPathReport::Relayed {
                        hops: 2,
                        via: "near".into(),
                    },
                ),
                member("away", false, DataPathReport::None),
            ],
            ..Default::default()
        };
        let all = devices(&network, "own");
        let far = all.iter().find(|d| d.id == "far").unwrap();
        assert!(far.online);
        assert!(matches!(
            far.path,
            Some(DataPathReport::Relayed { hops: 2, .. })
        ));
        assert!(!all.iter().find(|d| d.id == "away").unwrap().online);
        assert_eq!(online_count(&network, "own"), 1);
        assert_eq!(known_count(&network, "own"), 2);
    }

    #[test]
    fn a_name_somebody_else_holds_is_carried_to_the_row() {
        let mut taken = member("late", true, DataPathReport::None);
        taken.hostname_conflict = Some(HostnameConflictReport {
            name: "music".into(),
            holder: "early".into(),
        });
        let network = NetworkReport {
            members: vec![member("early", true, DataPathReport::None), taken],
            ..Default::default()
        };
        let all = devices(&network, "own");
        let late = all.iter().find(|d| d.id == "late").unwrap();
        assert_eq!(
            late.name_taken.as_ref().map(|(name, _)| *name),
            Some("music")
        );
        assert!(
            all.iter()
                .find(|d| d.id == "early")
                .unwrap()
                .name_taken
                .is_none()
        );
    }

    #[test]
    fn tunnel_and_direct_transport_are_named_as_different_layers() {
        assert_eq!(displayed_protocol("wg"), "wg");
        assert_eq!(tunnel_hint("wg"), "wg: WireGuard end-to-end encryption");
        assert_eq!(
            data_path_text(
                Some(&DataPathReport::Direct {
                    transport: "tcp-tls".into(),
                }),
                None,
                true,
            ),
            ("direct over tcp-tls".into(), true)
        );
        assert_eq!(
            tunnel_hint("tcp-tls"),
            "tcp-tls: Noise end-to-end encryption"
        );
    }

    #[test]
    fn incomplete_and_longer_paths_stay_explicit() {
        assert_eq!(handshake_rtt_text(None, Some(25), true), "waiting / 25 ms");
        assert_eq!(
            data_path_text(
                Some(&DataPathReport::Relayed {
                    hops: 2,
                    via: "near".into(),
                }),
                Some("iris"),
                true,
            ),
            ("via iris · 2 hops".into(), false)
        );
        assert_eq!(
            data_path_text(Some(&DataPathReport::None), None, true),
            ("no data path yet".into(), false)
        );
        assert_eq!(data_path_text(None, None, false), ("offline".into(), false));
    }

    #[test]
    fn handshake_rtt_has_no_invented_values_and_uses_control_measurements() {
        use tsunagi::ipc::{OverlayReport, PeerReport};
        let network = NetworkReport {
            peers: vec![PeerReport {
                endpoint_id: "peer".into(),
                rtt_ms: Some(27),
                ..Default::default()
            }],
            overlay: Some(OverlayReport {
                peers: vec![OverlayPeerReport {
                    endpoint_id: "peer".into(),
                    protocol: "wg".into(),
                    handshake_secs_ago: Some(5),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let rows = devices(&network, "own");
        assert_eq!(
            handshake_rtt_text(rows[0].handshake_secs, rows[0].control_rtt_ms, true),
            "5s / 27 ms"
        );
        assert_eq!(handshake_rtt_text(None, None, false), "— / —");
        assert_eq!(rows[0].tunnel_protocol, "wg");
        assert!(!tunnel_hint(rows[0].tunnel_protocol).contains("wg-quic"));
    }

    #[test]
    fn resized_table_fills_the_window_without_growing_fixed_columns() {
        let minimum = [100.0; 10];
        let wide = stretch_columns(minimum, 1440.0);
        assert!((wide.iter().sum::<f32>() + 90.0 - 1440.0).abs() < 0.1);
        assert_eq!(&wide[..9], &minimum[..9]);
        let narrow = stretch_columns(minimum, 800.0);
        assert_eq!(
            narrow, minimum,
            "narrow windows scroll rather than clipping columns"
        );
        assert_eq!(
            stretch_columns(minimum, 1440.0),
            wide,
            "a resize does not accumulate padding"
        );
    }

    #[test]
    fn rendered_table_uses_window_width_without_an_expanding_device_cell() {
        let context = egui::Context::default();
        let network = NetworkReport {
            members: vec![MemberReport {
                endpoint_id: "0123456789abcdef".into(),
                hostname: Some("laptop".into()),
                online: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let rows = devices(&network, "own");
        for width in [1440.0, 1200.0, 1440.0] {
            for _ in 0..3 {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 640.0),
                    )),
                    ..Default::default()
                };
                let _output = context.run(input, |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let right = ui.max_rect().right();
                        egui::ScrollArea::both()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                device_table(
                                    ui,
                                    Unit::Bytes,
                                    &network,
                                    &rows,
                                    &Traffic::default(),
                                    &mut None,
                                    &mut None,
                                );
                            });
                        assert!(
                            (ui.min_rect().right() - right).abs() < 2.0,
                            "table width after resize: {} vs {right}",
                            ui.min_rect().right()
                        );
                    });
                });
            }
        }
    }
}
