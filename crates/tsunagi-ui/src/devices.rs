//! The per-network devices window: full detail about one network — its
//! settings and counters, and one table of every device, online first, with
//! inline traffic plots for the connected ones.
//!
//! Rendered in a separate OS window (an egui viewport) opened from a tile in
//! the main window.

use std::collections::HashMap;
mod compact;
mod exit_picker;
mod speed;
#[cfg(test)]
mod speed_tests;
mod status;
pub use crate::exit::name_of;
pub use exit_picker::choose_exit;

use egui_phosphor::regular as icon;

use tsunagi::ipc::{DataPathReport, NetworkReport, OverlayPeerReport};

use crate::client::{Client, Command};
use crate::exit;
use crate::format;
use crate::stats::{Traffic, Unit};
use crate::widgets;

/// A hostname that another peer already holds.
const AMBER: egui::Color32 = egui::Color32::from_rgb(0xd9, 0xa4, 0x2c);

/// A readable title for a network's window.
pub fn title(network: &NetworkReport) -> String {
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
    agent_version: Option<&'a str>,
    /// What clicking the hostname copies: `hostname.network`, so it resolves.
    copy: Option<String>,
    /// The full endpoint id, which clicking the short form copies.
    id: &'a str,
    /// Why the permitted external data channel is unavailable, when known.
    data_error: Option<&'a str>,
    address: Option<String>,
    control_rtt_ms: Option<u64>,
    data_rtt_ms: Option<u64>,
    data_transport_detail: Option<&'a str>,
    overlay: Option<&'a OverlayPeerReport>,
    /// It is connected and offers to be an exit node.
    exit_node: bool,
    /// It is the exit node this device sends its internet traffic through.
    in_use: bool,
}

/// An exit-node choice the user has to confirm: all their traffic goes through
/// somebody else's device, or stops doing so.
pub struct ExitConfirm {
    network_id: String,
    peer_id: String,
    name: String,
    /// Stop using it, rather than start.
    stop: bool,
    /// Asked in the main window, not in the devices window of the network.
    main: bool,
}

/// An exact offline claim selected for durable cleanup.
pub struct ForgetConfirm {
    network_id: String,
    peer: String,
    version: u64,
    name: String,
    address: Option<String>,
}

impl ExitConfirm {
    /// A question about stopping the exit node a network's tile shows.
    pub fn stop_from_tile(network: &NetworkReport, peer_id: &str) -> Self {
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

    fn version_label(&self) -> String {
        self.agent_version
            .map_or_else(|| "v?".into(), |v| format!("v{}", format::short(v)))
    }
}

/// The first characters of an endpoint id, enough to tell devices apart.
fn short_id(id: &str) -> String {
    id.chars().take(5).collect()
}

/// The device cell: the hostname and, in brackets, the start of the id.
/// Clicking either copies its own full value.
fn name_cell(ui: &mut egui::Ui, device: &Device<'_>) {
    ui.spacing_mut().item_spacing.x = 4.0;
    let (rect, r) = ui.allocate_exact_size(egui::Vec2::splat(16.), egui::Sense::click());
    device.channel().paint(ui, rect);
    widgets::hint(r, device.channel_hint());
    match (device.hostname, &device.copy) {
        (Some(hostname), Some(copy)) => {
            format::copy_field(ui, hostname, copy);
            format::copy_field(ui, &format!("({})", short_id(device.id)), device.id);
        }
        _ => format::copy_field(ui, &short_id(device.id), device.id),
    }
    ui.label(egui::RichText::new(device.version_label()).small().weak())
        .on_hover_text(format!(
            "Tsunagi {}",
            device.agent_version.unwrap_or("version unknown")
        ));
    if let Some((name, holder)) = &device.name_taken {
        let warning = ui.add(
            egui::Label::new(egui::RichText::new(icon::WARNING).color(AMBER))
                .sense(egui::Sense::click()),
        );
        widgets::hint(
            warning,
            &format!("Name `{name}` belongs to {holder}. Use this device's address."),
        );
    }
}

/// Draws the window body into its viewport.
pub fn show(
    ctx: &egui::Context,
    agent: &dyn Client,
    unit: &mut Unit,
    confirmations: (&mut Option<ExitConfirm>, &mut Option<ForgetConfirm>),
    network: &NetworkReport,
    own_id: &str,
    traffic: &Traffic,
) {
    let (confirm, forget_confirm) = confirmations;
    let speed = speed::Controls::new(network, agent);
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.horizontal(|ui| {
            // Reserve the unit switch even when a network name fills the viewport.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.selectable_value(unit, Unit::Bytes, "bytes");
                ui.selectable_value(unit, Unit::Packets, "pkts");
                ui.label("show:");
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.add(
                        egui::Label::new(egui::RichText::new(&network.name).heading()).truncate(),
                    );
                });
            });
        });
        // A copy of the chosen unit for the read-only rendering below.
        let unit = *unit;
        let devices = devices(network, own_id);
        let roster_tools = |ui: &mut egui::Ui| {
            let online = devices.iter().filter(|d| d.online).count();
            ui.horizontal_wrapped(|ui| {
                ui.strong(format!(
                    "devices ({online} online / {} known)",
                    devices.len()
                ));
                speed.toolbar(ui);
            });
        };

        if ctx.os() == egui::os::OperatingSystem::Android || ui.available_width() < 620.0 {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.collapsing("Network details", |ui| summary(ui, network));
                    if widgets::landscape(ctx) {
                        ui.collapsing("Network traffic", |ui| {
                            format::sparkline(ui, traffic.network(&network.network_id), unit, 34.0)
                        });
                    } else {
                        format::sparkline(ui, traffic.network(&network.network_id), unit, 34.0);
                    }
                    roster_tools(ui);
                    compact::roster(
                        ui,
                        network,
                        &devices,
                        traffic,
                        unit,
                        (confirm, forget_confirm),
                        &speed,
                    );
                });
            return;
        }
        ui.columns(2, |columns| {
            roster_tools(&mut columns[0]);
            columns[0].collapsing("Network details", |ui| summary(ui, network));
            let plot = &mut columns[1];
            plot.label("Network traffic");
            let width = plot.available_width().min(440.0);
            plot.scope(|ui| {
                ui.set_max_width(width);
                format::sparkline(ui, traffic.network(&network.network_id), unit, 48.0);
            });
        });
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let table = desktop_columns(ui, unit, network, &devices, traffic);
                let required = table.widths.iter().sum::<f32>() + crate::table::GAP * 8.;
                if required <= ui.available_width() {
                    device_table(
                        ui,
                        network,
                        &devices,
                        (traffic, unit),
                        (confirm, forget_confirm),
                        &speed,
                        &table,
                    );
                } else {
                    compact::roster(
                        ui,
                        network,
                        &devices,
                        traffic,
                        unit,
                        (confirm, forget_confirm),
                        &speed,
                    );
                }
            });
    });
    confirm_exit(ctx, agent, confirm, Some(&network.network_id));
    confirm_forget(ctx, agent, forget_confirm, &network.network_id);
}

fn confirm_forget(
    ctx: &egui::Context,
    agent: &dyn Client,
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
                accepted = ui.add_enabled(!agent.busy(), egui::Button::new("Forget")).clicked();
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
pub fn confirm_exit(
    ctx: &egui::Context,
    agent: &dyn Client,
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
            ui.set_max_width((ctx.screen_rect().width() - 40.0).clamp(160.0, 380.0));
            let phone = ctx.os() == egui::os::OperatingSystem::Android;
            ui.label(if pending.stop {
                format!("Stop using {}?", pending.name)
            } else if phone {
                format!(
                    "Route this phone’s IPv4 internet traffic through {}?",
                    pending.name
                )
            } else {
                format!("Use {} as exit node?", pending.name)
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if phone {
                    ui.spacing_mut().interact_size = egui::vec2(104., 48.);
                    ui.spacing_mut().button_padding.x = 18.;
                }
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
            widgets::network_id(ui);
            let id = if ui.ctx().os() == egui::os::OperatingSystem::Android
                || ui.available_width() < 440.0
            {
                format::short(&network.network_id)
            } else {
                network.network_id.clone()
            };
            format::copy_field(ui, &id, &network.network_id);
            ui.end_row();

            widgets::field(ui, icon::POWER, "Active", "Network active on this device");
            ui.label(yes_no(network.active));
            ui.end_row();
            widgets::field(
                ui,
                icon::BROADCAST,
                "Broadcast",
                "Local broadcast participation",
            );
            ui.label(yes_no(network.broadcast));
            ui.end_row();

            if let Some(range) = &network.range {
                widgets::range(ui);
                format::copy_field(ui, range, range);
                ui.end_row();
            }
            if let Some(address) = network.overlay.as_ref().and_then(|o| o.address.as_ref()) {
                widgets::device_address(ui);
                format::copy_field(ui, address, address);
                ui.end_row();
            }
            widgets::field(
                ui,
                icon::MAGNIFYING_GLASS,
                "Candidates",
                "Unverified discovery candidates",
            );
            ui.label(network.candidates.to_string());
            ui.end_row();
            widgets::field(
                ui,
                icon::FLOW_ARROW,
                "Relay fwd / via / recv",
                "Datagrams forwarded / sent via relay / received via relay",
            );
            ui.label(format!(
                "{} / {} / {}",
                network.relay_forwarded, network.relay_sent_via, network.relay_received_via
            ));
            ui.end_row();
            widgets::field(
                ui,
                icon::WARNING,
                "Dial / handshake failures",
                "Failed connection attempts / failed membership handshakes",
            );
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
pub fn online_count(network: &NetworkReport, own_id: &str) -> usize {
    devices(network, own_id).iter().filter(|d| d.online).count()
}

/// How many other devices this network knows of, connected or not.
pub fn known_count(network: &NetworkReport, own_id: &str) -> usize {
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
            let peer = network.peers.iter().find(|p| p.endpoint_id == id);
            let online = member.is_some_and(|m| m.online) || peer.is_some();
            let path = peer.map(|p| &p.path).or_else(|| member.map(|m| &m.path));
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
                agent_version: peer.and_then(|p| p.agent_version.as_deref()),
                copy: hostname.map(|h| format!("{h}.{}", network.name)),
                id,
                data_error: peer.and_then(|p| p.data_error.as_deref()),
                address: overlay
                    .and_then(|p| p.address.clone())
                    .or_else(|| member.and_then(|m| m.overlay_address_v4.clone())),
                control_rtt_ms: peer.and_then(|p| p.rtt_ms),
                data_rtt_ms: peer.and_then(|p| p.data_rtt_ms),
                data_transport_detail: peer.and_then(|p| p.data_transport_detail.as_deref()),
                overlay,
                exit_node: peer.is_some_and(|p| p.exit_node),
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

fn column_headers(unit: Unit) -> [&'static str; 9] {
    [
        "device",
        "exit",
        "data",
        "RTT data / control",
        "address",
        "data path",
        match unit {
            Unit::Bytes => "bytes (TX / RX)",
            Unit::Packets => "pkts (TX / RX)",
        },
        "rate",
        "plot",
    ]
}

/// Initial column floors; actual headers, values and totals can grow them.
const COLUMN_SAMPLES: [&str; 9] = [
    "device",
    "exit",
    "data",
    "9999 ms",
    "255.255.255.255",
    "data path",
    "1023.9 MB / 1023.9 MB",
    "1023.9 kB/s",
    "plot",
];

fn traffic_pair(tx: u64, rx: u64, unit: Unit) -> String {
    format!(
        "{} / {}",
        format::amount(tx, unit),
        format::amount(rx, unit)
    )
}

/// Column widths that only ever grow, kept across frames.
///
/// Live values can change width between frames. A value that
/// gets shorter — `14.4 MB/s` giving way to `382 pkt/s` — would pull the
/// column in and push every cell after it. Remembering the widest seen keeps
/// the table where it is.
fn column_widths(ui: &egui::Ui, id: egui::Id) -> [f32; 9] {
    let stored: Option<[f32; 9]> = ui.memory(|m| m.data.get_temp(id));
    stored.unwrap_or_else(|| {
        let font = egui::FontSelection::Default.resolve(ui.style());
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

fn stretch_columns(mut widths: [f32; 9], available: f32) -> [f32; 9] {
    let gaps = crate::table::GAP * (widths.len() - 1) as f32;
    widths[8] = (available - gaps - widths[..8].iter().sum::<f32>()).clamp(100.0, 180.0);
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
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if widgets::hint(response, hint).clicked() {
        *confirm = Some(ExitConfirm {
            network_id: network_id.to_string(),
            peer_id: device.id.to_string(),
            name: device.name(),
            stop: device.in_use,
            main: false,
        });
    }
}

struct DesktopColumns {
    widths: [f32; 9],
    total: String,
    rate: String,
}

fn desktop_columns(
    ui: &egui::Ui,
    unit: Unit,
    network: &NetworkReport,
    devices: &[Device<'_>],
    traffic: &Traffic,
) -> DesktopColumns {
    let network_id = network.network_id.as_str();
    let widths_id = egui::Id::new(("devices column widths", network_id));
    let mut widths = column_widths(ui, widths_id);
    let previous_widths = widths;
    let font = egui::FontSelection::Default.resolve(ui.style());
    let measure = |text: String| {
        ui.fonts(|fonts| {
            fonts
                .layout_no_wrap(text, font.clone(), egui::Color32::WHITE)
                .size()
                .x
        })
    };
    let headers = column_headers(unit);
    for (column, header) in headers.iter().enumerate() {
        widths[column] = widths[column].max(measure((*header).to_owned()));
    }
    widths[1] = widths[1].max(measure("exit".into()) + 4. + speed::WIDTH);
    let (mut tx_total, mut rx_total) = (0_u64, 0_u64);
    for device in devices {
        let name = format!(
            "{} ({}) {}{}",
            device.name(),
            short_id(device.id),
            device.version_label(),
            if !device.online { " Forget" } else { "" }
        );
        widths[0] = widths[0].max(measure(name) + 44.0);
        let path = data_path_text(device.path, device.via_name.as_deref(), device.online);
        for (column, text) in [
            (2, device.channel().label().to_owned()),
            (3, rtt_pair(device)),
            (4, device.address.clone().unwrap_or_default()),
            (5, path),
        ] {
            widths[column] = widths[column].max(measure(text));
        }
        if let Some(peer) = device.overlay {
            let (tx, rx) = unit.counters(peer);
            tx_total = tx_total.saturating_add(tx);
            rx_total = rx_total.saturating_add(rx);
            widths[6] = widths[6].max(measure(traffic_pair(tx, rx, unit)));
            widths[7] = widths[7].max(measure(format::series_rate(
                traffic.peer(network_id, &peer.public_key),
                unit,
            )));
        }
    }
    let total = traffic_pair(tx_total, rx_total, unit);
    let rate = format::series_rate(traffic.network(network_id), unit);
    widths[6] = widths[6].max(measure(total.clone()));
    widths[7] = widths[7].max(measure(rate.clone()));
    if widths != previous_widths {
        ui.ctx().request_repaint();
    }
    ui.memory_mut(|m| m.data.insert_temp(widths_id, widths));
    let widths = stretch_columns(widths, ui.available_width());
    DesktopColumns {
        widths,
        total,
        rate,
    }
}

/// One table of all devices: online rows carry live counters and a plot,
/// offline rows show what is known (name and address) and dashes.
fn device_table(
    ui: &mut egui::Ui,
    network: &NetworkReport,
    devices: &[Device<'_>],
    (traffic, unit): (&Traffic, Unit),
    (confirm, forget_confirm): (&mut Option<ExitConfirm>, &mut Option<ForgetConfirm>),
    speed: &speed::Controls<'_>,
    table: &DesktopColumns,
) {
    if devices.is_empty() {
        ui.weak("none");
        return;
    }
    let network_id = &network.network_id;
    let headers = column_headers(unit);
    let widths = &table.widths;
    crate::table::row(ui, "device headers", widths, false, |column, ui| {
        let response = ui.weak(headers[column]);
        match column {
            1 => {
                let rect = ui.max_rect();
                let speed_rect = rect.split_left_right_at_x(rect.right() - speed::WIDTH).1;
                let r = ui.interact(
                    speed_rect,
                    ui.id().with("speed units"),
                    egui::Sense::click(),
                );
                ui.painter_at(speed_rect).text(
                    speed_rect.center(),
                    egui::Align2::CENTER_CENTER,
                    speed::HEADER,
                    egui::TextStyle::Body.resolve(ui.style()),
                    ui.visuals().weak_text_color(),
                );
                widgets::hint(r, speed::HEADER_HINT);
            }
            2 => {
                response.on_hover_text("Encrypted data channel readiness.");
            }
            3 => {
                response.on_hover_text("Data-link and control-connection round-trip times.");
            }
            6 => {
                response.on_hover_text("Sent / received IP traffic in the selected unit. Excludes relay transit and transport overhead.");
            }
            5 => {
                response.on_hover_text("External data transport or relay route.");
            }
            _ => {}
        }
    });
    for (index, device) in devices.iter().enumerate() {
        crate::table::row(
            ui,
            device.id,
            widths,
            index % 2 == 0,
            |column, ui| match column {
                0 => {
                    name_cell(ui, device);
                    forget_button(ui, device, network, forget_confirm);
                }
                1 => {
                    let rect = ui.max_rect();
                    let speed_rect = rect.split_left_right_at_x(rect.right() - speed::WIDTH).1;
                    exit_cell(ui, device, network_id, confirm);
                    speed.cell(ui, speed_rect, device);
                }
                2 => tunnel_cell(ui, device),
                3 => {
                    ui.label(rtt_pair(device)).on_hover_text(
                        "Median authenticated direct data-link RTT / selected control-connection RTT. A dash means there is no current measurement.",
                    );
                }
                4 => match &device.address {
                    Some(address) => format::copy_field(ui, address, address),
                    None => {
                        ui.weak("—");
                    }
                },
                5 => data_path_cell(ui, device),
                _ => {
                    if let Some(peer) = device.overlay.filter(|_| device.online) {
                        let series = traffic.peer(network_id, &peer.public_key);
                        match column {
                            6 => {
                                let (tx, rx) = unit.counters(peer);
                                ui.label(traffic_pair(tx, rx, unit));
                            }
                            7 => {
                                ui.label(format::series_rate(series, unit));
                            }
                            _ => format::sparkline(ui, series, unit, 24.0),
                        }
                    } else {
                        ui.weak("—");
                    }
                }
            },
        );
    }
    crate::table::row(
        ui,
        "device totals",
        widths,
        false,
        |column, ui| match column {
            0 => {
                ui.strong("total");
            }
            6 => {
                ui.strong(&table.total);
            }
            7 => {
                ui.strong(&table.rate);
            }
            _ => {}
        },
    );
}

fn rtt_text(rtt: Option<u64>) -> String {
    rtt.map_or_else(|| "—".into(), |value| format!("{value} ms"))
}

fn rtt_pair(device: &Device<'_>) -> String {
    format!(
        "{} / {}",
        rtt_text(device.data_rtt_ms),
        rtt_text(device.control_rtt_ms)
    )
}

fn tunnel_cell(ui: &mut egui::Ui, device: &Device<'_>) {
    let state = device.channel();
    let r = ui.add(
        egui::Label::new(egui::RichText::new(state.label()).color(state.color(ui)))
            .sense(egui::Sense::click()),
    );
    widgets::hint(r, device.channel_hint());
}

/// Compact route label for either client.
/// The icon font is embedded by egui-phosphor and installed in `App::new`.
fn data_path_text(path: Option<&DataPathReport>, via_name: Option<&str>, online: bool) -> String {
    if !online {
        return "offline".into();
    }
    match path {
        Some(DataPathReport::Direct { transport }) => format!("{} {transport}", icon::LINK),
        Some(DataPathReport::Relayed { hops, .. }) => format!(
            "{} {} · {hops} hops",
            icon::SHARE_NETWORK,
            via_name.unwrap_or("another device")
        ),
        Some(DataPathReport::None) | None => "no data path yet".into(),
    }
}

/// How a device is reached right now.
///
fn data_path_cell(ui: &mut egui::Ui, device: &Device<'_>) {
    let text = data_path_text(device.path, device.via_name.as_deref(), device.online);
    let mut text = egui::RichText::new(text);
    if !device.online {
        text = text.weak();
    }
    let response = ui.add(egui::Label::new(text).extend().sense(egui::Sense::click()));
    widgets::hint(
        response,
        match device.path {
            Some(DataPathReport::Direct { .. }) => device
                .data_transport_detail
                .unwrap_or("Direct link to this member."),
            Some(DataPathReport::Relayed { .. }) => "Traffic forwarded through another device.",
            _ if device.online => "Control connected; data transport unavailable.",
            _ => "Unreachable.",
        },
    );
}

fn forget_button(
    ui: &mut egui::Ui,
    device: &Device<'_>,
    network: &NetworkReport,
    confirm: &mut Option<ForgetConfirm>,
) {
    if !device.online
        && !device.in_use
        && let Some(version) = device.record_version
        && ui
            .add_enabled(network.active, egui::Button::new("Forget"))
            .on_hover_text("Free this offline device's name and IPv4")
            .clicked()
    {
        *confirm = Some(ForgetConfirm {
            network_id: network.network_id.clone(),
            peer: device.id.into(),
            version,
            name: device.name(),
            address: device.address.clone(),
        });
    }
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

    struct ReadOnly;
    impl Client for ReadOnly {
        fn send(&self, _: Command) {
            panic!("reading the devices view issued an action");
        }
        fn busy(&self) -> bool {
            false
        }
    }

    fn device_table(
        ui: &mut egui::Ui,
        unit: Unit,
        network: &NetworkReport,
        devices: &[Device<'_>],
        traffic: &Traffic,
        confirm: &mut Option<ExitConfirm>,
        forget: &mut Option<ForgetConfirm>,
    ) {
        let table = desktop_columns(ui, unit, network, devices, traffic);
        super::device_table(
            ui,
            network,
            devices,
            (traffic, unit),
            (confirm, forget),
            &speed::Controls::new(network, &ReadOnly),
            &table,
        );
    }

    #[test]
    fn phone_roster_fits_each_width_and_expands_only_the_tapped_member() {
        let mut network = NetworkReport {
            network_id: "a".repeat(60),
            name: "lab".into(),
            ..Default::default()
        };
        for (i, name) in [
            "alpha",
            "bravo",
            "charlie",
            "long-hostname-that-cannot-fit-a-phone-row",
        ]
        .into_iter()
        .enumerate()
        {
            let mut m = member(name, i < 2, DataPathReport::None);
            m.hostname = Some(name.into());
            m.overlay_address_v4 = Some(format!("192.168.254.{}", 240 + i));
            network.members.push(m);
        }
        network.peers.push(tsunagi::ipc::PeerReport {
            endpoint_id: "alpha".into(),
            agent_version: Some("2.0.0-rc.1".into()),
            ..Default::default()
        });
        network.overlay = Some(tsunagi::ipc::OverlayReport {
            peers: vec![OverlayPeerReport {
                endpoint_id: "alpha".into(),
                tx_bytes: 1024,
                rx_bytes: 512,
                ..Default::default()
            }],
            ..Default::default()
        });
        for width in [320.0, 360.0, 430.0, 870.0] {
            let ctx = egui::Context::default();
            ctx.set_os(egui::os::OperatingSystem::Android);
            ctx.set_fonts(crate::app_fonts());
            let frame = |events| {
                ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 720.),
                        )),
                        events,
                        ..Default::default()
                    },
                    |ctx| {
                        show(
                            ctx,
                            &ReadOnly,
                            &mut Unit::Bytes,
                            (&mut None, &mut None),
                            &network,
                            "self",
                            &Traffic::default(),
                        )
                    },
                )
            };
            let positions = |out: &egui::FullOutput, value: &str| -> Vec<egui::Pos2> {
                out.shapes
                    .iter()
                    .filter_map(|s| match &s.shape {
                        egui::Shape::Text(t) if t.galley.text() == value => {
                            Some(t.pos + t.galley.rect.center().to_vec2())
                        }
                        _ => None,
                    })
                    .collect()
            };
            frame(vec![]);
            let out = frame(vec![]);
            let a = positions(&out, "alpha")[0];
            let b = positions(&out, "bravo")[0];
            assert!(
                (15.0..=29.0).contains(&(b.y - a.y)),
                "one text line per device at {width}"
            );
            for i in 240..244 {
                let p = positions(&out, &format!("192.168.254.{i}"))[0];
                assert!(p.x < width - 30.0, "IPv4 outside row at {width}: {p:?}");
            }
            assert!(positions(&out, "Endpoint ID").is_empty());
            let click = |p: egui::Pos2| {
                for pressed in [true, false] {
                    frame(vec![
                        egui::Event::PointerMoved(p),
                        egui::Event::PointerButton {
                            pos: p,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: Default::default(),
                        },
                    ]);
                }
                frame(vec![])
            };
            let expanded = click(a);
            assert_eq!(positions(&expanded, "Endpoint ID").len(), 1);
            assert_eq!(positions(&expanded, "2.0.0-rc.1").len(), 1);
            let up = positions(&expanded, "1.0 kB")[0];
            let down = positions(&expanded, "512 B")[0];
            assert!(down.x - up.x > width * 0.25 && (up.y - down.y).abs() < 2.0);
            for (arrow, caption, value) in [
                (icon::ARROW_UP, "Sent", up),
                (icon::ARROW_DOWN, "Received", down),
            ] {
                let arrow = positions(&expanded, arrow)[0];
                let caption = positions(&expanded, caption)[0];
                assert!(arrow.x < caption.x && arrow.y < value.y);
                assert!((arrow.x - value.x).abs() < 35.0);
            }
            let switched = click(positions(&expanded, "bravo")[0]);
            assert_eq!(positions(&switched, "Endpoint ID").len(), 1);
            assert_eq!(positions(&switched, "Unknown").len(), 1);
            let closed = click(positions(&switched, "bravo")[0]);
            assert!(positions(&closed, "Endpoint ID").is_empty());
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
        assert_eq!(
            data_path_text(
                Some(&DataPathReport::Direct {
                    transport: "tcp-tls".into(),
                }),
                None,
                true,
            ),
            format!("{} tcp-tls", icon::LINK)
        );
    }

    #[test]
    fn incomplete_and_longer_paths_stay_explicit() {
        assert_eq!(rtt_text(Some(25)), "25 ms");
        assert_eq!(
            data_path_text(
                Some(&DataPathReport::Relayed {
                    hops: 2,
                    via: "near".into(),
                }),
                Some("iris"),
                true,
            ),
            format!("{} iris · 2 hops", icon::SHARE_NETWORK)
        );
        assert_eq!(
            data_path_text(Some(&DataPathReport::None), None, true),
            "no data path yet"
        );
        assert_eq!(data_path_text(None, None, false), "offline");
    }

    #[test]
    fn rtt_has_no_invented_values_and_ignores_the_internal_handshake_age() {
        use tsunagi::ipc::{OverlayReport, PeerReport};
        let network = NetworkReport {
            peers: vec![PeerReport {
                data_error: None,
                endpoint_id: "peer".into(),
                rtt_ms: Some(27),
                data_rtt_ms: Some(203),
                data_transport_detail: Some("relay via relay.example".into()),
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
        assert_eq!(rtt_text(rows[0].control_rtt_ms), "27 ms");
        assert_eq!(rtt_text(rows[0].data_rtt_ms), "203 ms");
        assert_eq!(
            rows[0].data_transport_detail,
            Some("relay via relay.example")
        );
        assert_eq!(rtt_text(None), "—");
    }

    #[test]
    fn wider_windows_keep_a_compact_plot_and_narrow_windows_preserve_column_floors() {
        let minimum = [100.0; 9];
        let wide = stretch_columns(minimum, 1440.0);
        assert!((100.0..=190.0).contains(&wide[8]));
        assert_eq!(&wide[..8], &minimum[..8]);
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

        let ctx = egui::Context::default();
        for window_width in [800.0, 1000.0, 1440.0] {
            let frame = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(window_width, 640.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    show(
                        ctx,
                        &ReadOnly,
                        &mut Unit::Bytes,
                        (&mut None, &mut None),
                        &NetworkReport::default(),
                        "self",
                        &Traffic::default(),
                    );
                },
            );
            let chart = frame
                .shapes
                .iter()
                .find_map(|s| match &s.shape {
                    egui::Shape::Rect(r) if r.rect.height() == 48.0 => Some(r.rect),
                    _ => None,
                })
                .expect("network traffic chart");
            assert!((300.0..=440.0).contains(&chart.width()), "{chart:?}");
        }
    }

    #[test]
    fn counters_headers_and_rtt_stay_on_one_line_without_overlapping() {
        use tsunagi::ipc::{OverlayReport, PeerReport};

        fn collect_text<'a>(
            shapes: &'a [egui::Shape],
            texts: &mut Vec<&'a egui::epaint::TextShape>,
        ) {
            for shape in shapes {
                match shape {
                    egui::Shape::Text(shape) => texts.push(shape),
                    egui::Shape::Vec(shapes) => collect_text(shapes, texts),
                    _ => {}
                }
            }
        }

        let context = egui::Context::default();
        for (width, packets, age, unit) in [
            (1600.0, 1569, 56, crate::home::UiState::default().unit),
            (1600.0, 55_555, 172_800, Unit::Packets),
            (1600.0, 137_245, 172_800, Unit::Bytes),
            (900.0, 9_876_543_210, 172_800, Unit::Packets),
            (1600.0, 42, 56, Unit::Bytes),
        ] {
            let network = NetworkReport {
                network_id: "network".into(),
                peers: ["peer", "other"]
                    .into_iter()
                    .map(|id| PeerReport {
                        agent_version: (id == "peer").then(|| "2.0.0-rc.1".into()),
                        data_error: None,
                        endpoint_id: id.into(),
                        rtt_ms: Some(12_345),
                        ..Default::default()
                    })
                    .collect(),
                overlay: Some(OverlayReport {
                    peers: ["peer", "other"]
                        .into_iter()
                        .map(|id| OverlayPeerReport {
                            endpoint_id: id.into(),
                            protocol: "wg-quic".into(),
                            address: Some("10.13.37.100".into()),
                            handshake_secs_ago: Some(age),
                            tx_packets: packets,
                            rx_packets: packets + 1,
                            tx_bytes: 123_456_789,
                            rx_bytes: 987_654_321,
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let rows = devices(&network, "own");
            for _ in 0..3 {
                let output = context.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(2400.0, 640.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            ui.allocate_ui(egui::vec2(width, 480.0), |ui| {
                                device_table(
                                    ui,
                                    unit,
                                    &network,
                                    &rows,
                                    &Traffic::default(),
                                    &mut None,
                                    &mut None,
                                );
                            });
                        });
                    },
                );
                let shapes: Vec<_> = output.shapes.into_iter().map(|s| s.shape).collect();
                let mut texts = Vec::new();
                collect_text(&shapes, &mut texts);
                let visible = |value: &str| texts.iter().any(|t| t.galley.text() == value);
                assert!(visible("v2.0.0-rc.1"));
                assert!(visible("v?"));
                let packet_counts = format!("{packets} / {}", packets + 1);
                let byte_counts = "117.7 MB / 941.9 MB";
                if packets == 1569 {
                    assert!(visible("bytes (TX / RX)"));
                    assert!(visible(byte_counts));
                }
                assert_eq!(visible(&packet_counts), unit == Unit::Packets);
                assert_eq!(visible(byte_counts), unit == Unit::Bytes);
                for (label, next_column) in [
                    ("RTT data / control".to_string(), "address"),
                    (rtt_pair(&rows[0]), "address"),
                    (
                        if unit == Unit::Packets {
                            packet_counts
                        } else {
                            byte_counts.into()
                        },
                        "rate",
                    ),
                    (
                        if unit == Unit::Packets {
                            format!("{} / {}", packets * 2, (packets + 1) * 2)
                        } else {
                            "235.5 MB / 1.8 GB".into()
                        },
                        "rate",
                    ),
                ] {
                    let right = texts
                        .iter()
                        .find(|shape| shape.galley.text() == next_column)
                        .unwrap()
                        .pos
                        .x;
                    let matching: Vec<_> = texts
                        .iter()
                        .filter(|shape| shape.galley.text() == label)
                        .collect();
                    assert!(!matching.is_empty(), "missing {label}");
                    for shape in &matching {
                        assert_eq!(shape.galley.rows.len(), 1, "wrapped {label}");
                        assert!(
                            shape.visual_bounding_rect().right() <= right,
                            "overlapping {label}: {} > {right} at width {width}",
                            shape.visual_bounding_rect().right()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn online_and_offline_rows_keep_text_buttons_and_graphs_in_their_own_bounds() {
        use tsunagi::ipc::OverlayReport;
        let mut network = NetworkReport {
            network_id: "row regression".into(),
            active: true,
            ..Default::default()
        };
        for index in 0..14 {
            let id = format!("node-{index:02}");
            let mut member = member(
                &id,
                index < 10,
                DataPathReport::Direct {
                    transport: "wg-quic".into(),
                },
            );
            member.hostname = Some(format!("node-with-a-long-name-{index:02}"));
            network.members.push(member);
        }
        network.overlay = Some(OverlayReport {
            peers: network.members[..10]
                .iter()
                .map(|member| OverlayPeerReport {
                    endpoint_id: member.endpoint_id.clone(),
                    protocol: "wg-quic".into(),
                    tx_packets: 9_876_543_210,
                    rx_packets: 12_345_678_901,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        });
        let rows = devices(&network, "own");
        for font_size in [14.0, 22.0] {
            let ctx = egui::Context::default();
            ctx.style_mut(|style| {
                style.override_font_id = Some(egui::FontId::proportional(font_size))
            });
            for width in [900.0, 2100.0] {
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 1600.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            egui::ScrollArea::both().show(ui, |ui| {
                                device_table(
                                    ui,
                                    Unit::Bytes,
                                    &network,
                                    &rows,
                                    &Traffic::default(),
                                    &mut None,
                                    &mut None,
                                )
                            });
                        });
                    },
                );
                let mut row_bounds = Vec::new();
                for member in &network.members {
                    let shape = output.shapes.iter().find(|s| matches!(&s.shape, egui::Shape::Text(text) if Some(text.galley.text()) == member.hostname.as_deref())).unwrap();
                    let egui::Shape::Text(text) = &shape.shape else {
                        unreachable!()
                    };
                    assert_eq!(text.galley.rows.len(), 1);
                    assert!(shape.clip_rect.top() <= text.visual_bounding_rect().top());
                    assert!(shape.clip_rect.bottom() >= text.visual_bounding_rect().bottom());
                    row_bounds.push(shape.clip_rect);
                }
                for pair in row_bounds.windows(2) {
                    assert!(
                        pair[0].bottom() < pair[1].top(),
                        "rows overlap at font size {font_size}"
                    );
                }
                let buttons: Vec<_> = output
                    .shapes
                    .iter()
                    .filter(
                        |s| matches!(&s.shape, egui::Shape::Text(t) if t.galley.text() == "Forget"),
                    )
                    .collect();
                assert_eq!(buttons.len(), 4, "offline cleanup remains visible");
                for button in buttons {
                    let egui::Shape::Text(text) = &button.shape else {
                        unreachable!()
                    };
                    assert!(
                        button.clip_rect.contains_rect(text.visual_bounding_rect()),
                        "Forget button clipped at {font_size}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_long_relay_name_gets_its_full_column_width() {
        let mut relay = member("near", true, DataPathReport::None);
        relay.hostname = Some("a-relay-with-a-long-device-name".into());
        let network = NetworkReport {
            network_id: "network".into(),
            members: vec![
                relay,
                member(
                    "far",
                    true,
                    DataPathReport::Relayed {
                        hops: 2,
                        via: "near".into(),
                    },
                ),
            ],
            ..Default::default()
        };
        let rows = devices(&network, "own");
        let far = rows.iter().find(|device| device.id == "far").unwrap();
        let label = data_path_text(far.path, far.via_name.as_deref(), far.online);
        let context = egui::Context::default();
        let mut fonts = egui::FontDefinitions::default();
        egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
        context.set_fonts(fonts);
        let _ = context.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                device_table(
                    ui,
                    Unit::Bytes,
                    &network,
                    &rows,
                    &Traffic::default(),
                    &mut None,
                    &mut None,
                );
                let stored: [f32; 9] = ui
                    .memory(|memory| {
                        memory
                            .data
                            .get_temp(egui::Id::new(("devices column widths", "network")))
                    })
                    .unwrap();
                let font = egui::FontSelection::Default.resolve(ui.style());
                let needed = ui.fonts(|fonts| {
                    fonts
                        .layout_no_wrap(label.clone(), font, egui::Color32::WHITE)
                        .size()
                        .x
                });
                assert!(stored[5] >= needed);
            });
        });
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
