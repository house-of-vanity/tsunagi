//! Live traffic inspector shared by the tray and Android clients.
mod history;
#[cfg(test)]
mod tests;
mod worker;

use crate::{
    format::{bytes, short},
    widgets,
};
use egui::{RichText, Ui};
use egui_phosphor::regular as icon;
use history::{Filter, Row};
use std::{collections::BTreeMap, net::Ipv4Addr, path::PathBuf, time::Duration};
use tsunagi::{
    NetworkId,
    ipc::StatusReport,
    iroh_types::EndpointId,
    traffic::{Flow, FlowKey, IpDetail, Role},
};
pub use worker::Feed;
use worker::Worker;

type Id = [u8; 32];
#[derive(Default)]
struct Network {
    name: String,
    peers: BTreeMap<Id, String>,
}
#[derive(Default)]
struct Names {
    networks: BTreeMap<Id, Network>,
    generation: Option<u64>,
}

fn public_id(id: &Id) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}
impl Names {
    fn refresh(&mut self, report: Option<&StatusReport>, generation: u64) {
        let Some(report) = report else { return };
        if self.generation == Some(generation) {
            return;
        }
        self.generation = Some(generation);
        for n in &report.networks {
            let Ok(id) = n.network_id.parse::<NetworkId>() else {
                continue;
            };
            let entry = self.networks.entry(*id.as_bytes()).or_default();
            entry.name = n.name.clone();
            for (key, name) in n
                .members
                .iter()
                .map(|m| (&m.endpoint_id, m.hostname.as_deref()))
                .chain(
                    n.peers
                        .iter()
                        .map(|p| (&p.endpoint_id, p.hostname.as_deref())),
                )
                .chain(std::iter::once((
                    &report.endpoint_id,
                    Some(report.hostname.as_str()),
                )))
            {
                if let Ok(peer) = key.parse::<EndpointId>() {
                    let label = name.filter(|s| !s.is_empty()).map(str::to_owned);
                    let current = entry
                        .peers
                        .entry(*peer.as_bytes())
                        .or_insert_with(|| short(key));
                    if let Some(label) = label {
                        *current = label;
                    }
                }
            }
        }
    }
    fn network(&self, id: &Id) -> String {
        let Some(n) = self.networks.get(id) else {
            return short(&NetworkId::from_bytes(*id).to_string());
        };
        if self
            .networks
            .values()
            .any(|other| !std::ptr::eq(other, n) && other.name == n.name)
        {
            format!(
                "{} · {}",
                n.name,
                short(&NetworkId::from_bytes(*id).to_string())
            )
        } else {
            n.name.clone()
        }
    }
    fn peer(&self, network: &Id, id: &Id) -> String {
        self.networks
            .get(network)
            .and_then(|n| n.peers.get(id))
            .cloned()
            .unwrap_or_else(|| short(&public_id(id)))
    }
}

fn role_name(r: Role) -> &'static str {
    match r {
        Role::Mesh => "Mesh",
        Role::ViaExit => "Via exit node",
        Role::ServeExit => "Serving exit",
        Role::Vip => "VIP",
        Role::Broadcast => "Broadcast",
        Role::SpeedTest => "Speed test",
        Role::Control => "Control",
        Role::Relay => "Encrypted relay",
    }
}
fn role_text(role: Role) -> String {
    let glyph = match role {
        Role::ViaExit => icon::SIGN_OUT,
        Role::ServeExit => icon::SIGN_IN,
        Role::Relay => icon::GIT_FORK,
        Role::Broadcast => icon::BROADCAST,
        Role::SpeedTest => icon::GAUGE,
        _ => return role_name(role).to_owned(),
    };
    format!("{glyph} {}", role_name(role))
}
fn protocol(n: u8) -> String {
    match n {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        n => format!("IP {n}"),
    }
}
fn endpoints(k: &FlowKey, n: &Names) -> (String, String, String) {
    match k.flow {
        Flow::Control => (
            "This agent".into(),
            n.peer(&k.network, &k.peer),
            "Control session".into(),
        ),
        Flow::Relay {
            other,
            wire_protocol,
        } => (
            n.peer(&k.network, &k.peer),
            n.peer(&k.network, &other),
            format!("Relay · {wire_protocol:x}"),
        ),
        Flow::Ip {
            near,
            far,
            protocol: p,
            detail,
        } => {
            let (a, b) = (Ipv4Addr::from(near), Ipv4Addr::from(far));
            match detail {
                IpDetail::Ports(x, y) => (format!("{a}:{x}"), format!("{b}:{y}"), protocol(p)),
                _ => (
                    a.to_string(),
                    b.to_string(),
                    match detail {
                        IpDetail::Echo => "ICMP echo".into(),
                        IpDetail::Icmp(t, c) => format!("ICMP {t}/{c}"),
                        IpDetail::Fragment => format!("{} fragment", protocol(p)),
                        _ => protocol(p),
                    },
                ),
            }
        }
    }
}
fn ago(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0 => "now".into(),
        1..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86400),
    }
}

/// State and temporary storage of exactly one visible monitor.
pub struct Window {
    worker: Worker,
    names: Names,
    filter: Filter,
    keep: bool,
    previous: Vec<Option<i64>>,
    selected: Option<i64>,
}
impl Window {
    /// Creates an empty view. Android supplies its application-private cache directory.
    pub fn new(directory: Option<PathBuf>) -> Self {
        Self {
            worker: Worker::new(directory),
            names: Names::default(),
            filter: Filter::default(),
            keep: false,
            previous: Vec::new(),
            selected: None,
        }
    }
    /// The endpoint into which this window's subscription feeds interval snapshots.
    pub fn feed(&self) -> Feed {
        self.worker.feed.clone()
    }

    fn controls(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            let layer = self.filter.transport;
            ui.selectable_value(&mut self.filter.transport, false, format!("{}  IP flows", icon::ARROWS_LEFT_RIGHT));
            ui.selectable_value(&mut self.filter.transport, true, format!("{}  Transport", icon::GIT_FORK))
                .on_hover_text("Authenticated control sessions and encrypted traffic relayed between peers");
            if layer != self.filter.transport {
                self.filter.role = None;
                self.filter.protocol = None;
            }
            widgets::hint(ui.checkbox(&mut self.keep,"Keep until close"),
                "Keep inactive flows for this window session. Otherwise they expire after 60 seconds.");
        });
        let width = ((ui.available_width() - ui.spacing().item_spacing.x) / 2.).clamp(60., 135.);
        if ui.available_width() < 580. {
            ui.horizontal(|ui| self.identity_filters(ui, width));
            ui.horizontal(|ui| self.flow_filters(ui, width));
        } else {
            ui.horizontal(|ui| {
                self.identity_filters(ui, width);
                self.flow_filters(ui, width);
            });
        }
    }

    fn identity_filters(&mut self, ui: &mut Ui, width: f32) {
        let network = self.filter.network;
        egui::ComboBox::from_id_salt("flow-network")
            .width(width)
            .truncate()
            .selected_text(
                network.map_or_else(|| "All networks".into(), |id| self.names.network(&id)),
            )
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.filter.network, None, "All networks");
                for id in self.names.networks.keys() {
                    ui.selectable_value(
                        &mut self.filter.network,
                        Some(*id),
                        self.names.network(id),
                    );
                }
            });
        if self.filter.network != network {
            self.filter.peer = None;
        }
        ui.add_enabled_ui(self.filter.network.is_some(), |ui| {
            let id = self.filter.network.unwrap_or_default();
            let peer = self
                .filter
                .peer
                .map_or_else(|| "All peers".into(), |p| self.names.peer(&id, &p));
            egui::ComboBox::from_id_salt("flow-peer")
                .width(width)
                .truncate()
                .selected_text(peer)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.filter.peer, None, "All peers");
                    if let Some(net) = self.names.networks.get(&id) {
                        for (peer, label) in &net.peers {
                            ui.selectable_value(&mut self.filter.peer, Some(*peer), label)
                                .on_hover_text(public_id(peer));
                        }
                    }
                });
        })
        .response
        .on_disabled_hover_text("Choose a network to filter its peers");
    }

    fn flow_filters(&mut self, ui: &mut Ui, width: f32) {
        if !self.filter.transport {
            egui::ComboBox::from_id_salt("flow-protocol")
                .width(width)
                .truncate()
                .selected_text(
                    self.filter
                        .protocol
                        .map_or_else(|| "All protocols".into(), protocol),
                )
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.filter.protocol, None, "All protocols");
                    for p in self.worker.protocols() {
                        ui.selectable_value(&mut self.filter.protocol, Some(p), protocol(p));
                    }
                });
        }
        let roles: &[Role] = if self.filter.transport {
            &[Role::Control, Role::Relay]
        } else {
            &[
                Role::Mesh,
                Role::ViaExit,
                Role::ServeExit,
                Role::Vip,
                Role::Broadcast,
                Role::SpeedTest,
            ]
        };
        egui::ComboBox::from_id_salt("flow-role")
            .width(width)
            .truncate()
            .selected_text(self.filter.role.map_or("All roles", role_name))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.filter.role, None, "All roles");
                for &role in roles {
                    ui.selectable_value(&mut self.filter.role, Some(role), role_name(role));
                }
            });
    }

    /// Draw the responsive inspector inside the current viewport.
    pub fn show(&mut self, ui: &mut Ui, report: Option<&StatusReport>, generation: u64) {
        self.names.refresh(report, generation);
        let before = self.filter.clone();
        let keep = self.keep;
        self.controls(ui);
        if self.filter != before {
            self.filter.before = None;
            self.previous.clear();
            self.selected = None;
        }
        if self.filter != before || self.keep != keep {
            self.worker.options(self.filter.clone(), self.keep);
        }
        let (page, omitted, error) = self.worker.view();
        if let Some(e) = &error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        if omitted > 0 {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                format!("{omitted} observations omitted during capture"),
            );
        }
        ui.separator();
        let now = self.worker.feed.elapsed();
        let wide = ui.available_width() >= 690.;
        if !self.previous.is_empty() || page.more {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !self.previous.is_empty(),
                        egui::Button::new(format!("{} Newer", icon::CARET_LEFT)),
                    )
                    .clicked()
                    && let Some(cursor) = self.previous.pop()
                {
                    self.filter.before = cursor;
                    self.selected = None;
                    self.worker.options(self.filter.clone(), self.keep);
                }
                ui.weak(format!("Page {}", self.previous.len() + 1));
                if ui
                    .add_enabled(
                        page.more,
                        egui::Button::new(format!("Older {}", icon::CARET_RIGHT)),
                    )
                    .clicked()
                    && let Some(r) = page.rows.last()
                {
                    self.previous.push(self.filter.before);
                    self.filter.before = Some(r.id);
                    self.selected = None;
                    self.worker.options(self.filter.clone(), self.keep);
                }
            });
        }
        if page.rows.is_empty() {
            ui.add_space(14.);
            ui.weak(if error.is_some() {
                "No captured flows in this view."
            } else if self.filter.network.is_some()
                || self.filter.role.is_some()
                || self.filter.protocol.is_some()
                || self.filter.before.is_some()
            {
                "No flows match these filters."
            } else {
                "Listening for traffic…"
            });
        } else {
            if wide {
                desktop_header(ui);
            }
            egui::ScrollArea::vertical()
                .id_salt("flow-rows")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for row in &page.rows {
                        let chosen = self.selected == Some(row.id);
                        egui::Frame::new()
                            .inner_margin(egui::Margin::symmetric(5, 3))
                            .fill(if chosen {
                                ui.visuals().selection.bg_fill
                            } else if row.id % 2 == 0 {
                                ui.visuals().faint_bg_color
                            } else {
                                egui::Color32::TRANSPARENT
                            })
                            .show(ui, |ui| {
                                let summary = ui.scope(|ui| self.row(ui, row, now, wide)).response;
                                let selected = ui.interact(
                                    summary.rect,
                                    ui.id().with(("flow", row.id)),
                                    egui::Sense::click(),
                                );
                                if selected.clicked() {
                                    self.selected = if chosen { None } else { Some(row.id) };
                                }

                                if chosen {
                                    ui.separator();
                                    let key = &row.data.key;
                                    let (a, b, p) = endpoints(key, &self.names);
                                    ui.label(format!("{a}  ↔  {b}   ·   {p}"));
                                    ui.label(format!(
                                        "{}  {} packets sent     {}  {} received",
                                        icon::ARROW_UP,
                                        row.data.tx_packets,
                                        icon::ARROW_DOWN,
                                        row.data.rx_packets
                                    ));
                                    let id = public_id(&key.peer);
                                    ui.horizontal_wrapped(|ui| {
                                        ui.weak("Peer ID");
                                        crate::format::copy_field(ui, &short(&id), &id);
                                    });
                                }
                            });
                    }
                });
        }
        ui.ctx().request_repaint_after(Duration::from_secs(1));
    }

    fn row(&self, ui: &mut Ui, r: &Row, now: u64, wide: bool) {
        let k = &r.data.key;
        let (a, b, p) = endpoints(k, &self.names);
        let network = self.names.network(&k.network);
        let peer = self.names.peer(&k.network, &k.peer);
        let role = role_text(k.role);
        let current = now.saturating_sub(r.sampled) < 1900;
        let rates = |n: f32| format!("{}/s", bytes(if current { n as f64 } else { 0. }));
        let (tx, rx) = (bytes(r.data.tx_bytes as f64), bytes(r.data.rx_bytes as f64));
        let age = ago(now.saturating_sub(r.last));
        if wide {
            let widths = widths(ui);
            ui.horizontal(|ui| {
                cell(ui, widths[0], &peer, &network);
                cell(ui, widths[1], &a, &b);
                cell(ui, widths[2], &p, &role);
                cell(ui, widths[3], &tx, &rates(r.tx_rate));
                cell(ui, widths[4], &rx, &rates(r.rx_rate));
                cell(ui, widths[5], &age, "");
            });
        } else {
            ui.set_min_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.strong(peer);
                ui.weak(&network);
                ui.label(role);
                ui.weak(age);
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(&p);
                ui.monospace(&a);
                ui.weak("↔");
                ui.monospace(&b);
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("{} {tx}", icon::ARROW_UP))
                    .on_hover_text("Sent");
                ui.weak(rates(r.tx_rate));
                ui.separator();
                ui.label(format!("{} {rx}", icon::ARROW_DOWN))
                    .on_hover_text("Received");
                ui.weak(rates(r.rx_rate));
            });
        }
    }
}
fn widths(ui: &Ui) -> [f32; 6] {
    let usable = (ui.available_width() - ui.spacing().item_spacing.x * 5. - 4.).max(0.);
    [0.18, 0.30, 0.18, 0.13, 0.13, 0.08].map(|s| s * usable)
}
fn cell(ui: &mut Ui, width: f32, one: &str, two: &str) {
    ui.allocate_ui_with_layout(
        egui::vec2(width, 0.),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.add(egui::Label::new(one).truncate()).on_hover_text(one);
            if !two.is_empty() {
                ui.add(egui::Label::new(RichText::new(two).weak().small()).truncate())
                    .on_hover_text(two);
            }
        },
    );
}
fn desktop_header(ui: &mut Ui) {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(5, 2))
        .show(ui, |ui| {
            let widths = widths(ui);
            ui.horizontal(|ui| {
                for ((title, hint), width) in [
                    ("Peer / network", "Authenticated peer and local network"),
                    (
                        "Endpoints",
                        "This side ↔ peer side. Encrypted relay shows the two named endpoints.",
                    ),
                    (
                        "Protocol / role",
                        "IP protocol or transport observation and forwarding role",
                    ),
                    (
                        "↑ Sent",
                        "Total and rate toward the peer (first to second endpoint for relay)",
                    ),
                    (
                        "↓ Received",
                        "Total and rate from the peer (second to first endpoint for relay)",
                    ),
                    ("Seen", "Time since last activity"),
                ]
                .into_iter()
                .zip(widths)
                {
                    ui.add_sized(
                        [width, 17.],
                        egui::Label::new(RichText::new(title).small().weak())
                            .halign(egui::Align::Min)
                            .truncate(),
                    )
                    .on_hover_text(hint);
                }
            });
        });
}
