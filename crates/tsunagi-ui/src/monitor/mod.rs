//! Live traffic inspector shared by the tray and Android clients.
mod columns;
mod history;
mod table;
use columns::{Column, Sort};
#[cfg(test)]
mod tests;
mod worker;

use crate::{format::short, widgets};
use egui::Ui;
use egui_phosphor::regular as icon;
use history::{Cursor, Filter};
use std::{collections::BTreeMap, net::Ipv4Addr, path::PathBuf, sync::Arc, time::Duration};
use tsunagi::{
    NetworkId,
    dns::ZoneName,
    ipc::{NetworkReport, StatusReport},
    iroh_types::EndpointId,
    traffic::{Flow, FlowKey, IpDetail, Role},
};
pub use worker::Feed;
use worker::Worker;

type Id = [u8; 32];
#[derive(Clone, Default)]
struct Network {
    name: String,
    peers: BTreeMap<Id, String>,
}
#[derive(Clone, Default)]
struct Names {
    networks: BTreeMap<Id, Network>,
    generation: Option<u64>,
    addresses: BTreeMap<(Id, Ipv4Addr), String>,
    resolve_addresses: bool,
}

fn public_id(id: &Id) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}
impl Names {
    fn refresh(&mut self, report: Option<&StatusReport>, generation: u64) -> bool {
        let Some(report) = report else { return false };
        if self.generation == Some(generation) {
            return false;
        }
        self.generation = Some(generation);
        self.addresses.clear();
        let mut changed = false;
        for n in &report.networks {
            let Ok(id) = n.network_id.parse::<NetworkId>() else {
                continue;
            };
            self.index_addresses(*id.as_bytes(), n, &report.hostname);
            let entry = self.networks.entry(*id.as_bytes()).or_default();
            if entry.name != n.name {
                entry.name.clone_from(&n.name);
                changed = true;
            }
            // Resolve duplicate membership and live entries first. A stale member name
            // must not trigger a rebuild of a multi-day capture's index every poll.
            let mut reported = BTreeMap::new();
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
                let label = reported.entry(key).or_default();
                if let Some(name) = name.filter(|s| !s.is_empty()) {
                    *label = Some(name);
                }
            }
            for (key, name) in reported {
                if let Ok(peer) = key.parse::<EndpointId>() {
                    use std::collections::btree_map::Entry;
                    match entry.peers.entry(*peer.as_bytes()) {
                        Entry::Vacant(e) => {
                            e.insert(name.map_or_else(|| short(key), str::to_owned));
                            changed = true;
                        }
                        Entry::Occupied(mut e) => {
                            if let Some(name) = name
                                && name != e.get()
                            {
                                *e.get_mut() = name.into();
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        changed
    }
    fn index_addresses(&mut self, id: Id, network: &NetworkReport, hostname: &str) {
        let Ok(zone) = ZoneName::new(&network.name) else {
            return;
        };
        let mut add = |address: Option<Ipv4Addr>, name: Option<&str>| {
            if let (Some(ip), Some(name)) = (
                address,
                name.map(|s| s.trim_matches('.')).filter(|s| !s.is_empty()),
            ) {
                self.addresses
                    .entry((id, ip))
                    .or_insert_with(|| format!("{}.{}", name.to_ascii_lowercase(), zone.as_str()));
            }
        };
        if network.hostname_conflict.is_none()
            && let Some(own) = &network.overlay
        {
            add(
                own.address.as_deref().and_then(|s| s.parse().ok()),
                Some(hostname),
            );
        }
        for member in &network.members {
            if member.hostname_conflict.is_none() {
                add(
                    member
                        .overlay_address_v4
                        .as_deref()
                        .and_then(|s| s.parse().ok()),
                    member.hostname.as_deref(),
                );
            }
        }
        for vip in &network.vips {
            if vip.error.is_none() {
                add(vip.address, Some(&vip.config.name));
            }
        }
    }
    fn resolved_endpoint(&self, key: &FlowKey, column: Column) -> Option<String> {
        let (ip, port) = column.ip_endpoint(key)?;
        let name = self.addresses.get(&(key.network, ip))?;
        Some(match port {
            Some(port) => format!("{name}:{port}"),
            None => name.clone(),
        })
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
    previous: Vec<Option<Cursor>>,
    column_page: usize,
}
impl Window {
    /// Creates an empty view. Android supplies its application-private cache directory.
    pub fn new(directory: Option<PathBuf>) -> Self {
        Self {
            worker: Worker::new(directory),
            names: Names {
                resolve_addresses: true,
                ..Names::default()
            },
            filter: Filter::default(),
            keep: false,
            previous: Vec::new(),
            column_page: 0,
        }
    }
    /// The endpoint into which this window's subscription feeds interval snapshots.
    pub fn feed(&self) -> Feed {
        self.worker.feed.clone()
    }

    fn controls(&mut self, ui: &mut Ui, grid: &table::Grid) {
        if ui.available_width() < 620. {
            ui.horizontal_wrapped(|ui| {
                self.layers(ui);
                self.resolve_option(ui);
            });
            ui.horizontal(|ui| self.history_controls(ui, grid));
        } else {
            ui.horizontal(|ui| {
                self.layers(ui);
                self.resolve_option(ui);
                self.history_controls(ui, grid);
            });
        }
        if ui.available_width() < 580. {
            let width = ((ui.available_width() - ui.spacing().item_spacing.x) / 2.).max(60.);
            ui.horizontal(|ui| self.identity_filters(ui, width));
            ui.horizontal(|ui| self.flow_filters(ui, width));
        } else {
            ui.horizontal(|ui| {
                self.identity_filters(ui, 135.);
                self.flow_filters(ui, 135.);
            });
        }
    }

    fn layers(&mut self, ui: &mut Ui) {
        let layer = self.filter.transport;
        ui.selectable_value(
            &mut self.filter.transport,
            false,
            format!("{}  IP flows", icon::ARROWS_LEFT_RIGHT),
        );
        ui.selectable_value(
            &mut self.filter.transport,
            true,
            format!("{}  Transport", icon::GIT_FORK),
        )
        .on_hover_text(
            "Authenticated control sessions and encrypted traffic relayed between peers",
        );
        if layer != self.filter.transport {
            self.filter.role = None;
            self.filter.protocol = None;
        }
    }

    fn resolve_option(&mut self, ui: &mut Ui) {
        if !self.filter.transport {
            widgets::hint(
                ui.checkbox(&mut self.names.resolve_addresses, "Resolve names"),
                "Show this network’s peer and VIP names. Hover or hold a name to see its IP address.",
            );
        }
    }

    fn history_controls(&mut self, ui: &mut Ui, grid: &table::Grid) {
        widgets::hint(
            ui.checkbox(&mut self.keep, "Keep until close"),
            "Keep inactive flows for this window session. Otherwise they expire after 60 seconds.",
        );
        grid.chooser(ui, &mut self.column_page);
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
        if self.names.refresh(report, generation) {
            self.worker.names(Arc::new(self.names.clone()));
        }
        table::style(ui);
        let before = self.filter.clone();
        let keep = self.keep;
        let grid = table::Grid::new(ui);
        self.column_page = self.column_page.min(grid.pages.len() - 1);
        self.controls(ui, &grid);
        if self.filter != before {
            self.filter.before = None;
            self.previous.clear();
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
        if !self.previous.is_empty() || page.more {
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        !self.previous.is_empty(),
                        egui::Button::new(format!("{} Previous", icon::CARET_LEFT)),
                    )
                    .clicked()
                    && let Some(cursor) = self.previous.pop()
                {
                    self.filter.before = cursor;
                    self.worker.options(self.filter.clone(), self.keep);
                }
                ui.label(format!("Page {}", self.previous.len() + 1));
                if ui
                    .add_enabled(
                        page.more,
                        egui::Button::new(format!("Next {}", icon::CARET_RIGHT)),
                    )
                    .clicked()
                    && let Some(row) = page.rows.last()
                {
                    self.previous.push(self.filter.before.clone());
                    self.filter.before = Some(row.cursor());
                    self.worker.options(self.filter.clone(), self.keep);
                }
            });
        }
        let columns = &grid.pages[self.column_page];
        if let Some(column) = grid.header(ui, columns, self.filter.sort) {
            self.filter.sort.select(column);
            self.filter.before = None;
            self.previous.clear();
            self.worker.options(self.filter.clone(), self.keep);
        }
        if page.rows.is_empty() {
            ui.add_space(10.);
            ui.label(if error.is_some() {
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
            egui::ScrollArea::vertical()
                .id_salt("flow-rows")
                .auto_shrink([false, false])
                .show_rows(ui, grid.row_height, page.rows.len(), |ui, visible| {
                    for index in visible {
                        grid.row(ui, columns, &page.rows[index], &self.names, now, index);
                    }
                });
        }
        ui.ctx().request_repaint_after(Duration::from_secs(1));
    }
}
