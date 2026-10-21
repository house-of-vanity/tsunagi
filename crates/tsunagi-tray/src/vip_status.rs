//! Local VIP observations, kept apart from editable configuration drafts.
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use eframe::egui;
use tsunagi::ipc::NetworkReport;
use tsunagi::vip::{Backend, BackendStatus, Counters, ListenerStatus, Protocol, VipStatus};

use crate::{
    format,
    stats::{Series, Unit},
    table,
};

const ACTIVE: egui::Color32 = egui::Color32::from_rgb(73, 190, 133);
const NEXT: egui::Color32 = egui::Color32::from_rgb(78, 157, 237);
const WARN: egui::Color32 = egui::Color32::from_rgb(225, 170, 73);
const BAD: egui::Color32 = egui::Color32::from_rgb(228, 112, 112);

#[derive(Default)]
struct Rates {
    tx: Series,
    rx: Series,
    total: Series,
    at: Option<Instant>,
}
impl Rates {
    fn sample(&mut self, at: Instant, c: &Counters) {
        self.tx.sample(at, c.tx_packets, c.tx_bytes);
        self.rx.sample(at, c.rx_packets, c.rx_bytes);
        self.total.sample(
            at,
            c.tx_packets.saturating_add(c.rx_packets),
            c.tx_bytes.saturating_add(c.rx_bytes),
        );
        self.at = Some(at);
    }
    fn active(&self, now: Instant) -> bool {
        self.at
            .is_some_and(|at| now.saturating_duration_since(at) <= Duration::from_secs(5))
            && self.total.rate(Unit::Packets) > 0.0
    }
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Key(String, String, u16, String, u16);
fn key(v: &VipStatus, l: &ListenerStatus, b: &Backend) -> Key {
    // Listener identity separates counter histories when a port is recreated.
    let listener = v
        .config
        .listeners
        .iter()
        .find(|entry| entry.protocol == l.protocol && entry.port == l.port)
        .map(|entry| entry.id.clone())
        .unwrap_or_else(|| l.protocol.to_string());
    Key(
        v.config.id.clone(),
        listener,
        l.port,
        b.peer.clone(),
        b.port,
    )
}
struct Camera {
    rect: egui::Rect,
    members: Vec<Backend>,
}
impl Default for Camera {
    fn default() -> Self {
        Self {
            rect: egui::Rect::NOTHING,
            members: Vec::new(),
        }
    }
}
pub(crate) struct View {
    totals: BTreeMap<String, Rates>,
    backends: BTreeMap<Key, Rates>,
    cameras: BTreeMap<(String, String, u16), Camera>,
    selected: Option<Key>,
    unit: Unit,
}
impl Default for View {
    fn default() -> Self {
        Self {
            totals: BTreeMap::new(),
            backends: BTreeMap::new(),
            cameras: BTreeMap::new(),
            selected: None,
            unit: Unit::Bytes,
        }
    }
}
impl View {
    pub(crate) fn observe(&mut self, network: &NetworkReport, at: Instant) {
        self.totals
            .retain(|id, _| network.vips.iter().any(|v| &v.config.id == id));
        let mut present = std::collections::BTreeSet::new();
        for v in &network.vips {
            let mut counters = Counters::default();
            for l in &v.listeners {
                counters.tx_packets = counters.tx_packets.saturating_add(l.counters.tx_packets);
                counters.rx_packets = counters.rx_packets.saturating_add(l.counters.rx_packets);
                counters.tx_bytes = counters.tx_bytes.saturating_add(l.counters.tx_bytes);
                counters.rx_bytes = counters.rx_bytes.saturating_add(l.counters.rx_bytes);
                for b in &l.backends {
                    let key = key(v, l, &b.backend);
                    self.backends
                        .entry(key.clone())
                        .or_default()
                        .sample(at, &b.counters);
                    present.insert(key);
                }
            }
            self.totals
                .entry(v.config.id.clone())
                .or_default()
                .sample(at, &counters);
        }
        self.backends.retain(|key, _| present.contains(key));
        if self
            .selected
            .as_ref()
            .is_some_and(|key| !present.contains(key))
        {
            self.selected = None;
        }
        self.cameras.retain(|(id, protocol, port), _| {
            network.vips.iter().any(|v| {
                &v.config.id == id
                    && v.listeners
                        .iter()
                        .any(|l| l.protocol.to_string() == *protocol && l.port == *port)
            })
        });
    }
}

fn name<'a>(n: &'a NetworkReport, id: &'a str) -> &'a str {
    n.members
        .iter()
        .find(|m| m.endpoint_id == id)
        .and_then(|m| m.hostname.as_deref())
        .unwrap_or(id)
}
fn backend_name(n: &NetworkReport, b: &Backend) -> String {
    format!("{}:{}", name(n, &b.peer), b.port)
}
fn rtt(b: &BackendStatus) -> String {
    b.rtt_us
        .map_or_else(|| "—".into(), |us| format!("{:.2} ms", us as f64 / 1000.0))
}
fn health_color(state: &str) -> egui::Color32 {
    match state {
        "ready" => ACTIVE,
        "checking port" | "measuring RTT" | "draining" => WARN,
        _ => BAD,
    }
}

pub(crate) fn show(ui: &mut egui::Ui, v: &VipStatus, n: &NetworkReport, view: &mut View) {
    ui.horizontal_wrapped(|ui| {
        ui.heading(format!("{}.{}", v.config.name, n.name));
        ui.weak("Traffic seen by this device");
        ui.selectable_value(&mut view.unit, Unit::Bytes, "bytes");
        ui.selectable_value(&mut view.unit, Unit::Packets, "pkts");
    });
    if let Some(error) = &v.error {
        ui.colored_label(BAD, error);
    }
    let total = view.totals.get(&v.config.id);
    ui.horizontal_wrapped(|ui| {
        metric(
            ui,
            "TX",
            &format::series_rate(total.map(|r| &r.tx), view.unit),
        );
        metric(
            ui,
            "RX",
            &format::series_rate(total.map(|r| &r.rx), view.unit),
        );
        let flows: u64 = v
            .listeners
            .iter()
            .flat_map(|l| &l.backends)
            .map(|b| u64::from(b.active_flows))
            .sum();
        metric(ui, "Open flows", &flows.to_string());
    });
    format::sparkline(ui, total.map(|r| &r.total), view.unit, 64.0);
    ui.add_space(8.0);
    if v.listeners.is_empty() {
        ui.weak("No listeners configured. Add one in Configuration.");
    }
    for l in &v.listeners {
        ui.push_id(
            (
                "vip live listener",
                &v.config.id,
                l.protocol.to_string(),
                l.port,
            ),
            |ui| {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_min_width((ui.available_width() - 2.0).max(0.0));
                    ui.horizontal_wrapped(|ui| {
                        ui.heading(format!("{}/{}", l.protocol, l.port));
                        ui.weak("New connections:");
                        if let Some(b) = &l.selected {
                            ui.colored_label(NEXT, backend_name(n, b));
                        } else {
                            ui.colored_label(WARN, "No eligible backend");
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        metric(ui, "TX", &format::bytes(l.counters.tx_bytes as f64));
                        metric(ui, "RX", &format::bytes(l.counters.rx_bytes as f64));
                        metric(
                            ui,
                            "Packets TX / RX",
                            &format!("{} / {}", l.counters.tx_packets, l.counters.rx_packets),
                        );
                        metric(ui, "Drops", &l.counters.dropped.to_string());
                        if l.protocol == Protocol::Udp {
                            metric(ui, "Failovers", &l.counters.failovers.to_string());
                        }
                    });
                    ui.separator();
                    diagram(ui, v, l, n, view);
                    ui.add_space(6.0);
                    egui::ScrollArea::horizontal()
                        .id_salt("backend table scroll")
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            backend_table(ui, v, l, n, view);
                        });
                    if let Some(b) = l
                        .backends
                        .iter()
                        .find(|b| view.selected.as_ref() == Some(&key(v, l, &b.backend)))
                    {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.strong(backend_name(n, &b.backend));
                                ui.colored_label(health_color(&b.state), &b.state);
                                ui.weak(format!("{} open flows", b.active_flows));
                                if let Some(age) = b.measurement_age_ms {
                                    ui.weak(format!(
                                        "RTT measured {:.1}s ago",
                                        age as f64 / 1000.0
                                    ));
                                } else {
                                    ui.weak("No RTT measurement yet");
                                }
                            });
                            ui.horizontal_wrapped(|ui| {
                                ui.weak("Node");
                                format::copy_field(
                                    ui,
                                    &format::short(&b.backend.peer),
                                    &b.backend.peer,
                                );
                                if let Some(address) = n
                                    .members
                                    .iter()
                                    .find(|m| m.endpoint_id == b.backend.peer)
                                    .and_then(|m| m.overlay_address_v4.as_deref())
                                {
                                    ui.weak("Address");
                                    format::copy_field(ui, address, address);
                                }
                            });
                        });
                    }
                });
            },
        );
        ui.add_space(8.0);
    }
    ui.collapsing("Internal address and identity", |ui| {
        egui::Grid::new(("vip identity", &v.config.id)).show(ui, |ui| {
            ui.weak("Address");
            if let Some(address) = v.address {
                format::copy_field(ui, &address.to_string(), &address.to_string());
            } else {
                ui.weak("Not allocated");
            }
            ui.end_row();
            ui.weak("ID");
            format::copy_field(ui, &v.config.id, &v.config.id);
            ui.end_row();
        });
    });
}
fn metric(ui: &mut egui::Ui, title: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.weak(title);
        ui.strong(value);
    });
    ui.add_space(8.0);
}

fn backend_table(
    ui: &mut egui::Ui,
    v: &VipStatus,
    l: &ListenerStatus,
    n: &NetworkReport,
    view: &mut View,
) {
    let headers = [
        "Backend",
        "Health",
        "Route",
        "RTT",
        "Flows",
        "TX / RX",
        "TX / RX rate",
        "Traffic",
    ];
    let mut widths = [170.0_f32, 110.0, 100.0, 90.0, 50.0, 160.0, 160.0, 160.0];
    // Measure every value before layout, including long identities and counters.
    let values: Vec<_> = l
        .backends
        .iter()
        .map(|b| {
            let rates = view.backends.get(&key(v, l, &b.backend));
            let route = if rates.is_some_and(|r| r.active(Instant::now())) {
                "Traffic"
            } else if l.selected.as_ref() == Some(&b.backend) {
                "Next flow"
            } else {
                "—"
            };
            [
                backend_name(n, &b.backend),
                b.state.clone(),
                route.into(),
                rtt(b),
                b.active_flows.to_string(),
                format!(
                    "{} / {}",
                    format::bytes(b.counters.tx_bytes as f64),
                    format::bytes(b.counters.rx_bytes as f64)
                ),
                format!(
                    "{} / {}",
                    format::series_rate(rates.map(|r| &r.tx), view.unit),
                    format::series_rate(rates.map(|r| &r.rx), view.unit)
                ),
            ]
        })
        .collect();
    for (column, width) in widths.iter_mut().enumerate().take(7) {
        let font = egui::FontSelection::Default.resolve(ui.style());
        for text in
            std::iter::once(headers[column]).chain(values.iter().map(|row| row[column].as_str()))
        {
            *width = width.max(
                ui.fonts(|f| {
                    f.layout_no_wrap(text.to_owned(), font.clone(), egui::Color32::WHITE)
                        .size()
                        .x
                }) + 12.0,
            );
        }
    }
    let widths_id = ui.id().with("backend column widths");
    if let Some(previous) = ui.memory(|memory| memory.data.get_temp::<[f32; 8]>(widths_id)) {
        for (width, previous) in widths.iter_mut().zip(previous) {
            *width = width.max(previous);
        }
    }
    ui.memory_mut(|memory| memory.data.insert_temp(widths_id, widths));
    let fixed = widths.iter().sum::<f32>() + table::GAP * 7.0;
    widths[7] += (ui.available_width() - fixed).max(0.0);
    table::row(ui, "backend headers", &widths, false, |column, ui| {
        ui.weak(headers[column]);
    });
    for (index, b) in l.backends.iter().enumerate() {
        let key = key(v, l, &b.backend);
        let rates = view.backends.get(&key);
        table::row(
            ui,
            &key,
            &widths,
            index % 2 == 0,
            |column, ui| match column {
                0 => {
                    if ui
                        .selectable_label(view.selected.as_ref() == Some(&key), &values[index][0])
                        .clicked()
                    {
                        view.selected = Some(key.clone());
                    }
                }
                1 => {
                    ui.colored_label(health_color(&b.state), &values[index][1])
                        .on_hover_text(&b.state);
                }
                2 => {
                    ui.colored_label(
                        if values[index][2] == "Traffic" {
                            ACTIVE
                        } else {
                            NEXT
                        },
                        &values[index][2],
                    )
                    .on_hover_text(
                        if l.selected.as_ref() == Some(&b.backend) {
                            "Selected for new connections. Existing flows can use other backends."
                        } else {
                            "Traffic during the latest sample interval."
                        },
                    );
                }
                3..=6 => {
                    ui.label(&values[index][column]);
                }
                _ => format::sparkline(ui, rates.map(|r| &r.total), view.unit, 24.0),
            },
        );
    }
    if l.backends.is_empty() {
        ui.weak("No backends. Add a node and target port in Configuration.");
    }
}

#[derive(Clone, Copy)]
struct Branch {
    active: bool,
    next: bool,
}
fn branch(l: &ListenerStatus, b: &BackendStatus, rates: Option<&Rates>, now: Instant) -> Branch {
    Branch {
        active: rates.is_some_and(|r| r.active(now)),
        next: l.selected.as_ref() == Some(&b.backend),
    }
}

fn diagram(
    ui: &mut egui::Ui,
    v: &VipStatus,
    l: &ListenerStatus,
    n: &NetworkReport,
    view: &mut View,
) {
    let camera = view
        .cameras
        .entry((v.config.id.clone(), l.protocol.to_string(), l.port))
        .or_default();
    let members: Vec<_> = l.backends.iter().map(|b| b.backend.clone()).collect();
    let height = (members.len().max(1) as f32 * 92.0 + 32.0).max(180.0);
    let bounds = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(860.0, height));
    if camera.members != members || !camera.rect.is_positive() {
        camera.rect = bounds;
        camera.members = members;
    }
    ui.horizontal_wrapped(|ui| {
        legend(ui, "Traffic", ACTIVE, true);
        legend(ui, "Next new flow", NEXT, false);
        ui.weak("Click a backend · drag to pan · Ctrl+scroll to zoom");
        if ui.small_button("Fit").clicked() {
            camera.rect = bounds;
        }
    });
    let size = egui::vec2(ui.available_width(), height.clamp(180.0, 360.0));
    let (outer, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter()
        .rect_filled(outer, 6.0, ui.visuals().extreme_bg_color);
    let mut child = ui.new_child(egui::UiBuilder::new().id_salt("vip graph").max_rect(outer));
    egui::Scene::new()
        .zoom_range(0.05..=1.5)
        .max_inner_size(bounds.size())
        .show(&mut child, &mut camera.rect, |ui| {
            ui.set_min_size(bounds.size());
            let center = height / 2.0;
            let source =
                egui::Rect::from_min_size(egui::pos2(18.0, center - 32.0), egui::vec2(204.0, 64.0));
            let listener = egui::Rect::from_min_size(
                egui::pos2(290.0, center - 32.0),
                egui::vec2(146.0, 64.0),
            );
            let active = l.backends.iter().any(|b| {
                view.backends
                    .get(&key(v, l, &b.backend))
                    .is_some_and(|r| r.active(Instant::now()))
            });
            edge(
                ui,
                source.right_center(),
                listener.left_center(),
                if active { ACTIVE } else { NEXT },
                active,
            );
            node(
                ui,
                source,
                &format!("{}.{}", v.config.name, n.name),
                "This device",
                NEXT,
                false,
            );
            node(
                ui,
                listener,
                &format!("{}/{}", l.protocol, l.port),
                "Listener",
                NEXT,
                false,
            );
            for (index, b) in l.backends.iter().enumerate() {
                let key = key(v, l, &b.backend);
                let rates = view.backends.get(&key);
                let state = branch(l, b, rates, Instant::now());
                let rect = egui::Rect::from_min_size(
                    egui::pos2(558.0, 24.0 + index as f32 * 92.0),
                    egui::vec2(278.0, 68.0),
                );
                let color = if state.active {
                    ACTIVE
                } else if state.next {
                    NEXT
                } else if b.state == "ready" {
                    ui.visuals().weak_text_color()
                } else {
                    health_color(&b.state)
                };
                edge(
                    ui,
                    listener.right_center(),
                    rect.left_center(),
                    color,
                    state.active,
                );
                if state.next {
                    ui.painter().circle_stroke(
                        rect.left_center(),
                        5.0,
                        egui::Stroke::new(2.0_f32, NEXT),
                    );
                }
                let response = ui
                    .interact(rect, ui.id().with((&key.3, key.4)), egui::Sense::click())
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text(format!(
                        "{}\n{} · RTT {}\n{} open flows\n{}{}",
                        backend_name(n, &b.backend),
                        b.state,
                        rtt(b),
                        b.active_flows,
                        if state.active {
                            "Traffic in latest sample. "
                        } else {
                            ""
                        },
                        if state.next {
                            "Selected for new connections."
                        } else {
                            ""
                        }
                    ));
                if response.clicked() {
                    view.selected = Some(key.clone());
                }
                let detail = format!("{} · {} · {} flows", b.state, rtt(b), b.active_flows);
                node(
                    ui,
                    rect,
                    &backend_name(n, &b.backend),
                    &detail,
                    color,
                    view.selected.as_ref() == Some(&key) || response.hovered(),
                );
            }
            if l.backends.is_empty() {
                ui.painter().text(
                    egui::pos2(570.0, center),
                    egui::Align2::LEFT_CENTER,
                    "No backends",
                    egui::FontId::proportional(15.0),
                    ui.visuals().weak_text_color(),
                );
            }
        });
}
fn legend(ui: &mut egui::Ui, text: &str, color: egui::Color32, filled: bool) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
        if filled {
            ui.painter().circle_filled(rect.center(), 4.0, color);
        } else {
            ui.painter()
                .circle_stroke(rect.center(), 4.0, egui::Stroke::new(1.5_f32, color));
        }
        ui.colored_label(color, text);
    });
}
fn node(
    ui: &egui::Ui,
    rect: egui::Rect,
    title: &str,
    detail: &str,
    color: egui::Color32,
    selected: bool,
) {
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 8.0, ui.visuals().widgets.inactive.bg_fill);
    painter.rect_stroke(
        rect.shrink(1.0),
        8.0,
        egui::Stroke::new(if selected { 3.0_f32 } else { 1.5_f32 }, color),
        egui::StrokeKind::Inside,
    );
    text_line(
        &painter,
        rect.min + egui::vec2(12.0, 9.0),
        title,
        16.0,
        ui.visuals().strong_text_color(),
        rect.width() - 24.0,
    );
    text_line(
        &painter,
        rect.min + egui::vec2(12.0, 34.0),
        detail,
        12.0,
        ui.visuals().text_color(),
        rect.width() - 24.0,
    );
}
fn text_line(
    painter: &egui::Painter,
    position: egui::Pos2,
    text: &str,
    size: f32,
    color: egui::Color32,
    width: f32,
) {
    let mut job = egui::text::LayoutJob::simple_singleline(
        text.into(),
        egui::FontId::proportional(size),
        color,
    );
    job.wrap.max_width = width;
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    painter.galley(position, painter.layout_job(job), color);
}
fn edge(ui: &egui::Ui, start: egui::Pos2, end: egui::Pos2, color: egui::Color32, active: bool) {
    let bend = (end.x - start.x) * 0.5;
    let curve = egui::epaint::CubicBezierShape::from_points_stroke(
        [
            start,
            start + egui::vec2(bend, 0.0),
            end - egui::vec2(bend, 0.0),
            end,
        ],
        false,
        egui::Color32::TRANSPARENT,
        egui::Stroke::new(if active { 3.0_f32 } else { 1.5_f32 }, color),
    );
    ui.painter().add(curve.clone());
    if active {
        let t = ui.input(|i| i.time) as f32 * 0.5 % 1.0;
        let position = curve.sample(t);
        ui.painter().circle_filled(position, 4.0, color);
        ui.ctx().request_repaint_after(Duration::from_millis(40));
    }
    ui.painter().arrow(
        end - egui::vec2(12.0, 0.0),
        egui::vec2(10.0, 0.0),
        egui::Stroke::new(1.5_f32, color),
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tsunagi::vip::{Listener, VipConfig};
    fn fixture() -> (NetworkReport, VipStatus) {
        let mut config = VipConfig::new("k8s");
        config.listeners.push(Listener::new(Protocol::Tcp, 6443));
        let backends: Vec<_> = ["ai", "master", "music"]
            .into_iter()
            .map(|peer| BackendStatus {
                backend: Backend {
                    peer: peer.into(),
                    port: 7443,
                },
                state: "ready".into(),
                rtt_us: Some(4500),
                measurement_age_ms: Some(500),
                active_flows: 5,
                counters: Counters::default(),
            })
            .collect();
        let v = VipStatus {
            config,
            revision: "r1".into(),
            address: None,
            error: None,
            listeners: vec![ListenerStatus {
                protocol: Protocol::Tcp,
                port: 6443,
                selected: Some(backends[0].backend.clone()),
                backends,
                counters: Counters::default(),
            }],
        };
        let n = NetworkReport {
            name: "test".into(),
            vips: vec![v.clone()],
            ..Default::default()
        };
        (n, v)
    }
    #[test]
    fn traffic_branches_are_sampled_independently_of_new_flow_selection_and_open_flows() {
        let (mut n, _) = fixture();
        let now = Instant::now();
        let mut view = View::default();
        view.observe(&n, now);
        n.vips[0].listeners[0].backends[2].counters.tx_packets = 20;
        n.vips[0].listeners[0].backends[2].counters.tx_bytes = 4000;
        n.vips[0].listeners[0].counters.tx_packets = 20;
        n.vips[0].listeners[0].counters.tx_bytes = 4000;
        view.observe(&n, now + Duration::from_secs(2));
        let v = &n.vips[0];
        let l = &v.listeners[0];
        let selected = branch(
            l,
            &l.backends[0],
            view.backends.get(&key(v, l, &l.backends[0].backend)),
            now + Duration::from_secs(2),
        );
        let carrying = branch(
            l,
            &l.backends[2],
            view.backends.get(&key(v, l, &l.backends[2].backend)),
            now + Duration::from_secs(2),
        );
        assert!(selected.next && !selected.active);
        assert!(carrying.active && !carrying.next);
        assert_eq!(view.totals[&v.config.id].total.rate(Unit::Bytes), 2000.0);
        assert!(
            !view.backends[&key(v, l, &l.backends[2].backend)].active(now + Duration::from_secs(8))
        );
        view.observe(&n, now + Duration::from_secs(4));
        assert!(
            !view.backends[&key(v, l, &l.backends[2].backend)].active(now + Duration::from_secs(4))
        );
    }
    #[test]
    fn removed_services_and_backends_release_history_selection_and_cameras() {
        let (mut n, v) = fixture();
        let mut view = View::default();
        view.observe(&n, Instant::now());
        view.selected = Some(key(
            &v,
            &v.listeners[0],
            &v.listeners[0].backends[0].backend,
        ));
        n.vips.clear();
        view.observe(&n, Instant::now());
        assert!(
            view.backends.is_empty()
                && view.totals.is_empty()
                && view.selected.is_none()
                && view.cameras.is_empty()
        );
    }
    #[test]
    fn clicking_a_scene_node_selects_its_backend_without_changing_configuration() {
        let (n, v) = fixture();
        let ctx = egui::Context::default();
        let mut view = View::default();
        let frame = |view: &mut View, events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 600.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default()
                        .show(ctx, |ui| diagram(ui, &v, &v.listeners[0], &n, view));
                },
            )
        };
        frame(&mut view, vec![]);
        let output = frame(&mut view, vec![]);
        let pos = output
            .shapes
            .iter()
            .find_map(|s| match &s.shape {
                egui::Shape::Text(t) if t.galley.text() == "music:7443" => {
                    Some(t.pos + egui::vec2(20.0, 10.0))
                }
                _ => None,
            })
            .expect("scene draws the backend node");
        for pressed in [true, false] {
            frame(
                &mut view,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
        assert!(
            view.selected
                == Some(key(
                    &v,
                    &v.listeners[0],
                    &v.listeners[0].backends[2].backend
                ))
        );
        assert_eq!(n.vips[0].config, v.config);
    }

    #[test]
    fn reset_counters_and_recreated_listeners_do_not_inherit_active_traffic() {
        let (mut n, _) = fixture();
        let mut view = View::default();
        let at = Instant::now();
        n.vips[0].listeners[0].backends[0].counters.tx_packets = 100;
        view.observe(&n, at);
        n.vips[0].listeners[0].backends[0].counters.tx_packets = 0;
        view.observe(&n, at + Duration::from_secs(2));
        let v = &n.vips[0];
        let l = &v.listeners[0];
        assert!(
            !view.backends[&key(v, l, &l.backends[0].backend)].active(at + Duration::from_secs(2))
        );
        n.vips[0].config.listeners[0].id = "new listener".into();
        n.vips[0].listeners[0].backends[0].counters.tx_packets = 200;
        view.observe(&n, at + Duration::from_secs(4));
        let v = &n.vips[0];
        let l = &v.listeners[0];
        assert!(
            !view.backends[&key(v, l, &l.backends[0].backend)].active(at + Duration::from_secs(4))
        );
        assert_eq!(view.backends.len(), 3);
    }

    #[test]
    fn live_tables_and_scenes_render_at_narrow_and_wide_sizes() {
        let (n, v) = fixture();
        let ctx = egui::Context::default();
        let mut view = View::default();
        for width in [650.0, 1000.0, 1800.0, 650.0] {
            for _ in 0..2 {
                let _ = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 1000.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            egui::ScrollArea::vertical().show(ui, |ui| show(ui, &v, &n, &mut view));
                            assert!(
                                ui.min_rect().right() <= width + 1.0,
                                "VIP content expands the window at {width}"
                            );
                        });
                    },
                );
            }
        }
    }
}
