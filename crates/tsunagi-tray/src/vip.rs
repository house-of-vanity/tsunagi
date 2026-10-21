//! Per-network VIP editor. Drafts never issue commands until Save is pressed.
use crate::agent::{AgentClient, Command, Snapshot};
use crate::stats::{Series, Unit};
use eframe::egui;
use std::collections::BTreeMap;
use tsunagi::ipc::NetworkReport;
use tsunagi::vip::{Backend, Listener, Protocol, VipConfig, VipStatus};
#[derive(Clone)]
struct Draft {
    config: VipConfig,
    original: VipConfig,
    revision: Option<String>,
    delete: bool,
}
impl Draft {
    fn new(config: VipConfig, revision: Option<String>) -> Self {
        Self {
            original: config.clone(),
            config,
            revision,
            delete: false,
        }
    }
    fn dirty(&self) -> bool {
        self.revision.is_none() || self.delete || self.config != self.original
    }
}
#[derive(Default)]
pub(crate) struct Window {
    draft: Option<Draft>,
    pending: Option<String>,
    error: Option<String>,
    close_question: bool,
    close_after_save: bool,
    rates: BTreeMap<String, (Series, Series)>,
    generation: u64,
    acknowledged_generation: Option<u64>,
}
impl Window {
    pub fn request_close(&mut self) {
        self.close_question = true;
        self.close_after_save = true;
    }
    pub fn dirty(&self) -> bool {
        self.draft.as_ref().is_some_and(Draft::dirty) || self.pending.is_some()
    }
}
fn peer_name<'a>(n: &'a NetworkReport, id: &'a str) -> &'a str {
    n.members
        .iter()
        .find(|m| m.endpoint_id == id)
        .and_then(|m| m.hostname.as_deref())
        .unwrap_or(id)
}
pub(crate) fn show(
    ctx: &egui::Context,
    agent: &AgentClient,
    state: &mut Window,
    n: &NetworkReport,
    snapshot: &Snapshot,
) -> bool {
    if state.generation != snapshot.generation {
        state.generation = snapshot.generation;
        if let Some(at) = snapshot.at {
            for v in &n.vips {
                let counters = v.listeners.iter().fold((0, 0, 0, 0), |a, l| {
                    (
                        a.0 + l.counters.tx_packets,
                        a.1 + l.counters.tx_bytes,
                        a.2 + l.counters.rx_packets,
                        a.3 + l.counters.rx_bytes,
                    )
                });
                let (tx, rx) = state.rates.entry(v.config.id.clone()).or_default();
                tx.sample(at, counters.0, counters.1);
                rx.sample(at, counters.2, counters.3);
            }
        }
    }
    if let Some(result) = &snapshot.vip_result
        && state.pending.as_deref() == Some(result.token.as_str())
    {
        state.pending = None;
        state.acknowledged_generation = Some(snapshot.generation);
        match &result.result {
            Ok(vips) => {
                if let Some(draft) = &state.draft {
                    state.draft = vips
                        .iter()
                        .find(|v| v.config.id == draft.config.id)
                        .map(|v| Draft::new(v.config.clone(), Some(v.revision.clone())));
                }
                state.error = None;
            }
            Err(error) => {
                state.error = Some(error.clone());
                state.close_after_save = false;
            }
        }
    }
    let mut close = state.close_after_save && !state.dirty();
    let mut discard_new = false;
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.heading(format!("VIP · {}", n.name));
        ui.weak("Configuration is shared with every member. Changes take effect only after Save.");
        if state.close_question {
            ui.horizontal(|ui| {
                ui.label("Unsaved changes.");
                if ui
                    .add_enabled(
                        state.pending.is_none(),
                        egui::Button::new("Discard and close"),
                    )
                    .clicked()
                {
                    state.draft = None;
                    state.close_question = false;
                    close = true;
                }
                if ui.button("Keep editing").clicked() {
                    state.close_question = false;
                    state.close_after_save = false;
                }
            });
        }
        if let Some(error) = &state.error {
            ui.colored_label(egui::Color32::LIGHT_RED, error);
        }
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            for vip in &n.vips {
                let selected = state
                    .draft
                    .as_ref()
                    .is_some_and(|d| d.config.id == vip.config.id);
                if ui.selectable_label(selected, &vip.config.name).clicked() {
                    if state.dirty() {
                        state.error = Some(
                            "Save or discard the current draft before selecting another VIP."
                                .into(),
                        );
                    } else {
                        state.draft =
                            Some(Draft::new(vip.config.clone(), Some(vip.revision.clone())));
                        state.error = None;
                    }
                }
            }
            if ui.button("+ New VIP").clicked() {
                if state.dirty() {
                    state.error = Some("Save or discard the current draft first.".into());
                } else {
                    state.draft = Some(Draft::new(VipConfig::new(""), None));
                    state.error = None;
                }
            }
        });
        let Some(draft) = &mut state.draft else {
            ui.label("Select a VIP or create one.");
            return;
        };
        let current = n.vips.iter().find(|v| v.config.id == draft.config.id);
        if state.pending.is_none()
            && state.acknowledged_generation != Some(snapshot.generation)
            && !draft.dirty()
            && let Some(current) = current
            && draft.revision.as_ref() != Some(&current.revision)
        {
            *draft = Draft::new(current.config.clone(), Some(current.revision.clone()));
        }
        let changed =
            current.is_some_and(|v| draft.revision.as_ref().is_some_and(|r| r != &v.revision));
        if changed {
            ui.colored_label(
                egui::Color32::YELLOW,
                "This VIP changed on the network. Reload before saving; your draft is retained.",
            );
        }
        if draft.revision.is_some() && current.is_none() {
            ui.colored_label(
                egui::Color32::YELLOW,
                "This VIP was removed on the network. The draft cannot overwrite its deletion.",
            );
        }
        let busy = state.pending.is_some();
        ui.horizontal(|ui| {
            let valid = draft.config.validate(&tsunagi::Limits::default());
            if !n.active {
                ui.weak("Start the network to save changes.");
            }
            if ui
                .add_enabled(
                    n.active
                        && !busy
                        && draft.dirty()
                        && !changed
                        && (valid.is_ok() || draft.delete),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let token = VipConfig::new("").id;
                state.pending = Some(token.clone());
                agent.send(Command::SaveVip {
                    token,
                    network_id: n.network_id.clone(),
                    config: draft.config.clone(),
                    expected: draft.revision.clone(),
                    delete: draft.delete,
                });
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Discard / reload"))
                .clicked()
            {
                if let Some(v) = current {
                    *draft = Draft::new(v.config.clone(), Some(v.revision.clone()));
                } else {
                    discard_new = true;
                }
                state.error = None;
            }
            if busy {
                ui.spinner();
                ui.label("Saving…");
            } else if draft.dirty() {
                ui.weak("Unsaved changes");
            }
            if let Err(error) = valid {
                ui.colored_label(egui::Color32::LIGHT_RED, error.to_string());
            }
        });
        ui.separator();
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name");
                    ui.add(
                        egui::TextEdit::singleline(&mut draft.config.name)
                            .id(egui::Id::new(("vip-name", &draft.config.id))),
                    );
                    ui.weak(format!(".{}", n.name));
                });
                if draft.revision.is_some() {
                    ui.checkbox(&mut draft.delete, "Delete this VIP when saved");
                }
                if !draft.delete {
                    edit_listeners(ui, &mut draft.config, n);
                }
            });
            if let Some(current) = current {
                ui.separator();
                status(ui, current, n, state.rates.get(&current.config.id));
            }
        });
    });
    if discard_new {
        state.draft = None;
        state.error = None;
    }
    close
}
fn edit_listeners(ui: &mut egui::Ui, config: &mut VipConfig, n: &NetworkReport) {
    let mut remove = None;
    for (index, l) in config.listeners.iter_mut().enumerate() {
        ui.push_id(index,|ui|{egui::Frame::group(ui.style()).show(ui,|ui|{
    ui.horizontal(|ui|{egui::ComboBox::from_id_salt("protocol").selected_text(l.protocol.to_string()).show_ui(ui,|ui|{ui.selectable_value(&mut l.protocol,Protocol::Tcp,"TCP");ui.selectable_value(&mut l.protocol,Protocol::Udp,"UDP");});ui.label("Port");ui.add(egui::DragValue::new(&mut l.port).range(1..=65535));if ui.button("Remove listener").clicked(){remove=Some(index);}});
    if l.protocol==Protocol::Tcp{ui.checkbox(&mut l.port_check,"Active TCP port checks");}else{ui.weak("UDP health: encrypted path probes and explicit port errors; application readiness is unknown.");}
    ui.collapsing("Checks and flow expiry",|ui|{egui::Grid::new("settings").show(ui,|ui|{
        ui.label("Check interval, ms");ui.add(egui::DragValue::new(&mut l.check_interval_ms).range(250..=3_600_000));ui.end_row();
        ui.label("Check timeout, ms");ui.add(egui::DragValue::new(&mut l.check_timeout_ms).range(100..=60_000));ui.end_row();
        ui.label("Failures before exclusion");ui.add(egui::DragValue::new(&mut l.failure_threshold).range(1..=255));ui.end_row();
        ui.label("Successes before recovery");ui.add(egui::DragValue::new(&mut l.recovery_threshold).range(1..=255));ui.end_row();
        ui.label("Flow idle timeout, seconds");ui.add(egui::DragValue::new(&mut l.idle_timeout_secs).range(1..=604800));ui.end_row();
    });});
    let mut remove_backend=None;for(i,b)in l.backends.iter_mut().enumerate(){ui.push_id(i,|ui|{ui.horizontal(|ui|{
        egui::ComboBox::from_id_salt("node").width(240.).selected_text(peer_name(n,&b.peer)).show_ui(ui,|ui|{for m in &n.members{let label=format!("{} ({})",m.hostname.as_deref().unwrap_or("unnamed"),m.endpoint_id.chars().take(8).collect::<String>());ui.selectable_value(&mut b.peer,m.endpoint_id.clone(),label);}});
        ui.label("Target port");ui.add(egui::DragValue::new(&mut b.port).range(1..=65535));if ui.button("Remove").clicked(){remove_backend=Some(i);}
    });});}if let Some(i)=remove_backend{l.backends.remove(i);}
    if ui.button("+ Backend").clicked(){l.backends.push(Backend{peer:n.members.first().map(|m|m.endpoint_id.clone()).unwrap_or_default(),port:l.port});}
});});
    }
    if let Some(index) = remove {
        config.listeners.remove(index);
    }
    if ui.button("+ Listener").clicked() {
        config.listeners.push(Listener::new(Protocol::Tcp, 443));
    }
}
fn status(ui: &mut egui::Ui, v: &VipStatus, n: &NetworkReport, rates: Option<&(Series, Series)>) {
    ui.heading("Status · this device");
    if let Some(error) = &v.error {
        ui.colored_label(egui::Color32::LIGHT_RED, error);
    }
    if let Some((tx, rx)) = rates {
        ui.label(format!(
            "TX {:.1} KiB/s · RX {:.1} KiB/s",
            tx.rate(Unit::Bytes) / 1024.,
            rx.rate(Unit::Bytes) / 1024.
        ));
    }
    for l in &v.listeners {
        ui.strong(format!("{}/{}", l.protocol, l.port));
        let selected = l
            .selected
            .as_ref()
            .map(|b| format!("{}:{}", peer_name(n, &b.peer), b.port))
            .unwrap_or_else(|| "none".into());
        ui.label(format!("Next new flow: {selected}"));
        ui.label(format!(
            "TX {} bytes / {} packets · RX {} bytes / {} packets · drops {} · UDP failovers {}",
            l.counters.tx_bytes,
            l.counters.tx_packets,
            l.counters.rx_bytes,
            l.counters.rx_packets,
            l.counters.dropped,
            l.counters.failovers
        ));
        for b in &l.backends {
            let rtt = b
                .rtt_us
                .map(|v| format!("{:.2} ms", v as f64 / 1000.))
                .unwrap_or_else(|| "unknown".into());
            let age = b
                .measurement_age_ms
                .map(|v| format!("{:.1}s", v as f64 / 1000.))
                .unwrap_or_else(|| "unknown".into());
            ui.label(format!(
                "{}:{} · {} · RTT {} (age {}) · {} active · TX/RX {}/{} bytes",
                peer_name(n, &b.backend.peer),
                b.backend.port,
                b.state,
                rtt,
                age,
                b.active_flows,
                b.counters.tx_bytes,
                b.counters.rx_bytes
            ));
        }
    }
    ui.collapsing("Internal address and identity", |ui| {
        ui.monospace(&v.config.id);
        if let Some(address) = v.address {
            ui.monospace(address.to_string());
        }
    });
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn editing_the_actual_form_sends_nothing_until_save_is_clicked() {
        let (agent, mut commands) = AgentClient::test_client();
        let ctx = egui::Context::default();
        let mut config = VipConfig::new("api");
        config.listeners.push(Listener::new(Protocol::Tcp, 443));
        let mut state = Window {
            draft: Some(Draft::new(config.clone(), Some("revision".into()))),
            ..Default::default()
        };
        let network = NetworkReport {
            active: true,
            name: "lab".into(),
            vips: vec![VipStatus {
                config: config.clone(),
                revision: "revision".into(),
                address: None,
                error: None,
                listeners: vec![],
            }],
            ..Default::default()
        };
        let snapshot = Snapshot::default();
        let frame = |events: Vec<egui::Event>, state: &mut Window| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000., 800.),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    show(ctx, &agent, state, &network, &snapshot);
                },
            )
        };
        frame(vec![], &mut state);
        ctx.memory_mut(|m| m.request_focus(egui::Id::new(("vip-name", &config.id))));
        frame(vec![egui::Event::Text("new".into())], &mut state);
        assert!(state.dirty());
        assert_ne!(state.draft.as_ref().unwrap().config.name, config.name);
        assert!(commands.try_recv().is_err());
        assert_eq!(network.vips[0].config, config);
        fn save_position(shape: &egui::Shape) -> Option<egui::Pos2> {
            match shape {
                egui::Shape::Text(text) if text.galley.text() == "Save" => {
                    Some(text.pos + text.galley.rect.center().to_vec2())
                }
                egui::Shape::Vec(shapes) => shapes.iter().find_map(save_position),
                _ => None,
            }
        }
        // Save was disabled before this edit; allow the next layout to register
        // its now-enabled hit target before dispatching the pointer press.
        let ready = frame(vec![], &mut state);
        let position = ready
            .shapes
            .iter()
            .find_map(|s| save_position(&s.shape))
            .unwrap();
        frame(
            vec![
                egui::Event::PointerMoved(position),
                egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            &mut state,
        );
        frame(
            vec![egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
            &mut state,
        );
        let Command::SaveVip {
            config: saved,
            expected,
            delete,
            ..
        } = commands.try_recv().unwrap()
        else {
            panic!("Save must submit one complete VIP draft");
        };
        assert_ne!(saved.name, config.name);
        assert_eq!(expected.as_deref(), Some("revision"));
        assert!(!delete);
        assert!(commands.try_recv().is_err());
    }
    #[test]
    fn all_listener_settings_render_without_a_live_agent() {
        let ctx = egui::Context::default();
        let mut cfg = VipConfig::new("api");
        cfg.listeners.push(Listener::new(Protocol::Tcp, 443));
        cfg.listeners.push(Listener::new(Protocol::Udp, 53));
        let n = NetworkReport::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| edit_listeners(ui, &mut cfg, &n));
        });
        assert_eq!(cfg.listeners.len(), 2);
    }
}
