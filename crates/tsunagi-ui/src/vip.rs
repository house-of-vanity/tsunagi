//! Per-network VIP editor. Drafts never issue commands until Save is pressed.
use crate::client::{Client, Command, Snapshot};
use crate::vip_status;
use tsunagi::ipc::NetworkReport;
use tsunagi::vip::VipConfig;
#[cfg(test)]
use tsunagi::vip::{Listener, Protocol};
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
/// A network’s edit draft, selection and traffic history.
pub struct Window {
    draft: Option<Draft>,
    pending: Option<String>,
    error: Option<String>,
    close_question: bool,
    close_after_save: bool,
    live: vip_status::View,
    configure: bool,
    generation: u64,
    acknowledged_generation: Option<u64>,
}
impl Window {
    /// Ask whether to discard an outstanding draft.
    pub fn request_close(&mut self) {
        self.close_question = true;
        self.close_after_save = true;
    }
    /// Whether closing needs confirmation.
    pub fn dirty(&self) -> bool {
        self.draft.as_ref().is_some_and(Draft::dirty) || self.pending.is_some()
    }
}
/// Render the editor and overview. Returns true when its view can close.
pub fn show(
    ctx: &egui::Context,
    agent: &dyn Client,
    state: &mut Window,
    n: &NetworkReport,
    snapshot: &Snapshot,
) -> bool {
    if state.generation == 0
        && state.draft.is_none()
        && let [vip] = n.vips.as_slice()
    {
        state.draft = Some(Draft::new(vip.config.clone(), Some(vip.revision.clone())));
    }
    if state.generation != snapshot.generation {
        state.generation = snapshot.generation;
        if let Some(at) = snapshot.at {
            state.live.observe(n, at);
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
        let wide = ui.available_width() >= 580.;
        ui.horizontal_wrapped(|ui| {
            ui.heading(format!("VIP · {}", n.name));
            crate::widgets::field(
                ui,
                egui_phosphor::regular::INFO,
                "",
                "Configuration is shared with every member. Changes take effect only after Save.",
            );
        });
        if state.close_question {
            ui.horizontal_wrapped(|ui| {
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
                    state.configure = true;
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
        let tabs = |ui: &mut egui::Ui, configure: &mut bool| {
            ui.selectable_value(configure, false, "Overview");
            ui.selectable_value(configure, true, "Configuration");
        };
        ui.horizontal_wrapped(|ui| {
            if wide {
                tabs(ui, &mut state.configure);
                ui.separator();
            }
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
        if !wide {
            ui.horizontal(|ui| tabs(ui, &mut state.configure));
        }
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if state.configure {
                    ui.add_enabled_ui(!busy, |ui| {
                        ui.horizontal_wrapped(|ui| {
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
                } else if let Some(current) = current {
                    vip_status::show(ui, current, n, &mut state.live);
                } else {
                    ui.weak("Save this VIP to see its live status.");
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
    let members = n
        .members
        .iter()
        .map(|m| {
            (
                m.endpoint_id.clone(),
                format!(
                    "{} ({})",
                    m.hostname.as_deref().unwrap_or("unnamed"),
                    crate::format::short(&m.endpoint_id)
                ),
            )
        })
        .collect::<Vec<_>>();
    crate::listeners::edit(ui, config, &members);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tsunagi::vip::VipStatus;
    #[test]
    fn editing_the_actual_form_sends_nothing_until_save_is_clicked() {
        let (tx, commands) = std::sync::mpsc::channel();
        struct TestClient(std::sync::mpsc::Sender<Command>);
        impl Client for TestClient {
            fn send(&self, command: Command) {
                self.0.send(command).unwrap();
            }
            fn busy(&self) -> bool {
                false
            }
        }
        let agent = TestClient(tx);
        let ctx = egui::Context::default();
        let mut config = VipConfig::new("api");
        config.listeners.push(Listener::new(Protocol::Tcp, 443));
        let mut state = Window {
            draft: Some(Draft::new(config.clone(), Some("revision".into()))),
            configure: true,
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
