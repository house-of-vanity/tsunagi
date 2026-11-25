//! The eframe application behind the window: the main view, the per-network
//! devices windows, and the agent worker.
//!
//! It runs in its own process, started by the tray when the user chooses Open
//! and gone when the window is closed. The tray, which has to outlive the
//! window, lives in the other process; see [`crate::tray`].

use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::about;
use crate::agent::AgentClient;
use crate::devices;
use crate::stats::Traffic;
use crate::ui::{self, UiState};

use tsunagi_ui::app_fonts;

#[derive(Default)]
struct Views {
    state: UiState,
    traffic: Traffic,
}

/// The window's state.
pub(crate) struct App {
    agent: AgentClient,
    runtime: tokio::runtime::Handle,
    monitor: Option<crate::monitor::Monitor>,
    views: Arc<Mutex<Views>>,
    device_revision: Option<(u64, tsunagi_ui::stats::Unit, bool)>,
    /// The snapshot generation last folded into `traffic`.
    sampled: u64,
}

impl App {
    /// Builds the app: resolves the socket and starts the worker.
    pub(crate) fn new(
        cc: &eframe::CreationContext<'_>,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, String> {
        let ctx = cc.egui_ctx.clone();
        // Add the Phosphor icon glyphs to the font set so the icon buttons
        // render instead of showing as tofu.
        ctx.set_fonts(app_fonts());

        let agent = AgentClient::spawn(&runtime, ctx);
        Ok(Self {
            agent,
            runtime,
            monitor: None,
            views: Default::default(),
            device_revision: None,
            sampled: 0,
        })
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let snapshot = self.agent.snapshot();
        let mut views = self.views.lock().unwrap_or_else(|e| e.into_inner());
        let Views { state, traffic } = &mut *views;
        if snapshot.generation != self.sampled
            && let (Some(Ok(report)), Some(at)) = (&snapshot.status, snapshot.at)
        {
            traffic.observe(report, at);
            self.sampled = snapshot.generation;
        }
        ui::draw(ctx, &self.agent, state, &snapshot, traffic);
        if state.monitor_open {
            let monitor = self.monitor.get_or_insert_with(|| {
                crate::monitor::Monitor::new(&self.runtime, self.agent.socket())
            });
            if !monitor.show(ctx, &snapshot) {
                self.monitor = None;
                state.monitor_open = false;
            }
        }
        Self::show_vip_windows(ctx, &self.agent, state, &snapshot);
        Self::show_about_window(ctx, &self.agent, state, &snapshot);
        let revision = (snapshot.generation, state.unit, snapshot.busy);
        let refresh = self.device_revision != Some(revision);
        self.device_revision = Some(revision);
        if let Some(Ok(report)) = &snapshot.status {
            state
                .open_devices
                .retain(|id| report.networks.iter().any(|n| n.network_id == *id));
            let open: Vec<_> = state.open_devices.iter().cloned().collect();
            // The embedded fallback can run the child callback immediately.
            drop(views);
            self.show_devices_windows(ctx, report, &open, refresh);
        }

        // A secret the worker fetched for the clipboard: copy it here, on the
        // UI thread that owns the clipboard, exactly once.
        if let Some(secret) = self.agent.take_pending_copy() {
            ctx.copy_text(secret);
        }
    }
}

impl App {
    fn show_vip_windows(
        ctx: &egui::Context,
        agent: &AgentClient,
        state: &mut UiState,
        snapshot: &crate::agent::Snapshot,
    ) {
        let Some(Ok(report)) = &snapshot.status else {
            return;
        };
        let ids: Vec<_> = state.vip_windows.keys().cloned().collect();
        for id in ids {
            let Some(network) = report.networks.iter().find(|n| n.network_id == id) else {
                state.vip_windows.remove(&id);
                continue;
            };
            let Some(editor) = state.vip_windows.get_mut(&id) else {
                continue;
            };
            let builder = egui::ViewportBuilder::default()
                .with_title(format!("tsunagi · VIP · {}", network.name))
                .with_app_id(crate::icon::APP_ID)
                .with_icon(crate::icon::window())
                .with_inner_size([1280., 860.])
                .with_min_inner_size([650., 400.]);
            let keep = ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of(("vip", &id)),
                builder,
                |vctx, _| {
                    let close = crate::vip::show(vctx, agent, editor, network, snapshot);
                    if close {
                        return false;
                    }
                    if vctx.input(|i| i.viewport().close_requested()) {
                        if editor.dirty() {
                            editor.request_close();
                            vctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                            true
                        } else {
                            false
                        }
                    } else {
                        true
                    }
                },
            );
            if !keep {
                state.vip_windows.remove(&id);
            }
        }
    }
    /// Renders the About window while it is open.
    fn show_about_window(
        ctx: &egui::Context,
        agent: &AgentClient,
        state: &mut UiState,
        snapshot: &crate::agent::Snapshot,
    ) {
        if !state.about_open {
            return;
        }
        let builder = egui::ViewportBuilder::default()
            .with_title("About tsunagi")
            .with_app_id(crate::icon::APP_ID)
            .with_icon(crate::icon::window())
            .with_inner_size([560.0, 520.0])
            .with_min_inner_size([380.0, 280.0]);
        let socket = agent.socket();
        let keep = ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("about"),
            builder,
            |vctx, _class| {
                about::show(vctx, Some(&socket), snapshot);
                !vctx.input(|i| i.viewport().close_requested())
            },
        );
        if !keep {
            state.about_open = false;
        }
    }

    /// Renders one separate window per open network-devices view.
    fn show_devices_windows(
        &self,
        ctx: &egui::Context,
        report: &Arc<tsunagi::ipc::StatusReport>,
        open: &[String],
        refresh: bool,
    ) {
        for id in open {
            let Some(index) = report.networks.iter().position(|n| n.network_id == *id) else {
                continue;
            };
            let viewport = egui::ViewportId::from_hash_of(("devices", id));
            let preferred = egui::vec2(1240., 740.);
            let size = ctx
                .input(|i| i.viewport().monitor_size)
                .map_or(preferred, |monitor| {
                    preferred.min((monitor - egui::vec2(48., 80.)).max(egui::vec2(560., 400.)))
                });
            let builder = egui::ViewportBuilder::default()
                .with_title(devices::title(&report.networks[index]))
                .with_app_id(crate::icon::APP_ID)
                .with_icon(crate::icon::window())
                .with_inner_size(size)
                .with_min_inner_size([560., 400.]);
            let views = self.views.clone();
            let agent = self.agent.clone();
            let report = report.clone();
            ctx.show_viewport_deferred(viewport, builder, move |ctx, _| {
                let mut views = views.lock().unwrap_or_else(|e| e.into_inner());
                let Views { state, traffic } = &mut *views;
                let network = &report.networks[index];
                if ctx.input(|i| i.viewport().close_requested()) {
                    state.open_devices.remove(&network.network_id);
                    ctx.request_repaint_of(egui::ViewportId::ROOT);
                    return;
                }
                let old_unit = state.unit;
                devices::show(
                    ctx,
                    &agent,
                    &mut state.unit,
                    (&mut state.exit_confirm, &mut state.forget_confirm),
                    network,
                    &report.endpoint_id,
                    traffic,
                );
                if old_unit != state.unit {
                    ctx.request_repaint_of(egui::ViewportId::ROOT);
                }
            });
            if refresh {
                ctx.request_repaint_of(viewport);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn device_frames_are_scheduled_independently_of_the_main_window() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let ctx = egui::Context::default();
        ctx.set_embed_viewports(false);
        let agent = AgentClient::spawn(runtime.handle(), ctx.clone());
        let app = App {
            agent,
            runtime: runtime.handle().clone(),
            monitor: None,
            views: Default::default(),
            sampled: 0,
            device_revision: None,
        };
        let report = Arc::new(tsunagi::ipc::StatusReport {
            networks: vec![tsunagi::ipc::NetworkReport {
                network_id: "test-id".into(),
                name: "lab".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        let id = egui::ViewportId::from_hash_of(("devices", "test-id"));
        let open = ["test-id".to_string()].into_iter().collect();
        app.views.lock().unwrap().state.open_devices = open;
        let out = ctx.run(Default::default(), |ctx| {
            app.show_devices_windows(ctx, &report, &["test-id".to_string()], true);
        });
        assert!(out.viewport_output[&id].class == egui::ViewportClass::Deferred);
        let draw = out.viewport_output[&id].viewport_ui_cb.as_ref().unwrap();
        let mut input = egui::RawInput {
            viewport_id: id,
            ..Default::default()
        };
        input
            .viewports
            .entry(id)
            .or_default()
            .events
            .push(egui::ViewportEvent::Close);
        let _ = ctx.run(input, |ctx| draw(ctx));
        assert!(app.views.lock().unwrap().state.open_devices.is_empty());
    }

    #[test]
    fn route_icons_have_an_embedded_font_in_the_app() {
        let fonts = app_fonts();
        assert!(fonts.font_data.contains_key("phosphor"));
        assert!(
            fonts
                .families
                .get(&egui::FontFamily::Proportional)
                .is_some_and(|family| family.iter().any(|name| name == "phosphor"))
        );
    }
}
