//! The eframe application: wires the tray, the main window, the per-network
//! devices windows, and the agent worker.

use std::time::Duration;

use eframe::egui;

use crate::agent::{AgentClient, resolve_socket};
use crate::devices;
use crate::stats::Traffic;
use crate::tray::{Action, Tray};
use crate::ui::{self, UiState};

/// The tray application state.
pub(crate) struct App {
    agent: AgentClient,
    tray: Tray,
    state: UiState,
    /// Traffic rates derived from successive snapshots.
    traffic: Traffic,
    /// The snapshot generation last folded into `traffic`.
    sampled: u64,
    /// Set when the user chose Quit, so the next close exits rather than hides.
    quitting: bool,
}

impl App {
    /// Builds the app: resolves the socket, starts the worker, creates the tray.
    pub(crate) fn new(
        cc: &eframe::CreationContext<'_>,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, String> {
        let ctx = cc.egui_ctx.clone();
        // Add the Phosphor icon glyphs to the font set so the icon buttons
        // render instead of showing as tofu.
        let mut fonts = egui::FontDefinitions::default();
        egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
        ctx.set_fonts(fonts);

        let agent = AgentClient::spawn(&runtime, ctx.clone(), resolve_socket());
        let tray = Tray::new(ctx)?;
        Ok(Self {
            agent,
            tray,
            state: UiState::default(),
            traffic: Traffic::default(),
            sampled: 0,
            quitting: false,
        })
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        for action in self.tray.poll() {
            match action {
                Action::Open => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                Action::Quit => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        // Closing the main window hides it to the tray; only Quit truly exits.
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        let snapshot = self.agent.snapshot();
        if snapshot.generation != self.sampled
            && let (Some(Ok(report)), Some(at)) = (&snapshot.status, snapshot.at)
        {
            self.traffic.observe(report, at);
            self.sampled = snapshot.generation;
        }

        ui::draw(ctx, &self.agent, &mut self.state, &snapshot, &self.traffic);
        self.show_devices_windows(ctx, &snapshot);

        // A secret the worker fetched for the clipboard: copy it here, on the
        // UI thread that owns the clipboard, exactly once.
        if let Some(secret) = self.agent.take_pending_copy() {
            ctx.copy_text(secret);
        }

        // Keep ticking so fresh status and tray actions are picked up.
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

impl App {
    /// Renders one separate window per open network-devices view.
    fn show_devices_windows(&mut self, ctx: &egui::Context, snapshot: &crate::agent::Snapshot) {
        let Some(Ok(report)) = &snapshot.status else {
            return;
        };
        let open: Vec<String> = self.state.open_devices.iter().cloned().collect();
        for id in open {
            let Some(network) = report.networks.iter().find(|n| n.network_id == id) else {
                // The network is gone (left/forgotten); close its window.
                self.state.open_devices.remove(&id);
                continue;
            };
            let viewport_id = egui::ViewportId::from_hash_of(("devices", &id));
            let builder = egui::ViewportBuilder::default()
                .with_title(devices::title(network))
                .with_inner_size([720.0, 540.0])
                .with_min_inner_size([480.0, 320.0]);
            let agent = &self.agent;
            let traffic = &self.traffic;
            // The window shares the single unit setting, so its toggle and the
            // main window's stay in step.
            let unit = &mut self.state.unit;
            let keep = ctx.show_viewport_immediate(viewport_id, builder, |vctx, _class| {
                devices::show(vctx, agent, unit, network, traffic);
                !vctx.input(|i| i.viewport().close_requested())
            });
            if !keep {
                self.state.open_devices.remove(&id);
            }
        }
    }
}
