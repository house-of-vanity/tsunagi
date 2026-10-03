//! The eframe application behind the window: the main view, the per-network
//! devices windows, and the agent worker.
//!
//! It runs in its own process, started by the tray when the user chooses Open
//! and gone when the window is closed. The tray, which has to outlive the
//! window, lives in the other process; see [`crate::tray`].

use std::time::Duration;

use eframe::egui;

use crate::about;
use crate::agent::AgentClient;
use crate::devices;
use crate::stats::Traffic;
use crate::ui::{self, UiState};

/// The window's state.
pub(crate) struct App {
    agent: AgentClient,
    state: UiState,
    /// Traffic rates derived from successive snapshots.
    traffic: Traffic,
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
        let mut fonts = egui::FontDefinitions::default();
        egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
        ctx.set_fonts(fonts);

        let agent = AgentClient::spawn(&runtime, ctx);
        Ok(Self {
            agent,
            state: UiState::default(),
            traffic: Traffic::default(),
            sampled: 0,
        })
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let snapshot = self.agent.snapshot();
        if snapshot.generation != self.sampled
            && let (Some(Ok(report)), Some(at)) = (&snapshot.status, snapshot.at)
        {
            self.traffic.observe(report, at);
            self.sampled = snapshot.generation;
        }

        ui::draw(ctx, &self.agent, &mut self.state, &snapshot, &self.traffic);
        self.show_devices_windows(ctx, &snapshot);
        self.show_about_window(ctx, &snapshot);

        // A secret the worker fetched for the clipboard: copy it here, on the
        // UI thread that owns the clipboard, exactly once.
        if let Some(secret) = self.agent.take_pending_copy() {
            ctx.copy_text(secret);
        }

        // Keep ticking so fresh status is picked up.
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

impl App {
    /// Renders the About window while it is open.
    fn show_about_window(&mut self, ctx: &egui::Context, snapshot: &crate::agent::Snapshot) {
        if !self.state.about_open {
            return;
        }
        let builder = egui::ViewportBuilder::default()
            .with_title("About tsunagi")
            .with_app_id(crate::icon::APP_ID)
            .with_icon(crate::icon::window())
            .with_inner_size([560.0, 520.0])
            .with_min_inner_size([380.0, 280.0]);
        let socket = self.agent.socket();
        let keep = ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("about"),
            builder,
            |vctx, _class| {
                about::show(vctx, &socket, snapshot);
                !vctx.input(|i| i.viewport().close_requested())
            },
        );
        if !keep {
            self.state.about_open = false;
        }
    }

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
                .with_app_id(crate::icon::APP_ID)
                .with_icon(crate::icon::window())
                .with_inner_size([940.0, 540.0])
                .with_min_inner_size([480.0, 320.0]);
            let agent = &self.agent;
            let traffic = &self.traffic;
            // The window shares the single unit setting, so its toggle and the
            // main window's stay in step.
            let unit = &mut self.state.unit;
            let confirm = &mut self.state.exit_confirm;
            let keep = ctx.show_viewport_immediate(viewport_id, builder, |vctx, _class| {
                devices::show(
                    vctx,
                    agent,
                    unit,
                    confirm,
                    network,
                    &report.endpoint_id,
                    traffic,
                );
                !vctx.input(|i| i.viewport().close_requested())
            });
            if !keep {
                self.state.open_devices.remove(&id);
            }
        }
    }
}
