//! The eframe application: wires the tray, the window and the agent worker.

use std::time::Duration;

use eframe::egui;

use crate::agent::{AgentClient, resolve_socket};
use crate::tray::{Action, Tray};
use crate::ui::{self, JoinForm};

/// The tray application state.
pub(crate) struct App {
    agent: AgentClient,
    tray: Tray,
    join: JoinForm,
    /// Set when the user chose Quit, so the next close actually exits instead
    /// of hiding to the tray.
    quitting: bool,
}

impl App {
    /// Builds the app: resolves the socket, starts the worker, creates the tray.
    pub(crate) fn new(
        cc: &eframe::CreationContext<'_>,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, String> {
        let ctx = cc.egui_ctx.clone();
        let agent = AgentClient::spawn(&runtime, ctx.clone(), resolve_socket());
        let tray = Tray::new(ctx)?;
        Ok(Self {
            agent,
            tray,
            join: JoinForm::default(),
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

        // Closing the window hides it to the tray; only Quit truly exits.
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        let snapshot = self.agent.snapshot();
        ui::draw(ctx, &self.agent, &mut self.join, &snapshot);

        // Keep ticking so fresh status and tray actions are picked up even when
        // nothing else requests a repaint.
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}
