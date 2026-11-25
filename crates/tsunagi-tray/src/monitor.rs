//! The local IPC subscription lives exactly as long as its viewport.
use eframe::egui;
use std::{path::PathBuf, time::Duration};
use tsunagi::ipc::TrafficStream;
use tsunagi_ui::monitor::Window;

pub(super) struct Monitor {
    view: Window,
    task: tokio::task::JoinHandle<()>,
}
impl Monitor {
    pub fn new(runtime: &tokio::runtime::Handle, socket: PathBuf) -> Self {
        let view = Window::new(None);
        let feed = view.feed();
        let task = runtime.spawn(async move {
            let capture = async {
                let mut stream = TrafficStream::open(&socket).await?;
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if !feed.sample(stream.snapshot().await?) {
                        return Ok::<_, tsunagi::Error>(());
                    }
                }
            };
            if let Err(e) = capture.await {
                feed.error(format!("Capture stopped · {e}"));
            }
        });
        Self { view, task }
    }
    pub fn show(&mut self, ctx: &egui::Context, snapshot: &crate::agent::Snapshot) -> bool {
        let builder = egui::ViewportBuilder::default()
            .with_title("tsunagi · Traffic monitor")
            .with_app_id(crate::icon::APP_ID)
            .with_icon(crate::icon::window())
            .with_inner_size([920., 580.])
            .with_min_inner_size([340., 320.]);
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("traffic-monitor"),
            builder,
            |ctx, _| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    self.view.show(
                        ui,
                        snapshot.status.as_ref().and_then(|r| r.as_deref().ok()),
                        snapshot.generation,
                    );
                });
                !ctx.input(|i| i.viewport().close_requested())
            },
        )
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
