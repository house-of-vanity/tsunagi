//! Tray application for managing a running tsunagi agent.
//!
//! A small window (networks, their peers and addresses, join/leave, per-network
//! active and broadcast switches) plus a tray menu (Open, Quit). It is a thin
//! client over the agent's local control socket — the same interface the CLI
//! uses — and owns its own runtime, logger and event loop, like the CLI binary.

// The window is created hidden-to-tray on close rather than exiting; the binary
// itself may exit on Quit. Nothing here is a library.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod agent;
mod app;
mod tray;
mod ui;

use eframe::egui;

use crate::app::App;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let handle = runtime.handle().clone();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("tsunagi")
            .with_inner_size([380.0, 540.0])
            .with_min_inner_size([320.0, 360.0]),
        ..Default::default()
    };

    eframe::run_native(
        "tsunagi",
        options,
        Box::new(move |cc| {
            App::new(cc, handle.clone())
                .map(|app| Box::new(app) as Box<dyn eframe::App>)
                .map_err(std::convert::Into::into)
        }),
    )?;

    // The window loop has ended (Quit); let the runtime wind down.
    drop(runtime);
    Ok(())
}
