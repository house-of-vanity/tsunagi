//! Tray application for managing a running tsunagi agent.
//!
//! A tray icon and menu (Open, Quit) that opens a small window (networks, their
//! peers and addresses, join/leave, per-network active and broadcast switches).
//! There is no window until Open, and closing it leaves the icon. The window
//! is a thin client over the agent's local control socket — the same interface
//! the CLI uses.

// Nothing here is a library.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod about;
mod agent;
mod app;
mod devices;
mod format;
mod stats;
mod tray;
mod ui;

use eframe::egui;

use crate::app::App;

/// The argument that makes this binary the window rather than the tray.
const WINDOW_ARG: &str = "--window";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();

    // Two processes from one binary. The tray is what stays; the window is
    // started by it and ends when it is closed. A window that merely hides is
    // not something every platform can do — Wayland has no such thing — and a
    // hidden one that stays is worse than none.
    if std::env::args().any(|arg| arg == WINDOW_ARG) {
        window()
    } else {
        tray::run()
    }
}

/// Runs the window until it is closed.
fn window() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let handle = runtime.handle().clone();

    let options = eframe::NativeOptions {
        // A fixed, small window; the whole layout targets this size.
        viewport: egui::ViewportBuilder::default()
            .with_title("tsunagi")
            .with_app_id("tsunagi")
            .with_inner_size([360.0, 600.0])
            .with_resizable(false),
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

    // The window loop has ended; let the runtime wind down.
    drop(runtime);
    Ok(())
}
