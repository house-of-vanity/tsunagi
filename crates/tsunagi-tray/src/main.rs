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
mod stats;
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

    #[cfg_attr(not(target_os = "macos"), expect(unused_mut))]
    let mut options = eframe::NativeOptions {
        // A fixed, small window; the whole layout targets this size.
        viewport: egui::ViewportBuilder::default()
            .with_title("tsunagi")
            .with_inner_size([360.0, 600.0])
            .with_resizable(false)
            // Start hidden: the app lives in the tray and the window opens from
            // the menu.
            .with_visible(false),
        ..Default::default()
    };

    // macOS: live in the menu bar with no Dock icon (tray-only).
    #[cfg(target_os = "macos")]
    {
        options.event_loop_builder = Some(Box::new(|builder| {
            use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
            builder.with_activation_policy(ActivationPolicy::Accessory);
        }));
    }

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
