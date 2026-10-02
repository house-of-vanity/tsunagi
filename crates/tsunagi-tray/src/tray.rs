//! The tray icon and its menu.
//!
//! The menu is just Open and Quit; everything else (per-network switches,
//! join/leave) lives in the window. Menu clicks are read on a background
//! thread and turned into [`Action`]s, so they are handled even while the
//! window is hidden and egui would otherwise not be repainting.

use std::sync::mpsc;

use eframe::egui;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

/// What the user picked from the tray menu.
pub(crate) enum Action {
    /// Show (and focus) the window.
    Open,
    /// Quit the application.
    Quit,
}

/// The live tray icon plus the channel of menu actions.
pub(crate) struct Tray {
    /// Kept alive for as long as the app runs; dropping it removes the icon.
    _icon: TrayIcon,
    actions: mpsc::Receiver<Action>,
}

impl Tray {
    /// Builds the tray and starts reading its menu events.
    ///
    /// Created on the main thread (required on macOS); `ctx` is used to wake the
    /// UI when a menu item is chosen.
    pub(crate) fn new(ctx: egui::Context) -> Result<Self, String> {
        let open = MenuItem::new("Open tsunagi", true, None);
        let quit = MenuItem::new("Quit", true, None);
        let menu = Menu::new();
        menu.append(&open).map_err(|err| err.to_string())?;
        menu.append(&PredefinedMenuItem::separator())
            .map_err(|err| err.to_string())?;
        menu.append(&quit).map_err(|err| err.to_string())?;

        let icon = make_icon()?;
        let tray = TrayIconBuilder::new()
            .with_tooltip("tsunagi")
            .with_menu(Box::new(menu))
            .with_icon(icon)
            .build()
            .map_err(|err| err.to_string())?;

        let open_id = open.id().clone();
        let quit_id = quit.id().clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            // The global menu-event channel is fed by the OS event loop.
            while let Ok(event) = MenuEvent::receiver().recv() {
                let action = if event.id == open_id {
                    Action::Open
                } else if event.id == quit_id {
                    Action::Quit
                } else {
                    continue;
                };
                if tx.send(action).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });

        Ok(Self {
            _icon: tray,
            actions: rx,
        })
    }

    /// The menu actions since the last call.
    pub(crate) fn poll(&self) -> impl Iterator<Item = Action> + '_ {
        self.actions.try_iter()
    }
}

/// A small round icon, drawn in code so there is no asset to ship yet.
fn make_icon() -> Result<Icon, String> {
    const SIZE: u32 = 32;
    let centre = (SIZE as f32 - 1.0) / 2.0;
    let radius = SIZE as f32 * 0.46;
    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let (dx, dy) = (x as f32 - centre, y as f32 - centre);
            if dx * dx + dy * dy <= radius * radius {
                let i = ((y * SIZE + x) * 4) as usize;
                rgba[i] = 0x2f;
                rgba[i + 1] = 0x80;
                rgba[i + 2] = 0xd8;
                rgba[i + 3] = 0xff;
            }
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE).map_err(|err| err.to_string())
}
