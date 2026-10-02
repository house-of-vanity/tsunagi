//! The tray icon and its menu.
//!
//! The menu is just Open and Quit; everything else (per-network switches,
//! join/leave) lives in the window. Menu clicks are read on a background
//! thread and turned into [`Action`]s, so they are handled even while the
//! window is hidden and egui would otherwise not be repainting.

use std::sync::mpsc;

use eframe::egui;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
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
    /// On Linux the icon lives on the GTK thread instead (it is not `Send`).
    #[cfg(not(target_os = "linux"))]
    _icon: TrayIcon,
    actions: mpsc::Receiver<Action>,
}

/// A built tray icon and the ids of its menu items.
struct Built {
    icon: TrayIcon,
    open: MenuId,
    quit: MenuId,
}

fn build() -> Result<Built, String> {
    let open = MenuItem::new("Open tsunagi", true, None);
    let quit = MenuItem::new("Quit", true, None);
    let menu = Menu::new();
    menu.append(&open).map_err(|err| err.to_string())?;
    menu.append(&PredefinedMenuItem::separator())
        .map_err(|err| err.to_string())?;
    menu.append(&quit).map_err(|err| err.to_string())?;

    let icon = TrayIconBuilder::new()
        .with_tooltip("tsunagi")
        .with_menu(Box::new(menu))
        .with_icon(make_icon()?)
        .build()
        .map_err(|err| err.to_string())?;
    Ok(Built {
        icon,
        open: open.id().clone(),
        quit: quit.id().clone(),
    })
}

impl Tray {
    /// Builds the tray and starts reading its menu events.
    ///
    /// Created on the main thread on macOS and Windows (required on macOS). On
    /// Linux the tray needs GTK, which eframe/winit never initialise, so it is
    /// built on a dedicated thread that initialises GTK and runs its main loop.
    /// `ctx` is used to wake the UI when a menu item is chosen.
    pub(crate) fn new(ctx: egui::Context) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        let (open_id, quit_id) = {
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            std::thread::Builder::new()
                .name("tray-gtk".into())
                .spawn(move || {
                    if let Err(err) = gtk::init() {
                        let _ = ready_tx.send(Err(format!("cannot initialise GTK: {err}")));
                        return;
                    }
                    match build() {
                        Ok(built) => {
                            let _ = ready_tx.send(Ok((built.open, built.quit)));
                            gtk::main();
                            drop(built.icon);
                        }
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                        }
                    }
                })
                .map_err(|err| err.to_string())?;
            ready_rx
                .recv()
                .map_err(|_| "the tray thread exited before it was ready".to_string())??
        };
        #[cfg(not(target_os = "linux"))]
        let (icon, open_id, quit_id) = {
            let built = build()?;
            (built.icon, built.open, built.quit)
        };

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
            #[cfg(not(target_os = "linux"))]
            _icon: icon,
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
