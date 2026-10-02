//! The tray: the icon, its menu, and starting the window.
//!
//! This is the process that stays. It holds no window and no GUI toolkit of
//! its own; choosing Open starts this same binary again as the window, which
//! is a perfectly ordinary program that ends when it is closed.

use std::process::{Child, Command};
use std::sync::{Arc, Mutex};

use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

/// The window process, when there is one.
struct Window {
    child: Mutex<Option<Child>>,
}

impl Window {
    /// Starts the window unless one is already open.
    ///
    /// Raising an existing one is not something a process can ask for on
    /// every platform, so choosing Open while it is open does nothing.
    fn open(&self) {
        let mut slot = self.child.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(child) = slot.as_mut() {
            match child.try_wait() {
                Ok(None) => return,
                _ => *slot = None,
            }
        }
        let started = std::env::current_exe()
            .map_err(|err| err.to_string())
            .and_then(|exe| {
                Command::new(exe)
                    .arg(crate::WINDOW_ARG)
                    .spawn()
                    .map_err(|err| err.to_string())
            });
        match started {
            Ok(child) => *slot = Some(child),
            Err(err) => eprintln!("cannot open the window: {err}"),
        }
    }

    /// Closes the window if it is open.
    fn close(&self) {
        let mut slot = self.child.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut child) = slot.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
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

/// Acts on menu choices as the platform's loop delivers them.
fn handle_menu(built: &Built, window: Arc<Window>) {
    let (open, quit) = (built.open.clone(), built.quit.clone());
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if event.id == open {
            window.open();
        } else if event.id == quit {
            window.close();
            std::process::exit(0);
        }
    }));
}

/// Shows the icon and runs until Quit.
///
/// Linux: the tray needs GTK, which nothing else here initialises, so this
/// thread does and runs its main loop.
#[cfg(target_os = "linux")]
pub(crate) fn run() -> Result<(), Box<dyn std::error::Error>> {
    gtk::init().map_err(|err| format!("cannot initialise GTK: {err}"))?;
    let built = build()?;
    handle_menu(
        &built,
        Arc::new(Window {
            child: Mutex::new(None),
        }),
    );
    gtk::main();
    drop(built.icon);
    Ok(())
}

/// Shows the icon and runs until Quit.
///
/// Windows and macOS: the icon needs an event loop on the main thread to be
/// served, and macOS wants it created once that loop is running. There are no
/// windows in it; it exists to be pumped.
#[cfg(not(target_os = "linux"))]
pub(crate) fn run() -> Result<(), Box<dyn std::error::Error>> {
    use winit::application::ApplicationHandler;
    use winit::event::WindowEvent;
    use winit::event_loop::{ActiveEventLoop, EventLoop};
    use winit::window::WindowId;

    struct Pump {
        window: Arc<Window>,
        icon: Option<TrayIcon>,
    }

    impl ApplicationHandler for Pump {
        fn resumed(&mut self, _event_loop: &ActiveEventLoop) {
            if self.icon.is_some() {
                return;
            }
            match build() {
                Ok(built) => {
                    handle_menu(&built, Arc::clone(&self.window));
                    self.icon = Some(built.icon);
                }
                Err(err) => {
                    eprintln!("cannot create the tray icon: {err}");
                    std::process::exit(1);
                }
            }
        }

        fn window_event(&mut self, _: &ActiveEventLoop, _: WindowId, _: WindowEvent) {}
    }

    let mut builder = EventLoop::builder();
    // macOS: live in the menu bar with no Dock icon.
    #[cfg(target_os = "macos")]
    {
        use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
        builder.with_activation_policy(ActivationPolicy::Accessory);
    }
    let event_loop = builder.build()?;
    let mut pump = Pump {
        window: Arc::new(Window {
            child: Mutex::new(None),
        }),
        icon: None,
    };
    event_loop.run_app(&mut pump)?;
    Ok(())
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
