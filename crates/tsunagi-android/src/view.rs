//! Android supplies navigation and the VPN lifecycle to the shared egui forms.
use crate::service::{Outcome, Response, State};
use egui::{Color32, Context};
use egui_phosphor::regular as icon;
use std::cell::RefCell;
use tsunagi_ui::{
    about,
    client::{Client, Command, Snapshot, VipSaveResult},
    devices,
    home::{self, UiState},
    stats::{Traffic, Unit},
    vip,
};
use zeroize::{Zeroize, Zeroizing};

const BAD: Color32 = Color32::from_rgb(0xd0, 0x4a, 0x3c);

#[derive(Default, PartialEq, Eq)]
enum Page {
    #[default]
    Home,
    About,
    Monitor,
    Join,
    Devices(String),
    Vips(String),
    Exits,
    Leave(String),
}
impl Page {
    fn network(&self) -> Option<&str> {
        match self {
            Self::Devices(id) | Self::Vips(id) | Self::Leave(id) => Some(id),
            _ => None,
        }
    }
    fn title(&self) -> &'static str {
        match self {
            Self::Home => "tsunagi",
            Self::About => "About",
            Self::Monitor => "Traffic monitor",
            Self::Join => "Join a network",
            Self::Devices(_) => "Devices",
            Self::Vips(_) => "VIP",
            Self::Exits => "Exit nodes",
            Self::Leave(_) => "Leave network",
        }
    }
}

/// Operations that require the Android activity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SystemAction {
    /// Request VPN consent and start the foreground service.
    Start,
    /// Stop the service while preserving this identity and its networks.
    Stop,
    /// Read the clipboard after a user gesture.
    PasteSecret,
    /// Return to the previous Android activity.
    Finish,
}

struct Actions {
    command: RefCell<Option<Command>>,
    busy: bool,
}
impl Client for Actions {
    fn send(&self, cmd: Command) {
        if !self.busy() {
            self.command.replace(Some(cmd));
        }
    }
    fn busy(&self) -> bool {
        self.busy || self.command.borrow().is_some()
    }
}

struct Pending {
    result: Response,
    vip: Option<String>,
    go_home: bool,
}

/// Presentation state of the single Android viewport.
#[derive(Default)]
pub struct Phone {
    page: Page,
    monitor: Option<crate::monitor::Monitor>,
    cache_dir: Option<std::path::PathBuf>,
    forms: UiState,
    traffic: Traffic,
    snapshot: Snapshot,
    pending: Option<Pending>,
    error: Option<String>,
    clipboard: Option<Zeroizing<String>>,
    landscape: bool,
    pick_exit: bool,
    before_picker: Option<Page>,
}

/// Keep reads at tray density. Extra hit area is reserved for the navigation bar.
pub fn configure(ctx: &Context) {
    ctx.set_os(egui::os::OperatingSystem::Android);
    ctx.set_fonts(tsunagi_ui::app_fonts());
    ctx.style_mut(|style| {
        style.spacing.interact_size.y = 19.0;
        style.spacing.button_padding = egui::vec2(6.0, 3.0);
        style.spacing.item_spacing = egui::vec2(6.0, 3.0);
    });
}

impl Phone {
    /// Private directory available to a window's temporary SQLite database.
    pub fn set_cache_dir(&mut self, path: std::path::PathBuf) {
        self.cache_dir = Some(path);
    }
    /// Release the agent subscription immediately when the activity goes into the background.
    pub fn pause_monitor(&mut self) {
        if let Some(m) = &mut self.monitor {
            m.pause();
        }
    }
    /// Poll the service only while a traffic screen is visible.
    pub fn poll_monitor(&mut self, open: impl FnOnce() -> Result<Response, String>) {
        if let Some(m) = &mut self.monitor {
            m.poll(open);
        }
    }
    fn home(&mut self) {
        self.monitor = None;
        if let Some(previous) = self.before_picker.take() {
            self.forms.exit_confirm = None;
            self.page = previous;
            return;
        }
        if let Page::Vips(id) = &self.page {
            self.forms.vip_windows.remove(id);
        }
        self.forms.join = Default::default();
        self.forms.exit_confirm = None;
        self.forms.forget_confirm = None;
        self.page = Page::Home;
    }

    /// System Back and toolbar Back use the same draft and confirmation state.
    pub fn back(&mut self) -> Option<SystemAction> {
        if self.pending.is_some() {
            return None;
        }
        if self.forms.exit_confirm.take().is_some() || self.forms.forget_confirm.take().is_some() {
            return None;
        }
        if let Page::Vips(id) = &self.page
            && let Some(editor) = self.forms.vip_windows.get_mut(id)
            && editor.dirty()
        {
            editor.request_close();
        } else if self.page == Page::Home && self.landscape && self.forms.close_selection() {
            return None;
        } else if self.page == Page::Home {
            return Some(SystemAction::Finish);
        } else {
            self.home();
        }
        None
    }
    /// Accept a user-initiated paste into the join form.
    pub fn paste_secret(&mut self, value: String) {
        if self.page == Page::Join {
            self.forms.join.secret.zeroize();
            self.forms.join.secret = Zeroizing::new(value);
        }
    }
    /// Request password input with IME suggestions disabled.
    pub fn secret_focused(&self, ctx: &Context) -> bool {
        ctx.memory(|m| m.has_focus("join-secret".into()))
    }
    /// Present an error from an Android operation.
    pub fn error(&mut self, message: String) {
        self.error = Some(message);
    }

    /// The first tile tap opens the chooser once the agent is ready.
    pub fn request_exit_picker(&mut self) {
        self.pick_exit = true;
    }

    fn open_exit_picker(&mut self) {
        if self.page != Page::Exits {
            self.before_picker = Some(std::mem::replace(&mut self.page, Page::Exits));
            self.forms.exit_confirm = None;
        }
    }

    /// This control lives outside both portrait and landscape scroll areas.
    fn exit_button(&mut self, ctx: &Context, ready: bool) {
        let clicked = egui::Area::new("home exit button".into())
            .anchor(egui::Align2::RIGHT_BOTTOM, [-16., -16.])
            .order(egui::Order::Middle)
            .movable(false)
            .show(ctx, |ui| {
                let (rect, response) = ui.allocate_exact_size(
                    egui::vec2(60., 60.),
                    if ready {
                        egui::Sense::click()
                    } else {
                        egui::Sense::hover()
                    },
                );
                let (mut fill, mut ink) = devices::exit_action_colors(ui.visuals().dark_mode);
                if !ready {
                    fill = ui.visuals().widgets.inactive.bg_fill;
                    ink = ui.visuals().weak_text_color();
                }
                ui.painter().circle_filled(rect.center(), 30., fill);
                if ready && (response.hovered() || response.has_focus()) {
                    ui.painter().circle_stroke(rect.center(), 27., (1_f32, ink));
                }
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    icon::SIGN_OUT,
                    egui::FontId::proportional(29.),
                    ink,
                );
                response.widget_info(|| {
                    egui::WidgetInfo::labeled(
                        egui::WidgetType::Button,
                        ready,
                        "Choose an exit node",
                    )
                });
                tsunagi_ui::widgets::hint(response, "Choose an exit node").clicked()
            })
            .inner;
        if ready && clicked {
            self.open_exit_picker();
        }
    }

    fn landscape_home(
        &mut self,
        ui: &mut egui::Ui,
        actions: &Actions,
        report: &tsunagi::ipc::StatusReport,
    ) {
        let width = (ui.available_width() / 3.)
            .clamp(146., 300.)
            .min(ui.available_width() * 0.45);
        egui::SidePanel::left("network selector")
            .resizable(false)
            .exact_width(width)
            .show_inside(ui, |ui| {
                if ui.button("Join or create a network").clicked() {
                    self.page = Page::Join;
                }
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("network list")
                    .show(ui, |ui| {
                        for network in &report.networks {
                            home::draw_network_selector(
                                ui,
                                network,
                                report,
                                &mut self.forms,
                                &self.traffic,
                            );
                        }
                    });
            });
        egui::CentralPanel::default().show_inside(ui, |ui| {
            let selected = report
                .networks
                .iter()
                .find(|n| self.forms.selected_network.as_deref() == Some(&n.network_id));
            egui::ScrollArea::vertical()
                .id_salt(("network settings", selected.map(|n| &n.network_id)))
                .show(ui, |ui| {
                    if let Some(n) = selected {
                        ui.heading(&n.name);
                        ui.push_id(&n.network_id, |ui| {
                            home::draw_network_details(
                                ui,
                                actions,
                                &mut self.forms,
                                &self.traffic,
                                n,
                                report,
                                false,
                            );
                        });
                    } else {
                        ui.heading("This device");
                        ui.label("Tsunagi Agent is running");
                        home::draw_header(ui, actions, &mut self.forms, report);
                    }
                    ui.add_space(80.);
                });
        });
    }

    /// Take a secret once for the platform’s sensitive clipboard.
    pub fn take_copied_secret(&mut self) -> Option<Zeroizing<String>> {
        self.clipboard.take()
    }

    fn acknowledge(&mut self) {
        let Some(pending) = &mut self.pending else {
            return;
        };
        let outcome = match pending.result.try_recv() {
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => return,
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                Err("Tsunagi Agent stopped".to_owned())
            }
            Ok(v) => v,
        };
        if let Some(token) = pending.vip.take() {
            let result = outcome.and_then(|r| match r {
                Outcome::Saved(vips) => Ok(vips),
                _ => Err("Missing VIP save acknowledgement".into()),
            });
            self.snapshot.vip_result = Some(VipSaveResult { token, result });
        } else {
            match outcome {
                Ok(Outcome::Clipboard(text)) => self.clipboard = Some(text),
                Ok(_) if pending.go_home => self.home(),
                Ok(_) => {}
                Err(e) => self.error = Some(e),
            }
        }
        self.pending = None;
    }

    /// Render a tray view in this viewport and send gestures to the service.
    pub fn draw(
        &mut self,
        ctx: &Context,
        state: &State,
        mut submit: impl FnMut(Command) -> Result<Response, String>,
    ) -> Option<SystemAction> {
        self.acknowledge();
        self.landscape = tsunagi_ui::widgets::landscape(ctx);
        let report = if let State::Ready(report, at) = state {
            if self.snapshot.at != Some(*at) {
                self.snapshot.generation = self.snapshot.generation.wrapping_add(1);
                self.snapshot.at = Some(*at);
                self.snapshot.status = Some(Ok(report.clone()));
                self.traffic.observe(report, *at);
            }
            if self
                .page
                .network()
                .is_some_and(|id| !report.networks.iter().any(|n| n.network_id == id))
            {
                self.home();
            }
            if self
                .forms
                .selected_network
                .as_ref()
                .is_some_and(|id| !report.networks.iter().any(|n| &n.network_id == id))
            {
                self.forms.close_selection();
            }
            if self.pick_exit && self.pending.is_none() {
                self.pick_exit = false;
                self.open_exit_picker();
            }
            Some(report)
        } else {
            if self.page.network().is_some()
                || matches!(self.page, Page::Join | Page::Monitor | Page::Exits)
            {
                self.home();
            }
            self.snapshot = Snapshot::default();
            self.traffic = Traffic::default();
            None
        };
        let actions = Actions {
            command: RefCell::default(),
            busy: self.pending.is_some(),
        };
        let mut system = None;
        egui::TopBottomPanel::top("navigation").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().interact_size.y = 32.0;
                if self.page != Page::Home
                    && tsunagi_ui::widgets::icon_button(ui, icon::ARROW_LEFT, "Back").clicked()
                {
                    system = self.back();
                }
                ui.heading(self.page.title());
                if self.page == Page::Home {
                    ui.weak(env!("CARGO_PKG_VERSION"));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if tsunagi_ui::widgets::icon_button(ui, icon::INFO, "About Tsunagi")
                            .clicked()
                        {
                            self.page = Page::About;
                        }
                        if report.is_some() {
                            if tsunagi_ui::widgets::icon_button(ui, icon::PULSE, "Traffic monitor")
                                .clicked()
                            {
                                self.page = Page::Monitor;
                            }
                            ui.selectable_value(&mut self.forms.unit, Unit::Bytes, "bytes");
                            ui.selectable_value(&mut self.forms.unit, Unit::Packets, "pkts");
                        }
                    });
                } else if self.page == Page::About
                    && !matches!(state, State::Off)
                    && ui.button("Stop Tsunagi Agent").clicked()
                {
                    self.home();
                    system = Some(SystemAction::Stop);
                }
            });
            if let Some(error) = &self.error {
                ui.colored_label(BAD, error);
            }
        });
        let selected = self
            .page
            .network()
            .and_then(|id| report?.networks.iter().find(|n| n.network_id == id));
        if self.page != Page::Monitor {
            self.monitor = None;
        }
        match (&self.page, selected) {
            (Page::Monitor, _) => {
                let m = self
                    .monitor
                    .get_or_insert_with(|| crate::monitor::Monitor::new(self.cache_dir.clone()));
                egui::CentralPanel::default().show(ctx, |ui| {
                    m.view
                        .show(ui, report.map(|r| r.as_ref()), self.snapshot.generation)
                });
            }
            (Page::About, _) => about::show(ctx, None, &self.snapshot),
            (Page::Vips(id), Some(network)) => {
                let editor = self.forms.vip_windows.entry(id.clone()).or_default();
                if vip::show(ctx, &actions, editor, network, &self.snapshot) {
                    self.home();
                }
            }
            (Page::Devices(_), Some(network)) => {
                if let Some(report) = report {
                    devices::show(
                        ctx,
                        &actions,
                        &mut self.forms.unit,
                        (&mut self.forms.exit_confirm, &mut self.forms.forget_confirm),
                        network,
                        &report.endpoint_id,
                        &self.traffic,
                    );
                }
            }
            _ => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    if let Some(report) = report && self.page == Page::Home && self.landscape {
                        self.landscape_home(ui, &actions, report);
                        return;
                    }
                    egui::ScrollArea::vertical().id_salt(self.page.title()).auto_shrink([false, false]).show(ui, |ui| {
                        let Some(report) = report else {
                            match state {
                                State::Starting => {ui.spinner(); ui.label("Starting Tsunagi Agent…");}
                                _ => {
                                    if let State::Error(e) = state {ui.colored_label(BAD, e);} else {ui.weak("Tsunagi Agent is stopped");}
                                    if ui.button("Start Tsunagi Agent").clicked() {self.error = None; system = Some(SystemAction::Start);}
                                }
                            }
                            return;
                        };
                        match &self.page {
                            Page::Home => {
                                home::draw_header(ui, &actions, &mut self.forms, report);
                                ui.separator();
                                if ui.button("Join or create a network").clicked() {self.page = Page::Join;}
                                for n in &report.networks {
                                    home::draw_network(ui, &actions, &mut self.forms, &self.traffic, n, report, false);
                                }
                                ui.add_space(80.);
                            }
                            Page::Join => {
                                home::draw_join(ui, &actions, &mut self.forms.join);
                                if ui.button(format!("{} Paste secret", icon::CLIPBOARD)).clicked() {system = Some(SystemAction::PasteSecret);}
                            }
                            Page::Exits => {
                                if let Some(choice) = devices::choose_exit_with_tests(ui, &report.networks, &report.endpoint_id, &actions) {
                                    self.forms.exit_confirm = Some(choice);
                                }
                                if report.networks.is_empty() && ui.button("Join or create a network").clicked() {
                                    self.before_picker = None;
                                    self.page = Page::Join;
                                }
                            }
                            Page::Leave(id) => {
                                if let Some(n) = selected {
                                    ui.label(format!("Leave {} on this phone? You will need its secret to join again.", n.name));
                                    if ui.button("Leave network").clicked() {actions.send(Command::Leave {network_id: id.clone()});}
                                    if ui.button("Cancel").clicked() {self.home();}
                                }
                            }
                            _ => {}
                        }
                    });
                });
                if let Some(report) = report
                    && self.page == Page::Home
                {
                    for n in &report.networks {
                        if self.forms.open_devices.remove(&n.network_id) {
                            self.page = Page::Devices(n.network_id.clone());
                            break;
                        }
                        if self.forms.vip_windows.contains_key(&n.network_id) {
                            self.page = Page::Vips(n.network_id.clone());
                            break;
                        }
                    }
                }
                if self.page == Page::Home && self.forms.exit_confirm.is_none() {
                    self.exit_button(ctx, report.is_some() && !actions.busy());
                }
                devices::confirm_exit(ctx, &actions, &mut self.forms.exit_confirm, None);
            }
        }
        if let Some(command) = actions.command.into_inner() {
            self.error = None;
            if let Command::Leave { network_id } = &command
                && !matches!(self.page, Page::Leave(_))
            {
                self.page = Page::Leave(network_id.clone());
            } else {
                let token = match &command {
                    Command::SaveVip { token, .. } => Some(token.clone()),
                    _ => None,
                };
                let go_home = matches!(
                    command,
                    Command::Join { .. } | Command::Leave { .. } | Command::SetExitNode { .. }
                );
                match submit(command) {
                    Ok(result) => {
                        self.pending = Some(Pending {
                            result,
                            vip: token,
                            go_home,
                        })
                    }
                    Err(error) => {
                        if let Some(token) = token {
                            self.snapshot.vip_result = Some(VipSaveResult {
                                token,
                                result: Err(error),
                            });
                        } else {
                            self.error = Some(error);
                        }
                    }
                }
            }
        }
        system
    }
}
