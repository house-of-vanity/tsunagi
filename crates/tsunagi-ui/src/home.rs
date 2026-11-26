//! Shared compact network tiles, device header and join form.
mod card;
use crate::{
    client::{Client, Command},
    devices, exit, format,
    stats::{Traffic, Unit},
    widgets,
};
use egui_phosphor::regular as icon;
use std::collections::BTreeSet;
use tsunagi::ipc::{NetworkReport, StatusReport};
use zeroize::{Zeroize, Zeroizing};

const BAD: egui::Color32 = egui::Color32::from_rgb(0xd0, 0x4a, 0x3c);
/// A neutral, not-garish red for the Leave button.
const LEAVE_RED: egui::Color32 = egui::Color32::from_rgb(0xa8, 0x3a, 0x3a);

/// Join form fields.
#[derive(Default)]
pub struct JoinForm {
    /// Visible network name.
    pub name: String,
    /// User-entered network secret.
    pub secret: Zeroizing<String>,
    revealed: bool,
}

/// Local UI state kept across frames.
pub struct UiState {
    /// Join form draft.
    pub join: JoinForm,
    /// Whether rates and sparklines are shown in packets or bytes.
    pub unit: Unit,
    /// Network details opened during this run, keyed by identity even for namesakes.
    expanded_networks: BTreeSet<String>,
    /// The network whose settings occupy the detail pane on a landscape phone.
    pub selected_network: Option<String>,
    /// An in-progress hostname edit (`None` when not editing).
    pub host_edit: Option<String>,
    /// Network ids whose devices window is open.
    pub open_devices: BTreeSet<String>,
    /// Per-network VIP drafts.
    pub vip_windows: std::collections::BTreeMap<String, crate::vip::Window>,
    /// Whether the About window is open.
    pub about_open: bool,
    /// Whether the global traffic monitor viewport is open.
    pub monitor_open: bool,
    /// An exit-node choice waiting for the user to confirm it.
    pub exit_confirm: Option<devices::ExitConfirm>,
    /// A selected offline claim waiting for cleanup confirmation.
    pub forget_confirm: Option<devices::ForgetConfirm>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            join: JoinForm::default(),
            unit: Unit::Bytes,
            expanded_networks: BTreeSet::new(),
            selected_network: None,
            host_edit: None,
            open_devices: BTreeSet::new(),
            vip_windows: Default::default(),
            about_open: false,
            monitor_open: false,
            exit_confirm: None,
            forget_confirm: None,
        }
    }
}

/// The device header: id (with a copy button) and an editable hostname.
pub fn draw_header(
    ui: &mut egui::Ui,
    agent: &dyn Client,
    state: &mut UiState,
    report: &StatusReport,
) {
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        widgets::field(ui, icon::FINGERPRINT, "", "Device endpoint ID");
        // Clicking the shortened id copies the full one.
        format::copy_field(ui, &format::short(&report.endpoint_id), &report.endpoint_id);
    });

    ui.horizontal(|ui| {
        widgets::field(ui, icon::DESKTOP_TOWER, "", "Device hostname");
        match &mut state.host_edit {
            None => {
                ui.label(&report.hostname);
                if widgets::icon_button(ui, icon::PENCIL_SIMPLE, "Rename this device").clicked() {
                    state.host_edit = Some(report.hostname.clone());
                }
            }
            Some(buffer) => {
                let response = ui.add(egui::TextEdit::singleline(buffer).desired_width(150.0));
                let submit = (response.lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    || widgets::icon_button(ui, icon::CHECK, "Save hostname").clicked();
                if submit {
                    agent.send(Command::SetHostname(buffer.trim().to_string()));
                    state.host_edit = None;
                } else if widgets::icon_button(ui, icon::X, "Cancel hostname edit").clicked() {
                    state.host_edit = None;
                }
            }
        }
    });

    if !report.cache_healthy {
        ui.colored_label(
            egui::Color32::from_rgb(0xd9, 0x9a, 0x00),
            "cache unavailable",
        );
    }
    if let Some(error) = &report.overlay_config_error {
        ui.colored_label(BAD, format!("Shared overlay interface {error}"));
    }
}

/// One compact network tile.
pub fn draw_network(
    ui: &mut egui::Ui,
    agent: &dyn Client,
    state: &mut UiState,
    traffic: &Traffic,
    network: &NetworkReport,
    report: &StatusReport,
    offer_exit: bool,
) {
    ui.add_space(5.0);
    ui.push_id(&network.network_id, |ui| {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            let open = state.expanded_networks.contains(&network.network_id);
            if overview(ui, network, report, state, open, traffic) {
                state.toggle_network(&network.network_id, !open);
            }
            if state.expanded_networks.contains(&network.network_id) {
                ui.separator();
                draw_network_details(ui, agent, state, traffic, network, report, offer_exit);
            }
        });
    });
}

impl UiState {
    fn toggle_network(&mut self, id: &str, open: bool) {
        if open {
            self.expanded_networks.insert(id.to_owned());
            self.selected_network = Some(id.to_owned());
        } else {
            self.expanded_networks.remove(id);
            if self.selected_network.as_deref() == Some(id) {
                self.selected_network = None;
            }
        }
    }

    /// Close the landscape detail pane and fold that card when rotated back.
    pub fn close_selection(&mut self) -> bool {
        if let Some(id) = self.selected_network.take() {
            self.expanded_networks.remove(&id);
            return true;
        }
        false
    }
}

fn overview(
    ui: &mut egui::Ui,
    network: &NetworkReport,
    report: &StatusReport,
    state: &mut UiState,
    open: bool,
    traffic: &Traffic,
) -> bool {
    let warnings = exit::warnings(network);
    let clicked = card::header(
        ui,
        network,
        report,
        open,
        traffic.network(&network.network_id),
        state.unit,
        warnings.first().map(|w| w.text.as_str()),
    )
    .clicked();
    if let Some(via) = &network.exit.via {
        draw_selected_exit(ui, network, via, state);
    }
    for warning in warnings {
        draw_exit_warning(ui, &warning);
    }
    if !network.range_conflicts.is_empty() {
        ui.colored_label(BAD, "Stopped: overlapping network ranges");
    }
    clicked
}

/// One network in the landscape selector. Exit status stays visible beside its network.
pub fn draw_network_selector(
    ui: &mut egui::Ui,
    network: &NetworkReport,
    report: &StatusReport,
    state: &mut UiState,
    traffic: &Traffic,
) {
    let open = state.selected_network.as_deref() == Some(&network.network_id);
    ui.push_id(&network.network_id, |ui| {
        let mut frame = egui::Frame::group(ui.style());
        if open {
            frame = frame.stroke(ui.visuals().selection.stroke);
        }
        frame.show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            if overview(ui, network, report, state, open, traffic) {
                state.toggle_network(&network.network_id, !open);
            }
        });
    });
}

/// Actions and settings shared by a folded card and the landscape detail pane.
pub fn draw_network_details(
    ui: &mut egui::Ui,
    agent: &dyn Client,
    state: &mut UiState,
    traffic: &Traffic,
    network: &NetworkReport,
    report: &StatusReport,
    offer_exit: bool,
) {
    ui.horizontal_wrapped(|ui| {
        if ui
            .button(format!("{} Copy secret", icon::COPY))
            .on_hover_text("Copy this network's secret to the clipboard")
            .clicked()
        {
            agent.send(Command::CopySecret {
                network_id: network.network_id.clone(),
            });
        }
        if ui.button("Show devices").clicked() {
            state.open_devices.insert(network.network_id.clone());
        }
        if widgets::hint(
            ui.button(format!("{} VIP", icon::NETWORK)),
            "Manage virtual IP services",
        )
        .clicked()
        {
            state
                .vip_windows
                .entry(network.network_id.clone())
                .or_default();
        }
    });
    ui.separator();
    card::metadata(ui, network, &report.endpoint_id);
    draw_protocols(ui, agent, network, &report.available_protocols);
    format::sparkline(ui, traffic.network(&network.network_id), state.unit, 34.0);
    network_settings(ui, agent, network, offer_exit)
}

fn draw_metadata(ui: &mut egui::Ui, network: &NetworkReport, own_id: &str) {
    egui::Grid::new(ui.id().with("metadata"))
        .num_columns(2)
        .min_col_width(0.)
        .max_col_width(ui.available_width())
        .spacing([3.0, 3.0])
        .show(ui, |ui| {
            widgets::field(ui, icon::TAG, "", "Network name");
            format::copy_field(ui, &network.name, &network.name);
            ui.end_row();
            widgets::network_id(ui);
            format::copy_field(ui, &format::short(&network.network_id), &network.network_id);
            ui.end_row();
            if let Some(range) = &network.range {
                widgets::range(ui);
                format::copy_field(ui, range, range);
                ui.end_row();
            }
            if let Some(address) = network.overlay.as_ref().and_then(|o| o.address.as_ref()) {
                widgets::device_address(ui);
                format::copy_field(ui, address, address);
                ui.end_row();
            }
            widgets::field(ui, icon::DEVICES, "", "Online and known peers");
            ui.label(format!(
                "{} online · {} known",
                devices::online_count(network, own_id),
                devices::known_count(network, own_id)
            ));
            ui.end_row();
        });
}

fn network_settings(
    ui: &mut egui::Ui,
    agent: &dyn Client,
    network: &NetworkReport,
    offer_exit: bool,
) {
    if !network.range_conflicts.is_empty() {
        for conflict in &network.range_conflicts {
            ui.label(format!(
                "{} ({}) uses {}",
                conflict.name, conflict.network_id, conflict.range
            ));
        }
        ui.label("Switching suspends these networks until this network stops, then resumes them automatically.");
        if network.auto_start {
            ui.weak("This network will resume automatically when its range is free.");
        }
    }
    ui.horizontal_wrapped(|ui| {
        if !network.active && !network.range_conflicts.is_empty() {
            if ui.button("Switch to this network").clicked() {
                agent.send(Command::SetActive {
                    network_id: network.network_id.clone(),
                    active: true,
                });
            }
            if network.auto_start && ui.button("Keep stopped").clicked() {
                agent.send(Command::SetActive {
                    network_id: network.network_id.clone(),
                    active: false,
                });
            }
        } else {
            let mut active = network.active;
            if ui.checkbox(&mut active, "active").changed() {
                agent.send(Command::SetActive {
                    network_id: network.network_id.clone(),
                    active,
                });
            }
        }
        let mut broadcast = network.broadcast;
        if ui.checkbox(&mut broadcast, "broadcast").changed() {
            agent.send(Command::SetBroadcast {
                network_id: network.network_id.clone(),
                enabled: broadcast,
            });
        }
        if offer_exit {
            let mut offering = network.exit.offering;
            if ui
                .checkbox(&mut offering, "exit node")
                .on_hover_text("Let members send all their internet traffic through this device, which can see it.")
                .changed()
            {
                agent.send(Command::SetExitOffer {
                    network_id: network.network_id.clone(),
                    enabled: offering,
                });
            }
            #[cfg(target_os = "macos")]
            if offering
                && network.exit.offer_rules.as_ref().is_some_and(|rules| {
                    !rules.ok && tsunagi::overlay::hostrules::macos_exit_needs_authorization(&rules.detail)
                })
                && ui.add_enabled(!agent.busy(), egui::Button::new("Authorize…"))
                    .on_hover_text("Allow this network to share the Mac’s internet connection")
                    .clicked()
            {
                agent.send(Command::SetExitOffer {
                    network_id: network.network_id.clone(),
                    enabled: true,
                });
            }
        }
        let leave = egui::Button::new(egui::RichText::new("Leave").color(egui::Color32::WHITE))
            .fill(LEAVE_RED);
        if ui.add(leave).clicked() {
            agent.send(Command::Leave {
                network_id: network.network_id.clone(),
            });
        }
    });
}

fn draw_selected_exit(ui: &mut egui::Ui, network: &NetworkReport, via: &str, state: &mut UiState) {
    ui.horizontal_wrapped(|ui| {
        let color = if network.exit.via_online {
            exit::GOOD
        } else {
            exit::LOUD
        };
        let name = exit::name_of(network, via);
        if ui.ctx().os() == egui::os::OperatingSystem::Android {
            ui.label(egui::RichText::new(icon::SIGN_OUT).color(color));
            ui.label(format!("Exit via {name}"));
        } else {
            let button = ui.add(
                egui::Button::new(egui::RichText::new(icon::SIGN_OUT).color(color)).frame(false),
            );
            let clicked = widgets::hint(button, "Stop using this exit node").clicked();
            if widgets::hint(
                ui.link(format!("Exit via {name}")),
                "Stop using this exit node",
            )
            .clicked()
                || clicked
            {
                state.exit_confirm = Some(devices::ExitConfirm::stop_from_tile(network, via));
            }
        }
        if let Some(t) = network.exit.traffic {
            for (glyph, bytes, hint) in [
                (icon::ARROW_UP, t.tx_bytes, "Sent through this exit"),
                (icon::ARROW_DOWN, t.rx_bytes, "Received through this exit"),
            ] {
                let text = format!("{glyph} {}", format::bytes(bytes as f64));
                widgets::hint(
                    ui.add(egui::Label::new(text).sense(egui::Sense::click())),
                    hint,
                );
            }
        }
    });
}

fn draw_protocols(
    ui: &mut egui::Ui,
    agent: &dyn Client,
    network: &NetworkReport,
    available: &[tsunagi::ipc::ProtocolReport],
) {
    let summary = if network.protocols.is_empty() {
        "none".into()
    } else {
        network.protocols.join(", ")
    };
    egui::CollapsingHeader::new(format!("data transports  {summary}"))
        .id_salt(("protocols", &network.network_id))
        .show(ui, |ui| {
            ui.weak("Order sets the first choice. Peers that support link comparison can switch to a faster enabled transport.");
            let mut selected = network.protocols.clone();
            let mut changed = false;
            ui.add_enabled_ui(!agent.busy(), |ui| {
                // Enabled items follow the user's preference; unchecked items
                // follow the agent's catalog. The worker refreshes after edits.
                let ordered: Vec<_> = network
                    .protocols
                    .iter()
                    .filter_map(|name| available.iter().find(|p| &p.name == name))
                    .chain(
                        available
                            .iter()
                            .filter(|p| !network.protocols.contains(&p.name)),
                    )
                    .collect();
                for protocol in ordered {
                    ui.horizontal(|ui| {
                        let mut on = selected.contains(&protocol.name);
                        if ui.checkbox(&mut on, &protocol.name).changed() {
                            if on {
                                selected.push(protocol.name.clone());
                            } else {
                                selected.retain(|p| p != &protocol.name);
                            }
                            changed = true;
                        }
                        if let Some(index) = selected.iter().position(|p| p == &protocol.name) {
                            if widgets::hint(ui.add_enabled(index > 0, egui::Button::new(icon::ARROW_UP)),
                                "Move transport up in preference order").clicked()
                            {
                                selected.swap(index, index - 1);
                                changed = true;
                            }
                            if widgets::hint(ui.add_enabled(
                                    index + 1 < selected.len(),
                                    egui::Button::new(icon::ARROW_DOWN),
                                ), "Move transport down in preference order").clicked()
                            {
                                selected.swap(index, index + 1);
                                changed = true;
                            }
                        }
                    });
                    ui.indent(("description", &network.network_id, &protocol.name), |ui| {
                        ui.weak(&protocol.summary);
                    });
                }
            });
            if selected.is_empty() {
                ui.weak("Control only; no IP traffic in this network.");
            }
            if changed {
                agent.send(Command::SetProtocols {
                    network_id: network.network_id.clone(),
                    protocols: selected,
                });
            }
        });
}

/// A prominent line about an exit node. One that carries a command copies it
/// when clicked.
fn draw_exit_warning(ui: &mut egui::Ui, warning: &exit::Warning) {
    let text = egui::RichText::new(format!("{} {}", icon::WARNING, warning.text))
        .color(exit::LOUD)
        .strong();
    let label = egui::Label::new(text).wrap();
    match warning.copy {
        Some(command) => {
            let response = ui
                .add(label.sense(egui::Sense::click()))
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text("click to copy the command");
            if response.clicked() {
                ui.ctx().copy_text(command.to_owned());
            }
        }
        None => {
            ui.add(label);
        }
    }
}

/// The join form: aligned name and secret, a generate button, and Join.
pub fn draw_join(ui: &mut egui::Ui, agent: &dyn Client, join: &mut JoinForm) {
    const INPUT_WIDTH: f32 = 208.0;
    ui.label("Join or create a network");
    egui::Grid::new("join")
        .num_columns(2)
        .spacing([8.0, 6.0])
        .show(ui, |ui| {
            ui.label("name");
            ui.add(egui::TextEdit::singleline(&mut join.name).desired_width(INPUT_WIDTH));
            ui.end_row();

            ui.label("secret");
            ui.horizontal(|ui| {
                let visuals = ui.visuals().widgets.inactive;
                egui::Frame::new()
                    .fill(ui.visuals().extreme_bg_color)
                    .stroke(visuals.bg_stroke)
                    .corner_radius(visuals.corner_radius)
                    .inner_margin(egui::Margin::symmetric(3, 1))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 2.0;
                            let input = ui.add(
                                egui::TextEdit::singleline(&mut *join.secret)
                                    .id("join-secret".into())
                                    .frame(false)
                                    .desired_width(INPUT_WIDTH - 65.0)
                                    .password(!join.revealed),
                            );
                            let (glyph, label) = if join.revealed {
                                (icon::EYE_SLASH, "Hide secret")
                            } else {
                                (icon::EYE, "Show secret")
                            };
                            let eye = ui.add(egui::Button::new(glyph).frame(false));
                            eye.widget_info(|| {
                                egui::WidgetInfo::labeled(
                                    egui::WidgetType::Button,
                                    eye.enabled(),
                                    label,
                                )
                            });
                            if widgets::hint(eye, label).clicked() {
                                join.revealed = !join.revealed;
                                if input.lost_focus() {
                                    input.request_focus();
                                }
                            }
                        });
                    });
                if widgets::icon_button(ui, icon::SHUFFLE, "Generate a new random secret").clicked()
                {
                    join.secret = tsunagi::identity::NetworkSecret::generate().encode();
                    join.revealed = false;
                }
            });
            ui.end_row();
        });

    let ready = !join.name.trim().is_empty() && !join.secret.trim().is_empty();
    if ui
        .add_enabled(ready, egui::Button::new("Join / create"))
        .clicked()
    {
        agent.send(Command::Join {
            name: join.name.trim().to_string(),
            secret: Zeroizing::new(join.secret.trim().to_owned()),
        });
        join.secret.zeroize();
        join.revealed = false;
    }
}
