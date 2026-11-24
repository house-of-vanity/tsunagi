//! Editor for the listener and backend portion of a shared VIP draft.
use tsunagi::vip::{Backend, Listener, Protocol, VipConfig};

/// Edit local draft fields. Callers own validation, signed revision and Save.
pub fn edit(ui: &mut egui::Ui, config: &mut VipConfig, members: &[(String, String)]) {
    let mut remove = None;
    for (index, listener) in config.listeners.iter_mut().enumerate() {
        ui.push_id(&listener.id, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    egui::ComboBox::from_id_salt("protocol")
                        .selected_text(listener.protocol.to_string())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut listener.protocol, Protocol::Tcp, "TCP");
                            ui.selectable_value(&mut listener.protocol, Protocol::Udp, "UDP");
                        });
                    port_field(ui, "Port", &mut listener.port);
                    if ui.button("Remove listener").clicked() {
                        remove = Some(index);
                    }
                });
                if listener.protocol == Protocol::Tcp {
                    ui.checkbox(&mut listener.port_check, "Active TCP port checks");
                } else {
                    ui.weak("UDP health uses path probes and explicit port errors.");
                }
                ui.collapsing("Checks and flow expiry", |ui| {
                    egui::Grid::new("settings").show(ui, |ui| {
                        macro_rules! setting {
                            ($label:literal, $value:ident, $range:expr) => {
                                ui.label($label);
                                ui.add(egui::DragValue::new(&mut listener.$value).range($range));
                                ui.end_row();
                            };
                        }
                        setting!("Check interval, ms", check_interval_ms, 250..=3_600_000);
                        setting!("Check timeout, ms", check_timeout_ms, 100..=60_000);
                        setting!("Failures before exclusion", failure_threshold, 1..=255);
                        setting!("Successes before recovery", recovery_threshold, 1..=255);
                        setting!("Flow idle timeout, seconds", idle_timeout_secs, 1..=604800);
                    });
                });
                let mut remove_backend = None;
                for (i, backend) in listener.backends.iter_mut().enumerate() {
                    ui.push_id(i, |ui| {
                        let width = ui.available_width().min(240.0);
                        ui.horizontal_wrapped(|ui| {
                            let selected = members
                                .iter()
                                .find(|(id, _)| id == &backend.peer)
                                .map(|(_, label)| label.to_owned())
                                .unwrap_or_else(|| crate::format::short(&backend.peer));
                            egui::ComboBox::from_id_salt("node")
                                .width(width)
                                .truncate()
                                .selected_text(selected)
                                .show_ui(ui, |ui| {
                                    for (id, label) in members {
                                        ui.selectable_value(&mut backend.peer, id.clone(), label);
                                    }
                                });
                            port_field(ui, "Target port", &mut backend.port);
                            if ui.button("Remove").clicked() {
                                remove_backend = Some(i);
                            }
                        });
                    });
                }
                if let Some(i) = remove_backend {
                    listener.backends.remove(i);
                }
                if ui.button("+ Backend").clicked() {
                    listener.backends.push(Backend {
                        peer: members
                            .first()
                            .map(|(id, _)| id.clone())
                            .unwrap_or_default(),
                        port: listener.port,
                    });
                }
            })
        });
    }
    if let Some(i) = remove {
        config.listeners.remove(i);
    }
    if ui.button("+ Listener").clicked() {
        config.listeners.push(Listener::new(Protocol::Tcp, 443));
    }
}
fn port_field(ui: &mut egui::Ui, label: &str, value: &mut u16) {
    ui.label(label);
    ui.add(egui::DragValue::new(value).range(1..=65535));
}
