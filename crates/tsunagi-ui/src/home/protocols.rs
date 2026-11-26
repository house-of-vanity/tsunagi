use crate::{
    client::{Client, Command},
    widgets,
};
use egui_phosphor::regular as icon;
use tsunagi::ipc::{NetworkReport, ProtocolReport};

fn set_members(selected: &mut Vec<String>, members: &[&ProtocolReport], on: bool) {
    if on {
        for p in members {
            if !selected.contains(&p.name) {
                selected.push(p.name.clone());
            }
        }
    } else {
        selected.retain(|name| !members.iter().any(|p| p.name == *name));
    }
}

pub(super) fn draw_protocols(
    ui: &mut egui::Ui,
    agent: &dyn Client,
    network: &NetworkReport,
    available: &[ProtocolReport],
) {
    let mut selected = network.protocols.clone();
    let caption = if selected.is_empty() {
        "Data transports · control only".into()
    } else {
        format!("Data transports  {}/{}", selected.len(), available.len())
    };
    egui::CollapsingHeader::new(caption)
        .id_salt(("protocols", &network.network_id))
        .show(ui, |ui| {
            let mut groups = Vec::new();
            for p in available {
                if !groups.contains(&p.group.as_str()) {
                    groups.push(p.group.as_str());
                }
            }
            for group in groups {
                let members: Vec<_> = available.iter().filter(|p| p.group == group).collect();
                let enabled = members
                    .iter()
                    .filter(|p| selected.contains(&p.name))
                    .count();
                let all = enabled == members.len();
                let id = ui.make_persistent_id((&network.network_id, "transport group", group));
                egui::collapsing_header::CollapsingState::load_with_default_open(
                    ui.ctx(),
                    id,
                    false,
                )
                .show_header(ui, |ui| {
                    let mut checked = all;
                    let checkbox =
                        egui::Checkbox::new(&mut checked, egui::RichText::new(group).strong())
                            .indeterminate(enabled != 0 && !all);
                    if ui.add_enabled(!agent.busy(), checkbox).changed() {
                        set_members(&mut selected, &members, !all);
                    }
                    ui.weak(format!("{enabled}/{}", members.len()));
                })
                .body(|ui| {
                    for p in &members {
                        ui.push_id(&p.name, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 4.;
                                let position = selected.iter().position(|n| n == &p.name);
                                let mut enabled = position.is_some();
                                if ui
                                    .add_enabled(
                                        !agent.busy(),
                                        egui::Checkbox::new(&mut enabled, &p.label),
                                    )
                                    .changed()
                                {
                                    set_members(&mut selected, &[p], enabled);
                                }
                                widgets::info(ui, &p.summary);
                                if let Some(i) = position {
                                    widgets::hint(
                                        ui.weak(format!("#{}", i + 1)),
                                        "Priority across all enabled transports",
                                    );
                                    for (glyph, next, help) in [
                                        (
                                            icon::CARET_UP,
                                            i.checked_sub(1),
                                            "Increase priority across all groups",
                                        ),
                                        (
                                            icon::CARET_DOWN,
                                            (i + 1 < selected.len()).then_some(i + 1),
                                            "Decrease priority across all groups",
                                        ),
                                    ] {
                                        let r = ui.add_enabled(
                                            next.is_some() && !agent.busy(),
                                            egui::Button::new(glyph).small().frame(false),
                                        );
                                        if widgets::hint(r, help).clicked()
                                            && let Some(j) = next
                                        {
                                            selected.swap(i, j);
                                        }
                                    }
                                }
                            })
                        });
                    }
                });
            }
            if selected != network.protocols {
                agent.send(Command::SetProtocols {
                    network_id: network.network_id.clone(),
                    protocols: selected,
                });
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_and_unchecked_groups_enable_every_child_and_keep_global_order() {
        let wg = ProtocolReport {
            name: "wg".into(),
            ..Default::default()
        };
        let awg = ProtocolReport {
            name: "awg".into(),
            ..Default::default()
        };
        let members = [&wg, &awg];
        let mut selected = vec!["ss2022".into(), "awg".into(), "tcp-tls".into()];
        set_members(&mut selected, &members, true);
        assert_eq!(selected, ["ss2022", "awg", "tcp-tls", "wg"]);
        set_members(&mut selected, &members, false);
        assert_eq!(selected, ["ss2022", "tcp-tls"]);
        set_members(&mut selected, &members, true);
        assert_eq!(selected, ["ss2022", "tcp-tls", "wg", "awg"]);
        set_members(&mut selected, &[&wg], false);
        assert_eq!(selected, ["ss2022", "tcp-tls", "awg"]);
    }
}
