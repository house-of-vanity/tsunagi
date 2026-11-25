//! The one-line network summary and the exit clients alongside its metadata.
use super::{draw_metadata, exit, format, widgets};
use crate::stats::{Series, Unit};
use egui::{
    Align, Align2, Color32, FontId, Layout, Rect, Sense, TextStyle, Ui, UiBuilder, pos2, vec2,
};
use egui_phosphor::regular as icon;
use tsunagi::ipc::{NetworkReport, StatusReport};

fn health<'a>(
    network: &'a NetworkReport,
    report: &'a StatusReport,
    warning: Option<&'a str>,
) -> (Color32, &'a str) {
    let amber = Color32::from_rgb(225, 164, 54);
    if network.range_conflict.is_some() || !network.range_conflicts.is_empty() {
        return (amber, "Overlapping network ranges");
    }
    if !network.active {
        return (Color32::GRAY, "Stopped");
    }
    if let Some(error) = report.overlay_config_error.as_deref() {
        return (exit::LOUD, error);
    }
    if let Some(message) = warning {
        return (
            if network.exit.via.is_some() && !network.exit.via_online {
                exit::LOUD
            } else {
                amber
            },
            message,
        );
    }
    if network.hostname_conflict.is_some() {
        return (amber, "Device hostname is already in use");
    }
    if network.handshake_failures > 0 && network.peers.is_empty() {
        return (amber, "Handshakes failed and no peers are connected");
    }
    (exit::GOOD, "Active")
}

pub(super) fn header(
    ui: &mut Ui,
    net: &NetworkReport,
    report: &StatusReport,
    open: bool,
    series: Option<&Series>,
    unit: Unit,
    warning: Option<&str>,
) -> egui::Response {
    let font = TextStyle::Body.resolve(ui.style());
    let ink = ui.visuals().text_color();
    let online = crate::devices::online_count(net, &report.endpoint_id);
    let known = crate::devices::known_count(net, &report.endpoint_id);
    let users = net.peers.iter().filter(|p| p.uses_our_exit).count();
    let (color, status) = health(net, report, warning);
    let height = ui.text_style_height(&TextStyle::Heading).max(30.);
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::labeled(
            egui::WidgetType::CollapsingHeader,
            ui.is_enabled(),
            format!("{} · {status}", net.name),
        )
    });
    if response.hovered() || response.has_focus() {
        ui.painter()
            .rect_filled(rect, 3., ui.style().interact(&response).weak_bg_fill);
    }
    let painter = ui.painter_at(rect);
    let center = rect.center().y;
    let caret = painter.text(
        rect.left_center(),
        Align2::LEFT_CENTER,
        if open {
            icon::CARET_DOWN
        } else {
            icon::CARET_RIGHT
        },
        font.clone(),
        ink,
    );
    let dot = pos2(caret.right() + 7., center);
    painter.circle_filled(dot, 4., color);
    let left = dot.x + 9.;
    let mut right = rect.right() - 2.;
    let quiet = ui.visuals().weak_text_color();
    // Preserve a useful piece of the name even on the narrow landscape selector.
    if right - left > 98. {
        let width = (rect.width() * 0.15).clamp(26., 64.);
        let plot = Rect::from_center_size(pos2(right - width / 2., center), vec2(width, 14.));
        format::mini_traffic(&painter, plot, series, unit, quiet, net.active);
        right = plot.left() - 7.;
    }
    let mut field = |text: String, reserved: f32| {
        let galley = painter.layout_no_wrap(text, font.clone(), ink);
        if right - left - galley.size().x >= reserved {
            right -= galley.size().x;
            painter.galley(pos2(right, center - galley.size().y / 2.), galley, ink);
            right -= 8.;
        }
    };
    field(format!("{} {online}/{known}", icon::DEVICES), 45.);
    if users > 0 {
        field(format!("{} {users}", icon::SIGN_IN), 60.);
    }
    if let Some(addr) = net.overlay.as_ref().and_then(|o| o.address.as_deref()) {
        field(addr.to_owned(), 110.);
    }
    let mut job = egui::text::LayoutJob::simple_singleline(
        net.name.clone(),
        FontId::new(font.size + 4., egui::FontFamily::Name("Bold".into())),
        ui.visuals().strong_text_color(),
    );
    job.wrap.max_width = (right - left).max(1.);
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    let name = painter.layout_job(job);
    painter.galley(pos2(left, center - name.size().y / 2.), name, ink);
    let mut hint = format!("{} · {status}\n{online} online · {known} known", net.name);
    if users > 0 {
        hint.push_str(&format!("\n{}", user_count(users)));
    }
    if let Some(series) = series {
        hint.push_str(&format!(
            "\nNetwork traffic  {}",
            format::rate(series.rate(unit), unit)
        ));
    }
    widgets::hint(
        response.on_hover_cursor(egui::CursorIcon::PointingHand),
        &hint,
    )
}

fn user_count(count: usize) -> String {
    format!("{count} exit user{}", if count == 1 { "" } else { "s" })
}

pub(super) fn metadata(ui: &mut Ui, net: &NetworkReport, own_id: &str) {
    let right = ui.max_rect().right();
    let top = ui.next_widget_position();
    let width = ui.available_width();
    let metadata_width = if ui.ctx().os() == egui::os::OperatingSystem::Android {
        (width * 0.43).min(140.)
    } else {
        (width * 0.46).min(158.)
    };
    // Keep identical geometry with zero, one or many exit users. The scroll pane
    // is bounded by the metadata the card already drew.
    let left = ui
        .scope_builder(
            UiBuilder::new()
                .max_rect(Rect::from_min_size(
                    top,
                    vec2(metadata_width, ui.available_height()),
                ))
                .layout(Layout::top_down(Align::Min)),
            |ui| {
                ui.set_max_width(metadata_width);
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                draw_metadata(ui, net, own_id);
            },
        )
        .response
        .rect;
    if !net.exit.offering {
        return;
    }
    let mut users: Vec<_> = net
        .peers
        .iter()
        .filter(|p| p.uses_our_exit)
        .map(|p| {
            let name = p
                .hostname
                .as_ref()
                .cloned()
                .unwrap_or_else(|| exit::name_of(net, &p.endpoint_id));
            (name, p.endpoint_id.as_str())
        })
        .collect();
    if users.is_empty() {
        return;
    }
    users.sort_unstable();
    // The roster is a small block attached to the metadata, even on a wide window.
    let x = top.x + metadata_width + 6.;
    let rect = Rect::from_min_max(
        pos2(x, left.top()),
        pos2(right.min(x + 142.), left.bottom()),
    );
    if rect.width() < 34. {
        return;
    }
    let mut pane = ui.new_child(
        UiBuilder::new()
            .id_salt("exit users")
            .max_rect(rect)
            .layout(Layout::top_down(Align::Min)),
    );
    pane.set_clip_rect(ui.clip_rect().intersect(rect));
    pane.spacing_mut().item_spacing.y = 0.;
    pane.painter()
        .rect_filled(rect, 5., pane.visuals().faint_bg_color);
    user_list(&mut pane, rect.shrink2(vec2(5., 1.)), &users);
}

fn user_list(ui: &mut Ui, rect: Rect, peers: &[(String, &str)]) {
    use egui::scroll_area::{ScrollBarVisibility, State};
    let font = TextStyle::Body.resolve(ui.style());
    let title_font = FontId::new(font.size + 1., egui::FontFamily::Name("Bold".into()));
    let heading = Rect::from_min_size(rect.min, vec2(rect.width(), (font.size + 6.).ceil()));
    let row = ui.text_style_height(&TextStyle::Body).ceil() + 1.;
    let available = (rect.bottom() - heading.bottom() - 1.).max(0.);
    let height = ((available / row).floor().max(1.) * row).min(available);
    let overflow = peers.len() as f32 * row > height + 0.1;
    let step_width = 20.;
    let text_right = heading.right() - if overflow { 2. * step_width } else { 0. };
    let title = Rect::from_min_max(heading.min, pos2(text_right, heading.bottom()));
    widgets::single_line(
        ui.painter(),
        title,
        Align::Min,
        &user_count(peers.len()),
        title_font,
        ui.visuals().strong_text_color(),
    );
    let hint = ui.interact(title, ui.id().with("exit user count"), Sense::hover());
    widgets::hint(
        hint,
        "Peers using this device for internet access. Older peers appear for one minute after forwarding traffic.",
    );
    if height <= 0. {
        return;
    }
    let bounds = Rect::from_min_size(
        pos2(rect.left(), heading.bottom() + 1.),
        vec2(rect.width(), height),
    );
    let mut list = ui.new_child(
        UiBuilder::new()
            .id_salt("peer names")
            .max_rect(bounds)
            .layout(Layout::top_down(Align::Min)),
    );
    let salt = egui::Id::new("scroll");
    let id = list.make_persistent_id(salt);
    let mut scroll = egui::ScrollArea::vertical()
        .id_salt(salt)
        .max_height(height)
        .auto_shrink([false, false])
        .scroll_bar_visibility(ScrollBarVisibility::AlwaysHidden);
    if overflow {
        let offset = State::load(ui.ctx(), id).unwrap_or_default().offset.y;
        let last = (peers.len() as f32 * row - height).max(0.);
        for (x, glyph, hint, delta) in [
            (text_right, icon::CARET_UP, "Scroll up one peer", -row),
            (
                text_right + step_width,
                icon::CARET_DOWN,
                "Scroll down one peer",
                row,
            ),
        ] {
            let arrow =
                Rect::from_min_size(pos2(x, heading.top()), vec2(step_width, heading.height()));
            let next = (offset + delta).clamp(0., last);
            let enabled = (next - offset).abs() > 0.5;
            let r = ui.interact(
                arrow,
                id.with(glyph),
                if enabled {
                    Sense::click()
                } else {
                    Sense::hover()
                },
            );
            let ink = if enabled {
                ui.visuals().text_color()
            } else {
                ui.visuals().weak_text_color()
            };
            if enabled && (r.hovered() || r.has_focus()) {
                ui.painter()
                    .rect_filled(arrow, 3., ui.style().interact(&r).weak_bg_fill);
            }
            ui.painter().text(
                arrow.center(),
                Align2::CENTER_CENTER,
                glyph,
                font.clone(),
                ink,
            );
            r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, hint));
            if enabled
                && widgets::hint(r.on_hover_cursor(egui::CursorIcon::PointingHand), hint).clicked()
            {
                scroll = scroll.vertical_scroll_offset(next);
            }
        }
    }
    scroll.show_rows(&mut list, row, peers.len(), |ui, range| {
        for (name, id) in &peers[range] {
            let (cell, response) =
                ui.allocate_exact_size(vec2(ui.available_width(), row), Sense::hover());
            widgets::single_line(
                ui.painter(),
                cell,
                Align::Min,
                name,
                font.clone(),
                ui.visuals().text_color(),
            );
            response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, name));
            widgets::hint(response, &format!("{name}\n{id}"));
        }
    });
}
