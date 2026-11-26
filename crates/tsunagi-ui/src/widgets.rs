//! Icons with the same meaning and input behavior across both clients.
use egui::{Response, Sense, Ui, WidgetInfo, WidgetType};
use egui_phosphor::regular as icon;

/// Supplied by Android so the soft keyboard never looks like an orientation change.
pub fn set_landscape(ctx: &egui::Context, landscape: bool) {
    ctx.data_mut(|d| d.insert_temp(egui::Id::new("window landscape"), landscape));
}

/// Whether this viewport has a landscape layout.
pub fn landscape(ctx: &egui::Context) -> bool {
    ctx.data(|d| d.get_temp(egui::Id::new("window landscape")))
        .unwrap_or_else(|| ctx.screen_rect().width() > ctx.screen_rect().height())
}

/// A tooltip for mouse hover, keyboard focus or a deliberate long press.
pub fn hint(response: Response, description: &str) -> Response {
    let ctx = &response.ctx;
    let touch = ctx.os() == egui::os::OperatingSystem::Android;
    let now = ctx.input(|i| i.time);
    let key = egui::Id::new(("touch explanation", ctx.viewport_id()));
    if response.long_touched() {
        ctx.data_mut(|d| d.insert_temp(key, (response.id, now + 2.5)));
        ctx.request_repaint();
    }
    let held = ctx
        .data(|d| d.get_temp::<(egui::Id, f64)>(key))
        .filter(|(id, until)| touch && *id == response.id && now < *until);
    let contents = |ui: &mut Ui| {
        let padding = egui::Frame::popup(ui.style()).total_margin().sum().x;
        let available = (ui.ctx().screen_rect().width() - padding).max(1.);
        ui.set_max_width(ui.spacing().tooltip_width.min(available));
        ui.add(egui::Label::new(description).wrap());
    };
    if held.is_some() || (!touch && response.has_focus()) {
        egui::show_tooltip_for(
            ctx,
            response.layer_id,
            response.id,
            &response.rect,
            contents,
        );
        if let Some((_, until)) = held {
            ctx.request_repaint_after_secs((until - now) as f32);
        }
        response
    } else {
        response
            .on_hover_ui(contents)
            .on_disabled_hover_ui(contents)
    }
}

/// A compact help button. Tapping reveals the same detail as desktop hover.
pub(crate) fn info(ui: &mut Ui, description: &str) {
    let r = ui.add(egui::Button::new(egui::RichText::new(icon::INFO).weak()).frame(false));
    r.widget_info(|| WidgetInfo::labeled(WidgetType::Button, true, description));
    if r.clicked() && ui.ctx().os() == egui::os::OperatingSystem::Android {
        let until = ui.input(|i| i.time) + 2.5;
        let key = egui::Id::new(("touch explanation", ui.ctx().viewport_id()));
        ui.ctx().data_mut(|d| d.insert_temp(key, (r.id, until)));
    }
    hint(r, description);
}

/// A glyph-only button with its action exposed to assistive technology.
pub fn icon_button(ui: &mut Ui, glyph: &str, description: &str) -> Response {
    let r = ui.button(glyph);
    r.widget_info(|| WidgetInfo::labeled(WidgetType::Button, r.enabled(), description));
    hint(r, description)
}

/// A field caption, or just its icon when the adjacent value is self-explanatory.
pub(crate) fn field(ui: &mut Ui, glyph: &str, caption: &str, description: &str) {
    let label = if caption.is_empty() {
        glyph.to_string()
    } else {
        format!("{glyph}  {caption}")
    };
    let r = ui.add(egui::Label::new(egui::RichText::new(label).weak()).sense(Sense::click()));
    r.widget_info(|| WidgetInfo::labeled(WidgetType::Label, r.enabled(), description));
    hint(r, description);
}

pub(crate) fn network_id(ui: &mut Ui) {
    field(ui, icon::HASH, "", "Network ID");
}
pub(crate) fn range(ui: &mut Ui) {
    field(ui, icon::TREE_STRUCTURE, "", "Network range (CIDR)");
}
pub(crate) fn device_address(ui: &mut Ui) {
    let glyph = if ui.ctx().os() == egui::os::OperatingSystem::Android {
        icon::DEVICE_MOBILE
    } else {
        icon::LAPTOP
    };
    field(ui, glyph, "", "This device’s IPv4 address");
}

/// Paint a bounded line in a fixed cell, with an ellipsis for long hostnames.
pub(crate) fn single_line(
    painter: &egui::Painter,
    cell: egui::Rect,
    align: egui::Align,
    value: &str,
    font: egui::FontId,
    ink: egui::Color32,
) {
    if !cell.is_positive() {
        return;
    }
    let mut job = egui::text::LayoutJob::simple_singleline(value.into(), font, ink);
    job.wrap.max_width = cell.width();
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    let text = painter.layout_job(job);
    let bounds =
        egui::Align2([align, egui::Align::Center]).align_size_within_rect(text.size(), cell);
    painter.galley(bounds.min, text, ink);
}
