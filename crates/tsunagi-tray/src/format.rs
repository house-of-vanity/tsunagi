//! Formatting and small shared widgets: humanized ages, byte sizes and rates,
//! a fixed-size sparkline, and click-to-copy labels.

use eframe::egui;

use crate::stats::{Series, Unit};

/// Sparkline accent.
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x2f, 0x80, 0xd8);

/// A short, readable prefix of a long identifier (char-safe, no panic).
pub(crate) fn short(id: &str) -> String {
    const KEEP: usize = 12;
    if id.chars().count() <= KEEP {
        id.to_string()
    } else {
        format!("{}…", id.chars().take(KEEP).collect::<String>())
    }
}

/// A duration in seconds as a compact age (`5s`, `12m`, `3h 20m`, `2d 4h`).
pub(crate) fn age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h {}m", secs / 3_600, (secs % 3_600) / 60)
    } else {
        format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3_600)
    }
}

/// A byte count in binary units.
pub(crate) fn bytes(n: f64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = n.max(0.0);
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} B", value as u64)
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A rate in the chosen unit, per second.
pub(crate) fn rate(value: f32, unit: Unit) -> String {
    match unit {
        Unit::Packets => {
            if value >= 1000.0 {
                format!("{:.1}k pkt/s", value / 1000.0)
            } else {
                format!("{value:.0} pkt/s")
            }
        }
        Unit::Bytes => format!("{}/s", bytes(f64::from(value))),
    }
}

/// A fixed-height sparkline of a series' recent rate, with the peak (top-left)
/// and current value (bottom-right) overlaid. The space is always reserved —
/// even with no data — so the layout never jumps when data arrives.
pub(crate) fn sparkline(ui: &mut egui::Ui, series: Option<&Series>, unit: Unit, height: f32) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let visuals = ui.visuals();
    painter.rect_filled(rect, 2.0, visuals.extreme_bg_color);

    let Some(series) = series else {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "no data yet",
            egui::FontId::proportional(10.0),
            visuals.weak_text_color(),
        );
        return;
    };

    let history = series.history(unit);
    let peak = history.iter().copied().fold(1.0_f32, f32::max);
    if history.len() >= 2 {
        let count = history.len();
        let points: Vec<egui::Pos2> = history
            .iter()
            .enumerate()
            .map(|(i, value)| {
                let x = rect.left() + rect.width() * (i as f32 / (count - 1) as f32);
                let y = rect.bottom() - 2.0 - (rect.height() - 12.0) * (value / peak);
                egui::pos2(x, y)
            })
            .collect();
        painter.add(egui::Shape::line(
            points,
            egui::Stroke::new(1.5_f32, ACCENT),
        ));
    }

    painter.text(
        rect.left_top() + egui::vec2(4.0, 2.0),
        egui::Align2::LEFT_TOP,
        format!("peak {}", rate(peak, unit)),
        egui::FontId::proportional(9.0),
        visuals.weak_text_color(),
    );
    painter.text(
        rect.right_bottom() + egui::vec2(-4.0, -2.0),
        egui::Align2::RIGHT_BOTTOM,
        rate(series.rate(unit), unit),
        egui::FontId::proportional(10.0),
        visuals.strong_text_color(),
    );
}

/// A label that copies `value` to the clipboard when clicked.
pub(crate) fn copy_label(ui: &mut egui::Ui, display: &str, value: &str) {
    let response = ui
        .add(egui::Label::new(display).sense(egui::Sense::click()))
        .on_hover_text("click to copy");
    if response.clicked() {
        ui.ctx().copy_text(value.to_owned());
    }
}

/// A tiny clipboard button that copies `value`.
pub(crate) fn copy_button(ui: &mut egui::Ui, value: &str) {
    if ui
        .small_button("copy")
        .on_hover_text("copy to clipboard")
        .clicked()
    {
        ui.ctx().copy_text(value.to_owned());
    }
}

/// The current rate of a series as a string, or a dash when unsampled.
pub(crate) fn series_rate(series: Option<&Series>, unit: Unit) -> String {
    series.map_or_else(|| "—".to_string(), |s| rate(s.rate(unit), unit))
}
