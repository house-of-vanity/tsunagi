//! Fixed row geometry for dense live tables. Children cannot resize a row or
//! paint into its neighbours; the enclosing scroll area owns overflow.

pub(crate) const GAP: f32 = 10.0;

pub(crate) fn row_height(ctx: &egui::Context, style: &egui::Style) -> f32 {
    let font = egui::FontSelection::Default.resolve(style);
    style
        .spacing
        .interact_size
        .y
        .max(ctx.fonts(|fonts| fonts.row_height(&font)))
        + 10.
}

pub(crate) fn row(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash,
    widths: &[f32],
    stripe: bool,
    mut cell: impl FnMut(usize, &mut egui::Ui),
) {
    let height = row_height(ui.ctx(), ui.style());
    let width = widths.iter().sum::<f32>() + GAP * widths.len().saturating_sub(1) as f32;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    if stripe {
        ui.painter()
            .rect_filled(rect, 2.0, ui.visuals().faint_bg_color);
    }
    let mut x = rect.left();
    for (column, width) in widths.iter().enumerate() {
        let bounds = egui::Rect::from_min_size(
            egui::pos2(x, rect.top() + 3.0),
            egui::vec2(*width, height - 6.0),
        );
        let mut child = ui.new_child(
            egui::UiBuilder::new()
                .id_salt((&id, column))
                .max_rect(bounds)
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        child.set_clip_rect(ui.clip_rect().intersect(bounds));
        child.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
        cell(column, &mut child);
        x += width + GAP;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn oversized_content_is_clipped_to_its_cell_at_every_scale() {
        for size in [13.0, 20.0, 28.0] {
            let ctx = egui::Context::default();
            ctx.style_mut(|style| {
                style.override_font_id = Some(egui::FontId::proportional(size));
            });
            let output = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    for index in 0..4 {
                        row(ui, index, &[90.0, 120.0], index % 2 == 0, |column, ui| {
                            if column == 0 {
                                ui.horizontal(|ui| {
                                    ui.label("very long device name that cannot fit");
                                    ui.button("Forget").on_hover_text("Forget");
                                });
                            } else {
                                ui.label(format!("row {index}"));
                            }
                        });
                    }
                });
            });
            let mut previous_bottom = 0.0;
            for index in 0..4 {
                let shape = output.shapes.iter().find(|shape| matches!(&shape.shape, egui::Shape::Text(t) if t.galley.text() == format!("row {index}"))).unwrap();
                let egui::Shape::Text(text) = &shape.shape else {
                    unreachable!()
                };
                assert!(text.visual_bounding_rect().top() >= previous_bottom);
                assert!(
                    shape.clip_rect.contains_rect(text.visual_bounding_rect()),
                    "font {size}: clip {:?}, text {:?}",
                    shape.clip_rect,
                    text.visual_bounding_rect()
                );
                assert!(shape.clip_rect.left() >= 108.0);
                previous_bottom = shape.clip_rect.bottom();
            }
        }
    }
}
