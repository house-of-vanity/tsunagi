//! One shared column layout for the pinned header and the virtualized rows.
use super::{
    Column, Names, Sort, ago, endpoints,
    history::{RATE_LIFETIME_MS, Row},
    public_id, role_name,
};
use crate::{
    format::{bytes, short},
    widgets,
};
use egui::{
    Align, Align2, Color32, FontFamily, FontId, Layout, Rect, RichText, Sense, Ui, UiBuilder, pos2,
    vec2,
};
use egui_phosphor::regular as icon;

const PAD: f32 = 8.;
const GAP: f32 = 12.;

struct Colors {
    text: Color32,
    secondary: Color32,
    sent: Color32,
    received: Color32,
    header: Color32,
    stripe: Color32,
}
impl Colors {
    fn new(dark: bool) -> Self {
        let tone = |dark_rgb: [u8; 3], light_rgb: [u8; 3]| {
            let [r, g, b] = if dark { dark_rgb } else { light_rgb };
            Color32::from_rgb(r, g, b)
        };
        Self {
            text: tone([239, 244, 249], [27, 40, 53]),
            secondary: tone([195, 207, 219], [62, 79, 96]),
            sent: tone([140, 211, 255], [16, 89, 145]),
            received: tone([145, 226, 185], [16, 102, 72]),
            header: tone([42, 55, 68], [224, 234, 243]),
            stripe: tone([35, 42, 49], [240, 245, 249]),
        }
    }
}
pub(super) fn style(ui: &mut Ui) {
    let colors = Colors::new(ui.visuals().dark_mode);
    let style = ui.style_mut();
    for id in [egui::TextStyle::Body, egui::TextStyle::Button] {
        if let Some(font) = style.text_styles.get_mut(&id) {
            font.size = font.size.max(15.);
        }
    }
    style.visuals.widgets.noninteractive.fg_stroke.color = colors.text;
    style.visuals.widgets.inactive.fg_stroke.color = colors.text;
}
#[derive(Clone, Copy)]
pub(super) struct Slot {
    column: Column,
    left: f32,
    width: f32,
}
pub(super) struct Grid {
    pub pages: Vec<Vec<Slot>>,
    pub row_height: f32,
    width: f32,
    body: FontId,
    bold: FontId,
    mono: FontId,
    colors: Colors,
}

impl Grid {
    pub fn new(ui: &Ui) -> Self {
        use Column::*;
        // Leave the same scroll gutter above and below, even while the bar animates.
        let width = (ui.available_width() - ui.spacing().scroll.allocated_width()).max(1.);
        let body = egui::FontSelection::Default.resolve(ui.style());
        let bold = FontId::new(body.size, FontFamily::Name("Bold".into()));
        let mono = FontId::monospace(body.size);
        let measure = |s: &str, f: &FontId| {
            ui.painter()
                .layout_no_wrap(s.into(), f.clone(), Color32::WHITE)
                .size()
                .x
        };
        let height = ui.fonts(|f| {
            f.row_height(&body)
                .max(f.row_height(&bold))
                .max(f.row_height(&mono))
        });
        let minimum = |col: Column| {
            let sample = match col {
                Near | Far => "255.255.255.255:65535",
                Network => "network",
                Protocol => "ICMP echo",
                Role => "Serving exit",
                Sent | Received => "1024.0 MB",
                SendRate | ReceiveRate => "1024.0 MB/s",
                SentPackets | ReceivedPackets => "99999999",
                Seen => "Last seen",
                PeerId => "0123456789ab…",
                Peer => "device-name",
            };
            let font = if matches!(col, Near | Far | PeerId) {
                &mono
            } else {
                &body
            };
            measure(sample, font)
                .max(measure(col.title(), &bold) + 15.)
                .ceil()
                + 2.
        };
        // Keep the peer visible on each column page. Put the most useful live
        // numbers on the first page, then arrange each page in reading order.
        let mut remaining = vec![
            Sent,
            Received,
            Seen,
            Far,
            Near,
            Protocol,
            Role,
            Network,
            SendRate,
            ReceiveRate,
            SentPackets,
            ReceivedPackets,
            PeerId,
        ];
        let inner = (width - 2. * PAD).max(1.);
        let pinned = minimum(Peer).min(inner * 0.32);
        let room = (inner - pinned - GAP).max(0.);
        let mut pages = Vec::new();
        while !remaining.is_empty() {
            let mut fields = vec![(Peer, pinned)];
            let mut free = room;
            remaining.retain(|c| {
                let w = minimum(*c).min(room);
                if fields.len() == 1 || w <= free {
                    fields.push((*c, w));
                    free -= w + GAP;
                    false
                } else {
                    true
                }
            });
            fields.sort_by_key(|(c, _)| *c);
            let weight = |c: Column| {
                if matches!(c, Peer | Near | Far | Network | Role) {
                    2.
                } else {
                    1.
                }
            };
            let parts: f32 = fields.iter().map(|(c, _)| weight(*c)).sum();
            let extra = (free + GAP).max(0.) / parts;
            let mut x = PAD;
            pages.push(
                fields
                    .into_iter()
                    .map(|(column, w)| {
                        let slot = Slot {
                            column,
                            left: x,
                            width: w + extra * weight(column),
                        };
                        x += slot.width + GAP;
                        slot
                    })
                    .collect(),
            );
        }
        Self {
            pages,
            row_height: height.ceil() + 8.,
            width,
            body,
            bold,
            mono,
            colors: Colors::new(ui.visuals().dark_mode),
        }
    }
    pub fn chooser(&self, ui: &mut Ui, page: &mut usize) {
        if self.pages.len() == 1 {
            return;
        }
        let response = egui::ComboBox::from_id_salt("traffic-columns")
            .selected_text(format!(
                "{}  Columns {}/{}",
                icon::COLUMNS,
                *page + 1,
                self.pages.len()
            ))
            .show_ui(ui, |ui| {
                ui.set_max_width((ui.ctx().screen_rect().width() - 45.).clamp(100., 400.));
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                for (i, slots) in self.pages.iter().enumerate() {
                    let fields = slots
                        .iter()
                        .skip(1)
                        .map(|s| s.column.title())
                        .collect::<Vec<_>>()
                        .join(" · ");
                    ui.selectable_value(page, i, fields);
                }
            })
            .response;
        widgets::hint(
            response,
            "Choose which columns to show. The peer stays visible.",
        );
    }
    fn ink(&self, column: Column) -> Color32 {
        match column {
            Column::Sent | Column::SentPackets | Column::SendRate => self.colors.sent,
            Column::Received | Column::ReceivedPackets | Column::ReceiveRate => {
                self.colors.received
            }
            Column::Network | Column::Seen => self.colors.secondary,
            _ => self.colors.text,
        }
    }
    pub fn header(&self, ui: &mut Ui, slots: &[Slot], sort: Sort) -> Option<Column> {
        let (row, _) =
            ui.allocate_exact_size(vec2(self.width, self.row_height + 3.), Sense::hover());
        ui.painter().rect_filled(row, 3., self.colors.header);
        let mut clicked = None;
        for slot in slots {
            let col = slot.column;
            let bounds = slot.rect(row);
            let active = sort.column == col;
            let mut text = bounds;
            if active {
                let right = numeric(col);
                let x = if right {
                    text.min.x += 14.;
                    bounds.left()
                } else {
                    text.max.x -= 14.;
                    bounds.right()
                };
                ui.painter().text(
                    pos2(x, row.center().y),
                    if right {
                        Align2::LEFT_CENTER
                    } else {
                        Align2::RIGHT_CENTER
                    },
                    if sort.descending {
                        icon::CARET_DOWN
                    } else {
                        icon::CARET_UP
                    },
                    self.body.clone(),
                    self.colors.text,
                );
            }
            cell(
                ui,
                text,
                col.title(),
                &self.bold,
                self.ink(col),
                numeric(col),
            );
            let r = ui
                .interact(
                    bounds,
                    ui.id().with(("sort traffic", col.title())),
                    Sense::click(),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand);
            let direction = if active && sort.descending {
                "descending"
            } else {
                "ascending"
            };
            let hint = if active {
                format!("{} · Sorted {direction}. Select to reverse.", col.hint())
            } else {
                format!("{} · Select to sort.", col.hint())
            };
            r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, &hint));
            if widgets::hint(r, &hint).clicked() {
                clicked = Some(col);
            }
        }
        clicked
    }
    pub fn row(&self, ui: &mut Ui, slots: &[Slot], r: &Row, names: &Names, now: u64, index: usize) {
        let (row, _) = ui.allocate_exact_size(vec2(self.width, self.row_height), Sense::hover());
        if index % 2 == 1 {
            ui.painter().rect_filled(row, 0., self.colors.stripe);
        }
        let key = &r.data.key;
        let (near, far, protocol) = endpoints(key, names);
        let live = now.saturating_sub(r.sampled) < RATE_LIFETIME_MS;
        for slot in slots {
            use Column::*;
            let col = slot.column;
            let label = match col {
                Peer => names.peer(&key.network, &key.peer),
                Network => names.network(&key.network),
                Near => near.clone(),
                Far => far.clone(),
                Protocol => protocol.clone(),
                Role => role_name(key.role).into(),
                Sent => bytes(r.data.tx_bytes as f64),
                Received => bytes(r.data.rx_bytes as f64),
                SendRate | ReceiveRate => {
                    let rate = if !live {
                        0.
                    } else if col == SendRate {
                        r.tx_rate
                    } else {
                        r.rx_rate
                    };
                    format!("{}/s", bytes(f64::from(rate)))
                }
                SentPackets => r.data.tx_packets.to_string(),
                ReceivedPackets => r.data.rx_packets.to_string(),
                Seen => ago(now.saturating_sub(r.last)),
                PeerId => short(&public_id(&key.peer)),
            };
            let font = match col {
                Peer => &self.bold,
                Near | Far | PeerId => &self.mono,
                _ => &self.body,
            };
            let bounds = slot.rect(row);
            let resolved = if names.resolve_addresses {
                names.resolved_endpoint(key, col)
            } else {
                None
            };
            let response = cell(
                ui,
                bounds,
                resolved.as_deref().unwrap_or(&label),
                font,
                self.ink(col),
                numeric(col),
            );
            if col == PeerId {
                let full = public_id(&key.peer);
                let button = ui
                    .interact(
                        bounds,
                        ui.id().with(("copy flow peer", r.id)),
                        Sense::click(),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                button.widget_info(|| {
                    egui::WidgetInfo::labeled(egui::WidgetType::Button, true, "Copy peer ID")
                });
                if widgets::hint(button, &format!("Copy peer ID\n{full}")).clicked() {
                    ui.ctx().copy_text(full);
                }
            } else if resolved.is_some() {
                // A click sense also gives Android long presses a target.
                widgets::hint(response.interact(Sense::click()), &label);
            } else {
                widgets::hint(response, &label);
            }
        }
    }
}
impl Slot {
    fn rect(&self, row: Rect) -> Rect {
        Rect::from_min_size(
            pos2(row.left() + self.left, row.top()),
            vec2(self.width, row.height()),
        )
    }
}
fn numeric(c: Column) -> bool {
    c.descending_first()
}
fn cell(
    ui: &mut Ui,
    bounds: Rect,
    text: &str,
    font: &FontId,
    color: Color32,
    right: bool,
) -> egui::Response {
    let layout = if right {
        Layout::right_to_left(Align::Center)
    } else {
        Layout::left_to_right(Align::Center)
    };
    // Glyph origins are snapped to physical pixels. Leave a point inside each
    // edge so the overhang of a right-aligned digit or bold header stays visible.
    let content = bounds.shrink2(vec2(1., 0.));
    let mut child = ui.new_child(UiBuilder::new().max_rect(content).layout(layout));
    child.set_clip_rect(ui.clip_rect().intersect(bounds));
    child.add(
        egui::Label::new(RichText::new(text).font(font.clone()).color(color))
            .selectable(false)
            .truncate(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn all_columns_are_reachable_without_horizontal_scrolling() {
        use Column::*;
        let expected = BTreeSet::from([
            Network,
            Near,
            Far,
            Protocol,
            Role,
            Sent,
            Received,
            SendRate,
            ReceiveRate,
            SentPackets,
            ReceivedPackets,
            Seen,
            PeerId,
        ]);
        for size in [15., 20.] {
            let ctx = egui::Context::default();
            ctx.set_fonts(crate::app_fonts());
            ctx.style_mut(|s| {
                s.text_styles
                    .insert(egui::TextStyle::Body, FontId::proportional(size));
            });
            for width in [320., 480., 760., 920., 1600.] {
                let input = egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(width, 400.))),
                    ..Default::default()
                };
                let _ = ctx.run(input, |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        style(ui);
                        let grid = Grid::new(ui);
                        let mut seen = BTreeSet::new();
                        for page in &grid.pages {
                            assert_eq!(page[0].column, Peer);
                            for slot in &page[1..] {
                                assert!(seen.insert(slot.column));
                                assert!(
                                    slot.width > 0. && slot.left + slot.width <= grid.width + 0.1
                                );
                            }
                        }
                        assert_eq!(seen, expected);
                    });
                });
            }
        }
    }
}
