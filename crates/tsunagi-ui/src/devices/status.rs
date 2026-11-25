use super::{DataPathReport, Device, icon};
use tsunagi::agent::{DATA_CONNECTING, DATA_DISABLED};

#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) enum Channel {
    Ready,
    Waiting,
    Error,
    Offline,
    Disabled,
}

impl Device<'_> {
    pub(super) fn channel(&self) -> Channel {
        if !self.online {
            return Channel::Offline;
        }
        match self.data_error {
            Some(DATA_DISABLED) => Channel::Disabled,
            Some(DATA_CONNECTING) => Channel::Waiting,
            Some(_) => Channel::Error,
            None if self.overlay.is_some_and(|p| p.is_up())
                && !matches!(self.path, None | Some(DataPathReport::None)) =>
            {
                Channel::Ready
            }
            None => Channel::Waiting,
        }
    }
    pub(super) fn channel_hint(&self) -> &str {
        match self.channel() {
            Channel::Offline => "Offline · peer unreachable",
            Channel::Ready => "Ready · encrypted data channel available",
            Channel::Waiting => "Waiting for the encrypted data channel",
            Channel::Disabled => "Control only · data transports disabled locally",
            Channel::Error => self.data_error.unwrap_or("Data channel error"),
        }
    }
}
impl Channel {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::Waiting => "Waiting",
            Self::Error => "Error",
            Self::Offline => "Offline",
            Self::Disabled => "Control only",
        }
    }
    pub(super) fn color(self, ui: &egui::Ui) -> egui::Color32 {
        use egui::Color32;
        match (self, ui.visuals().dark_mode) {
            (Self::Ready, true) => Color32::from_rgb(100, 210, 136),
            (Self::Ready, false) => Color32::from_rgb(25, 120, 61),
            (Self::Waiting, true) => Color32::from_rgb(244, 190, 85),
            (Self::Waiting, false) => Color32::from_rgb(150, 94, 8),
            (Self::Error, true) => Color32::from_rgb(255, 129, 116),
            (Self::Error, false) => Color32::from_rgb(179, 52, 44),
            (Self::Offline | Self::Disabled, true) => Color32::from_rgb(136, 139, 145),
            (Self::Offline | Self::Disabled, false) => Color32::from_rgb(98, 102, 108),
        }
    }
    pub(super) fn paint(self, ui: &egui::Ui, rect: egui::Rect) {
        if !ui.is_rect_visible(rect) {
            return;
        }
        let color = self.color(ui);
        let glyph = match self {
            Self::Ready => icon::CHECK_CIRCLE,
            Self::Error => icon::WARNING,
            Self::Offline => icon::MINUS_CIRCLE,
            Self::Disabled => icon::PAUSE_CIRCLE,
            Self::Waiting => {
                let start = ui.input(|i| (i.time % 1.2) as f32) * std::f32::consts::TAU / 1.2;
                let radius = rect.height() * 0.34;
                let points = (0..=12)
                    .map(|i| {
                        rect.center()
                            + egui::Vec2::angled(start + std::f32::consts::PI * i as f32 / 12.)
                                * radius
                    })
                    .collect();
                ui.painter()
                    .add(egui::Shape::line(points, egui::Stroke::new(1.8_f32, color)));
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(65));
                return;
            }
        };
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            glyph,
            egui::FontId::proportional(rect.height()),
            color,
        );
    }
}
