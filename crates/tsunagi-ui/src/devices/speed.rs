//! The same speed control occupies one fixed cell throughout a measurement.
use super::{Client, Command, Device, NetworkReport, format, icon, widgets};
use crate::client::speed_running;
use egui::{Align2, Color32, FontId, Rect, Sense, Ui, pos2, vec2};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tsunagi::ipc::{SpeedPeerReport, SpeedPhase, SpeedRate};

pub(super) const WIDTH: f32 = 108.;
pub(super) const PORTRAIT_WIDTH: f32 = 56.;
pub(super) const HEADER: &str = "Mbit/s";
pub(super) const HEADER_HINT: &str = "Peer speed test · download / upload in megabits per second";

pub(super) struct Controls<'a> {
    network: &'a NetworkReport,
    client: &'a dyn Client,
    running: bool,
}

impl<'a> Controls<'a> {
    pub(super) fn new(network: &'a NetworkReport, client: &'a dyn Client) -> Self {
        Self {
            network,
            client,
            running: speed_running(&network.speed),
        }
    }

    fn capable(&self, id: &str) -> bool {
        self.network.speed.capable.iter().any(|peer| peer == id)
    }

    pub(super) fn toolbar(&self, ui: &mut Ui) {
        let (label, help, available) = if self.running {
            ui.ctx().request_repaint_after(Duration::from_millis(250));
            let label = self.network.speed.batch.map_or_else(
                || format!("{}  Stop test", icon::STOP_CIRCLE),
                |batch| {
                    format!(
                        "{}  Stop  {}/{}",
                        icon::STOP_CIRCLE,
                        batch.done,
                        batch.total
                    )
                },
            );
            (
                label,
                "Stop this speed test and skip any queued exits.",
                true,
            )
        } else {
            let available = self.network.active
                && self
                    .network
                    .peers
                    .iter()
                    .any(|p| p.exit_node && self.capable(&p.endpoint_id));
            (
                format!("{}  Test exits", icon::GAUGE),
                if available {
                    "Test each compatible online exit node in this network, one at a time."
                } else {
                    "No online exit in this network supports peer speed tests."
                },
                available,
            )
        };
        // Leave room for the batch count before starting. A wrapping toolbar
        // must keep the same height when the button becomes Stop.
        let width = ui
            .painter()
            .layout_no_wrap(
                format!("{}  Stop  9999/9999", icon::STOP_CIRCLE),
                egui::TextStyle::Button.resolve(ui.style()),
                ui.visuals().text_color(),
            )
            .size()
            .x
            + 2. * ui.spacing().button_padding.x;
        let button = ui.add_enabled(
            available && !self.client.busy(),
            egui::Button::new(label).min_size(vec2(width, 0.)),
        );
        if widgets::hint(button, help).clicked() {
            let network_id = self.network.network_id.clone();
            let command = if self.running {
                Command::StopSpeedTest { network_id }
            } else {
                Command::StartSpeedTest {
                    network_id,
                    peer: None,
                }
            };
            self.client.send(command);
        }
    }

    pub(super) fn cell(&self, ui: &mut Ui, rect: Rect, peer: &Device<'_>) {
        if !ui.is_rect_visible(rect) {
            return;
        }
        let reading = self.network.speed.peers.get(peer.id);
        let supported = self.capable(peer.id);
        let ready = self.network.active && peer.online && supported;
        let can_start = ready && !self.running && !self.client.busy();
        let id = ui.make_persistent_id(("test peer speed", &self.network.network_id, peer.id));
        let r = ui.interact(rect, id, Sense::click());
        let r = if can_start {
            r.on_hover_cursor(egui::CursorIcon::PointingHand)
        } else {
            r
        };
        let v = ui.visuals();
        let color = if ready {
            v.hyperlink_color
        } else {
            v.weak_text_color()
        };
        if can_start && (r.hovered() || r.has_focus()) {
            ui.painter()
                .rect_filled(rect.shrink(1.), 3., v.widgets.hovered.weak_bg_fill);
        }
        paint_reading(ui, rect, reading, ready, color);
        let hint = tooltip(peer, reading, supported, self.running);
        r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, can_start, &hint));
        if widgets::hint(r, &hint).clicked() && can_start {
            self.client.send(Command::StartSpeedTest {
                network_id: self.network.network_id.clone(),
                peer: Some(peer.id.into()),
            });
        }
    }
}

fn paint_reading(
    ui: &Ui,
    rect: Rect,
    reading: Option<&SpeedPeerReport>,
    ready: bool,
    color: Color32,
) {
    let painter = ui.painter_at(rect);
    let Some(test) = reading else {
        let glyph = if ready { icon::GAUGE } else { "—" };
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            glyph,
            FontId::proportional(16.),
            color,
        );
        return;
    };
    let v = ui.visuals();
    let small = egui::TextStyle::Small.resolve(ui.style());
    let label = |s: &str, ink: Color32| {
        painter.text(rect.center(), Align2::CENTER_CENTER, s, small.clone(), ink);
    };
    match test.phase {
        SpeedPhase::Queued => label("Queued", v.weak_text_color()),
        SpeedPhase::Preparing => {
            label("Starting", color);
            activity(ui, rect, color);
        }
        SpeedPhase::Failed(_) => label(&format!("{} Retry", icon::WARNING), v.error_fg_color),
        SpeedPhase::Cancelled => label(&format!("{} Retry", icon::ARROW_CLOCKWISE), color),
        SpeedPhase::Download | SpeedPhase::Upload | SpeedPhase::Done => {
            // Reserve the same two slots for idle, live and completed readings.
            let inline = rect.width() >= WIDTH - 1.;
            let font = if inline {
                small.clone()
            } else {
                FontId::proportional(small.size.min(rect.height() * 0.46))
            };
            for (offset, arrow, rate, phase) in [
                (-0.23, icon::ARROW_DOWN, test.down, SpeedPhase::Download),
                (0.23, icon::ARROW_UP, test.up, SpeedPhase::Upload),
            ] {
                let measuring = test.phase == phase;
                let value = rate.map_or_else(
                    || if measuring { "…" } else { "—" }.to_owned(),
                    compact_rate,
                );
                let ink = if measuring {
                    v.hyperlink_color
                } else if rate.is_some() {
                    v.text_color()
                } else {
                    v.weak_text_color()
                };
                painter.text(
                    rect.center()
                        + if inline {
                            vec2(rect.width() * offset, 0.)
                        } else {
                            vec2(0., rect.height() * offset)
                        },
                    Align2::CENTER_CENTER,
                    format!("{arrow} {value}"),
                    font.clone(),
                    ink,
                );
            }
            if test.phase != SpeedPhase::Done {
                activity(ui, rect, color);
            }
        }
    }
}

// A moving mark indicates an active phase even before the first receiver
// report arrives. Repaint only visible, active cells.
fn activity(ui: &Ui, rect: Rect, color: Color32) {
    let bar = rect.shrink2(vec2(4., 1.));
    let width = bar.width() * 0.24;
    let t = ui.input(|i| (i.time % 1.) as f32);
    let x = bar.left() + (bar.width() - width) * (t * std::f32::consts::PI).sin().powi(2);
    ui.painter_at(rect).line_segment(
        [pos2(x, bar.bottom()), pos2(x + width, bar.bottom())],
        (1., color),
    );
    ui.ctx().request_repaint_after(Duration::from_millis(80));
}

// Round positive lower bounds down so the displayed minimum is supported by
// the measurement, including near a precision or unit boundary.
fn detailed_rate(rate: SpeedRate, divisor: f64) -> String {
    let value = rate.bps as f64 / divisor;
    if rate.lower_bound {
        format!("at least {:.2}", (value * 100.).floor() / 100.)
    } else {
        format!("{value:.2}")
    }
}

fn compact_rate(rate: SpeedRate) -> String {
    let (unit, precision, suffix) = match rate.bps {
        0 => return "0".into(),
        1..10_000 => return "<0.01".into(),
        10_000..1_000_000 => (1e6, 2, ""),
        1_000_000..10_000_000 => (1e6, 1, ""),
        10_000_000..10_000_000_000 => (1e6, 0, ""),
        _ => (1e9, 0, "k"),
    };
    format!("{:.precision$}{suffix}", rate.bps as f64 / unit)
}

fn tooltip(
    peer: &Device<'_>,
    test: Option<&SpeedPeerReport>,
    supported: bool,
    running: bool,
) -> String {
    let mut hint = format!("Speed to {}", peer.name());
    if let Some(test) = test {
        let phase = match &test.phase {
            SpeedPhase::Queued => "Waiting for the previous exit",
            SpeedPhase::Preparing => "Opening the data channel",
            SpeedPhase::Download => "Measuring download",
            SpeedPhase::Upload => "Measuring upload",
            SpeedPhase::Done => "Completed",
            SpeedPhase::Failed(error) => error.as_str(),
            SpeedPhase::Cancelled => "Stopped",
        };
        hint.push_str(&format!("\n{phase}"));
        for (label, rate) in [("Download", test.down), ("Upload", test.up)] {
            if let Some(rate) = rate {
                let (divisor, suffix) = if rate.bps < 1_000_000 {
                    (1000., "kbit/s")
                } else {
                    (1e6, "Mbit/s")
                };
                hint.push_str(&format!(
                    "\n{label}  {} {suffix}",
                    detailed_rate(rate, divisor)
                ));
            }
        }
        if let Some(path) = &test.path {
            hint.push_str(&format!("\nPath at start  {path}"));
        }
        if test.elapsed_ms > 0 || test.bytes > 0 {
            hint.push_str(&format!(
                "\n{} transferred in {:.1} s",
                format::bytes(test.bytes as f64),
                f64::from(test.elapsed_ms) / 1000.
            ));
        }
        if test.measured_at_unix_secs > 0
            && matches!(
                test.phase,
                SpeedPhase::Done | SpeedPhase::Failed(_) | SpeedPhase::Cancelled
            )
            && let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH)
        {
            let age = now.as_secs().saturating_sub(test.measured_at_unix_secs);
            let age = if age < 60 {
                format!("{age} s")
            } else if age < 3600 {
                format!("{} min", age / 60)
            } else {
                format!("{} h", age / 3600)
            };
            hint.push_str(&format!("\nMeasured {age} ago"));
        }
    }
    if !peer.online {
        hint.push_str("\nPeer is offline.");
    } else if !supported {
        hint.push_str("\nNo compatible speed-test session with this peer.");
    } else if !running {
        hint.push_str(if test.is_some() {
            "\nTap to test again."
        } else {
            "\nTap to test download and upload."
        });
    }
    hint
}
