//! The application's picture: the logo drawn in code, in the colour of the
//! state it stands for, so there is no asset to ship or to go missing.
//!
//! It is the same shape as `dist/linux/tsunagi.svg` (a disc, a ring, a dot).

use crate::watch::Health;

/// Normal operation. The colour of the logo itself.
const BLUE: [u8; 3] = [0x2f, 0x80, 0xd8];
/// An exit node is in use.
const GREEN: [u8; 3] = [0x3c, 0xb0, 0x4a];
/// Nothing is connected, or the exit node in use is gone.
const DARK_RED: [u8; 3] = [0x9a, 0x1f, 0x1f];

/// The window application id, which is also the name of the desktop entry
/// (`tsunagi-tray.desktop`). The compositor finds the icon through it.
pub(crate) const APP_ID: &str = "tsunagi-tray";

const SIZE: u32 = 64;
const SAMPLES: u32 = 4;

/// What the logo looks like at a point of its 128 × 128 design, as
/// premultiplied-free RGBA in `0.0..=1.0`.
fn shade(x: f32, y: f32, color: [u8; 3]) -> [f32; 4] {
    let distance = ((x - 64.0).powi(2) + (y - 64.0).powi(2)).sqrt();
    if distance > 56.0 {
        return [0.0; 4];
    }
    let mut pixel = [
        f32::from(color[0]) / 255.0,
        f32::from(color[1]) / 255.0,
        f32::from(color[2]) / 255.0,
    ];
    let mut white = 0.0;
    if (26.5..=33.5).contains(&distance) {
        white = 0.9;
    }
    if distance <= 9.0 {
        white = 1.0;
    }
    for channel in &mut pixel {
        *channel = *channel * (1.0 - white) + white;
    }
    [pixel[0], pixel[1], pixel[2], 1.0]
}

/// The logo as RGBA pixels, antialiased by supersampling.
fn rgba(color: [u8; 3]) -> Vec<u8> {
    let scale = 128.0 / SIZE as f32;
    let mut out = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for py in 0..SIZE {
        for px in 0..SIZE {
            let mut sum = [0.0f32; 4];
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let x = (px as f32 + (sx as f32 + 0.5) / SAMPLES as f32) * scale;
                    let y = (py as f32 + (sy as f32 + 0.5) / SAMPLES as f32) * scale;
                    let [r, g, b, a] = shade(x, y, color);
                    sum[0] += r * a;
                    sum[1] += g * a;
                    sum[2] += b * a;
                    sum[3] += a;
                }
            }
            let count = (SAMPLES * SAMPLES) as f32;
            let alpha = sum[3] / count;
            let unmultiply = if sum[3] > 0.0 { 1.0 / sum[3] } else { 0.0 };
            for channel in &sum[..3] {
                out.push((channel * unmultiply * 255.0).round() as u8);
            }
            out.push((alpha * 255.0).round() as u8);
        }
    }
    out
}

fn colour_of(health: Health) -> [u8; 3] {
    match health {
        Health::Disconnected => DARK_RED,
        Health::Connected => BLUE,
        Health::ExitNode => GREEN,
    }
}

/// The tray icon for a state.
pub(crate) fn tray(health: Health) -> Option<tray_icon::Icon> {
    tray_icon::Icon::from_rgba(rgba(colour_of(health)), SIZE, SIZE).ok()
}

/// The icon of the application's windows.
pub(crate) fn window() -> eframe::egui::IconData {
    eframe::egui::IconData {
        rgba: rgba(BLUE),
        width: SIZE,
        height: SIZE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(pixels: &[u8], x: u32, y: u32) -> [u8; 4] {
        let at = ((y * SIZE + x) * 4) as usize;
        [pixels[at], pixels[at + 1], pixels[at + 2], pixels[at + 3]]
    }

    #[test]
    fn the_logo_is_a_coloured_disc_with_a_white_centre_and_clear_corners() {
        let pixels = rgba(GREEN);
        assert_eq!(pixels.len(), (SIZE * SIZE * 4) as usize);
        assert_eq!(pixel(&pixels, 0, 0)[3], 0, "the corner is transparent");
        let centre = pixel(&pixels, SIZE / 2, SIZE / 2);
        assert_eq!(
            centre,
            [255, 255, 255, 255],
            "the dot in the middle is white"
        );
        // Halfway between the ring and the edge is the colour itself.
        let body = pixel(&pixels, SIZE / 2, SIZE / 2 - (SIZE * 44 / 128));
        assert_eq!(body, [GREEN[0], GREEN[1], GREEN[2], 255]);
    }

    #[test]
    fn each_state_has_its_own_colour() {
        let colours = [
            colour_of(Health::Disconnected),
            colour_of(Health::Connected),
            colour_of(Health::ExitNode),
        ];
        assert_ne!(colours[0], colours[1]);
        assert_ne!(colours[1], colours[2]);
        assert_ne!(colours[0], colours[2]);
    }
}
