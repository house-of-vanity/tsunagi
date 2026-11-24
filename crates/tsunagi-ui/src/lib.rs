//! Shared presentation for the egui clients.
pub mod about;
pub mod client;
pub mod devices;
mod exit;
pub mod format;
pub mod home;
pub mod listeners;
pub mod stats;
mod table;
pub mod vip;
mod vip_status;

/// Install the tray's regular Phosphor glyphs alongside egui's standard fonts.
pub fn app_fonts() -> egui::FontDefinitions {
    let mut fonts = egui::FontDefinitions::default();
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    fonts
}
