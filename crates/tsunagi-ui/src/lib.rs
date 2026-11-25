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

/// Install the Phosphor icons and bold network title face for both egui clients.
pub fn app_fonts() -> egui::FontDefinitions {
    let mut fonts = egui::FontDefinitions::default();
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    let mut bold = fonts.families[&egui::FontFamily::Proportional].clone();
    bold.insert(0, "Source Sans Pro Bold".into());
    fonts.font_data.insert(
        "Source Sans Pro Bold".into(),
        egui::FontData::from_static(include_bytes!("../fonts/SourceSansPro-Bold.ttf")).into(),
    );
    fonts
        .families
        .insert(egui::FontFamily::Name("Bold".into()), bold);
    fonts
}
