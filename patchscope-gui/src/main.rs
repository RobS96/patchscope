//! patchscope desktop app.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod backend;
#[cfg(test)]
mod ui_tests;

use eframe::egui;
use std::sync::Arc;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("patchscope")
            .with_inner_size([1100.0, 760.0])
            .with_min_inner_size([720.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "patchscope",
        options,
        Box::new(|_cc| {
            Ok(Box::new(app::App::new(
                Arc::new(backend::RealBackend),
                patchscope_core::paths::policy_file(),
            )))
        }),
    )
}
