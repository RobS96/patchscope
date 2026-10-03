//! patchscope desktop app.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod backend;
#[cfg(test)]
mod ui_tests;

use eframe::egui;
use std::sync::Arc;

fn run(renderer: eframe::Renderer) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("patchscope")
            .with_inner_size([1100.0, 760.0])
            .with_min_inner_size([720.0, 480.0]),
        renderer,
        // Reuse the event loop, so the OpenGL fallback can open a window
        // after a failed Direct3D attempt (winit allows one loop per process).
        run_and_return: true,
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

fn main() -> eframe::Result {
    // Direct3D 12 first on Windows: it works without a GPU (WARP), where
    // the OpenGL driver of a VM or Remote Desktop session is too old.
    #[cfg(windows)]
    match run(eframe::Renderer::Wgpu) {
        Ok(()) => return Ok(()),
        Err(e) => eprintln!("patchscope: Direct3D renderer unavailable ({e}); trying OpenGL"),
    }
    run(eframe::Renderer::Glow)
}
