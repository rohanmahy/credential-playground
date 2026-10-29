//! The `tokenator` binary: runs the desktop app.

// No console window on Windows release builds (harmless on macOS).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tokenator_desktop::run();
}
