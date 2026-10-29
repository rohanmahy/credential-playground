//! The `tokenator` binary: runs the desktop app.

// No console window on Windows release builds (a no-op on macOS and Linux).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tokenator_desktop::run();
}
