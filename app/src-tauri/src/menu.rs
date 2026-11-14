//! The native menu bar (SPEC §4, desktop only): File (New Tab, Open
//! File…, From Clipboard, Close Tab), Edit (the predefined items, so
//! copy and paste keep working in the webview), View, Tools, and Help
//! (About; on macOS About sits in the app menu). The web build has none.
//!
//! Items the webview handles are forwarded by id over the Channel the
//! front end hands to [`menu_listen`] (`TauriPlatform.onMenu`). A command
//! with a Channel, not an event, so the webview needs no core event
//! permission.
use std::sync::Mutex;

use tauri::ipc::Channel;
use tauri::menu::{Menu, MenuBuilder, MenuItemBuilder, SubmenuBuilder};
use tauri::{AppHandle, Manager, Runtime, State};

/// The ids of the items forwarded to the webview.
pub const MENU_IDS: &[&str] = &[
    "new_tab",
    "open_file",
    "from_clipboard",
    "close_tab",
    "split_view",
    "raw_pane",
    "datetime",
    "settings",
    "about",
];

/// The webview's Channel for menu ids; the latest `menu_listen` wins (a
/// reload subscribes again).
#[derive(Default)]
pub struct MenuChannel(Mutex<Option<Channel<String>>>);

impl MenuChannel {
    /// Sends `id` to the webview if it is one of [`MENU_IDS`] and someone
    /// listens. Returns whether it was sent.
    pub fn forward(&self, id: &str) -> bool {
        if !MENU_IDS.contains(&id) {
            return false;
        }
        let Ok(guard) = self.0.lock() else {
            return false;
        };
        guard
            .as_ref()
            .is_some_and(|channel| channel.send(id.to_owned()).is_ok())
    }
}

/// `TauriPlatform.onMenu`: menu item ids arrive on `channel` from now on.
#[tauri::command]
pub fn menu_listen(state: State<'_, MenuChannel>, channel: Channel<String>) {
    if let Ok(mut guard) = state.0.lock() {
        *guard = Some(channel);
    }
}

/// Builds the menu bar.
pub fn build<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
    let item = |id: &str, text: &str, accelerator: Option<&str>| {
        let builder = MenuItemBuilder::with_id(id, text);
        match accelerator {
            Some(a) => builder.accelerator(a),
            None => builder,
        }
        .build(app)
    };

    let file = SubmenuBuilder::new(app, "File")
        .item(&item("new_tab", "New Tab", Some("CmdOrCtrl+T"))?)
        .item(&item("open_file", "Open File…", Some("CmdOrCtrl+O"))?)
        .item(&item("from_clipboard", "From Clipboard", None)?)
        .separator()
        .item(&item("close_tab", "Close Tab", Some("CmdOrCtrl+W"))?);
    #[cfg(not(target_os = "macos"))]
    let file = file.separator().quit();
    let file = file.build()?;

    let edit = SubmenuBuilder::new(app, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;

    let view = SubmenuBuilder::new(app, "View")
        .item(&item("split_view", "Split View", None)?)
        .item(&item("raw_pane", "Raw Pane", None)?)
        .separator()
        .fullscreen()
        .build()?;

    let tools = SubmenuBuilder::new(app, "Tools")
        .item(&item("datetime", "Date/time", None)?)
        .item(&item("settings", "Settings…", None)?)
        .build()?;

    let about = item("about", "About The Tokenator", None)?;
    let menu = MenuBuilder::new(app);
    #[cfg(target_os = "macos")]
    let menu = menu.item(
        &SubmenuBuilder::new(app, "The Tokenator")
            .item(&about)
            .separator()
            .services()
            .separator()
            .hide()
            .hide_others()
            .show_all()
            .separator()
            .quit()
            .build()?,
    );
    let menu = menu.item(&file).item(&edit).item(&view).item(&tools);
    #[cfg(target_os = "macos")]
    let menu = menu.item(&SubmenuBuilder::new(app, "Window").minimize().build()?);
    #[cfg(not(target_os = "macos"))]
    let menu = menu.item(&SubmenuBuilder::new(app, "Help").item(&about).build()?);
    menu.build()
}

/// The menu event handler: forwards an item to the webview.
pub fn on_event<R: Runtime>(app: &AppHandle<R>, id: &str) {
    if let Some(channel) = app.try_state::<MenuChannel>() {
        channel.forward(id);
    }
}
