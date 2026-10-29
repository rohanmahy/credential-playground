//! Build script: the Tauri context and the app command permissions.

// An explicit app manifest: every command gets an `allow-<command>`
// permission and is denied unless capabilities/main.json grants it.
// Keep this list equal to `tokenator_desktop::COMMANDS` (tests/config.rs).
const COMMANDS: &[&str] = &[
    "engine_init",
    "engine_info",
    "engine_detect",
    "engine_open",
    "engine_render",
    "engine_parse_edit",
    "engine_issue",
    "engine_redact",
    "engine_disclose",
    "engine_present",
    "engine_validate",
    "engine_lint",
    "engine_resign",
    "engine_tamper",
    "engine_reencode",
    "engine_edit_disclosures",
    "engine_decode_embedded",
    "engine_key_import",
    "engine_key_export",
    "engine_key_public",
    "engine_key_generate",
    "engine_key_thumbprint",
    "engine_key_assign_kid",
    "engine_key_to_jwk",
    "engine_key_to_cwk",
    "engine_datetime",
    "engine_registry_lookup",
    "engine_registry_merge",
    "fetch_url",
    "open_file",
    "save_file",
    "read_clipboard",
    "write_clipboard",
    "registry_cache_get",
    "registry_cache_put",
    "registry_cache_clear",
];

fn main() {
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    if let Err(e) = tauri_build::try_build(attributes) {
        eprintln!("tauri-build: {e:#}");
        std::process::exit(1);
    }
}
