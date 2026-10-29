//! The registry cache: one file in the app data dir, the ONLY data the app
//! persists (SPEC §1, §7). Nothing else in this crate writes to disk except
//! `save_file` to the path the user picked.
use std::path::{Path, PathBuf};

use tauri::State;
use tokenator_core::Bytes;

use crate::error::PlatformError;

/// `<dir>/registry-snapshot.bin`, written atomically (a temp file in the
/// same dir, then a rename).
pub struct RegistryCacheFile {
    path: PathBuf,
}

impl RegistryCacheFile {
    /// The cache file's name.
    pub const FILE_NAME: &'static str = "registry-snapshot.bin";

    /// The cache in `dir` (the app data dir in the app).
    pub fn in_dir(dir: impl Into<PathBuf>) -> RegistryCacheFile {
        let _ = dir.into();
        unimplemented!("RegistryCacheFile::in_dir")
    }

    /// The cache file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The cached snapshot; `None` when there is none.
    pub fn get(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        unimplemented!("RegistryCacheFile::get")
    }

    /// Replaces the snapshot (creating the dir if needed).
    pub fn put(&self, snapshot: &[u8]) -> Result<(), PlatformError> {
        let _ = snapshot;
        unimplemented!("RegistryCacheFile::put")
    }

    /// Removes the snapshot; no error when absent.
    pub fn clear(&self) -> Result<(), PlatformError> {
        unimplemented!("RegistryCacheFile::clear")
    }
}

/// The cached registry snapshot, or `null`.
#[tauri::command(rename_all = "snake_case")]
pub async fn registry_cache_get(
    state: State<'_, RegistryCacheFile>,
) -> Result<Option<Bytes>, PlatformError> {
    let _ = state;
    unimplemented!("registry_cache_get")
}

/// Caches a snapshot from `engine_registry_merge`.
#[tauri::command(rename_all = "snake_case")]
pub async fn registry_cache_put(
    state: State<'_, RegistryCacheFile>,
    snapshot: Bytes,
) -> Result<(), PlatformError> {
    let _ = (state, snapshot);
    unimplemented!("registry_cache_put")
}

/// Removes the cached snapshot.
#[tauri::command(rename_all = "snake_case")]
pub async fn registry_cache_clear(
    state: State<'_, RegistryCacheFile>,
) -> Result<(), PlatformError> {
    let _ = state;
    unimplemented!("registry_cache_clear")
}
