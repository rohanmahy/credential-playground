//! The registry cache: one file in the app data dir, the ONLY data the app
//! persists (SPEC §1, §7). Nothing else in this crate writes to disk except
//! `save_file` to the path the user picked.
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use tauri::State;
use tokenator_core::Bytes;

use crate::error::{PlatformError, PlatformErrorKind};

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
        RegistryCacheFile {
            path: dir.into().join(RegistryCacheFile::FILE_NAME),
        }
    }

    /// The cache file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The cached snapshot; `None` when there is none.
    pub fn get(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error("reading the registry cache", &e)),
        }
    }

    /// Replaces the snapshot (creating the dir if needed).
    pub fn put(&self, snapshot: &[u8]) -> Result<(), PlatformError> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| PlatformError::new(PlatformErrorKind::Io, "no cache directory"))?;
        std::fs::create_dir_all(dir)
            .map_err(|e| io_error("creating the registry cache directory", &e))?;
        let tmp = dir.join(format!("{}.tmp", RegistryCacheFile::FILE_NAME));
        let written = std::fs::File::create(&tmp)
            .and_then(|mut f| {
                f.write_all(snapshot)?;
                f.sync_all()
            })
            .and_then(|()| std::fs::rename(&tmp, &self.path));
        written.map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            io_error("writing the registry cache", &e)
        })
    }

    /// Removes the snapshot; no error when absent.
    pub fn clear(&self) -> Result<(), PlatformError> {
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != ErrorKind::NotFound => {
                Err(io_error("removing the registry cache", &e))
            }
            _ => Ok(()),
        }
    }
}

fn io_error(what: &str, e: &std::io::Error) -> PlatformError {
    PlatformError::new(PlatformErrorKind::Io, format!("{what}: {e}"))
}

/// The cached registry snapshot, or `null`.
#[tauri::command(rename_all = "snake_case")]
pub async fn registry_cache_get(
    state: State<'_, RegistryCacheFile>,
) -> Result<Option<Bytes>, PlatformError> {
    Ok(state.get()?.map(Bytes))
}

/// Caches a snapshot from `engine_registry_merge`.
#[tauri::command(rename_all = "snake_case")]
pub async fn registry_cache_put(
    state: State<'_, RegistryCacheFile>,
    snapshot: Bytes,
) -> Result<(), PlatformError> {
    state.put(&snapshot)
}

/// Removes the cached snapshot.
#[tauri::command(rename_all = "snake_case")]
pub async fn registry_cache_clear(
    state: State<'_, RegistryCacheFile>,
) -> Result<(), PlatformError> {
    state.clear()
}
