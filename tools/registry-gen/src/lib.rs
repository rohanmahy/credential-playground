//! Build-time generator for the `tokenator-registry` snapshot.
//!
//! Reads the four IANA registry XML files (default `testdata/iana/`) and the
//! local additions (`crates/tokenator-registry/data/local-additions.json`),
//! builds a [`Registry`], and writes its snapshot to
//! `crates/tokenator-registry/data/snapshot.json`. All parsing lives in
//! `tokenator-registry`; this crate only does file I/O and argument handling.
//!
//! ```text
//! cargo run -p registry-gen -- [--input-dir DIR] [--local FILE] [--out FILE]
//! ```

use std::fmt;
use std::path::PathBuf;

use tokenator_registry::{LocalAdditions, Registry, RegistryError, RegistryId};

/// The generator inputs, already read into memory.
#[derive(Clone, Copy, Debug)]
pub struct Inputs<'a> {
    /// `cwt.xml`.
    pub cwt: &'a [u8],
    /// `cose.xml`.
    pub cose: &'a [u8],
    /// `jwt.xml`.
    pub jwt: &'a [u8],
    /// `jose.xml`.
    pub jose: &'a [u8],
    /// `local-additions.json`.
    pub local_additions: &'a str,
}

/// Builds the registry from `inputs` and returns its snapshot bytes.
/// Deterministic: the same inputs always produce the same bytes.
pub fn generate(inputs: &Inputs<'_>) -> Result<Vec<u8>, GenError> {
    build(inputs)?
        .to_snapshot()
        .map_err(|source| GenError::Registry {
            registry: None,
            source,
        })
}

/// Builds the [`Registry`] from `inputs` (what [`generate`] serializes).
pub fn build(inputs: &Inputs<'_>) -> Result<Registry, GenError> {
    let local =
        LocalAdditions::parse(inputs.local_additions).map_err(|source| GenError::Registry {
            registry: None,
            source,
        })?;
    let iana = [
        (RegistryId::Cwt, inputs.cwt),
        (RegistryId::Cose, inputs.cose),
        (RegistryId::Jwt, inputs.jwt),
        (RegistryId::Jose, inputs.jose),
    ];
    Registry::build(&iana, local).map_err(|source| GenError::Registry {
        registry: match &source {
            RegistryError::Xml { registry, .. } => Some(*registry),
            RegistryError::WrongRegistry { expected, .. } => Some(*expected),
            RegistryError::Snapshot(_) | RegistryError::LocalAdditions(_) => None,
        },
        source,
    })
}

/// Command-line arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    /// Directory containing `cwt.xml`, `cose.xml`, `jwt.xml`, `jose.xml`.
    pub input_dir: PathBuf,
    /// Path to the local-additions file.
    pub local_additions: PathBuf,
    /// Output snapshot path.
    pub out: PathBuf,
}

impl Args {
    /// Workspace root, resolved at compile time.
    pub const WORKSPACE_ROOT: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

    /// Parses arguments (without the program name). Flags: `--input-dir`,
    /// `--local`, `--out`, each taking a path. Missing flags default to the
    /// in-repo paths under [`Self::WORKSPACE_ROOT`]. Unknown flags or a flag
    /// without a value give [`GenError::Usage`].
    pub fn parse<I>(args: I) -> Result<Self, GenError>
    where
        I: IntoIterator<Item = String>,
    {
        let root = PathBuf::from(Self::WORKSPACE_ROOT);
        let mut parsed = Self {
            input_dir: root.join("testdata/iana"),
            local_additions: root.join("crates/tokenator-registry/data/local-additions.json"),
            out: root.join("crates/tokenator-registry/data/snapshot.json"),
        };
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let slot = match flag.as_str() {
                "--input-dir" => &mut parsed.input_dir,
                "--local" => &mut parsed.local_additions,
                "--out" => &mut parsed.out,
                other => return Err(GenError::Usage(format!("unexpected argument {other:?}"))),
            };
            *slot = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| GenError::Usage(format!("{flag} needs a value")))?;
        }
        Ok(parsed)
    }
}

/// Reads the inputs named by `args`, generates, and writes the snapshot.
/// Returns the number of entries written.
pub fn run(args: &Args) -> Result<usize, GenError> {
    let read = |path: PathBuf| std::fs::read(&path).map_err(|source| GenError::Io { path, source });
    let cwt = read(args.input_dir.join("cwt.xml"))?;
    let cose = read(args.input_dir.join("cose.xml"))?;
    let jwt = read(args.input_dir.join("jwt.xml"))?;
    let jose = read(args.input_dir.join("jose.xml"))?;
    let local = read(args.local_additions.clone())?;
    let local_additions = std::str::from_utf8(&local).map_err(|e| GenError::Io {
        path: args.local_additions.clone(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;
    let inputs = Inputs {
        cwt: &cwt,
        cose: &cose,
        jwt: &jwt,
        jose: &jose,
        local_additions,
    };
    let registry = build(&inputs)?;
    let bytes = registry
        .to_snapshot()
        .map_err(|source| GenError::Registry {
            registry: None,
            source,
        })?;
    std::fs::write(&args.out, bytes).map_err(|source| GenError::Io {
        path: args.out.clone(),
        source,
    })?;
    Ok(registry.len())
}

/// Generator errors.
#[derive(Debug)]
pub enum GenError {
    /// Parsing an input failed. `registry` is `None` for the local additions.
    Registry {
        /// Which IANA input failed, if it was one.
        registry: Option<RegistryId>,
        /// The underlying error.
        source: RegistryError,
    },
    /// Reading or writing a file failed.
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// Bad command-line arguments.
    Usage(String),
}

impl fmt::Display for GenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry {
                registry: Some(id),
                source,
            } => write!(f, "{}: {source}", id.xml_id()),
            Self::Registry {
                registry: None,
                source,
            } => write!(f, "local additions: {source}"),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Usage(m) => write!(f, "usage: {m}"),
        }
    }
}

impl std::error::Error for GenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Usage(_) => None,
        }
    }
}
