//! Application-extensions (prefixed literals such as `h'…'` and `dt'…'`).

use std::fmt;

use tokenator_cbor::Item;

/// Tag number for an app-extension literal that no registered extension
/// resolved (draft-ietf-cbor-edn-literals-27 §5.1, "CPA999").
///
/// The content is `[prefix, [args…]]`: the prefix as written, then the
/// arguments. A string literal (`cri'…'` or ``cri`…` ``) has one text
/// string argument holding the decoded string content; a sequence literal
/// (`cri<<…>>`) has one argument per item, each with its encoding indicators.
pub const UNRESOLVED_EXTENSION_TAG: u64 = 999;

/// Why an app-extension rejected its input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtError(pub String);

impl fmt::Display for ExtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ExtError {}

/// An app-extension: turns the input of a prefixed literal into an item.
///
/// The input is a CBOR sequence. A string literal (`p'…'` or ``p`…` ``)
/// arrives as a single text string holding the decoded string content
/// (escapes processed, CRs removed); a sequence literal `p<<…>>` arrives as
/// its items, which keep their encoding indicators. As the draft requires,
/// an extension cannot tell `p'x'` from `p<<"x">>`.
pub trait AppExtension: Send + Sync {
    /// The app-extension identifier: lowercase, `[a-z][a-z0-9-]*`.
    fn name(&self) -> &str;

    /// Evaluates the literal. `uppercase` is true when the prefix was the
    /// all-uppercase variant (`DT`, `IP`); extensions without one return an
    /// error for it.
    fn evaluate(&self, args: &[Item<'static>], uppercase: bool) -> Result<Item<'static>, ExtError>;
}

/// The set of app-extensions a parse can use.
///
/// [`Extensions::builtin`] (also the [`Default`]) holds `h`, `b64`, `dt`,
/// `ip`, `hash`, `b1`, `t1`, `ilbs`, `ilts`, and `float`.
pub struct Extensions {
    exts: Vec<Box<dyn AppExtension>>,
}

impl Extensions {
    /// No extensions at all (every prefixed literal is unknown).
    pub fn empty() -> Extensions {
        Extensions { exts: Vec::new() }
    }

    /// The built-in extensions.
    pub fn builtin() -> Extensions {
        unimplemented!()
    }

    /// Adds an extension, replacing any existing one with the same name.
    pub fn register(&mut self, ext: Box<dyn AppExtension>) {
        unimplemented!()
    }

    /// The extension registered under `name` (lowercase identifier).
    pub fn get(&self, name: &str) -> Option<&dyn AppExtension> {
        unimplemented!()
    }

    /// Names of the registered extensions, in registration order.
    pub fn names(&self) -> Vec<&str> {
        unimplemented!()
    }

    /// Whether `name` is the identifier of a built-in extension.
    pub fn is_builtin_name(name: &str) -> bool {
        unimplemented!()
    }
}

impl Default for Extensions {
    fn default() -> Extensions {
        Extensions::builtin()
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.exts.iter().map(|e| e.name()))
            .finish()
    }
}
