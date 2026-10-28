//! Comments added by the printer and the hex view.

use std::borrow::Cow;

use tokenator_cbor::Item;

use crate::path::Path;

/// Supplies a comment for a node, printed as `/ comment /` in front of it.
///
/// tokenator-core adapts the claim/header registry to this trait. Any
/// `Fn(&Path, &Item) -> Option<String>` closure is an `Annotator` too.
///
/// The printer emits the comment so that it always parses as a comment: text
/// containing `/` is written as `/* … */`, and `*/` inside the text is
/// broken up.
pub trait Annotator {
    /// The comment for the node at `path`, or `None` for no comment.
    fn comment(&self, path: &Path, item: &Item<'_>) -> Option<Cow<'_, str>>;
}

impl<F> Annotator for F
where
    F: Fn(&Path, &Item<'_>) -> Option<String>,
{
    fn comment(&self, path: &Path, item: &Item<'_>) -> Option<Cow<'_, str>> {
        self(path, item).map(Cow::Owned)
    }
}
