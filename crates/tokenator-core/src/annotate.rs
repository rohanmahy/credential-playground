//! Registry annotations: the adapter from `tokenator-registry` to node
//! [`Annotation`]s and EDN comments.

use tokenator_registry::{Annotator, Context, Entry, Family, Label, Registry};

use crate::dto::document::{Annotation, SpecLink};

/// Spec links as hover text: `display_text()`, so no draft revisions.
pub(crate) fn spec_links(entry: &Entry) -> Vec<SpecLink> {
    entry
        .reference
        .iter()
        .map(|r| SpecLink {
            text: r.display_text(),
            url: r.url.clone(),
        })
        .collect()
}

/// The registry, or nothing when annotations are off.
#[derive(Clone, Copy)]
pub(crate) struct Notes<'r> {
    registry: Option<&'r Registry>,
}

/// What [`Notes::lookup`] found for one map entry.
pub(crate) struct Note {
    /// For the node.
    pub(crate) annotation: Annotation,
    /// The EDN comment in front of the key.
    pub(crate) key_comment: String,
    /// The EDN comment in front of the value (a registered value name).
    pub(crate) value_comment: Option<String>,
}

impl<'r> Notes<'r> {
    pub(crate) fn new(registry: &'r Registry, on: bool) -> Notes<'r> {
        Notes {
            registry: on.then_some(registry),
        }
    }

    /// The annotation of the entry `key: value` in `ctx`, if registered.
    pub(crate) fn lookup(
        &self,
        family: Family,
        ctx: &Context,
        key: &Label,
        value: Option<&Label>,
    ) -> Option<Note> {
        let reg = self.registry?;
        let entry = reg.entry(family, ctx, key)?;
        let value_entry = value.and_then(|v| reg.value_entry(family, ctx, key, v));
        Some(Note {
            annotation: Annotation {
                name: entry.name.clone(),
                description: entry.description.clone(),
                value_name: value_entry.map(|e| e.name.clone()),
                spec: spec_links(entry),
            },
            key_comment: reg.display_name(family, ctx, key)?.to_owned(),
            value_comment: value
                .and_then(|v| reg.value_name(family, ctx, key, v).map(str::to_owned)),
        })
    }
}
