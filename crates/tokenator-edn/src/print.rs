//! Items to EDN text.

use std::fmt;

use tokenator_cbor::Item;

use crate::annotate::Annotator;
use crate::spans::SpanMap;

/// Overall layout of the printed text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Layout {
    /// One line: `[1, {"a": 2}]`, with `, ` and `: ` separators.
    #[default]
    Compact,
    /// Every element of a non-empty array, map, embedded sequence, or
    /// streamstring on its own line, indented by `indent` spaces per level,
    /// closing delimiter on its own line, no trailing commas. A map entry is
    /// `key: value` on one line (a container value opens on that line). A tag
    /// is `N(` directly followed by its content and `)` after the content's
    /// last character. Empty containers stay `[]`, `{}`, `[_ ]`.
    Indented {
        /// Spaces per nesting level.
        indent: usize,
    },
}

/// When to emit encoding indicators (`_i`, `_0`..`_3`, `_`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EncodingIndicators {
    /// Only where the encoding differs from preferred serialization with
    /// definite lengths, so the output re-encodes to the original bytes.
    #[default]
    NonPreferred,
    /// On every item that has an argument width (`[_i 1_i]`, `1.5_1`).
    Always,
    /// Never: the data-model view. Indefinite containers print as definite
    /// and indefinite strings as one string.
    Never,
}

/// When to show a byte string as embedded CBOR `<<…>>`. Only definite-length
/// byte strings qualify; chunks of indefinite-length strings never do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EmbeddedCbor {
    /// Always as a byte string.
    #[default]
    Off,
    /// If the bytes decode as exactly one array, map, or tag, or if the byte
    /// string is the content of tag 24 or 63 and decodes as exactly one item.
    Containers,
    /// If the bytes decode as exactly one item of any kind.
    AnyItem,
}

/// How to print byte strings that are not shown as embedded CBOR.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ByteStyle {
    /// `h'0102'` (lowercase hex).
    #[default]
    Hex,
    /// `b64'AQI'` (base64url, no padding).
    Base64,
}

/// How to print indefinite-length strings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IndefiniteStringStyle {
    /// `(_ "a", "b")`; no chunks: `''_` / `""_`.
    #[default]
    Streamstring,
    /// `ilts<<"a", "b">>` / `ilbs<<h'01'>>`.
    AppExtension,
}

/// Options for [`print`]. [`Default`] is [`PrintOptions::new`].
#[derive(Clone, Copy)]
pub struct PrintOptions<'a> {
    /// Compact or indented.
    pub layout: Layout,
    /// When to emit encoding indicators.
    pub encoding_indicators: EncodingIndicators,
    /// When to render byte strings as `<<…>>`.
    pub embedded_cbor: EmbeddedCbor,
    /// How to render other byte strings.
    pub bytes: ByteStyle,
    /// How to render indefinite-length strings.
    pub indefinite_strings: IndefiniteStringStyle,
    /// Escape every non-ASCII character in text strings as `\uXXXX`
    /// (surrogate pairs above U+FFFF), lowercase hex.
    pub ascii: bool,
    /// Print tag 1 as `DT'…'` (whole seconds and fractions) where that
    /// re-encodes exactly; otherwise as a plain tag.
    pub dt_literals: bool,
    /// Print tags 52/54 holding an address or `[prefix-length, address]` as
    /// `IP'…'` where that re-encodes exactly.
    pub ip_literals: bool,
    /// Print `999([prefix, [args…]])` as `prefix'…'` / `prefix<<…>>` where
    /// that re-encodes exactly and the prefix is not a built-in extension.
    pub unresolved_as_prefixed: bool,
    /// Adds `/ comment /` in front of nodes.
    pub annotator: Option<&'a dyn Annotator>,
}

impl PrintOptions<'_> {
    /// The defaults: compact, indicators only where needed, `h''`,
    /// streamstrings, UTF-8 text, no `DT''`/`IP''`, opaque extensions
    /// printed as prefixed literals, no annotator.
    pub fn new() -> Self {
        PrintOptions {
            layout: Layout::Compact,
            encoding_indicators: EncodingIndicators::NonPreferred,
            embedded_cbor: EmbeddedCbor::Off,
            bytes: ByteStyle::Hex,
            indefinite_strings: IndefiniteStringStyle::Streamstring,
            ascii: false,
            dt_literals: false,
            ip_literals: false,
            unresolved_as_prefixed: true,
            annotator: None,
        }
    }

    /// [`PrintOptions::new`] with [`Layout::Indented`].
    pub fn indented(indent: usize) -> Self {
        PrintOptions {
            layout: Layout::Indented { indent },
            ..PrintOptions::new()
        }
    }
}

impl Default for PrintOptions<'_> {
    fn default() -> Self {
        PrintOptions::new()
    }
}

impl fmt::Debug for PrintOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrintOptions")
            .field("layout", &self.layout)
            .field("encoding_indicators", &self.encoding_indicators)
            .field("embedded_cbor", &self.embedded_cbor)
            .field("bytes", &self.bytes)
            .field("indefinite_strings", &self.indefinite_strings)
            .field("ascii", &self.ascii)
            .field("dt_literals", &self.dt_literals)
            .field("ip_literals", &self.ip_literals)
            .field("unresolved_as_prefixed", &self.unresolved_as_prefixed)
            .field("annotator", &self.annotator.is_some())
            .finish()
    }
}

/// Printed EDN and where each node ended up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// The EDN text.
    pub text: String,
    /// One entry per node of the item tree, plus embedded items that are
    /// shown as `<<…>>`, in pre-order. Chunks of an indefinite string get
    /// entries when printed as chunks. Nodes inside an item printed as a
    /// single prefixed literal (`DT'…'`, `IP'…'`, an unresolved extension)
    /// share that literal's text range.
    pub spans: SpanMap,
}

/// Prints `item` as EDN.
///
/// Map entries are printed in arrival order. With
/// [`EncodingIndicators::NonPreferred`] or [`EncodingIndicators::Always`],
/// `encode(&parse(&text)?, Preserve) == encode(item, Preserve)` for every
/// item (widths too narrow for their value count as the preferred width,
/// as in the encoder).
pub fn print(item: &Item<'_>, options: &PrintOptions<'_>) -> Rendered {
    unimplemented!()
}
