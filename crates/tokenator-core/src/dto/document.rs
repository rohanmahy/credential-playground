//! The document model shared by the main pane, the raw pane, and the tree.

use serde::{Deserialize, Serialize};

use super::common::{ByteRange, Bytes, NodeId, RawRange, TextRange};
use super::detect::{Kind, Layer};

/// An opened (or derived) credential, claim set, or COSE_Key, with
/// everything the UI needs to show it. See `TEST-PLAN.md` §3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Document {
    /// What it is.
    pub kind: Kind,
    /// Outer transport layers around `bytes`, outermost first (never the
    /// COSE tags, which stay in `bytes`). Empty for derived documents.
    pub layers: Vec<Layer>,
    /// The credential bytes (token text, CBOR item with tags, claim set).
    pub bytes: Bytes,
    /// Whether the kind carries a signature.
    pub signed: bool,
    /// Signed content changed without re-signing.
    pub signature_stale: bool,
    /// The node tree (root id `""`).
    pub tree: Node,
    /// The main pane.
    pub main: Rendered,
    /// The raw pane.
    pub raw: RawView,
    /// SD disclosures in input order (empty when not SD).
    pub disclosures: Vec<DisclosureInfo>,
    /// Digest slots no disclosure fills (decoys or withheld claims).
    pub undisclosed: Vec<SlotInfo>,
    /// Parse problems and warnings.
    pub diagnostics: Vec<Diagnostic>,
}

/// The main pane text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Rendered {
    /// JSON for JOSE and JSON claim sets, EDN otherwise.
    pub language: Language,
    /// The text.
    pub text: String,
    /// Number of lines (`text.lines()`, at least 1).
    pub line_count: u32,
}

/// Main pane language.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// JSON.
    Json,
    /// CBOR extended diagnostic notation.
    Edn,
}

/// One node of the tree shared by both panes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Node {
    /// Path-based id (`TEST-PLAN.md` §4).
    pub id: NodeId,
    /// What the node is.
    pub kind: NodeKind,
    /// Short tree label: part name, member name, CBOR key EDN, or index.
    pub label: String,
    /// Registry annotation of the key (or of the value, for registered
    /// values such as `alg`).
    pub annotation: Option<Annotation>,
    /// Range in the main pane.
    pub main: Option<TextRange>,
    /// Range in the raw pane.
    pub raw: Option<RawRange>,
    /// For a map entry: the key's node (id ending in `~k`).
    pub key: Option<Box<Node>>,
    /// Human-readable time for time-valued nodes.
    pub time: Option<TimeHint>,
    /// SD role of the node.
    pub sd: Option<SdMark>,
    /// Children in arrival order.
    pub children: Vec<Node>,
}

/// What a [`Node`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// The document root of a JOSE view object.
    Document,
    /// A token part (segment, COSE_Sign1 element, disclosure, KB-JWT).
    Part,
    /// A decoded view (`~e`).
    Decoded,
    /// A CBOR map or JSON object.
    Map,
    /// An array.
    Array,
    /// A text string.
    Text,
    /// A byte string.
    Bytes,
    /// A CBOR integer.
    Integer,
    /// A CBOR float.
    Float,
    /// A JSON number (lexeme kept).
    Number,
    /// true/false.
    Bool,
    /// null.
    Null,
    /// CBOR undefined.
    Undefined,
    /// Another CBOR simple value.
    Simple,
    /// A CBOR tag.
    Tag,
}

/// Registry information for a node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Annotation {
    /// Registered name (`kid`, `iss`, `cnf`).
    pub name: String,
    /// Registered description.
    pub description: String,
    /// Name of a registered value (`ES256` for alg `-7`).
    pub value_name: Option<String>,
    /// Specification references (`display_text()`, no draft revisions).
    pub spec: Vec<SpecLink>,
}

/// A specification reference for hover text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SpecLink {
    /// `RFC 7519, Section 4.1.1`, `draft-ietf-spice-sd-cwt, Section 3`.
    pub text: String,
    /// Link with the exact revision.
    pub url: Option<String>,
}

/// Inline date for a time-valued node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct TimeHint {
    /// Whole epoch seconds (floor).
    pub epoch: i64,
    /// RFC 3339 in UTC.
    pub rfc3339: String,
    /// Relative to `ViewOptions.now`, when given (`"in 3 h 12 m"`).
    pub relative: Option<String>,
}

/// SD role of a node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SdMark {
    /// A digest slot (`_sd` entry, `{"...": d}`, `simple(59)` entry,
    /// `60(d)`), and the disclosure that fills it.
    Slot {
        /// The digest (base64url for JOSE, hex for COSE).
        digest: String,
        /// Index into `Document.disclosures`.
        disclosure: Option<u32>,
    },
    /// The SD-CWT redacted-keys array (`simple(59)`), or a JOSE `_sd` array.
    DigestList,
    /// A disclosure node.
    Disclosure {
        /// Index into `Document.disclosures`.
        index: u32,
    },
}

/// One disclosure in the SD view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct DisclosureInfo {
    /// Input order index.
    pub index: u32,
    /// The disclosure's node.
    pub node_id: NodeId,
    /// Digest (base64url for JOSE, hex for COSE).
    pub digest: String,
    /// Salt (the string for JOSE, hex for COSE).
    pub salt: String,
    /// Claim name (JOSE) or key as compact EDN (COSE); `None` for array
    /// elements and decoys.
    pub claim: Option<String>,
    /// The value as compact JSON / EDN (empty for decoys).
    pub value: String,
    /// A COSE decoy disclosure (`[salt]`).
    pub decoy: bool,
    /// Matching result.
    pub status: DisclosureStatus,
    /// The digest slot it fills.
    pub slot: Option<NodeId>,
}

/// How a disclosure matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    /// Fills exactly one slot.
    Matched,
    /// Fills no slot.
    Unmatched,
    /// Same digest as an earlier disclosure.
    Duplicate,
    /// Does not decode.
    Malformed,
    /// Property named `_sd` or `...`.
    ForbiddenName,
    /// Property in an array slot or element in an `_sd` slot.
    KindMismatch,
    /// The name already exists next to the slot.
    NameCollision,
}

/// A digest slot without a disclosure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SlotInfo {
    /// The slot's node.
    pub node_id: NodeId,
    /// The digest.
    pub digest: String,
    /// An array element slot rather than a claim slot.
    pub array_element: bool,
}

/// A parse problem or warning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Diagnostic {
    /// How bad.
    pub severity: Severity,
    /// Stable dotted code (`jose.base64`, `cbor.trailing_bytes`, …).
    pub code: String,
    /// Human-readable text.
    pub message: String,
    /// The node concerned.
    pub node_id: Option<NodeId>,
    /// Where in the main pane (for edit errors, the error position).
    pub main: Option<TextRange>,
    /// Where in the raw pane buffer.
    pub raw: Option<ByteRange>,
}

/// Diagnostic severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational.
    Info,
    /// Accepted but suspicious.
    Warning,
    /// Could not be read.
    Error,
}

/// The raw pane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RawView {
    /// Annotated hex, one row per data item or break.
    Hex {
        /// The buffer the rows index.
        bytes: Bytes,
        /// Rows in byte order.
        rows: Vec<HexRow>,
    },
    /// JOSE segments.
    Segments {
        /// Segments in token order.
        segments: Vec<Segment>,
    },
    /// No raw pane (JSON claim sets).
    None,
}

/// One annotated hex row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct HexRow {
    /// The node the row belongs to (`""` for envelope tag heads).
    pub node_id: NodeId,
    /// Item or break.
    pub kind: HexRowKind,
    /// Indentation depth.
    pub depth: u32,
    /// Head bytes (whole item for scalars).
    pub head: ByteRange,
    /// Content bytes of a definite string (empty at `head.end` otherwise).
    pub payload: ByteRange,
    /// `unsigned(1)`, `bytes(4)`, `map(2)`, `break`, …
    pub description: String,
    /// Registry comment.
    pub comment: Option<String>,
}

/// What a [`HexRow`] stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum HexRowKind {
    /// A data item or string chunk.
    Item,
    /// The `0xff` ending an indefinite-length item.
    Break,
}

/// One JOSE segment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Segment {
    /// The part node (`protected`, `disclosures/2`, `kb/signature`, …).
    pub node_id: NodeId,
    /// `Protected header`, `Payload`, `Signature`, `Disclosure 2`, …
    pub label: String,
    /// Range in `Document.bytes`.
    pub range: ByteRange,
    /// The segment text.
    pub text: String,
    /// The separator after it in compact form (`.` or `~`).
    pub separator: Option<String>,
}

/// How to render a document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct ViewOptions {
    /// EDN layout.
    pub layout: Layout,
    /// Indent width for indented layouts.
    pub indent: u32,
    /// Show decoded views at the format-defined locations.
    pub decoded_views: bool,
    /// Byte string nodes whose decoded view is toggled off.
    pub hide_decoded: Vec<NodeId>,
    /// Byte string nodes the user chose to decode as CBOR.
    pub manual_decode: Vec<NodeId>,
    /// Registry comments and hover annotations.
    pub annotations: bool,
    /// How byte strings that are not decoded are printed.
    pub byte_style: ByteStyle,
    /// Print tag 1 as `DT'…'` where exact.
    pub dt_literals: bool,
    /// Layout of decoded JOSE JSON.
    pub json_layout: JsonLayout,
    /// Clock for relative times in [`TimeHint`]s.
    pub now: Option<i64>,
    /// Local offset east of UTC, in minutes, for display.
    pub local_offset_minutes: i32,
}

impl Default for ViewOptions {
    fn default() -> ViewOptions {
        ViewOptions {
            layout: Layout::Indented,
            indent: 2,
            decoded_views: true,
            hide_decoded: Vec::new(),
            manual_decode: Vec::new(),
            annotations: true,
            byte_style: ByteStyle::Hex,
            dt_literals: false,
            json_layout: JsonLayout::Original,
            now: None,
            local_offset_minutes: 0,
        }
    }
}

/// EDN layout.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// One element per line.
    #[default]
    Indented,
    /// One line.
    Compact,
}

/// Byte string style.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum ByteStyle {
    /// `h'…'`.
    #[default]
    Hex,
    /// `b64'…'`.
    Base64,
}

/// Layout of decoded JOSE JSON.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum JsonLayout {
    /// The decoded text verbatim.
    #[default]
    Original,
    /// Re-indented for display.
    Pretty,
}
