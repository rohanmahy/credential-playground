//! The CBOR tree: NodeIds, kinds, annotations, decoded views, main-pane
//! ranges (from the EDN printer's span map), and hex rows.
//!
//! One walk over the decoded item decides everything that depends on the
//! format: which byte strings are decoded (only at defined locations,
//! #15), which keys are registered, and how paths become NodeIds. The EDN
//! printer and `annotated_hex` then get the same embedded paths and
//! comments, so the two panes line up row for row.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use tokenator_cbor::{Item, Value, Width};
use tokenator_edn::{
    Annotator, EmbeddedCbor, EmbeddedWarning, HexOptions, Path, PathSegment, PrintOptions, SpanMap,
};
use tokenator_registry::{Context, Family, Label};

use crate::annotate::Notes;
use crate::cbor::{abs_span, bstr_contents, compact_edn, exact_sequence, int_of, label_of, map_get};
use crate::datetime::cbor_hint;
use crate::dto::common::{ByteRange, NodeId, RawRange};
use crate::dto::document::{
    ByteStyle, Diagnostic, HexRow, HexRowKind, Layout, Node, NodeKind, Severity, ViewOptions,
};
use crate::util::{TextIndex, u32_of};

/// Where an item sits, as far as the format defines it.
#[derive(Clone, Debug)]
pub(crate) enum Role {
    /// No format meaning.
    Plain,
    /// A COSE_Sign1, maybe inside envelope tags (61, 18), which fold into
    /// this node.
    Sign1,
    /// A header map (protected or unprotected).
    Header(Context),
    /// A top-level claims map (CWT/KBT payload, claim set).
    Claims,
    /// A `cnf` map.
    Cnf,
    /// A COSE_Key map.
    Key,
    /// A COSE_KeySet array.
    KeySet,
    /// `sd_claims`: an array of disclosure byte strings.
    SdClaims,
    /// A byte string whose content is CBOR at a defined location; the first
    /// embedded item gets the inner role.
    Embedded(Box<Role>),
}

/// The result of a walk plus rendering.
pub(crate) struct CborView {
    /// The tree.
    pub(crate) tree: Node,
    /// The main pane text.
    pub(crate) text: String,
    /// Hex rows over the raw buffer.
    pub(crate) rows: Vec<HexRow>,
    /// Problems found while walking (manual decodes).
    pub(crate) diagnostics: Vec<Diagnostic>,
    /// `(start, end, id)` of every node with a raw range, in pre-order.
    pub(crate) index: Vec<(usize, usize, NodeId)>,
}

/// Comments by path, for the printer and the hex view.
struct Comments<'c>(&'c BTreeMap<Path, String>);

impl Annotator for Comments<'_> {
    fn comment(&self, path: &Path, _item: &Item<'_>) -> Option<Cow<'_, str>> {
        self.0.get(path).map(|s| Cow::Borrowed(s.as_str()))
    }
}

struct Walker<'v> {
    notes: Notes<'v>,
    view: &'v ViewOptions,
    /// For EDN claim sets: the user's own text decides what is embedded.
    edn_spans: Option<&'v SpanMap>,
    /// The whole raw buffer.
    bytes: &'v [u8],
    /// Every path to the node id it belongs to (rows).
    ids: BTreeMap<Path, NodeId>,
    /// The outermost path of each node (main ranges).
    primary: BTreeMap<NodeId, Path>,
    comments: BTreeMap<Path, String>,
    embedded: Vec<Path>,
    diagnostics: Vec<Diagnostic>,
    index: Vec<(usize, usize, NodeId)>,
}

fn kind_of(item: &Item<'_>) -> NodeKind {
    match item.value {
        Value::Uint(_) | Value::Nint(_) => NodeKind::Integer,
        Value::Bytes(_) => NodeKind::Bytes,
        Value::Text(_) => NodeKind::Text,
        Value::Array(_) => NodeKind::Array,
        Value::Map(_) => NodeKind::Map,
        Value::Tag(..) => NodeKind::Tag,
        Value::Bool(_) => NodeKind::Bool,
        Value::Null => NodeKind::Null,
        Value::Undefined => NodeKind::Undefined,
        Value::Simple(_) => NodeKind::Simple,
        Value::Float(..) => NodeKind::Float,
    }
}

fn leaf(id: NodeId, kind: NodeKind, label: String) -> Node {
    Node {
        id,
        kind,
        label,
        annotation: None,
        main: None,
        raw: None,
        key: None,
        time: None,
        sd: None,
        children: Vec::new(),
    }
}

/// The NodeId segment of map entry `i` with key `k` (TEST-PLAN §4).
fn key_segment(k: &Item<'_>, i: usize, seen: &mut BTreeSet<String>) -> (String, String) {
    let edn = compact_edn(k);
    let fallback = format!("~i{i}");
    if matches!(k.value, Value::Array(_) | Value::Map(_)) || edn.chars().count() > 64 {
        return (fallback, edn);
    }
    let seg = crate::dto::common::escape_segment(&edn);
    if seen.insert(seg.clone()) {
        (seg, edn)
    } else {
        (fallback, edn)
    }
}

fn registry_context(role: &Role, map: &Item<'_>) -> Option<Context> {
    match role {
        Role::Header(c) => Some(c.clone()),
        Role::Claims => Some(Context::Claims),
        Role::Cnf => Some(Context::Cnf),
        Role::Key => Some(Context::Key {
            kty: map_get(map, 1).and_then(int_of).map(Label::Int),
        }),
        _ => None,
    }
}

/// The role of the value of entry `key` in a map with `role`.
fn entry_role(role: &Role, key: &Item<'_>) -> Role {
    match (role, int_of(key)) {
        (Role::Header(Context::ProtectedHeader), Some(13)) => Role::Sign1,
        (Role::Header(Context::UnprotectedHeader), Some(17)) => Role::SdClaims,
        (Role::Claims, Some(8)) => Role::Cnf,
        (Role::Cnf, Some(1)) => Role::Key,
        _ => Role::Plain,
    }
}

const PARTS: [&str; 4] = ["protected", "unprotected", "payload", "signature"];

impl Walker<'_> {
    fn register(&mut self, path: &Path, id: &NodeId) {
        self.ids.insert(path.clone(), id.clone());
        self.primary.entry(id.clone()).or_insert_with(|| path.clone());
    }

    fn node(
        &mut self,
        item: &Item<'_>,
        path: Path,
        id: NodeId,
        label: String,
        base: usize,
        role: &Role,
    ) -> Node {
        if let (Role::Sign1, Value::Tag(18 | 61, inner)) = (role, &item.value) {
            // Envelope tags fold into the token's node.
            self.register(&path, &id);
            let mut n = self.node(inner, path.child(PathSegment::TagContent), id, label, base, role);
            n.raw = abs_span(item, base).map(|(s, e)| RawRange {
                start: u32_of(s),
                end: u32_of(e),
                ..RawRange::default()
            });
            if let (Some((s, e)), Some(last)) = (abs_span(item, base), self.index.iter().position(|(_, _, i)| *i == n.id)) {
                if let Some(entry) = self.index.get_mut(last) {
                    *entry = (s, e, n.id.clone());
                }
            }
            return n;
        }
        self.register(&path, &id);
        let span = abs_span(item, base);
        if let Some((s, e)) = span {
            self.index.push((s, e, id.clone()));
        }
        let mut n = leaf(id, kind_of(item), label);
        n.raw = span.map(|(s, e)| RawRange {
            start: u32_of(s),
            end: u32_of(e),
            ..RawRange::default()
        });
        match &item.value {
            Value::Array(items) => {
                let sign1 = matches!(role, Role::Sign1) && items.len() >= 4;
                for (i, child) in items.iter().enumerate() {
                    let (name, child_role) = match (sign1, i) {
                        (true, 0) => (
                            PARTS[0],
                            Role::Embedded(Box::new(Role::Header(Context::ProtectedHeader))),
                        ),
                        (true, 1) => (PARTS[1], Role::Header(Context::UnprotectedHeader)),
                        (true, 2) => (PARTS[2], Role::Embedded(Box::new(Role::Claims))),
                        (true, 3) => (PARTS[3], Role::Plain),
                        _ => ("", if matches!(role, Role::KeySet) { Role::Key } else if matches!(role, Role::SdClaims) { Role::Embedded(Box::new(Role::Plain)) } else { Role::Plain }),
                    };
                    let (cid, label) = if name.is_empty() {
                        (n.id.index(i), i.to_string())
                    } else {
                        (n.id.child(name), name.to_owned())
                    };
                    let mut c = self.node(child, path.child(PathSegment::Index(i)), cid, label, base, &child_role);
                    if !name.is_empty() {
                        c.kind = NodeKind::Part;
                    }
                    n.children.push(c);
                }
            }
            Value::Map(entries) => {
                let ctx = registry_context(role, item);
                let mut seen = BTreeSet::new();
                for (i, (k, v)) in entries.iter().enumerate() {
                    let (seg, edn) = key_segment(k, i, &mut seen);
                    let eid = n.id.push_raw(&seg);
                    let kpath = path.child(PathSegment::Key(i));
                    let vpath = path.child(PathSegment::Value(i));
                    let knode = self.node(k, kpath.clone(), eid.key(), edn.clone(), base, &Role::Plain);
                    let vrole = entry_role(role, k);
                    let mut vnode = self.node(v, vpath.clone(), eid, edn, base, &vrole);
                    if let (Some(ctx), Some(label)) = (&ctx, label_of(k))
                        && let Some(note) = self.notes.lookup(Family::Cose, ctx, &label, label_of(v).as_ref())
                    {
                        vnode.annotation = Some(note.annotation);
                        self.comments.insert(kpath, note.key_comment);
                        if let Some(c) = note.value_comment {
                            self.comments.insert(vpath, c);
                        }
                    }
                    if matches!(role, Role::Claims) && matches!(int_of(k), Some(4..=6)) && vnode.time.is_none() {
                        vnode.time = cbor_hint(v, self.view.now);
                    }
                    vnode.key = Some(Box::new(knode));
                    n.children.push(vnode);
                }
            }
            Value::Tag(tag, inner) => {
                let tagged = self.edn_spans.is_none() && self.view.decoded_views;
                let inner_role = match (tagged, tag) {
                    (true, 24 | 63) => Role::Embedded(Box::new(Role::Plain)),
                    _ => Role::Plain,
                };
                let c = self.node(inner, path.child(PathSegment::TagContent), n.id.push_raw("~t"), "content".to_owned(), base, &inner_role);
                if matches!(tag, 0 | 1) {
                    n.time = cbor_hint(item, self.view.now);
                }
                n.children.push(c);
            }
            Value::Bytes(_) => self.bytes_children(item, &path, &mut n, base, role),
            _ => {}
        }
        if item.width == Width::Indefinite && matches!(item.value, Value::Bytes(_) | Value::Text(_)) {
            for (i, chunk) in item.chunks.iter().enumerate() {
                let c = self.node(chunk, path.child(PathSegment::Chunk(i)), n.id.push_raw(&format!("~c{i}")), format!("chunk {i}"), base, &Role::Plain);
                n.children.push(c);
            }
        }
        n
    }

    /// Decoded views of a byte string: at defined locations, on request
    /// (`manual_decode`), or where the user wrote `<<…>>` (EDN claim sets).
    fn bytes_children(&mut self, item: &Item<'_>, path: &Path, n: &mut Node, base: usize, role: &Role) {
        let Some((start, end)) = bstr_contents(item, base) else {
            return;
        };
        let Some(content) = self.bytes.get(start..end) else {
            return;
        };
        let manual = self.view.manual_decode.contains(&n.id);
        if manual {
            self.manual_diagnostics(start, end, &n.id);
        }
        let expand = match self.edn_spans {
            Some(spans) => spans.get(&path.child(PathSegment::Embedded(0))).is_some(),
            None => {
                manual
                    || (matches!(role, Role::Embedded(_))
                        && self.view.decoded_views
                        && !self.view.hide_decoded.contains(&n.id))
            }
        };
        if !expand {
            return;
        }
        let Some(items) = exact_sequence(content) else {
            return;
        };
        let inner = match role {
            Role::Embedded(inner) => inner.as_ref().clone(),
            _ => Role::Plain,
        };
        self.embedded.push(path.clone());
        for (j, child) in items.iter().enumerate() {
            let child_role = if j == 0 { inner.clone() } else { Role::Plain };
            let c = self.node(child, path.child(PathSegment::Embedded(j)), n.id.decoded(j), "decoded".to_owned(), start, &child_role);
            n.children.push(c);
        }
    }

    fn manual_diagnostics(&mut self, start: usize, end: usize, id: &NodeId) {
        let range = |s: usize, e: usize| ByteRange {
            start: u32_of(s),
            end: u32_of(e),
        };
        match tokenator_edn::decode_embedded(self.bytes, start..end) {
            Ok(view) => {
                for w in view.warnings {
                    let EmbeddedWarning::TrailingBytes { offset, len } = w else {
                        continue;
                    };
                    self.diagnostics.push(Diagnostic {
                        severity: Severity::Warning,
                        code: "cbor.trailing_bytes".to_owned(),
                        message: format!("{len} byte(s) after the first item"),
                        node_id: Some(id.clone()),
                        main: None,
                        raw: Some(range(offset, offset + len)),
                    });
                }
            }
            Err(e) => self.diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                code: "cbor.decode".to_owned(),
                message: format!("not CBOR: {:?} at byte {}", e.kind, e.offset),
                node_id: Some(id.clone()),
                main: None,
                raw: Some(range(start, end)),
            }),
        }
    }
}

/// The text and span map of the main pane.
pub(crate) enum MainText<'t> {
    /// Print the item as EDN.
    Print,
    /// The user's EDN text and its parse spans (EDN claim sets).
    Given { text: &'t str, spans: &'t SpanMap },
}

/// Walks `item` (decoded from `bytes`) with `role` at the root and renders
/// both panes.
pub(crate) fn build(
    item: &Item<'_>,
    bytes: &[u8],
    role: &Role,
    notes: Notes<'_>,
    view: &ViewOptions,
    main: &MainText<'_>,
) -> CborView {
    let edn_spans = match main {
        MainText::Given { spans, .. } => Some(*spans),
        MainText::Print => None,
    };
    let mut w = Walker {
        notes,
        view,
        edn_spans,
        bytes,
        ids: BTreeMap::new(),
        primary: BTreeMap::new(),
        comments: BTreeMap::new(),
        embedded: Vec::new(),
        diagnostics: Vec::new(),
        index: Vec::new(),
    };
    let mut tree = w.node(item, Path::root(), NodeId::root(), String::new(), 0, role);
    let tagged = edn_spans.is_none() && view.decoded_views;
    let embedded = EmbeddedCbor {
        paths: &w.embedded,
        tagged,
    };
    let comments = Comments(&w.comments);
    let annotator: Option<&dyn Annotator> = if w.comments.is_empty() {
        None
    } else {
        Some(&comments)
    };
    let printed;
    let (text, spans) = match main {
        MainText::Given { text, spans } => (*text, *spans),
        MainText::Print => {
            let opts = PrintOptions {
                layout: match view.layout {
                    Layout::Indented => tokenator_edn::Layout::Indented {
                        indent: usize::try_from(view.indent).unwrap_or(2),
                    },
                    Layout::Compact => tokenator_edn::Layout::Compact,
                },
                embedded_cbor: embedded,
                bytes: match view.byte_style {
                    ByteStyle::Hex => tokenator_edn::ByteStyle::Hex,
                    ByteStyle::Base64 => tokenator_edn::ByteStyle::Base64,
                },
                dt_literals: view.dt_literals,
                annotator,
                ..PrintOptions::new()
            };
            printed = tokenator_edn::print(item, &opts);
            (printed.text.as_str(), &printed.spans)
        }
    };
    let hex = tokenator_edn::annotated_hex(
        item,
        bytes,
        &HexOptions {
            embedded_cbor: embedded,
            annotator,
        },
    );
    let rows: Vec<HexRow> = hex
        .rows
        .iter()
        .map(|r| HexRow {
            node_id: nearest_id(&w.ids, &r.path),
            kind: match r.kind {
                tokenator_edn::HexRowKind::Item => HexRowKind::Item,
                tokenator_edn::HexRowKind::Break => HexRowKind::Break,
            },
            depth: u32_of(r.depth),
            head: ByteRange {
                start: u32_of(r.head.start),
                end: u32_of(r.head.end),
            },
            payload: ByteRange {
                start: u32_of(r.payload.start),
                end: u32_of(r.payload.end),
            },
            description: r.description.clone(),
            comment: r.comment.clone(),
        })
        .collect();
    let index = TextIndex::new(text);
    fill_ranges(&mut tree, &w.primary, spans, &index, &rows);
    CborView {
        tree,
        text: text.to_owned(),
        rows,
        diagnostics: w.diagnostics,
        index: w.index,
    }
}

/// The node id of a path, or of its nearest registered ancestor.
fn nearest_id(ids: &BTreeMap<Path, NodeId>, path: &Path) -> NodeId {
    let mut segs = path.segments().to_vec();
    loop {
        if let Some(id) = ids.get(&Path(segs.clone())) {
            return id.clone();
        }
        if segs.pop().is_none() {
            return NodeId::root();
        }
    }
}

/// Sets main ranges from the span map and row ranges from the rows.
fn fill_ranges(
    tree: &mut Node,
    primary: &BTreeMap<NodeId, Path>,
    spans: &SpanMap,
    index: &TextIndex,
    rows: &[HexRow],
) {
    let mut stack: Vec<&mut Node> = vec![tree];
    while let Some(n) = stack.pop() {
        if let Some(span) = primary.get(&n.id).and_then(|p| spans.get(p)) {
            n.main = Some(index.range(span.text.clone()));
        }
        if let Some(raw) = n.raw.as_mut() {
            raw.row_start = u32_of(rows.partition_point(|r| r.head.start < raw.start));
            raw.row_end = u32_of(rows.partition_point(|r| r.head.start < raw.end));
        }
        if let Some(k) = n.key.as_deref_mut() {
            stack.push(k);
        }
        stack.extend(n.children.iter_mut());
    }
}
